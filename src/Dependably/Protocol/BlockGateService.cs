using System.Globalization;
using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Decides whether a proxy fetch should be blocked. Policies in priority order:
///   1. Manual block flag (operator-set on the version row) — always wins.
///   2. Manual allow flag (operator override) — short-circuits to Allowed, skipping the
///      automatic gates below.
///   3. Release-age gate — blocks versions younger than the tenant's
///      <c>MinReleaseAgeHours</c> hold, measured against the upstream publish timestamp.
///      Fail-open when the timestamp is missing (some upstream metadata omits it).
///   4. OSV vulnerability score exceeds the tenant's <c>MaxOsvScoreTolerance</c>.
/// Records the corresponding <c>blocked_manual</c> / <c>blocked_release_age</c> /
/// <c>blocked_vuln_score</c> activity row when a block fires so the dashboard can surface
/// why a download was denied.
/// </summary>
public sealed class BlockGateService
{
    private readonly VulnerabilityRepository _vulns;
    private readonly AuditRepository _audit;

    public BlockGateService(VulnerabilityRepository vulns, AuditRepository audit)
    {
        _vulns = vulns;
        _audit = audit;
    }

    public async Task<BlockDecision> EvaluateAsync(BlockGateRequest request, CancellationToken ct = default)
    {
        if (request.ManualState == "blocked")
        {
            await _audit.LogActivityAsync(
                request.OrgId, request.Ecosystem, request.Purl,
                "blocked_manual", request.UserId, sourceIp: request.SourceIp, ct: ct);
            return BlockDecision.Blocked;
        }
        if (request.ManualState == "allowed")
            return BlockDecision.Allowed;

        // Release-age hold runs ahead of the OSV check so a fresh upload that already trips
        // a CVE still surfaces as "too new" first — the supply-chain story (community hasn't
        // had time to assess this version yet) matches the operator's mental model better
        // than a vuln-score block on a version they would have rejected on age alone.
        if (request.MinReleaseAgeHours is { } minHours && minHours > 0 && request.PublishedAt is { } publishedAt)
        {
            var ageHours = (DateTimeOffset.UtcNow - publishedAt).TotalHours;
            if (ageHours < minHours)
            {
                var publishedIso = publishedAt.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
                var ageRounded = Math.Round(ageHours, 2);
                await _audit.LogActivityAsync(
                    request.OrgId, request.Ecosystem, request.Purl,
                    "blocked_release_age", request.UserId,
                    detail: string.Format(
                        CultureInfo.InvariantCulture,
                        "{{\"published_at\":\"{0}\",\"min_age_hours\":{1},\"age_at_block_hours\":{2}}}",
                        publishedIso, minHours, ageRounded),
                    sourceIp: request.SourceIp, ct: ct);
                return BlockDecision.Blocked;
            }
        }

        if (request.VulnCheckedAt is null)
            return BlockDecision.Allowed;

        var maxScore = await _vulns.GetMaxScoreForVersionAsync(request.VersionId, ct);
        if (!maxScore.HasValue || maxScore.Value <= request.MaxOsvScoreTolerance)
            return BlockDecision.Allowed;

        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_vuln_score", request.UserId,
            detail: $"{{\"max_score\":{maxScore.Value},\"tolerance\":{request.MaxOsvScoreTolerance}}}",
            sourceIp: request.SourceIp, ct: ct);
        return BlockDecision.Blocked;
    }
}

public enum BlockDecision
{
    Allowed,
    Blocked,
}

public sealed record BlockGateRequest(
    string OrgId,
    string Ecosystem,
    string Purl,
    string VersionId,
    string? ManualState,
    DateTimeOffset? VulnCheckedAt,
    string? UserId,
    double MaxOsvScoreTolerance,
    string? SourceIp = null,
    int? MinReleaseAgeHours = null,
    DateTimeOffset? PublishedAt = null);
