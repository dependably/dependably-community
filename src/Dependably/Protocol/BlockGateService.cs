using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Decides whether a proxy fetch should be blocked. Two policies in priority order:
///   1. Manual block flag (operator-set on the version row) — always wins.
///   2. OSV vulnerability score exceeds the tenant's <c>MaxOsvScoreTolerance</c>.
/// Records the corresponding <c>blocked_manual</c> / <c>blocked_vuln_score</c> activity
/// row when a block fires so the dashboard can surface why a download was denied.
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
        if (request.ManualState == "allowed" || request.VulnCheckedAt is null)
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
    string? SourceIp = null);
