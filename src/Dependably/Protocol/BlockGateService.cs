using System.Globalization;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;

namespace Dependably.Protocol;

/// <summary>
/// Decides whether a proxy fetch should be blocked. Policies in priority order:
///   1. Manual block flag (operator-set on the version row) — always wins.
///   2. Manual allow flag (operator override) — short-circuits to Allowed, skipping the
///      automatic gates below.
///   3. Deprecated gate — keyed on the upstream deprecation message (<c>Deprecated</c>) and the
///      tenant's <c>BlockDeprecatedMode</c>. The call site is the discriminator between the two
///      blocking modes: <see cref="EvaluateAsync"/> (this method) runs on the cache-hit / serve
///      path and blocks only <c>block_all</c>; the cache-miss first-fetch path calls
///      <see cref="EvaluateFirstFetchDeprecationAsync"/>, which blocks both <c>block_new</c> and
///      <c>block_all</c> so a brand-new deprecated version is never cached or served. "warn" and
///      "off" let the version through. (Legacy <c>block</c> is treated as <c>block_all</c>.)
///   4. Release-age gate — blocks versions younger than the tenant's
///      <c>MinReleaseAgeHours</c> hold, measured against the upstream publish timestamp.
///      Fail-open when the timestamp is missing (some upstream metadata omits it).
///   5. Malicious-advisory gate — blocks versions linked to an OSV <c>MAL-</c> advisory
///      (OpenSSF malicious-packages feed) when the tenant's <c>BlockMaliciousMode</c> is
///      'block'. Runs ahead of the score gate because MAL advisories usually carry no CVSS
///      score and the score comparison would otherwise never see them.
///   6. KEV gate — blocks versions whose advisories alias a CISA-KEV-listed CVE
///      (exploited-in-the-wild) when the tenant's <c>BlockKevMode</c> is 'block'.
///   7. EPSS gate — blocks when the maximum EPSS exploitation probability across the
///      version's advisories exceeds the tenant's <c>MaxEpssTolerance</c> ceiling.
///   8. OSV vulnerability score exceeds the tenant's <c>MaxOsvScoreTolerance</c>.
/// Records the corresponding <c>blocked_manual</c> / <c>blocked_deprecated</c> /
/// <c>blocked_release_age</c> / <c>blocked_malicious</c> / <c>blocked_kev</c> /
/// <c>blocked_epss</c> / <c>blocked_vuln_score</c> activity row when a block fires so the
/// dashboard can surface why a download was denied.
///
/// Every automatic policy block (everything except <c>blocked_manual</c>, which is already a
/// human decision) additionally upserts a pending <c>quarantine</c> review row, best-effort —
/// a review-queue write failure must never turn a correct 403 into a 500.
/// </summary>
public sealed class BlockGateService
{
    private readonly VulnerabilityRepository _vulns;
    private readonly AuditRepository _audit;
    private readonly QuarantineRepository _quarantine;
    private readonly ILogger<BlockGateService> _logger;

    public BlockGateService(
        VulnerabilityRepository vulns,
        AuditRepository audit,
        QuarantineRepository quarantine,
        ILogger<BlockGateService> logger)
    {
        _vulns = vulns;
        _audit = audit;
        _quarantine = quarantine;
        _logger = logger;
    }

    // Best-effort review-queue write beside each policy block's activity row. Failures are
    // logged and swallowed: the 403 already protects the tenant; losing one review row is
    // recoverable (the next blocked request re-upserts it).
    private async Task QueueForReviewAsync(
        BlockGateRequest request, string gate, string? detail, CancellationToken ct)
    {
        try
        {
            await _quarantine.UpsertPendingAsync(
                request.OrgId, request.Ecosystem, request.Purl, gate, detail,
                string.IsNullOrEmpty(request.VersionId) ? null : request.VersionId, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // deepcode ignore LogForging: Serilog structured parameter — the purl is encoded
            // as a property value, never spliced into the message text.
            _logger.LogWarning(ex,
                "Quarantine review-row upsert failed for {Purl} (gate {Gate}); block still served.",
                request.Purl, gate);
        }
    }

    public async Task<BlockDecision> EvaluateAsync(BlockGateRequest request, CancellationToken ct = default)
    {
        if (request.ManualState == "blocked")
        {
            await _audit.LogActivityAsync(
                request.OrgId, request.Ecosystem, request.Purl,
                "blocked_manual", request.UserId, actorKind: request.ActorKind,
                sourceIp: request.SourceIp, ct: ct);
            return BlockDecision.Blocked;
        }
        if (request.ManualState == "allowed")
        {
            return BlockDecision.Allowed;
        }

        // Cache-hit / serve path: only block_all denies an already-cached deprecated version.
        // block_new lets cached versions keep serving — its blocking happens earlier, on the
        // cache-miss first-fetch path (EvaluateFirstFetchDeprecationAsync).
        if (request.Deprecated is not null && IsBlockAll(request.BlockDeprecatedMode))
        {
            return await RecordDeprecatedBlockAsync(request, ct);
        }

        // Release-age hold runs ahead of the OSV check so a fresh upload that already trips
        // a CVE still surfaces as "too new" first — the supply-chain story (community hasn't
        // had time to assess this version yet) matches the operator's mental model better
        // than a vuln-score block on a version they would have rejected on age alone.
        var ageDecision = await EvaluateReleaseAgeAsync(request, ct);
        if (ageDecision == BlockDecision.Blocked)
        {
            return BlockDecision.Blocked;
        }

        if (request.VulnCheckedAt is null)
        {
            return BlockDecision.Allowed;
        }

        var signals = await _vulns.GetGateSignalsForVersionAsync(request.VersionId, ct);
        return await EvaluateVulnGatesAsync(request, signals, ct);
    }

    // Release-age hold: blocks versions younger than the configured hold period, measured
    // against the upstream publish timestamp. Fail-open when the timestamp is absent.
    private async Task<BlockDecision> EvaluateReleaseAgeAsync(BlockGateRequest request, CancellationToken ct)
    {
        if (request.MinReleaseAgeHours is not { } minHours || minHours <= 0 || request.PublishedAt is not { } publishedAt)
        {
            return BlockDecision.Allowed;
        }

        double ageHours = (DateTimeOffset.UtcNow - publishedAt).TotalHours;
        if (ageHours >= minHours)
        {
            return BlockDecision.Allowed;
        }

        string publishedIso = publishedAt.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
        double ageRounded = Math.Round(ageHours, 2);
        string ageDetail = string.Format(
            CultureInfo.InvariantCulture,
            "{{\"published_at\":\"{0}\",\"min_age_hours\":{1},\"age_at_block_hours\":{2}}}",
            publishedIso, minHours, ageRounded);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_release_age", request.UserId, actorKind: request.ActorKind,
            detail: ageDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "release_age", ageDetail, ct);
        return BlockDecision.Blocked;
    }

    // Evaluates the malicious-advisory, KEV, EPSS, and CVSS score gates in priority order.
    // Called only when vuln data has been checked (VulnCheckedAt is not null).
    private async Task<BlockDecision> EvaluateVulnGatesAsync(
        BlockGateRequest request, VulnGateSignals signals, CancellationToken ct)
    {
        // Malicious-advisory gate runs before the score comparison: MAL- advisories usually
        // carry no CVSS score, so the score aggregate alone would let known malware through.
        // 'warn' and 'off' fall through — the advisory still surfaces in the vuln report UI.
        if (signals.HasMalicious && request.BlockMaliciousMode == "block")
        {
            DependablyMeter.MaliciousBlocks.Add(1,
                new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
            // Advisory ids fetched only on the (rare) block path so the hot-path aggregate
            // stays free of per-row string assembly.
            var malIds = await _vulns.GetMaliciousOsvIdsForVersionAsync(request.VersionId, ct);
            string malDetail = System.Text.Json.JsonSerializer.Serialize(new { osv_ids = malIds });
            await _audit.LogActivityAsync(
                request.OrgId, request.Ecosystem, request.Purl,
                "blocked_malicious", request.UserId, actorKind: request.ActorKind,
                detail: malDetail,
                sourceIp: request.SourceIp, ct: ct);
            await QueueForReviewAsync(request, "malicious", malDetail, ct);
            return BlockDecision.Blocked;
        }

        // KEV gate: exploited-in-the-wild beats any score-based reasoning, so it runs ahead of
        // the EPSS and CVSS comparisons. 'warn' and 'off' fall through.
        if (signals.HasKev && request.BlockKevMode == "block")
        {
            DependablyMeter.KevBlocks.Add(1,
                new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
            var kevIds = await _vulns.GetKevOsvIdsForVersionAsync(request.VersionId, ct);
            string kevDetail = System.Text.Json.JsonSerializer.Serialize(new { osv_ids = kevIds });
            await _audit.LogActivityAsync(
                request.OrgId, request.Ecosystem, request.Purl,
                "blocked_kev", request.UserId, actorKind: request.ActorKind,
                detail: kevDetail,
                sourceIp: request.SourceIp, ct: ct);
            await QueueForReviewAsync(request, "kev", kevDetail, ct);
            return BlockDecision.Blocked;
        }

        // EPSS gate: probability ceiling, same pass-on-equal convention as the CVSS tolerance.
        if (request.MaxEpssTolerance is { } epssTolerance
            && signals.MaxEpss is { } maxEpss && maxEpss > epssTolerance)
        {
            DependablyMeter.EpssBlocks.Add(1,
                new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
            string epssDetail = $"{{\"max_epss\":{maxEpss.ToString(CultureInfo.InvariantCulture)},\"tolerance\":{epssTolerance.ToString(CultureInfo.InvariantCulture)}}}";
            await _audit.LogActivityAsync(
                request.OrgId, request.Ecosystem, request.Purl,
                "blocked_epss", request.UserId, actorKind: request.ActorKind,
                detail: epssDetail,
                sourceIp: request.SourceIp, ct: ct);
            await QueueForReviewAsync(request, "epss", epssDetail, ct);
            return BlockDecision.Blocked;
        }

        if (signals.MaxCvss is not { } maxScore || maxScore <= request.MaxOsvScoreTolerance)
        {
            return BlockDecision.Allowed;
        }

        string scoreDetail = $"{{\"max_score\":{maxScore},\"tolerance\":{request.MaxOsvScoreTolerance}}}";
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_vuln_score", request.UserId, actorKind: request.ActorKind,
            detail: scoreDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "vuln_score", scoreDetail, ct);
        return BlockDecision.Blocked;
    }

    /// <summary>
    /// Cache-miss first-fetch deprecation gate. Blocks a deprecated version under both
    /// <c>block_new</c> and <c>block_all</c> (and legacy <c>block</c>) so a brand-new deprecated
    /// upstream version is never recorded, cached, or served. Called by
    /// <see cref="Storage.ProxyFetchService"/> before it records the version; the broader
    /// <see cref="EvaluateAsync"/> still runs afterwards for the manual / release-age / vuln gates.
    /// </summary>
    public async Task<BlockDecision> EvaluateFirstFetchDeprecationAsync(
        BlockGateRequest request, CancellationToken ct = default)
    {
        if (request.Deprecated is null || !IsAnyDeprecatedBlock(request.BlockDeprecatedMode))
        {
            return BlockDecision.Allowed;
        }

        // First-fetch analog of the manual allow override: this block fires before any version
        // row exists, so there is no manual_block_state to set — an approved review row on the
        // purl is the unblock signal. Checked only when the gate would otherwise deny, so the
        // hot path pays nothing.
        return await _quarantine.HasApprovedForPurlAsync(request.OrgId, request.Purl, ct)
            ? BlockDecision.Allowed
            : await RecordDeprecatedBlockAsync(request, ct);
    }

    // Single home for the deprecated-block side effects (meter + activity row + review row) so
    // the cache-hit and first-fetch paths emit one consistent event shape.
    private async Task<BlockDecision> RecordDeprecatedBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
        DependablyMeter.DeprecatedBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        string detail = $"{{\"deprecated\":{System.Text.Json.JsonSerializer.Serialize(request.Deprecated)}}}";
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_deprecated", request.UserId, actorKind: request.ActorKind,
            detail: detail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "deprecated", detail, ct);
        return BlockDecision.Blocked;
    }

    // 'block_all' denies on every request (cache hit or miss). Legacy 'block' predates the
    // new/all split and had identical deny-everything semantics, so it maps to block_all.
    private static bool IsBlockAll(string? mode) => mode is "block_all" or "block";

    // Any deprecated-blocking mode — used only on the first-fetch path, where block_new and
    // block_all behave identically (both refuse a brand-new deprecated version).
    private static bool IsAnyDeprecatedBlock(string? mode) => mode is "block_new" or "block_all" or "block";
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
    DateTimeOffset? PublishedAt = null,
    /// <summary>
    /// Discriminator persisted alongside <see cref="UserId"/> in <c>activity.actor_kind</c> on
    /// the block-decision rows. Without this, service-token-driven block events would render
    /// as "anonymous" in the audit UI even though they are perfectly authenticated. See
    /// <see cref="Infrastructure.ActorKinds"/>.
    /// </summary>
    string? ActorKind = null,
    /// <summary>Upstream deprecation message from <c>package_versions.deprecated</c>. NULL = not deprecated.</summary>
    string? Deprecated = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_deprecated</c>: 'off' | 'warn' | 'block_new' |
    /// 'block_all' (legacy 'block' is honoured as 'block_all'). 'block_new' blocks only on the
    /// first-fetch path; 'block_all' blocks on every request.
    /// </summary>
    string? BlockDeprecatedMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_malicious</c>: 'off' | 'warn' | 'block'.
    /// Only 'block' denies; 'warn' relies on the vuln report UI surfacing the advisory.
    /// Null (callers that predate the gate) behaves as 'off'.
    /// </summary>
    string? BlockMaliciousMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_kev</c>: 'off' | 'warn' | 'block'. Only 'block'
    /// denies versions whose advisories alias a CISA-KEV-listed CVE. Null behaves as 'off'.
    /// </summary>
    string? BlockKevMode = null,
    /// <summary>
    /// Tenant ceiling from <c>org_settings.max_epss_tolerance</c> (0.0–1.0). Blocks when the
    /// version's maximum EPSS exploitation probability exceeds it. Null = policy off.
    /// </summary>
    double? MaxEpssTolerance = null);
