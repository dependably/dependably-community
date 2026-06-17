using System.Diagnostics.CodeAnalysis;
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
    private readonly TimeProvider _time;

    public BlockGateService(
        VulnerabilityRepository vulns,
        AuditRepository audit,
        QuarantineRepository quarantine,
        ILogger<BlockGateService> logger,
        TimeProvider time)
    {
        _vulns = vulns;
        _audit = audit;
        _quarantine = quarantine;
        _logger = logger;
        _time = time;
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
        // Load vuln signals when the version has been scanned — same condition as today.
        VulnGateSignals? signals = null;
        if (request.VulnCheckedAt is not null)
        {
            signals = await _vulns.GetGateSignalsForVersionAsync(request.VersionId, ct);
        }

        var facts = new VersionFacts(
            ManualState: request.ManualState,
            Deprecated: request.Deprecated,
            PublishedAt: request.PublishedAt,
            Scanned: request.VulnCheckedAt is not null,
            // Download path: use the aggregate signals flag (HasMalicious), not the row flag.
            HasMalicious: signals?.HasMalicious ?? false,
            HasKev: signals?.HasKev ?? false,
            MaxEpss: signals?.MaxEpss,
            MaxCvss: signals?.MaxCvss);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: request.MinReleaseAgeHours,
            BlockDeprecatedMode: request.BlockDeprecatedMode,
            BlockMaliciousMode: request.BlockMaliciousMode,
            BlockKevMode: request.BlockKevMode,
            MaxEpssTolerance: request.MaxEpssTolerance,
            MaxOsvScoreTolerance: request.MaxOsvScoreTolerance);

        var verdict = Evaluate(facts, policy, _time.GetUtcNow());

        if (!verdict.Servable)
        {
            await ApplySideEffectsAsync(verdict.Arm, request, signals, ct);
            return BlockDecision.Blocked;
        }

        return BlockDecision.Allowed;
    }

    // Performs the audit-log, meter, and quarantine side effects for each blocking arm.
    // Called only when the pure core signals a block; routes to the matching side-effect
    // body preserving all existing meter names, event types, and detail JSON shapes.
    private async Task ApplySideEffectsAsync(
        BlockArm arm, BlockGateRequest request, VulnGateSignals? signals, CancellationToken ct)
    {
        switch (arm)
        {
            case BlockArm.Manual:
                await _audit.LogActivityAsync(
                    request.OrgId, request.Ecosystem, request.Purl,
                    "blocked_manual", request.UserId, actorKind: request.ActorKind,
                    sourceIp: request.SourceIp, ct: ct);
                // Manual block is a human decision — no quarantine row needed.
                break;

            case BlockArm.Deprecated:
                await RecordDeprecatedBlockAsync(request, ct);
                break;

            case BlockArm.ReleaseAge:
                var publishedAt = request.PublishedAt!.Value;
                double ageHours = (_time.GetUtcNow() - publishedAt).TotalHours;
                string publishedIso = publishedAt.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
                double ageRounded = Math.Round(ageHours, 2);
                string ageDetail = string.Format(
                    CultureInfo.InvariantCulture,
                    "{{\"published_at\":\"{0}\",\"min_age_hours\":{1},\"age_at_block_hours\":{2}}}",
                    publishedIso, request.MinReleaseAgeHours!.Value, ageRounded);
                await _audit.LogActivityAsync(
                    request.OrgId, request.Ecosystem, request.Purl,
                    "blocked_release_age", request.UserId, actorKind: request.ActorKind,
                    detail: ageDetail,
                    sourceIp: request.SourceIp, ct: ct);
                await QueueForReviewAsync(request, "release_age", ageDetail, ct);
                break;

            case BlockArm.Malicious:
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
                break;

            case BlockArm.Kev:
                DependablyMeter.KevBlocks.Add(1,
                    new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
                // KEV ids fetched only on the block path, same pattern as malicious above.
                var kevIds = await _vulns.GetKevOsvIdsForVersionAsync(request.VersionId, ct);
                string kevDetail = System.Text.Json.JsonSerializer.Serialize(new { osv_ids = kevIds });
                await _audit.LogActivityAsync(
                    request.OrgId, request.Ecosystem, request.Purl,
                    "blocked_kev", request.UserId, actorKind: request.ActorKind,
                    detail: kevDetail,
                    sourceIp: request.SourceIp, ct: ct);
                await QueueForReviewAsync(request, "kev", kevDetail, ct);
                break;

            case BlockArm.Epss:
                DependablyMeter.EpssBlocks.Add(1,
                    new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
                double maxEpss = signals!.MaxEpss!.Value;
                double epssTolerance = request.MaxEpssTolerance!.Value;
                string epssDetail = $"{{\"max_epss\":{maxEpss.ToString(CultureInfo.InvariantCulture)},\"tolerance\":{epssTolerance.ToString(CultureInfo.InvariantCulture)}}}";
                await _audit.LogActivityAsync(
                    request.OrgId, request.Ecosystem, request.Purl,
                    "blocked_epss", request.UserId, actorKind: request.ActorKind,
                    detail: epssDetail,
                    sourceIp: request.SourceIp, ct: ct);
                await QueueForReviewAsync(request, "epss", epssDetail, ct);
                break;

            case BlockArm.VulnScore:
                double maxScore = signals!.MaxCvss!.Value;
                string scoreDetail = $"{{\"max_score\":{maxScore},\"tolerance\":{request.MaxOsvScoreTolerance}}}";
                await _audit.LogActivityAsync(
                    request.OrgId, request.Ecosystem, request.Purl,
                    "blocked_vuln_score", request.UserId, actorKind: request.ActorKind,
                    detail: scoreDetail,
                    sourceIp: request.SourceIp, ct: ct);
                await QueueForReviewAsync(request, "vuln_score", scoreDetail, ct);
                break;
        }
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

    /// <summary>
    /// Pure, synchronous predicate: returns <see langword="true"/> when a version is hard-blocked
    /// by any policy arm that is evaluable from already-loaded per-version state, so the simple-index
    /// renderers can filter an entire version list with a single call per version without per-version
    /// I/O. Delegates to <see cref="Evaluate"/> after projecting the row and settings into
    /// <see cref="VersionFacts"/> and <see cref="BlockPolicy"/> so the policy lives in one place.
    ///
    /// Arms covered (same priority order as <see cref="EvaluateAsync"/>):
    ///   1. Manual block — <c>ManualBlockState == "blocked"</c>.
    ///   2. Deprecated block_all — <c>Deprecated</c> set and policy is <c>block_all</c>/<c>block</c>.
    ///      <c>block_new</c> is NOT included: already-cached deprecated versions still serve under
    ///      that mode, so hiding them from the index would create the opposite inconsistency.
    ///   3. Release-age hold — version is younger than <c>MinReleaseAgeHours</c>. Fail-open when
    ///      <c>PublishedAt</c> is null (same behaviour as <see cref="EvaluateAsync"/>).
    ///   4. Malicious advisory — <c>IsMalicious</c> and policy is <c>block</c>.
    ///   5. KEV gate — <c>HasKev</c> in <paramref name="signals"/> and policy is <c>block</c>.
    ///   6. EPSS ceiling — <c>MaxEpss</c> exceeds <c>MaxEpssTolerance</c>.
    ///   7. CVSS score ceiling — <c>MaxCvss</c> exceeds <c>MaxOsvScoreTolerance</c>.
    ///   Arms 4–7 are skipped when <c>VulnCheckedAt</c> is null (version not yet scanned),
    ///   matching the fail-open behaviour of <see cref="EvaluateAsync"/>.
    ///
    /// Upstream-only (not-yet-cached) versions cannot be filtered here because stored state
    /// does not exist for them — first-fetch dynamic blocks remain listed until first-fetch.
    /// </summary>
    public static bool IsHardBlockedByStoredState(
        PackageVersion v, OrgSettings settings, VulnGateSignals? signals, DateTimeOffset now)
    {
        var facts = new VersionFacts(
            ManualState: v.ManualBlockState,
            Deprecated: v.Deprecated,
            PublishedAt: v.PublishedAt,
            Scanned: v.VulnCheckedAt is not null,
            // Index path: use the pre-computed row flag (IsMalicious), not the aggregate signal.
            HasMalicious: v.IsMalicious,
            HasKev: signals?.HasKev ?? false,
            MaxEpss: signals?.MaxEpss,
            MaxCvss: signals?.MaxCvss);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance);

        return !Evaluate(facts, policy, now).Servable;
    }

    /// <summary>
    /// Pure policy core: maps <see cref="VersionFacts"/> + <see cref="BlockPolicy"/> to a
    /// <see cref="BlockVerdict"/> with no I/O or side effects. Applies the eight arms in
    /// priority order (Manual > Deprecated > ReleaseAge > Malicious > Kev > Epss > VulnScore).
    /// Both <see cref="EvaluateAsync"/> and <see cref="IsHardBlockedByStoredState"/> project
    /// their inputs into these types and delegate here so the policy logic has one home.
    /// </summary>
    public static BlockVerdict Evaluate(VersionFacts facts, BlockPolicy policy, DateTimeOffset now)
    {
        // Arm 1: manual block — always wins.
        if (facts.ManualState == "blocked")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Manual);
        }

        // Manual allow is an operator override that short-circuits all automatic gates.
        if (facts.ManualState == "allowed")
        {
            return new BlockVerdict(Servable: true, Arm: BlockArm.None);
        }

        // Arm 2: deprecated block_all / legacy block — only modes that deny the serve path.
        // block_new is intentionally excluded: it only fires on the first-fetch path and
        // lets already-cached deprecated versions keep serving (and stay listed).
        if (facts.Deprecated is not null && IsBlockAll(policy.BlockDeprecatedMode))
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Deprecated);
        }

        // Arm 3: release-age hold. Fail-open when PublishedAt is absent.
        if (policy.MinReleaseAgeHours is { } minHours && minHours > 0 && facts.PublishedAt is { } publishedAt)
        {
            double ageHours = (now - publishedAt).TotalHours;
            if (ageHours < minHours)
            {
                return new BlockVerdict(Servable: false, Arm: BlockArm.ReleaseAge);
            }
        }

        // Arms 4–7 require vuln data. Scanned false means not yet scanned — fail-open.
        // Extracted into a separate helper so this method stays below the S3776 threshold.
        return EvaluateVulnArms(facts, policy);
    }

    // Arms 4–7: malicious, KEV, EPSS, and CVSS score gates. All require a scanned version row;
    // the caller guards with !facts.Scanned before delegating here.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private static BlockVerdict EvaluateVulnArms(VersionFacts facts, BlockPolicy policy)
    {
        if (!facts.Scanned)
        {
            return new BlockVerdict(Servable: true, Arm: BlockArm.None);
        }

        // Arm 4: malicious advisory. Runs before score comparison; MAL- advisories usually
        // carry no CVSS score so the score gate alone would let known malware through.
        if (facts.HasMalicious && policy.BlockMaliciousMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Malicious);
        }

        // Arms 5–7 need aggregate signals; null signals means no linked advisories — all pass.
        // When HasKev is false and MaxEpss/MaxCvss are both null, no score arm can fire.
        if (!facts.HasKev && facts.MaxEpss is null && facts.MaxCvss is null)
        {
            return new BlockVerdict(Servable: true, Arm: BlockArm.None);
        }

        // Arm 5: KEV gate — exploited-in-the-wild beats score-based reasoning.
        if (facts.HasKev && policy.BlockKevMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Kev);
        }

        // Arm 6: EPSS probability ceiling, pass-on-equal.
        if (policy.MaxEpssTolerance is { } epssTol && facts.MaxEpss is { } maxEpss && maxEpss > epssTol)
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Epss);
        }

        // Arm 7: CVSS score ceiling, pass-on-equal.
        return facts.MaxCvss is { } maxCvss && maxCvss > policy.MaxOsvScoreTolerance
            ? new BlockVerdict(Servable: false, Arm: BlockArm.VulnScore)
            : new BlockVerdict(Servable: true, Arm: BlockArm.None);
    }
}

/// <summary>
/// Identifies which policy arm triggered a block verdict. <see cref="None"/> means the
/// version is servable (no arm fired).
/// </summary>
public enum BlockArm { None, Manual, Deprecated, ReleaseAge, Malicious, Kev, Epss, VulnScore }

/// <summary>
/// Outcome of the pure policy core: whether the version is servable and, if not, which arm
/// triggered the block.
/// </summary>
public readonly record struct BlockVerdict(bool Servable, BlockArm Arm);

/// <summary>
/// Immutable projection of the per-version facts that every policy arm reads. Built from
/// either a DB row (<see cref="BlockGateService.IsHardBlockedByStoredState"/>) or the
/// download-path request (<see cref="BlockGateService.EvaluateAsync"/>).
/// </summary>
public readonly record struct VersionFacts(
    string? ManualState,
    string? Deprecated,
    DateTimeOffset? PublishedAt,
    bool Scanned,
    bool HasMalicious,
    bool HasKev,
    double? MaxEpss,
    double? MaxCvss);

/// <summary>
/// Immutable projection of the tenant policy knobs that every arm reads. Built from
/// <see cref="OrgSettings"/> on the index path or from <see cref="BlockGateRequest"/> on the
/// download path so the pure core is decoupled from both call shapes.
/// </summary>
public readonly record struct BlockPolicy(
    int? MinReleaseAgeHours,
    string? BlockDeprecatedMode,
    string? BlockMaliciousMode,
    string? BlockKevMode,
    double? MaxEpssTolerance,
    double MaxOsvScoreTolerance);

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
