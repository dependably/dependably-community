using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol.Provenance;

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
///   3b. Revoked gate — keyed on <c>RevokedAt</c> (the version was removed upstream) and the
///      tenant's <c>BlockRevokedMode</c>. Only 'block' denies the serve/listing path; 'warn'/'off'
///      surface the badge but keep serving. A revoked version cannot be first-fetched, so this is
///      serve-path only (no first-fetch analog).
///   4. Release-age gate — blocks versions younger than the tenant's
///      <c>MinReleaseAgeHours</c> hold, measured against the upstream publish timestamp.
///      Fail-open when the timestamp is missing (some upstream metadata omits it).
///   5. Malicious-advisory gate — blocks versions linked to an OSV <c>MAL-</c> advisory
///      (OpenSSF malicious-packages feed) when the tenant's <c>BlockMaliciousMode</c> is
///      'block'. Runs ahead of the score gate because MAL advisories usually carry no CVSS
///      score and the score comparison would otherwise never see them.
///   5b. Provenance/signature gate — blocks versions whose <c>ProvenanceStatus</c> is
///      <c>Failed</c>/<c>Unsigned</c> when the tenant's <c>VerifyProvenanceMode</c> is 'block'.
///      Just below malicious (a known-malicious advisory is a stronger reason to deny than a
///      missing signature); independent of scan state.
///   6. KEV gate — blocks versions whose advisories alias a CISA-KEV-listed CVE
///      (exploited-in-the-wild) when the tenant's <c>BlockKevMode</c> is 'block'.
///   7. EPSS gate — blocks when the maximum EPSS exploitation probability across the
///      version's advisories exceeds the tenant's <c>MaxEpssTolerance</c> ceiling.
///   8. OSV vulnerability score exceeds the tenant's <c>MaxOsvScoreTolerance</c>.
///   9. Install-script gate — blocks versions that ship an install/lifecycle script
///      (<c>HasInstallScript</c>) when the tenant's <c>BlockInstallScriptsMode</c> is 'block'.
///      Lowest priority: a vuln/KEV/malicious signal is a stronger reason to deny, so this arm
///      only fires when nothing above it did.
/// Records the corresponding <c>blocked_manual</c> / <c>blocked_deprecated</c> /
/// <c>blocked_release_age</c> / <c>blocked_malicious</c> / <c>blocked_kev</c> /
/// <c>blocked_epss</c> / <c>blocked_vuln_score</c> / <c>blocked_install_script</c> activity row
/// when a block fires so the dashboard can surface why a download was denied.
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
    private readonly InstallScriptAllowlistService _installScriptAllowlist;
    private readonly ILogger<BlockGateService> _logger;
    private readonly TimeProvider _time;

    public BlockGateService(
        VulnerabilityRepository vulns,
        AuditRepository audit,
        QuarantineRepository quarantine,
        InstallScriptAllowlistService installScriptAllowlist,
        ILogger<BlockGateService> logger,
        TimeProvider time)
    {
        _vulns = vulns;
        _audit = audit;
        _quarantine = quarantine;
        _installScriptAllowlist = installScriptAllowlist;
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
        // Load vuln signals when the artifact has been scanned. Route to the global-plane arm
        // when CacheArtifactId is set (proxy path, P3+), otherwise use the per-version arm.
        VulnGateSignals? signals = null;
        if (request.VulnCheckedAt is not null)
        {
            signals = request.CacheArtifactId is not null
                ? await _vulns.GetGateSignalsAsync("cache_artifact", request.CacheArtifactId, ct)
                : await _vulns.GetGateSignalsAsync("package_version", request.VersionId, ct);
        }

        // Resolve install-script allowlist only when the arm could fire: saves a cache lookup on
        // the common path (no install script, or policy is off/warn). The PURL name and version
        // segments are extracted via PurlParser; a parse failure returns false (fail-closed).
        bool installScriptAllowlisted = false;
        if (request.HasInstallScript && request.BlockInstallScriptsMode == "block")
        {
            var parsed = PurlParser.TryParse(request.Purl);
            if (parsed is not null)
            {
                installScriptAllowlisted = await _installScriptAllowlist.IsAllowlistedAsync(
                    request.OrgId, parsed.Ecosystem, parsed.Name, parsed.Version, ct);
            }
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
            MaxCvss: signals?.MaxCvss,
            Origin: request.Origin,
            HasInstallScript: request.HasInstallScript,
            ProvenanceStatus: request.ProvenanceStatus,
            InstallScriptAllowlisted: installScriptAllowlisted,
            RevokedAt: request.RevokedAt);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: request.MinReleaseAgeHours,
            BlockDeprecatedMode: request.BlockDeprecatedMode,
            BlockMaliciousMode: request.BlockMaliciousMode,
            BlockKevMode: request.BlockKevMode,
            MaxEpssTolerance: request.MaxEpssTolerance,
            MaxOsvScoreTolerance: request.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: request.BlockInstallScriptsMode,
            VerifyProvenanceMode: request.VerifyProvenanceMode,
            BlockRevokedMode: request.BlockRevokedMode);

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

            case BlockArm.Revoked:
                await RecordRevokedBlockAsync(request, ct);
                break;

            case BlockArm.ReleaseAge:
                await RecordReleaseAgeBlockAsync(request, ct);
                break;

            case BlockArm.Malicious:
                await RecordMaliciousBlockAsync(request, ct);
                break;

            case BlockArm.Provenance:
                await RecordProvenanceBlockAsync(request, ct);
                break;

            case BlockArm.Kev:
                await RecordKevBlockAsync(request, ct);
                break;

            case BlockArm.Epss:
                await RecordEpssBlockAsync(request, signals!, ct);
                break;

            case BlockArm.VulnScore:
                await RecordVulnScoreBlockAsync(request, signals!, ct);
                break;

            case BlockArm.InstallScript:
                await RecordInstallScriptBlockAsync(request, ct);
                break;
        }
    }

    // Side effects for the release-age arm: computes the age gap, formats the detail JSON,
    // logs the activity row, and queues a review entry.
    private async Task RecordReleaseAgeBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
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
    }

    // Side effects for the malicious arm: fetches the OSV advisory ids (only on the block
    // path so the hot-path aggregate stays free of per-row string assembly), increments the
    // meter, logs the activity row, and queues a review entry.
    private async Task RecordMaliciousBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
        DependablyMeter.MaliciousBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        // Route to the cache_artifact arm when CacheArtifactId is set (proxy serve path),
        // otherwise use the per-version arm.
        var malIds = request.CacheArtifactId is not null
            ? await _vulns.GetMaliciousOsvIdsForCacheArtifactAsync(request.CacheArtifactId, ct)
            : await _vulns.GetMaliciousOsvIdsForVersionAsync(request.VersionId, ct);
        string malDetail = System.Text.Json.JsonSerializer.Serialize(new { osv_ids = malIds });
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_malicious", request.UserId, actorKind: request.ActorKind,
            detail: malDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "malicious", malDetail, ct);
    }

    // Side effects for the KEV arm: fetches advisory ids (block path only), increments the
    // meter, logs the activity row, and queues a review entry.
    private async Task RecordKevBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
        DependablyMeter.KevBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        // Route to the cache_artifact arm when CacheArtifactId is set (proxy serve path).
        var kevIds = request.CacheArtifactId is not null
            ? await _vulns.GetKevOsvIdsForCacheArtifactAsync(request.CacheArtifactId, ct)
            : await _vulns.GetKevOsvIdsForVersionAsync(request.VersionId, ct);
        string kevDetail = System.Text.Json.JsonSerializer.Serialize(new { osv_ids = kevIds });
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_kev", request.UserId, actorKind: request.ActorKind,
            detail: kevDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "kev", kevDetail, ct);
    }

    // Side effects for the EPSS arm: formats the probability + tolerance detail JSON,
    // increments the meter, logs the activity row, and queues a review entry.
    private async Task RecordEpssBlockAsync(
        BlockGateRequest request, VulnGateSignals signals, CancellationToken ct)
    {
        DependablyMeter.EpssBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        double maxEpss = signals.MaxEpss!.Value;
        double epssTolerance = request.MaxEpssTolerance!.Value;
        string epssDetail = $"{{\"max_epss\":{maxEpss.ToString(CultureInfo.InvariantCulture)},\"tolerance\":{epssTolerance.ToString(CultureInfo.InvariantCulture)}}}";
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_epss", request.UserId, actorKind: request.ActorKind,
            detail: epssDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "epss", epssDetail, ct);
    }

    // Side effects for the CVSS-score arm: formats the max-score + tolerance detail JSON,
    // logs the activity row, and queues a review entry.
    private async Task RecordVulnScoreBlockAsync(
        BlockGateRequest request, VulnGateSignals signals, CancellationToken ct)
    {
        double maxScore = signals.MaxCvss!.Value;
        string scoreDetail = $"{{\"max_score\":{maxScore},\"tolerance\":{request.MaxOsvScoreTolerance}}}";
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_vuln_score", request.UserId, actorKind: request.ActorKind,
            detail: scoreDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "vuln_score", scoreDetail, ct);
    }

    // Side effects for the install-script arm: formats the script-kind detail JSON,
    // increments the meter, logs the activity row, and queues a review entry.
    private async Task RecordInstallScriptBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
        DependablyMeter.InstallScriptBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        string scriptDetail = System.Text.Json.JsonSerializer.Serialize(
            new { install_script_kind = request.InstallScriptKind });
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_install_script", request.UserId, actorKind: request.ActorKind,
            detail: scriptDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "install_script", scriptDetail, ct);
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

    /// <summary>
    /// Records the side effects of a provenance/signature block (meter + tenant-level audit event
    /// forwarded to SIEM + per-version activity row + review-queue row) so the cache-miss
    /// first-fetch path and the serve path emit one consistent event shape. Called by
    /// <see cref="Storage.ProxyFetchService"/> before it records the version (fail closed) and by
    /// <see cref="ApplySideEffectsAsync"/> on the serve path.
    /// </summary>
    public async Task RecordProvenanceBlockAsync(BlockGateRequest request, CancellationToken ct = default)
    {
        DependablyMeter.ProvenanceBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        string provDetail = System.Text.Json.JsonSerializer.Serialize(
            new { provenance_status = request.ProvenanceStatus });
        // Tenant-level security event: forwarded to SIEM via the audit_log path.
        await _audit.LogAsync(
            "provenance_verification_failed",
            orgId: request.OrgId,
            actorId: request.UserId,
            actorKind: request.ActorKind,
            ecosystem: request.Ecosystem,
            purl: request.Purl,
            detail: provDetail,
            sourceIp: request.SourceIp,
            ct: ct);
        // Per-version activity row so the dashboard surfaces why the download was denied.
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_provenance", request.UserId, actorKind: request.ActorKind,
            detail: provDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "provenance", provDetail, ct);
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

    // Side effects for the revoked arm: meter + per-version activity row + review-queue row,
    // mirroring the deprecated arm. The version was removed upstream, so the detail carries the
    // first-observed removal timestamp.
    private async Task RecordRevokedBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
        DependablyMeter.RevokedBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        string detail = System.Text.Json.JsonSerializer.Serialize(
            new { revoked_at = request.RevokedAt?.ToString("yyyy-MM-ddTHH:mm:ssZ") });
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_revoked", request.UserId, actorKind: request.ActorKind,
            detail: detail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "revoked", detail, ct);
    }

    // 'block_all' denies on every request (cache hit or miss). Legacy 'block' predates the
    // new/all split and had identical deny-everything semantics, so it maps to block_all.
    private static bool IsBlockAll(string? mode) => mode is "block_all" or "block";

    // Any deprecated-blocking mode — used only on the first-fetch path, where block_new and
    // block_all behave identically (both refuse a brand-new deprecated version).
    private static bool IsAnyDeprecatedBlock(string? mode) => mode is "block_new" or "block_all" or "block";

    // Upstream-derived origins are subject to the release-age cooldown. Hosted and local_only
    // versions are exempt: their PublishedAt is the local push timestamp, not an upstream
    // release date, so the cooldown would self-block an org's own fresh publishes.
    // proxy, mixed, and null (legacy rows predating the origin column) remain eligible.
    private static bool IsCooldownEligible(string? origin) => origin is not ("hosted" or "local_only");

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
        PackageVersion v, OrgSettings settings, VulnGateSignals? signals, DateTimeOffset now,
        bool installScriptAllowlisted = false)
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
            MaxCvss: signals?.MaxCvss,
            Origin: v.Origin,
            HasInstallScript: v.HasInstallScript,
            ProvenanceStatus: v.ProvenanceStatus,
            InstallScriptAllowlisted: installScriptAllowlisted,
            RevokedAt: v.RevokedAt);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            // The provenance policy is per-ecosystem (npm vs nuget have independent toggles), so
            // pick the right one from the version's PURL — the stored provenance_status column is
            // ecosystem-agnostic but the gate that interprets it is not.
            VerifyProvenanceMode: settings.VerifyProvenanceMode(EcosystemFromPurl(v.Purl)),
            BlockRevokedMode: settings.BlockRevoked);

        return !Evaluate(facts, policy, now).Servable;
    }

    /// <summary>
    /// Block-gate filter for a proxy artifact entry sourced from the global plane
    /// (<c>cache_artifact</c> + <c>tenant_artifact_access</c>) rather than
    /// <c>package_versions</c>. Used by the list/index/metadata renderers when proxy
    /// versions no longer have <c>package_versions</c> rows. The policy evaluation is
    /// identical to <see cref="IsHardBlockedByStoredState"/> — both delegate to
    /// <see cref="Evaluate"/> with the same <see cref="VersionFacts"/> shape.
    /// </summary>
    public static bool IsHardBlockedByCacheEntry(
        Infrastructure.CacheArtifactIndexFacts entry, OrgSettings settings,
        VulnGateSignals? signals, DateTimeOffset now,
        bool installScriptAllowlisted = false)
    {
        var facts = new VersionFacts(
            ManualState: entry.ManualBlockState,
            Deprecated: entry.Deprecated,
            PublishedAt: entry.PublishedAt,
            Scanned: entry.VulnCheckedAt is not null,
            HasMalicious: signals?.HasMalicious ?? false,
            HasKev: signals?.HasKev ?? false,
            MaxEpss: signals?.MaxEpss,
            MaxCvss: signals?.MaxCvss,
            Origin: "proxy",
            HasInstallScript: entry.HasInstallScript,
            ProvenanceStatus: entry.ProvenanceStatus,
            InstallScriptAllowlisted: installScriptAllowlisted,
            RevokedAt: entry.RevokedAt);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            VerifyProvenanceMode: settings.VerifyProvenanceMode(EcosystemFromPurl(entry.Purl ?? string.Empty)),
            BlockRevokedMode: settings.BlockRevoked);

        return !Evaluate(facts, policy, now).Servable;
    }

    // Extracts the ecosystem segment from a canonical PURL ("pkg:nuget/name@version" → "nuget").
    // Returns an empty string when the value is not PURL-shaped, which maps to an 'off' provenance
    // policy (never blocks) — a safe default for a malformed or legacy row.
    private static string EcosystemFromPurl(string purl)
    {
        const string prefix = "pkg:";
        if (!purl.StartsWith(prefix, StringComparison.Ordinal))
        {
            return string.Empty;
        }

        int slash = purl.IndexOf('/', prefix.Length);
        return slash < 0 ? string.Empty : purl[prefix.Length..slash];
    }

    /// <summary>
    /// Pure policy core: maps <see cref="VersionFacts"/> + <see cref="BlockPolicy"/> to a
    /// <see cref="BlockVerdict"/> with no I/O or side effects. Applies the arms in priority
    /// order (Manual > Deprecated > Revoked > ReleaseAge > Malicious > Provenance > Kev > Epss >
    /// VulnScore > InstallScript).
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

        // Arm 2b: revoked — the version was removed from the upstream registry (a takedown can
        // signal a compromised release). Only 'block' denies; 'warn'/'off'/null surface the badge
        // but keep serving. A revoked version cannot be first-fetched (it is gone upstream), so
        // this is a serve-path / listing gate only.
        if (facts.RevokedAt is not null && policy.BlockRevokedMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Revoked);
        }

        // Arm 3: release-age hold. Applies only to upstream-derived origins so locally-hosted
        // packages are not self-blocked by a cooldown measured against their own push timestamp.
        // Fail-open when PublishedAt is absent.
        if (IsReleaseAgeBlocked(facts, policy, now))
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.ReleaseAge);
        }

        // Arms 4–7 require vuln data. Scanned false means not yet scanned — fail-open.
        // Extracted into a separate helper so this method stays below the S3776 threshold.
        var vulnVerdict = EvaluateVulnArms(facts, policy);
        if (!vulnVerdict.Servable)
        {
            return vulnVerdict;
        }

        // Arm 8: provenance/signature gate. Sits just below the malicious arm in priority (a
        // known-malicious advisory is a stronger reason to deny than a missing signature) and
        // above the install-script arm. Independent of scan state — provenance is captured at
        // ingest, not from the OSV scan. Only the require mode ('block') denies; under 'block'
        // both a Failed and an Unsigned outcome refuse the version (fail closed). 'warn'/'off'/
        // null and a NULL status (verification not applicable) all pass.
        if (policy.VerifyProvenanceMode == "block" &&
            facts.ProvenanceStatus is ProvenanceStatuses.Failed or ProvenanceStatuses.Unsigned)
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Provenance);
        }

        // Arm 9 (lowest priority): install-script gate. Independent of scan state — a shipped
        // install hook is a static artefact property, not a vuln signal — so it runs whether or
        // not the version has been scanned, but only when no stronger arm above already blocked.
        // The allowlist exemption takes effect here: a package on the per-org install-script
        // allowlist is treated as if it has no install script for this arm only.
        return facts.HasInstallScript && policy.BlockInstallScriptsMode == "block"
               && !facts.InstallScriptAllowlisted
            ? new BlockVerdict(Servable: false, Arm: BlockArm.InstallScript)
            : vulnVerdict;
    }

    // Arm 3 predicate: true when the version is upstream-derived, a positive cooldown is
    // configured, PublishedAt is known, and that timestamp is still within the cooldown window.
    private static bool IsReleaseAgeBlocked(VersionFacts facts, BlockPolicy policy, DateTimeOffset now)
    {
        if (!IsCooldownEligible(facts.Origin) ||
            policy.MinReleaseAgeHours is not { } minHours || minHours <= 0 ||
            facts.PublishedAt is not { } publishedAt)
        {
            return false;
        }

        double ageHours = (now - publishedAt).TotalHours;
        return ageHours < minHours;
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
public enum BlockArm { None, Manual, Deprecated, Revoked, ReleaseAge, Malicious, Provenance, Kev, Epss, VulnScore, InstallScript }

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
    double? MaxCvss,
    string? Origin = null,
    bool HasInstallScript = false,
    /// <summary>
    /// Provenance/signature-verification outcome from <c>package_versions.provenance_status</c>:
    /// <c>'verified'</c> / <c>'failed'</c> / <c>'unsigned'</c>, or NULL when verification was not
    /// applicable. Drives the provenance arm under a require policy.
    /// </summary>
    string? ProvenanceStatus = null,
    /// <summary>
    /// True when the package is on the per-org install-script allowlist. When true, arm 9
    /// (install-script gate) is skipped regardless of <see cref="BlockPolicy.BlockInstallScriptsMode"/>.
    /// Computed at the call site by <see cref="InstallScriptAllowlistService.IsAllowlistedAsync"/>
    /// on the download path; always false on the listing path (callers pass the default).
    /// </summary>
    bool InstallScriptAllowlisted = false,
    /// <summary>
    /// Upstream-removal timestamp from <c>revoked_at</c>. Non-null = the version was removed from
    /// the upstream registry. Drives the revoked arm under a 'block' policy.
    /// </summary>
    DateTimeOffset? RevokedAt = null);

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
    double MaxOsvScoreTolerance,
    string? BlockInstallScriptsMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.verify_npm_signatures</c>: 'off' | 'warn' | 'block'.
    /// Only 'block' denies a Failed/Unsigned version; 'warn'/'off'/null let it through. The npm
    /// proxy ingest path is responsible for actually running verification and persisting the
    /// status; this gate only acts on the persisted result.
    /// </summary>
    string? VerifyProvenanceMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_revoked</c>: 'off' | 'warn' | 'block'. Only
    /// 'block' denies a version removed upstream; 'warn'/'off'/null surface the badge but keep
    /// serving. Three values (no <c>block_new</c> analog — revocation is always a full removal).
    /// </summary>
    string? BlockRevokedMode = null);

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
    double? MaxEpssTolerance = null,
    /// <summary>
    /// Version origin from <c>package_versions.origin</c>: 'proxy' (default), 'hosted',
    /// 'local_only', or 'mixed'. The release-age cooldown applies only to upstream-derived
    /// origins ('proxy', 'mixed', or null); hosted and local_only versions are exempt because
    /// their <c>PublishedAt</c> reflects the local push time, not an upstream release date.
    /// </summary>
    string? Origin = null,
    /// <summary>
    /// True when the version ships an install/lifecycle script
    /// (<c>package_versions.has_install_script</c>). Drives the lowest-priority install-script arm.
    /// </summary>
    bool HasInstallScript = false,
    /// <summary>
    /// Detected script kind for the audit detail JSON (e.g. <c>'npm:postinstall'</c>). NULL when
    /// <see cref="HasInstallScript"/> is false. Read only on the block path.
    /// </summary>
    string? InstallScriptKind = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_install_scripts</c>: 'off' | 'warn' | 'block'.
    /// Only 'block' denies; 'warn'/'off'/null let the version through. Null behaves as 'off'.
    /// </summary>
    string? BlockInstallScriptsMode = null,
    /// <summary>
    /// Provenance/signature-verification outcome from <c>package_versions.provenance_status</c>:
    /// <c>'verified'</c> / <c>'failed'</c> / <c>'unsigned'</c>, or NULL when not applicable.
    /// Drives the provenance arm.
    /// </summary>
    string? ProvenanceStatus = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.verify_npm_signatures</c>: 'off' | 'warn' | 'block'.
    /// Only 'block' denies a Failed/Unsigned version. Null behaves as 'off'.
    /// </summary>
    string? VerifyProvenanceMode = null,
    /// <summary>
    /// Global-plane artifact id from <c>cache_artifact.id</c>. When set, the vuln-signal lookup
    /// routes through the <c>cache_artifact</c> owner arm
    /// (<c>GetGateSignalsAsync("cache_artifact", …)</c>) instead of the per-version arm. NULL
    /// for all current call sites (behaviour-equivalent to the pre-P2 path). P3 will set this
    /// on the proxy serve path once the global plane is authoritative.
    /// </summary>
    string? CacheArtifactId = null,
    /// <summary>
    /// Upstream-removal timestamp from <c>revoked_at</c>. Non-null = removed upstream. Drives the
    /// revoked arm. NULL for NuGet/Maven (no per-version revocation detection) and uploaded versions.
    /// </summary>
    DateTimeOffset? RevokedAt = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_revoked</c>: 'off' | 'warn' | 'block'. Only 'block'
    /// denies a revoked version. Null behaves as 'off'.
    /// </summary>
    string? BlockRevokedMode = null)
{
    /// <summary>
    /// Constructs a <see cref="BlockGateRequest"/> from the standard download-path inputs shared
    /// across all ecosystem controllers. <paramref name="token"/> is nullable so both hosted paths
    /// (authenticated, non-null token) and proxy paths (anonymous pull, nullable token) use the
    /// same factory without overload branching. <paramref name="settings"/> is nullable to
    /// accommodate controllers that retrieve settings with a nullable result (e.g. Maven);
    /// absent settings fall back to the policy-off defaults on each field.
    /// </summary>
    // CVSS scores range 0.0–10.0; when org settings are absent, use the maximum (allow all).
    private const double DefaultMaxOsvScore = 10.0;

    public static BlockGateRequest For(
        string orgId,
        string ecosystem,
        PackageVersion version,
        TokenRecord? token,
        OrgSettings? settings,
        string? sourceIp) =>
        new(orgId, ecosystem, version.Purl, version.Id,
            version.ManualBlockState, version.VulnCheckedAt,
            token?.UserId, settings?.MaxOsvScoreTolerance ?? DefaultMaxOsvScore, sourceIp,
            MinReleaseAgeHours: settings?.MinReleaseAgeHours,
            PublishedAt: version.PublishedAt,
            ActorKind: token?.ActorKind,
            Deprecated: version.Deprecated,
            BlockDeprecatedMode: settings?.BlockDeprecated,
            BlockMaliciousMode: settings?.BlockMalicious,
            BlockKevMode: settings?.BlockKev,
            MaxEpssTolerance: settings?.MaxEpssTolerance,
            Origin: version.Origin,
            HasInstallScript: version.HasInstallScript,
            InstallScriptKind: version.InstallScriptKind,
            BlockInstallScriptsMode: settings?.BlockInstallScripts,
            RevokedAt: version.RevokedAt,
            BlockRevokedMode: settings?.BlockRevoked);
}
