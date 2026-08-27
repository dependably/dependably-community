using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
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
///      <c>Failed</c>/<c>Unsigned</c> when the tenant's <c>VerifyProvenanceMode</c> is 'block',
///      and blocks every version of that ecosystem when 'block' is set with no trust anchor
///      configured (enforcement that cannot be satisfied denies rather than degrading to
///      allow-all — see <see cref="IsProvenanceEnforcementUnbackedAsync"/>).
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
/// a review-queue write failure must never turn a correct 403 into a 500. A fresh insert (not a
/// conflict-refresh of an already-pending row, and not a no-op against an already-decided one)
/// also raises a <c>quarantine_new</c> alert via <see cref="AlertService"/>, so a repeat block on
/// the same purl never re-alerts.
/// </summary>
public sealed class BlockGateService
{
    private readonly VulnerabilityRepository _vulns;
    private readonly AuditRepository _audit;
    private readonly QuarantineRepository _quarantine;
    private readonly AlertService _alerts;
    private readonly InstallScriptAllowlistService _installScriptAllowlist;
    private readonly LicenseRepository _licenses;
    private readonly IPerOrgTrustAnchorStore _anchors;
    private readonly ILogger<BlockGateService> _logger;
    private readonly TimeProvider _time;
    private readonly OrgRepository _orgs;
    private readonly Infrastructure.Webhooks.IPackageEventSink _eventSink;
    private readonly BlockRefusalWebhookThrottle _webhookThrottle;

#pragma warning disable S107 // DI constructor — each dependency is a distinct policy-arm collaborator.
    public BlockGateService(
        VulnerabilityRepository vulns,
        AuditRepository audit,
        QuarantineRepository quarantine,
        AlertService alerts,
        InstallScriptAllowlistService installScriptAllowlist,
        LicenseRepository licenses,
        IPerOrgTrustAnchorStore anchors,
        ILogger<BlockGateService> logger,
        TimeProvider time,
        OrgRepository orgs,
        Infrastructure.Webhooks.IPackageEventSink eventSink,
        BlockRefusalWebhookThrottle webhookThrottle)
#pragma warning restore S107
    {
        _vulns = vulns;
        _audit = audit;
        _quarantine = quarantine;
        _alerts = alerts;
        _installScriptAllowlist = installScriptAllowlist;
        _licenses = licenses;
        _anchors = anchors;
        _logger = logger;
        _time = time;
        _orgs = orgs;
        _eventSink = eventSink;
        _webhookThrottle = webhookThrottle;
    }

    /// <summary>
    /// True when the tenant requires provenance verification for <paramref name="ecosystem"/>
    /// (<paramref name="verifyMode"/> == 'block') but has no trust anchors configured for it, so
    /// no artifact can ever produce a <c>verified</c> verdict. Enforcement that cannot be
    /// satisfied must deny, not pass: the settings API refuses to turn verification on without an
    /// anchor, but nothing stops the anchors being deleted afterwards, and that drift would
    /// otherwise turn the policy into a silent no-op.
    ///
    /// Only called when the mode is 'block', and the anchor read is served from the trust-anchor
    /// store's per-org hot cache, so the serve path pays one cached lookup and 'off'/'warn'
    /// tenants pay nothing.
    /// </summary>
    public async Task<bool> IsProvenanceEnforcementUnbackedAsync(
        string orgId, string ecosystem, string? verifyMode, CancellationToken ct = default)
    {
        if (verifyMode != "block")
        {
            return false;
        }

        // PyPI needs BOTH a sigstore root and a trusted publisher to verify anything, so the
        // generic any-anchor-present test would call a half-configured org backed. The other
        // ecosystems verify from a single anchor kind.
        bool configured = ecosystem == "pypi"
            ? (await _anchors.GetPyPiTrustAsync(orgId, ct)).IsConfigured
            : await _anchors.IsConfiguredForAsync(orgId, ecosystem, ct);

        if (!configured)
        {
            _logger.LogWarning(
                "Provenance verification is set to 'block' for {Ecosystem} in org {OrgId} but no trust "
                + "anchors are configured; denying the artifact — add a trust anchor or lower the policy.",
                ecosystem, orgId);
        }

        return !configured;
    }

    // Best-effort review-queue write beside each policy block's activity row. Failures are
    // logged and swallowed: the 403 already protects the tenant; losing one review row is
    // recoverable (the next blocked request re-upserts it). Raises a quarantine_new alert only
    // when the upsert produced a fresh row — AlertService itself swallows its own failures, so
    // this method's try/catch exists solely to protect the upsert.
    private async Task QueueForReviewAsync(
        BlockGateRequest request, string gate, string? detail, CancellationToken ct)
    {
        try
        {
            var result = await _quarantine.UpsertPendingAsync(
                request.OrgId, request.Ecosystem, request.Purl, gate, detail,
                string.IsNullOrEmpty(request.VersionId) ? null : request.VersionId, ct);

            if (result.Inserted)
            {
                await _alerts.RaiseQuarantineAlertAsync(
                    request.OrgId, result.RowId, request.Ecosystem, request.Purl, gate, detail, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Serilog structured parameter — the purl is encoded
            // as a property value, never spliced into the message text.
            _logger.LogWarning(ex,
                "Quarantine review-row upsert failed for {Purl} (gate {Gate}); block still served.",
                request.Purl, gate);
        }
    }

    // A tenant's proxy content binding diverging from the shared cache_artifact row is only ever
    // reported through CacheAccessRecorder's log line and the CacheContentDivergences meter today —
    // both operational, neither operator-actionable per divergence. Every gate evaluation that sees
    // ContentDiverges routes it through the same review-queue/alert path every blocking arm already
    // uses, so a divergence surfaces as a reviewable item regardless of whether anything else on
    // this request actually blocked. Best-effort like every other QueueForReviewAsync call: losing
    // one upsert is recoverable on the next diverging request, and must never turn a servable
    // download into a 500.
    private async Task QueueDivergenceReviewAsync(BlockGateRequest request, CancellationToken ct)
    {
        string detail = System.Text.Json.JsonSerializer.Serialize(
            new { reason = "tenant_content_binding_diverges_from_shared_row" },
            Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        await QueueForReviewAsync(request, "content_divergence", detail, ct);
    }

    /// <summary>
    /// Single emission site for the <c>package.blocked</c> webhook event, called from every
    /// per-arm side-effect method (and the inline manual case in <see cref="ApplySideEffectsAsync"/>)
    /// once that arm's audit/activity/quarantine rows are already written. Both the cache-hit
    /// serve path (via <see cref="ApplySideEffectsAsync"/>) and the cache-miss first-fetch path
    /// (the deprecated and provenance arms are called directly by <c>ProxyFetchService</c>) land
    /// here through the same per-arm helper, so the two paths emit one consistent event shape.
    ///
    /// Best-effort and throttled: <see cref="BlockRefusalWebhookThrottle"/> coalesces repeated
    /// refusals of the same (org, purl, arm) inside its window before this method ever resolves
    /// the org or builds the envelope, and any failure resolving the org or dispatching is
    /// logged and swallowed — a lost webhook notification must never turn a correct 403 into a
    /// 500, and it never rolls back the audit/activity/quarantine rows already written above it.
    /// </summary>
    private async Task EmitBlockWebhookEventAsync(
        BlockGateRequest request, string arm, string? severity, CancellationToken ct)
    {
        if (!_webhookThrottle.ShouldDispatch(request.OrgId, request.Purl, arm))
        {
            return;
        }

        try
        {
            var parsed = PurlParser.TryParse(request.Purl);
            string name = parsed?.Name ?? request.Purl;
            string version = parsed?.Version ?? "";
            var data = new Infrastructure.Audit.Events.PackageEvents.Blocked(
                request.Ecosystem, name, version, request.Purl, arm, severity);
            var org = await _orgs.GetByIdAsync(request.OrgId, ct);
            string orgSlug = org?.Slug ?? request.OrgId;
            _eventSink.Dispatch(new Infrastructure.Webhooks.PackageEventEnvelope(
                EventType: Infrastructure.Audit.Events.PackageEvents.TypeBlocked,
                OrgId: request.OrgId,
                OrgSlug: orgSlug,
                Ecosystem: request.Ecosystem,
                Name: name,
                Version: version,
                Purl: request.Purl,
                ArtifactHash: null,
                Actor: request.AuditActorId,
                OccurredAt: _time.GetUtcNow(),
                DataJson: data.ToJson()));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to dispatch block webhook for {Purl} (org {OrgId}, arm {Arm}); skipped.",
                request.Purl, request.OrgId, arm);
        }
    }

    public async Task<BlockOutcome> EvaluateAsync(BlockGateRequest request, CancellationToken ct = default)
    {
        // Surfaced regardless of the eventual Allowed/Blocked verdict below — divergence itself,
        // not any one gate's reaction to it, is the actionable signal.
        if (request.ContentDiverges)
        {
            await QueueDivergenceReviewAsync(request, ct);
        }

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

        // Under a 'block' policy with no configured trust anchor the stored status is NULL for
        // every artifact (verification was never attempted), which would read as "not applicable"
        // and pass. Synthesize the unverifiable marker so the arm denies and the audit trail
        // names the reason.
        string? provenanceStatus = request.ProvenanceStatus;
        if (await IsProvenanceEnforcementUnbackedAsync(
                request.OrgId, request.Ecosystem, request.VerifyProvenanceMode, ct))
        {
            provenanceStatus = ProvenanceStatuses.Unverifiable;
        }

        var facts = new VersionFacts(
            ManualState: request.ManualState,
            Deprecated: request.Deprecated,
            PublishedAt: request.PublishedAt,
            Scanned: request.VulnCheckedAt is not null,
            // Download path: use the aggregate signals' own malicious flag, not a row flag.
            Vulnerability: ProjectVulnFacts(signals),
            Origin: request.Origin,
            HasInstallScript: request.HasInstallScript,
            ProvenanceStatus: provenanceStatus,
            InstallScriptAllowlisted: installScriptAllowlisted,
            RevokedAt: request.RevokedAt);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: request.MinReleaseAgeHours,
            BlockDeprecatedMode: request.BlockDeprecatedMode,
            BlockMaliciousMode: request.BlockMaliciousMode,
            BlockKevMode: request.BlockKevMode,
            MaxEpssTolerance: request.MaxEpssTolerance,
            BlockKevRansomwareMode: request.BlockKevRansomwareMode,
            BlockSsvcExploitationMode: request.BlockSsvcExploitationMode,
            MaxEpssPercentileTolerance: request.MaxEpssPercentileTolerance,
            MaxOsvScoreTolerance: request.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: request.BlockInstallScriptsMode,
            VerifyProvenanceMode: request.VerifyProvenanceMode,
            BlockRevokedMode: request.BlockRevokedMode);

        NoteStaleEnrichment(signals, request.Ecosystem);

        var verdict = Evaluate(facts, policy, _time.GetUtcNow());

        if (!verdict.Servable)
        {
            // Side effects read the effective status so an unbacked-enforcement denial is audited
            // as 'unverifiable' rather than as a null verdict.
            await ApplySideEffectsAsync(
                verdict.Arm,
                provenanceStatus == request.ProvenanceStatus
                    ? request
                    : request with { ProvenanceStatus = provenanceStatus },
                signals, ct);
            return new BlockOutcome(BlockDecision.Blocked, verdict.Arm);
        }

        // Lowest-priority arm: license enforcement. It runs after the pure core has already
        // ruled the version servable, so every stronger arm above wins first. The license
        // policy read is strictly guarded — it fires ONLY when the tenant enforces licenses
        // ('block'), the operator has not manually allowed the version (that override wins),
        // and nothing above blocked. Under 'off'/'warn', a manual allow, or an already-blocked
        // verdict, no license row is ever read, so the hot path pays zero extra DB cost.
        if (request.LicenseEnforcementMode == "block" && request.ManualState != "allowed" &&
            await EvaluateLicenseArmAsync(request, ct) == BlockDecision.Blocked)
        {
            return new BlockOutcome(BlockDecision.Blocked, BlockArm.License);
        }

        // Recorded here rather than beside the pure core, because only at this point is the
        // artefact known to be SERVED: the licence arm above can still refuse it, and a refusal
        // subsumes the warning. Recording earlier would report "would have blocked" for an
        // artefact that was in fact blocked, by a different arm.
        await RecordWarnAsync(request, verdict.WarnArm, ct);
        return BlockOutcome.Allow();
    }

    /// <summary>
    /// Records that an arm in <c>warn</c> mode <em>would</em> have refused this artefact, which
    /// was nonetheless served.
    ///
    /// <para>
    /// One event type rather than a <c>warned_*</c> family mirroring the seven <c>blocked_*</c>
    /// ones: the question an operator asks is "what would my gates have refused?", which is one
    /// filter over one event type with the arm as structured detail — not seven filters they
    /// have to know to union. The arm is not lost; it is in the detail and on the metric.
    /// </para>
    ///
    /// <para>
    /// Deliberately does <b>not</b> queue a quarantine review row, unlike every block path. The
    /// review queue exists so an operator can approve something that was <em>refused</em>; a warn
    /// refuses nothing, so there is no decision to make and queueing would fill the queue with
    /// items that need none.
    /// </para>
    /// </summary>
    private async Task RecordWarnAsync(BlockGateRequest request, BlockArm warnArm, CancellationToken ct)
    {
        if (warnArm == BlockArm.None)
        {
            return;
        }

        string? reason = new BlockOutcome(BlockDecision.Blocked, warnArm).ReasonToken;

        DependablyMeter.GateWarnings.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem),
            new KeyValuePair<string, object?>("reason", reason));

        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "gate_warned", request.AuditActorId, actorKind: request.ActorKind,
            actorLabel: request.AuditActorLabel,
            detail: System.Text.Json.JsonSerializer.Serialize(
                new { arm = reason },
                Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: request.SourceIp, ct: ct);
    }

    /// <summary>
    /// Ecosystems whose package manifests carry a declared license field that ingest extracts into
    /// <c>package_version_licenses</c>. For these, an artifact with zero recorded SPDX entries is
    /// an <em>absent</em> signal, not a "this ecosystem has no licenses" signal — under an
    /// enforcing policy it is treated as an unknown license and denied, so omitting or malforming
    /// the manifest's license field is not a way around the tenant's allowlist.
    ///
    /// Ecosystems outside this set (go — LICENSE-text classification only; apk — no license
    /// metadata; oci — the SPDX expression lives on the manifest's <c>oci_blobs</c> row and is
    /// evaluated by <see cref="EvaluateLicenseExpressionAsync"/>) keep the empty-set pass-through:
    /// they routinely record nothing, so denying on absence would refuse every artifact.
    /// </summary>
    // Internal (not private) so PackagePublishService's publish-side licence gate reads the
    // same set rather than maintaining a second, driftable copy.
    internal static readonly HashSet<string> DeclaredLicenseEcosystems =
        new(StringComparer.Ordinal) { "npm", "pypi", "nuget", "maven", "cargo", "rpm" };

    // The SPDX token for "no license assertion was made". Named as the offending license on an
    // unknown-license block so the activity row and the review queue say what is actually wrong.
    // Internal so the publish-side gate can record the same token for its own 'warn'/'block' cases.
    internal const string NoLicenseAssertion = "NOASSERTION";

    // License-policy arm. Reads the artifact's SPDX license entries by owner (cache_artifact on
    // the proxy/global-plane path, package_version otherwise), evaluates them against the tenant's
    // allow/block policy in 'block' mode, and — on a rejection — records the side effects
    // (meter + activity row + review row) mirroring the other arms. An empty entry set is
    // resolved by ecosystem: a declared-license ecosystem denies (unknown license), the rest
    // pass through. See <see cref="DeclaredLicenseEcosystems"/>.
    private async Task<BlockDecision> EvaluateLicenseArmAsync(BlockGateRequest request, CancellationToken ct)
    {
        // package_version_licenses is keyed by cache_artifact_id — a single global row — so a
        // tenant whose content binding diverges from that row has no license evidence of its own
        // to read. Skip the lookup entirely rather than reading the shared row's entries: the
        // empty-entries branch below already resolves to the correct posture per ecosystem
        // (unknown-license block for DeclaredLicenseEcosystems, pass-through otherwise), the same
        // treatment as a coordinate that has never been license-scanned at all.
        List<string> entries;
        if (request.ContentDiverges)
        {
            entries = [];
        }
        else
        {
            var lookup = request.CacheArtifactId is not null
                ? await _licenses.GetSpdxForCacheArtifactsAsync([request.CacheArtifactId], ct)
                : await _licenses.GetSpdxForVersionsAsync([request.VersionId], ct);
            string ownerId = request.CacheArtifactId ?? request.VersionId;
            entries = lookup[ownerId].ToList();
        }

        if (entries.Count == 0)
        {
            if (!DeclaredLicenseEcosystems.Contains(request.Ecosystem))
            {
                return BlockDecision.Allowed;
            }

            await RecordLicenseBlockAsync(request, NoLicenseAssertion, ct);
            return BlockDecision.Blocked;
        }

        // A conditional verdict is an allow: the licence serves, and the review signal is
        // derived from the policy tables by the license-risk read model rather than written
        // here — this arm runs on every gate pass including cache hits.
        var verdict = await _licenses.CheckPolicyAsync(request.OrgId, "block", entries, ct);
        if (verdict.Allowed)
        {
            return BlockDecision.Allowed;
        }

        await RecordLicenseBlockAsync(request, verdict.BlockedLicense, ct);
        return BlockDecision.Blocked;
    }

    /// <summary>
    /// Evaluates the license arm alone against a caller-supplied set of SPDX expressions, for
    /// artifacts whose license facts live outside the <c>package_versions</c>/<c>cache_artifact</c>
    /// planes — the OCI plane stores its SPDX expression on the manifest's <c>oci_blobs</c> row, so
    /// the standard owner-keyed lookup in <see cref="EvaluateLicenseArmAsync"/> has nothing to read.
    /// Only 'block' mode engages; an empty <paramref name="licenseEntries"/> set fails open,
    /// matching the main gate's license arm. On denial the same side effects fire (blocked_license
    /// activity row, <c>DependablyMeter.LicenseBlocks</c>, and a pending quarantine review row) so
    /// the OCI plane's blocks are one shape with every other license block.
    /// </summary>
    public async Task<BlockDecision> EvaluateLicenseExpressionAsync(
        BlockGateRequest request, IReadOnlyList<string> licenseEntries, CancellationToken ct = default)
    {
        if (request.LicenseEnforcementMode != "block" || licenseEntries.Count == 0)
        {
            return BlockDecision.Allowed;
        }

        var verdict = await _licenses.CheckPolicyAsync(request.OrgId, "block", licenseEntries, ct);
        if (verdict.Allowed)
        {
            return BlockDecision.Allowed;
        }

        await RecordLicenseBlockAsync(request, verdict.BlockedLicense, ct);
        return BlockDecision.Blocked;
    }

    // Side effects for the license arm: increments the meter, logs the activity row naming the
    // offending leaf, and queues a review entry. Mirrors the other block arms' shape.
    private async Task RecordLicenseBlockAsync(BlockGateRequest request, string? offendingLeaf, CancellationToken ct)
    {
        DependablyMeter.LicenseBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        string detail = System.Text.Json.JsonSerializer.Serialize(
            new { license = offendingLeaf }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_license", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: detail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "license", offendingLeaf, ct);
        await EmitBlockWebhookEventAsync(request, "license", severity: null, ct);
    }

    /// <summary>
    /// Counts gate evaluations of a version whose enrichment is past the operator's staleness
    /// horizon, so the softening that staleness causes stays visible.
    ///
    /// <para>
    /// The horizon is applied in the aggregate query, not at the arms, which means a stale value
    /// simply is not there by the time policy runs. For the SSVC arm that absence is caught and
    /// refused — <see cref="SsvcExploitationTriggers"/> fires on staleness as well as on an active
    /// assessment. For the CVSS ceiling it is not: the NVD fallback drops out and OSV's own score
    /// is compared, which is a complete signal rather than an unknown one. That second case is a
    /// return to the pre-overlay baseline rather than a degradation, and this counter is how an
    /// operator sees it happening. A sustained non-zero rate means the tracker is behind.
    /// </para>
    /// </summary>
    private static void NoteStaleEnrichment(VulnGateSignals? signals, string ecosystem)
    {
        if (signals?.HasStaleEnrichment == true)
        {
            DependablyMeter.StaleEnrichmentEvaluations.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem));
        }
    }

    /// <summary>
    /// Projects one call site's aggregate <see cref="VulnGateSignals"/> into the
    /// <see cref="VulnFacts"/> the arm ladder reads, folding the NVD fallback into
    /// <see cref="VulnFacts.Cvss"/> so the ladder itself has one score to compare rather than a
    /// two-source split it would otherwise have to re-resolve on every read. No signals (an
    /// unscanned version) projects to <see cref="VulnFacts.None"/>.
    /// </summary>
    /// <param name="maliciousOverride">
    /// The index/listing path reads a pre-computed row flag (<c>package_versions.is_malicious</c>)
    /// rather than the aggregate signal — see <see cref="IsHardBlockedByStoredState"/>. Omitted,
    /// the aggregate's own malicious flag is used, matching every other call site.
    /// </param>
    private static VulnFacts ProjectVulnFacts(VulnGateSignals? signals, bool? maliciousOverride = null) =>
        (signals?.Facts ?? VulnFacts.None) with
        {
            IsMalicious = maliciousOverride ?? signals?.HasMalicious ?? false,
            Cvss = signals?.EffectiveMaxCvss,
        };

    // Performs the audit-log, meter, and quarantine side effects for each blocking arm.
    // Called only when the pure core signals a block; routes to the matching side-effect
    // body preserving all existing meter names, event types, and detail JSON shapes.
    //
    // Every arm that can refuse must have a case here: an arm wired into the policy core but not
    // into this switch still refuses the artefact, it just refuses it invisibly — no activity
    // row, no quarantine entry, no webhook — and nothing fails, because there is no default arm.
    // BlockArmSideEffectComplianceTests is what makes that a gate rather than a convention.
    private async Task ApplySideEffectsAsync(
        BlockArm arm, BlockGateRequest request, VulnGateSignals? signals, CancellationToken ct)
    {
        switch (arm)
        {
            case BlockArm.Manual:
                await _audit.LogActivityAsync(
                    request.OrgId, request.Ecosystem, request.Purl,
                    "blocked_manual", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
                    sourceIp: request.SourceIp, ct: ct);
                // Manual block is a human decision — no quarantine row needed.
                await EmitBlockWebhookEventAsync(request, "manual", severity: null, ct);
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

            case BlockArm.KevRansomware:
                await RecordKevRansomwareBlockAsync(request, ct);
                break;

            case BlockArm.SsvcExploitation:
                await RecordSsvcExploitationBlockAsync(request, signals!, ct);
                break;

            case BlockArm.Epss:
                await RecordEpssBlockAsync(request, signals!, ct);
                break;

            case BlockArm.EpssPercentile:
                await RecordEpssPercentileBlockAsync(request, signals!, ct);
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
        string publishedIso = publishedAt.ToUtcIso();
        double ageRounded = Math.Round(ageHours, 2);
        string ageDetail = string.Format(
            CultureInfo.InvariantCulture,
            "{{\"published_at\":\"{0}\",\"min_age_hours\":{1},\"age_at_block_hours\":{2}}}",
            publishedIso, request.MinReleaseAgeHours!.Value, ageRounded);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_release_age", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: ageDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "release_age", ageDetail, ct);
        await EmitBlockWebhookEventAsync(request, "release_age", severity: null, ct);
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
        string malDetail = System.Text.Json.JsonSerializer.Serialize(new { osv_ids = malIds }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_malicious", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: malDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "malicious", malDetail, ct);
        await EmitBlockWebhookEventAsync(request, "malicious", severity: null, ct);
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
        string kevDetail = System.Text.Json.JsonSerializer.Serialize(new { osv_ids = kevIds }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_kev", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: kevDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "kev", kevDetail, ct);
        await EmitBlockWebhookEventAsync(request, "kev", severity: null, ct);
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
            "blocked_epss", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: epssDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "epss", epssDetail, ct);
        await EmitBlockWebhookEventAsync(request, "epss", severity: null, ct);
    }

    // Side effects for the narrow KEV arm. Shares the broad arm's advisory-id lookup — a
    // ransomware-flagged CVE is by construction a KEV-listed one — but records its own reason,
    // so the review queue distinguishes "exploited" from "used in ransomware campaigns".
    private async Task RecordKevRansomwareBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
        DependablyMeter.EnrichmentGateBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem),
            new KeyValuePair<string, object?>("reason", "kev_ransomware"));
        var kevIds = request.CacheArtifactId is not null
            ? await _vulns.GetKevOsvIdsForCacheArtifactAsync(request.CacheArtifactId, ct)
            : await _vulns.GetKevOsvIdsForVersionAsync(request.VersionId, ct);
        string detail = System.Text.Json.JsonSerializer.Serialize(
            new { kev_osv_ids = kevIds }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_kev_ransomware", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: detail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "kev_ransomware", detail, ct);
        await EmitBlockWebhookEventAsync(request, "kev_ransomware", severity: null, ct);
    }

    // Side effects for the SSVC exploitation arm. The detail names the assessment rather than a
    // list of advisory ids: the value is an overlay attribute of the linked advisories, and the
    // aggregate that fired the arm does not carry which of them supplied it.
    private async Task RecordSsvcExploitationBlockAsync(
        BlockGateRequest request, VulnGateSignals signals, CancellationToken ct)
    {
        DependablyMeter.EnrichmentGateBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem),
            new KeyValuePair<string, object?>("reason", "ssvc_exploitation"));
        // Two different operator problems: "CISA assesses this as actively exploited" is resolved
        // by a policy decision about the package, "we can no longer tell" by fixing the tracker.
        string detail = signals.HasSsvcActiveExploitation
            ? "{\"ssvc_exploitation\":\"active\"}"
            : "{\"ssvc_exploitation\":\"stale\"}";
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_ssvc_exploitation", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: detail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "ssvc_exploitation", detail, ct);
        await EmitBlockWebhookEventAsync(request, "ssvc_exploitation", severity: null, ct);
    }

    // Side effects for the EPSS percentile arm: the rank sibling of RecordEpssBlockAsync, kept
    // separate so the recorded detail names the ceiling the operator actually set.
    private async Task RecordEpssPercentileBlockAsync(
        BlockGateRequest request, VulnGateSignals signals, CancellationToken ct)
    {
        DependablyMeter.EnrichmentGateBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem),
            new KeyValuePair<string, object?>("reason", "epss_percentile"));
        double maxPercentile = signals.MaxEpssPercentile!.Value;
        double tolerance = request.MaxEpssPercentileTolerance!.Value;
        string detail = string.Format(
            CultureInfo.InvariantCulture,
            "{{\"max_epss_percentile\":{0},\"tolerance\":{1}}}",
            maxPercentile, tolerance);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_epss_percentile", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: detail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "epss_percentile", detail, ct);
        await EmitBlockWebhookEventAsync(request, "epss_percentile", severity: null, ct);
    }

    // Side effects for the CVSS-score arm: formats the max-score + tolerance detail JSON,
    // logs the activity row, and queues a review entry.
    private async Task RecordVulnScoreBlockAsync(
        BlockGateRequest request, VulnGateSignals signals, CancellationToken ct)
    {
        double maxScore = signals.EffectiveMaxCvss!.Value;
        string scoreDetail = $"{{\"max_score\":{maxScore},\"tolerance\":{request.MaxOsvScoreTolerance}}}";
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_vuln_score", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: scoreDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "vuln_score", scoreDetail, ct);
        // Vuln-score is the one arm whose block reason is itself a CVSS score, so severity is
        // meaningful here in a way it isn't for the OSV-id-only malicious/KEV arms above.
        await EmitBlockWebhookEventAsync(request, "vuln_score", OsvScoring.CvssScoreToSeverity(maxScore), ct);
    }

    // Side effects for the install-script arm: formats the script-kind detail JSON,
    // increments the meter, logs the activity row, and queues a review entry.
    private async Task RecordInstallScriptBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
        DependablyMeter.InstallScriptBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        string scriptDetail = System.Text.Json.JsonSerializer.Serialize(
            new { install_script_kind = request.InstallScriptKind }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_install_script", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: scriptDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "install_script", scriptDetail, ct);
        await EmitBlockWebhookEventAsync(request, "install_script", severity: null, ct);
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
            new { provenance_status = request.ProvenanceStatus }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        // Tenant-level security event: forwarded to SIEM via the audit_log path.
        await _audit.LogAsync(
            "provenance_verification_failed",
            orgId: request.OrgId,
            actorId: request.AuditActorId, actorLabel: request.AuditActorLabel,
            actorKind: request.ActorKind,
            ecosystem: request.Ecosystem,
            purl: request.Purl,
            detail: provDetail,
            sourceIp: request.SourceIp,
            ct: ct);
        // Per-version activity row so the dashboard surfaces why the download was denied.
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_provenance", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: provDetail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "provenance", provDetail, ct);
        await EmitBlockWebhookEventAsync(request, "provenance", severity: null, ct);
    }

    // Single home for the deprecated-block side effects (meter + activity row + review row) so
    // the cache-hit and first-fetch paths emit one consistent event shape.
    private async Task<BlockDecision> RecordDeprecatedBlockAsync(BlockGateRequest request, CancellationToken ct)
    {
        DependablyMeter.DeprecatedBlocks.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        string detail = $"{{\"deprecated\":{System.Text.Json.JsonSerializer.Serialize(request.Deprecated, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail)}}}";
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_deprecated", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: detail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "deprecated", detail, ct);
        await EmitBlockWebhookEventAsync(request, "deprecated", severity: null, ct);
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
            new { revoked_at = request.RevokedAt?.ToUtcIso() }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        await _audit.LogActivityAsync(
            request.OrgId, request.Ecosystem, request.Purl,
            "blocked_revoked", request.AuditActorId, actorKind: request.ActorKind, actorLabel: request.AuditActorLabel,
            detail: detail,
            sourceIp: request.SourceIp, ct: ct);
        await QueueForReviewAsync(request, "revoked", detail, ct);
        await EmitBlockWebhookEventAsync(request, "revoked", severity: null, ct);
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
            Vulnerability: ProjectVulnFacts(signals, maliciousOverride: v.IsMalicious),
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
            BlockKevRansomwareMode: settings.BlockKevRansomware,
            BlockSsvcExploitationMode: settings.BlockSsvcExploitation,
            MaxEpssPercentileTolerance: settings.MaxEpssPercentileTolerance,
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
            // OSV findings are coordinate-keyed (ecosystem/name/version), not byte-keyed — see
            // CacheArtifactIndexFacts.ToPackageVersionSynthetic — so vuln_checked_at and the
            // malicious/KEV/EPSS/CVSS signals are read unmasked here regardless of divergence.
            Scanned: entry.VulnCheckedAt is not null,
            Vulnerability: ProjectVulnFacts(signals),
            Origin: "proxy",
            HasInstallScript: entry.EffectiveHasInstallScript,
            ProvenanceStatus: entry.EffectiveProvenanceStatus,
            InstallScriptAllowlisted: installScriptAllowlisted,
            RevokedAt: entry.RevokedAt);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            BlockKevRansomwareMode: settings.BlockKevRansomware,
            BlockSsvcExploitationMode: settings.BlockSsvcExploitation,
            MaxEpssPercentileTolerance: settings.MaxEpssPercentileTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            VerifyProvenanceMode: settings.VerifyProvenanceMode(EcosystemFromPurl(entry.Purl ?? string.Empty)),
            BlockRevokedMode: settings.BlockRevoked);

        return !Evaluate(facts, policy, now).Servable;
    }

    // Extracts the ecosystem segment from a canonical PURL ("pkg:nuget/name@version" → "nuget").
    // Returns an empty string when the value is not PURL-shaped, which maps to an 'off' provenance
    // policy (never blocks) — a safe default for a malformed or legacy row.
    private static string EcosystemFromPurl(string purl) => PurlParser.TryGetEcosystem(purl) ?? string.Empty;

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
        var verdict = EvaluateBlocking(facts, policy, now);

        // A refusal subsumes any warning: the artefact was not served, so "what would have
        // refused it" is already answered by the arm that did. Only a servable verdict carries a
        // warn, which is also what keeps `Arm != None` meaning exactly "blocked" for every
        // existing consumer.
        return verdict.Servable
            ? verdict with { WarnArm = FirstWarnArm(facts, policy) }
            : verdict;
    }

    private static BlockVerdict EvaluateBlocking(VersionFacts facts, BlockPolicy policy, DateTimeOffset now)
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
        if (DeprecatedTriggers(facts) && IsBlockAll(policy.BlockDeprecatedMode))
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Deprecated);
        }

        // Arm 2b: revoked — the version was removed from the upstream registry (a takedown can
        // signal a compromised release). Only 'block' denies; 'warn'/'off'/null surface the badge
        // but keep serving. A revoked version cannot be first-fetched (it is gone upstream), so
        // this is a serve-path / listing gate only.
        if (RevokedTriggers(facts) && policy.BlockRevokedMode == "block")
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
        // ingest, not from the OSV scan. Only the require mode ('block') denies; under 'block' a
        // Failed, an Unsigned, and an Unverifiable outcome all refuse the version (fail closed).
        // Unverifiable is the caller-synthesized "enforcement on, no trust anchor configured"
        // marker, never a stored value. 'warn'/'off'/null and a NULL status (verification not
        // applicable) all pass.
        if (ProvenanceTriggers(facts) && policy.VerifyProvenanceMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Provenance);
        }

        // Arm 9 (lowest priority): install-script gate. Independent of scan state — a shipped
        // install hook is a static artefact property, not a vuln signal — so it runs whether or
        // not the version has been scanned, but only when no stronger arm above already blocked.
        // The allowlist exemption takes effect here: a package on the per-org install-script
        // allowlist is treated as if it has no install script for this arm only.
        return InstallScriptTriggers(facts) && policy.BlockInstallScriptsMode == "block"
            ? new BlockVerdict(Servable: false, Arm: BlockArm.InstallScript)
            : vulnVerdict;
    }

    // ── Arm trigger predicates ────────────────────────────────────────────────
    //
    // One predicate per warn-capable arm, used by BOTH the blocking pass and the warning pass.
    // That sharing is the point: a warn pass with its own copy of each condition is a second
    // copy of the policy, which drifts silently — the same hazard the pre-filter rule guards
    // against, where the safe direction is "may only drop rows Evaluate would also reject".
    // Here the invariant is tighter: warn and block must trigger on exactly the same facts, and
    // differ only in what the tenant's mode says to do about them.

    private static bool DeprecatedTriggers(VersionFacts f) => f.Deprecated is not null;

    private static bool RevokedTriggers(VersionFacts f) => f.RevokedAt is not null;

    // The vuln arms additionally require a scanned row: unscanned is fail-open, so an unscanned
    // version must not warn either — a warning implies a judgement that was never made.
    private static bool MaliciousTriggers(VersionFacts f) => f.Scanned && f.Vulnerability.IsMalicious;

    private static bool KevRansomwareTriggers(VersionFacts f) =>
        f.Scanned && f.Vulnerability.IsKevRansomware == true;

    private static bool KevTriggers(VersionFacts f) => f.Scanned && f.Vulnerability.IsKev;

    private static bool SsvcExploitationTriggers(VersionFacts f) =>
        f.Scanned && (f.Vulnerability.SsvcExploitation == "active" || f.Vulnerability.HasStaleEnrichment);

    private static bool ProvenanceTriggers(VersionFacts f) =>
        f.ProvenanceStatus is ProvenanceStatuses.Failed or ProvenanceStatuses.Unsigned
            or ProvenanceStatuses.Unverifiable;

    private static bool InstallScriptTriggers(VersionFacts f) =>
        f.HasInstallScript && !f.InstallScriptAllowlisted;

    private static bool IsWarn(string? mode) => mode == "warn";

    /// <summary>
    /// The highest-priority arm whose fact is present and whose tenant mode is <c>warn</c>, or
    /// <see cref="BlockArm.None"/>. Walks the same order as the blocking pass, using the same
    /// trigger predicates, so an arm cannot be enforced-but-not-warned or the reverse.
    ///
    /// <para>
    /// A manual allow silences warnings as well as blocks. The override means "an operator has
    /// judged this version acceptable"; continuing to report what would have refused it would
    /// generate a permanent stream of records for a decision already made.
    /// </para>
    /// </summary>
    private static BlockArm FirstWarnArm(VersionFacts facts, BlockPolicy policy) =>
        facts.ManualState == "allowed"
            ? BlockArm.None
            // Priority order, mirroring the blocking pass exactly. Written as a null-coalescing
            // chain rather than a sequence of ifs so the order is one readable list, and rather
            // than an array so the serve path allocates nothing per evaluation.
            : Warned(DeprecatedTriggers(facts), policy.BlockDeprecatedMode, BlockArm.Deprecated)
              ?? Warned(RevokedTriggers(facts), policy.BlockRevokedMode, BlockArm.Revoked)
              ?? Warned(MaliciousTriggers(facts), policy.BlockMaliciousMode, BlockArm.Malicious)
              ?? Warned(KevRansomwareTriggers(facts), policy.BlockKevRansomwareMode, BlockArm.KevRansomware)
              ?? Warned(KevTriggers(facts), policy.BlockKevMode, BlockArm.Kev)
              ?? Warned(SsvcExploitationTriggers(facts), policy.BlockSsvcExploitationMode, BlockArm.SsvcExploitation)
              ?? Warned(ProvenanceTriggers(facts), policy.VerifyProvenanceMode, BlockArm.Provenance)
              ?? Warned(InstallScriptTriggers(facts), policy.BlockInstallScriptsMode, BlockArm.InstallScript)
              ?? BlockArm.None;

    private static BlockArm? Warned(bool triggered, string? mode, BlockArm arm) =>
        triggered && IsWarn(mode) ? arm : null;

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
        if (MaliciousTriggers(facts) && policy.BlockMaliciousMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Malicious);
        }

        // The exploitation/score arms need aggregate signals; null signals means no linked
        // advisories — all pass. Every fact those arms read must appear here: a signal missing
        // from this guard makes its arm unreachable rather than merely unused, and the arm still
        // looks correct at its own call site. IsKevRansomware implies IsKev and so is covered
        // by it, but is named anyway so the guard stays honest if that ever stops holding.
        if (!facts.Vulnerability.IsKev && facts.Vulnerability.IsKevRansomware != true
            && facts.Vulnerability.SsvcExploitation != "active" && !facts.Vulnerability.HasStaleEnrichment
            && facts.Vulnerability.Epss is null && facts.Vulnerability.EpssPercentile is null
            && facts.Vulnerability.Cvss is null)
        {
            return new BlockVerdict(Servable: true, Arm: BlockArm.None);
        }

        // Arm 5a: the narrow KEV gate, evaluated BEFORE the broad one. The two are independent
        // settings and the useful combination is block_kev='warn' with this at 'block' — which
        // only produces a block if the narrow arm is reached first. Ordering it second would let
        // the broad arm's 'warn' fall through and lose the ransomware attribution entirely.
        if (KevRansomwareTriggers(facts) && policy.BlockKevRansomwareMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.KevRansomware);
        }

        // Arm 5: KEV gate — exploited-in-the-wild beats score-based reasoning.
        if (KevTriggers(facts) && policy.BlockKevMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Kev);
        }

        // Arm 5b: SSVC exploitation. Sits below both KEV arms because KEV is CISA's curated,
        // higher-confidence list, and above the score arms for the same reason KEV is: evidence
        // that something is being exploited outranks an estimate that it might be.
        if (SsvcExploitationTriggers(facts) && policy.BlockSsvcExploitationMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.SsvcExploitation);
        }

        // Arm 6: EPSS probability ceiling, pass-on-equal.
        if (policy.MaxEpssTolerance is { } epssTol && facts.Vulnerability.Epss is { } maxEpss && maxEpss > epssTol)
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.Epss);
        }

        // Arm 6a: EPSS percentile ceiling, pass-on-equal. Independent of the probability ceiling
        // above rather than an alternative spelling of it: absolute risk and relative rank are
        // different policies, both may be set, and either tripping is enough.
        if (policy.MaxEpssPercentileTolerance is { } pctTol
            && facts.Vulnerability.EpssPercentile is { } maxPct && maxPct > pctTol)
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.EpssPercentile);
        }

        // Arm 7: CVSS score ceiling, pass-on-equal.
        return facts.Vulnerability.Cvss is { } maxCvss && maxCvss > policy.MaxOsvScoreTolerance
            ? new BlockVerdict(Servable: false, Arm: BlockArm.VulnScore)
            : new BlockVerdict(Servable: true, Arm: BlockArm.None);
    }
}

/// <summary>
/// Identifies which policy arm triggered a block verdict. <see cref="None"/> means the
/// version is servable (no arm fired).
/// </summary>
public enum BlockArm { None, Manual, Deprecated, Revoked, ReleaseAge, Malicious, Provenance, Kev, KevRansomware, SsvcExploitation, Epss, EpssPercentile, VulnScore, InstallScript, License }

/// <summary>
/// Outcome of the pure policy core: whether the version is servable and, if not, which arm
/// triggered the block.
/// </summary>
/// <param name="WarnArm">
/// The arm that <em>would</em> have blocked had its mode been <c>block</c> — the highest-priority
/// arm whose fact is present and whose tenant mode is <c>warn</c>. Meaningful only when
/// <paramref name="Servable"/> is true: a refusal subsumes any warning, because the artefact was
/// not served and there is nothing left to warn about.
///
/// <para>
/// Deliberately a separate field rather than reusing <paramref name="Arm"/> on a servable
/// verdict. Every existing consumer reads "<c>Arm != None</c>" as "blocked", so widening that
/// field's meaning would have turned warnings into refusals everywhere at once.
/// </para>
/// </param>
public readonly record struct BlockVerdict(bool Servable, BlockArm Arm, BlockArm WarnArm = BlockArm.None);

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
    /// <summary>
    /// Every exploitation/decision-support signal the version's linked advisories carry, in the
    /// vocabulary shared with the SBOM inventory and the projects-plane priority derivation. A
    /// required field rather than a defaulted one — the record threads a dozen policy modes and
    /// a comparable number of facts, and a signal omitted at a call site must fail to compile
    /// rather than silently read as "no vulnerabilities". <see cref="VulnFacts.Cvss"/> here
    /// carries whichever score the constructing call site already resolved as the ceiling arm's
    /// input (the NVD fallback is folded in at construction for the callers that apply it — see
    /// each call site) rather than the two-source split <see cref="VulnFacts"/> otherwise allows.
    /// </summary>
    VulnFacts Vulnerability,
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
    DateTimeOffset? RevokedAt = null)
{
    /// <summary>
    /// Projects a coordinate that exists only in an upstream's metadata — advertised by an index
    /// merge, never fetched, so carrying no row on either plane. Every fact a local row would
    /// supply is absent, and absent is spelled out here once so a fact added to
    /// <see cref="VersionFacts"/> later cannot reach one ecosystem's index filter while silently
    /// missing another's.
    ///
    /// Only the release-age and deprecation arms can decide such an entry. The manual arm is
    /// vacuous — there is no row to carry a manual state — and the vulnerability, provenance,
    /// install-script and licence arms each need an artifact nobody has fetched. An index
    /// therefore reaches parity with its download path for the arms decidable from metadata
    /// alone, and no further; the rest are enforced at first fetch.
    ///
    /// A null <paramref name="publishedAt"/> fails the release-age hold open, matching
    /// <see cref="BlockGateService.Evaluate"/>'s posture for an unknown publish time.
    /// </summary>
    public static VersionFacts ForUpstreamOnly(string? deprecated, DateTimeOffset? publishedAt) =>
        new(ManualState: null,
            Deprecated: deprecated,
            PublishedAt: publishedAt,
            Scanned: false,
            Vulnerability: VulnFacts.None);
}

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
    string? BlockRevokedMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_kev_ransomware</c>: 'off' | 'warn' | 'block'.
    /// The narrow companion to <see cref="BlockKevMode"/>, matching only advisories CISA marks as
    /// used in ransomware campaigns. Independent rather than a mode on the broad arm, so
    /// <c>BlockKevMode = "warn"</c> with this at <c>"block"</c> is expressible.
    /// </summary>
    string? BlockKevRansomwareMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.max_epss_percentile_tolerance</c> (0.0–1.0), the rank
    /// sibling of <see cref="MaxEpssTolerance"/>. NULL = off. Both may be set; either tripping
    /// blocks.
    /// </summary>
    double? MaxEpssPercentileTolerance = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_ssvc_exploitation</c>: 'off' | 'warn' | 'block'.
    /// Acts on <c>VersionFacts.Vulnerability.SsvcExploitation == "active"</c>. Independent of
    /// <see cref="BlockKevMode"/> — the two read different catalogues and either may be the
    /// stricter one for a given tenant.
    /// </summary>
    string? BlockSsvcExploitationMode = null);

public enum BlockDecision
{
    Allowed,
    Blocked,
}

/// <summary>
/// A gate verdict together with the arm that produced it. The arm is what lets a refusal explain
/// itself on the wire: without it, every policy denial reaches the client as a bare 403 that is
/// indistinguishable from an authorization failure, and an operator diagnosing a broken build has
/// nothing to correlate against their own policy.
///
/// It converts implicitly to <see cref="BlockDecision"/> so the existing <c>== BlockDecision.Blocked</c>
/// call sites keep reading as they did. Widening the return type this way rather than rewriting
/// three dozen comparisons keeps the diff about the new capability instead of about mechanical
/// churn, and leaves no site silently changed.
/// </summary>
public readonly record struct BlockOutcome(BlockDecision Decision, BlockArm Arm)
{
    public static implicit operator BlockDecision(BlockOutcome outcome) => outcome.Decision;

    /// <summary>Allowed, with no arm — nothing refused it.</summary>
    public static BlockOutcome Allow() => new(BlockDecision.Allowed, BlockArm.None);

    /// <summary>
    /// The arm's wire spelling: the same vocabulary the quarantine queue and the dashboard already
    /// use (<c>release_age</c>, <c>malicious</c>, …), so an operator reading a response header and
    /// an operator reading the review queue are looking at one name for one thing.
    /// </summary>
    public string? ReasonToken => Arm switch
    {
        BlockArm.None => null,
        BlockArm.Manual => "manual",
        BlockArm.Deprecated => "deprecated",
        BlockArm.Revoked => "revoked",
        BlockArm.ReleaseAge => "release_age",
        BlockArm.Malicious => "malicious",
        BlockArm.Provenance => "provenance",
        BlockArm.Kev => "kev",
        BlockArm.KevRansomware => "kev_ransomware",
        BlockArm.SsvcExploitation => "ssvc_exploitation",
        BlockArm.Epss => "epss",
        BlockArm.EpssPercentile => "epss_percentile",
        BlockArm.VulnScore => "vuln_score",
        BlockArm.InstallScript => "install_script",
        BlockArm.License => "license",
        _ => null,
    };
}

public sealed record BlockGateRequest(
    string OrgId,
    string Ecosystem,
    string Purl,
    string VersionId,
    string? ManualState,
    DateTimeOffset? VulnCheckedAt,
    string? AuditActorId,
    double MaxOsvScoreTolerance,
    string? SourceIp = null,
    int? MinReleaseAgeHours = null,
    DateTimeOffset? PublishedAt = null,
    /// <summary>
    /// Discriminator persisted alongside <see cref="AuditActorId"/> in <c>activity.actor_kind</c> on
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
    /// Tenant policy from <c>org_settings.block_kev_ransomware</c>: 'off' | 'warn' | 'block'.
    /// Narrow companion to <see cref="BlockKevMode"/> — matches only advisories CISA marks as
    /// used in ransomware campaigns, and is independent of the broad arm so the two compose.
    /// </summary>
    string? BlockKevRansomwareMode = null,
    /// <summary>
    /// Tenant ceiling from <c>org_settings.max_epss_percentile_tolerance</c> (0.0–1.0), the rank
    /// sibling of <see cref="MaxEpssTolerance"/>. Null = policy off.
    /// </summary>
    double? MaxEpssPercentileTolerance = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_ssvc_exploitation</c>: 'off' | 'warn' | 'block'.
    /// Acts on the vulnerability-tracker overlay's CISA Vulnrichment assessment; inert on a
    /// deployment with no tracker configured, because no advisory carries an SSVC value there.
    /// </summary>
    string? BlockSsvcExploitationMode = null,
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
    string? BlockRevokedMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.license_enforcement_mode</c>: 'off' | 'warn' | 'block'.
    /// Only 'block' engages the license arm (the lowest-priority hard-block gate); 'warn'/'off'/null
    /// keep the license signal advisory and never deny the download.
    /// </summary>
    string? LicenseEnforcementMode = null,
    /// <summary>
    /// True when this tenant's proxy content binding differs from the shared <c>cache_artifact</c>
    /// row's bytes (<see cref="Infrastructure.CacheArtifactServeFacts.ContentDivergesFromSharedFacts"/>).
    /// Every other byte-derived field on this record is already the divergence-adjusted
    /// <c>Effective*</c> value read off that projection; this flag exists for the one byte-derived
    /// fact that is not carried on the record at all — <c>package_version_licenses</c>, read by a
    /// separate keyed lookup in <see cref="EvaluateLicenseArmAsync"/> — so that arm can apply the
    /// same "no evidence about this tenant's own bytes" treatment without reading the shared row's
    /// license entries. Always <see langword="false"/> for the hosted (non-proxy) path.
    /// </summary>
    bool ContentDiverges = false,
    /// <summary>
    /// The actor's display name, carried alongside <see cref="AuditActorId"/> and written to
    /// <c>actor_label</c> so the row stays readable after the row it would otherwise join to
    /// is gone. Non-null for a service token only — <c>TokenRecord.AuditActorLabel</c> derives
    /// it, so no call site can put a user's email in that column. NULL means "resolve through
    /// the existing join", which is what rows predating the column already do.
    /// </summary>
    string? AuditActorLabel = null)
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
            token?.AuditActorId, settings?.MaxOsvScoreTolerance ?? DefaultMaxOsvScore, sourceIp,
            AuditActorLabel: token?.AuditActorLabel,
            MinReleaseAgeHours: settings?.MinReleaseAgeHours,
            PublishedAt: version.PublishedAt,
            ActorKind: token?.ActorKind,
            Deprecated: version.Deprecated,
            BlockDeprecatedMode: settings?.BlockDeprecated,
            BlockMaliciousMode: settings?.BlockMalicious,
            BlockKevMode: settings?.BlockKev,
            MaxEpssTolerance: settings?.MaxEpssTolerance,
            BlockKevRansomwareMode: settings?.BlockKevRansomware,
            BlockSsvcExploitationMode: settings?.BlockSsvcExploitation,
            MaxEpssPercentileTolerance: settings?.MaxEpssPercentileTolerance,
            Origin: version.Origin,
            HasInstallScript: version.HasInstallScript,
            InstallScriptKind: version.InstallScriptKind,
            BlockInstallScriptsMode: settings?.BlockInstallScripts,
            ProvenanceStatus: version.ProvenanceStatus,
            // Per-ecosystem toggle over the ecosystem-agnostic stored status, matching the
            // index-filter path so a version hidden from the index is not downloadable by URL.
            VerifyProvenanceMode: settings?.VerifyProvenanceMode(ecosystem),
            RevokedAt: version.RevokedAt,
            BlockRevokedMode: settings?.BlockRevoked,
            LicenseEnforcementMode: settings?.LicenseEnforcementMode);

    /// <summary>
    /// Constructs a <see cref="BlockGateRequest"/> for a proxy artifact served from the global
    /// plane (<c>cache_artifact</c> + <c>tenant_artifact_access</c>) from the per-tenant serve
    /// facts. The single home for the proxy cache-hit gate inputs: every ecosystem download
    /// handler builds the request here rather than cloning the field-by-field projection, so a
    /// new gate signal is threaded once. <paramref name="settings"/> is nullable to accommodate
    /// callers whose settings lookup returns null (e.g. Maven); absent settings fall back to the
    /// policy-off defaults on each field.
    /// </summary>
    public static BlockGateRequest ForProxyCacheFacts(
        string orgId,
        string ecosystem,
        Infrastructure.CacheArtifactServeFacts caFacts,
        TokenRecord? token,
        OrgSettings? settings,
        string? sourceIp) =>
        new(orgId, ecosystem, caFacts.Purl ?? string.Empty, string.Empty,
            // OSV findings (this and the signals GetGateSignalsAsync loads below) are keyed by
            // package coordinate, not by bytes — see EvaluateAsync's remark on VulnCheckedAt —
            // so this is the shared row's real stamp, unmasked by divergence.
            caFacts.ManualBlockState, caFacts.VulnCheckedAt,
            token?.AuditActorId, settings?.MaxOsvScoreTolerance ?? DefaultMaxOsvScore, sourceIp,
            AuditActorLabel: token?.AuditActorLabel,
            MinReleaseAgeHours: settings?.MinReleaseAgeHours,
            PublishedAt: caFacts.PublishedAt,
            ActorKind: token?.ActorKind,
            Deprecated: caFacts.Deprecated,
            BlockDeprecatedMode: settings?.BlockDeprecated,
            BlockMaliciousMode: settings?.BlockMalicious,
            BlockKevMode: settings?.BlockKev,
            MaxEpssTolerance: settings?.MaxEpssTolerance,
            BlockKevRansomwareMode: settings?.BlockKevRansomware,
            BlockSsvcExploitationMode: settings?.BlockSsvcExploitation,
            MaxEpssPercentileTolerance: settings?.MaxEpssPercentileTolerance,
            Origin: "proxy",
            HasInstallScript: caFacts.EffectiveHasInstallScript,
            InstallScriptKind: caFacts.EffectiveInstallScriptKind,
            BlockInstallScriptsMode: settings?.BlockInstallScripts,
            ProvenanceStatus: caFacts.EffectiveProvenanceStatus,
            // The stored provenance_status column is ecosystem-agnostic; the toggle that interprets
            // it is per-ecosystem. Without the mode the persisted verdict is inert on the serve
            // path and a 'block' policy would only ever be enforced by the index filters.
            VerifyProvenanceMode: settings?.VerifyProvenanceMode(ecosystem),
            RevokedAt: caFacts.RevokedAt,
            BlockRevokedMode: settings?.BlockRevoked,
            LicenseEnforcementMode: settings?.LicenseEnforcementMode,
            CacheArtifactId: caFacts.Id,
            ContentDiverges: caFacts.ContentDivergesFromSharedFacts);

    /// <summary>
    /// Constructs a <see cref="BlockGateRequest"/> for the proxy FIRST-FETCH serve gate — the
    /// evaluation that runs after the artifact is recorded and scanned, before its bytes reach the
    /// client that triggered the fetch.
    ///
    /// <para>
    /// It reads the same <see cref="Infrastructure.CacheArtifactServeFacts"/> projection the
    /// cache-hit path reads, and differs from <see cref="ForProxyCacheFacts"/> in exactly one
    /// respect: the tenant policy arrives as loose fields rather than an <see cref="OrgSettings"/>,
    /// because <c>ProxyFetchService</c>'s callers resolve those values well before the fetch. Every
    /// FACT still comes from the row. That is what makes the two paths symmetric by construction:
    /// a new fact added to the projection reaches both gates, and neither can read a fact the other
    /// cannot see.
    /// </para>
    ///
    /// <para>
    /// The predecessor of this factory built the request field-by-field at the call site against a
    /// narrower, tenant-blind projection. That shape silently dropped <c>manual_block_state</c> and
    /// <c>revoked_at</c> from the first-fetch decision — so a tenant that had manually blocked a
    /// proxy artifact, or an artifact upstream had withdrawn, was served anyway whenever the cached
    /// blob had been evicted and the request re-entered the fetch path. Building both proxy gate
    /// requests in this one file from this one facts type is the fix for the class, not just the
    /// instance.
    /// </para>
    /// </summary>
    /// <param name="ownProvenanceStatus">
    /// This request's own just-computed provenance verdict, over the bytes this fetch staged —
    /// <c>ProxyFetchRequest.ProvenanceStatus</c> at the call site. Preferred over
    /// <see cref="Infrastructure.CacheArtifactServeFacts.EffectiveProvenanceStatus"/> when supplied:
    /// <c>UpdateGlobalFactsAsync</c>'s COALESCE keep-existing semantics mean the shared row can
    /// carry an earlier tenant's verdict rather than this one's, and <c>EffectiveProvenanceStatus</c>
    /// additionally masks that stored value to <c>Unverifiable</c> on divergence — discarding, in
    /// either case, strictly better evidence this call already has in hand for the tenant it is
    /// actually gating. NULL when the caller has none (no provenance verification configured for
    /// this ecosystem), in which case the masked shared-row value is used exactly as before.
    /// </param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Single-source factory for the proxy first-fetch gate request: the parameter list IS " +
            "the threaded field set, and grouping it would reintroduce the field-by-field indirection this " +
            "factory exists to remove.")]
    public static BlockGateRequest ForProxyFirstFetch(
        string orgId,
        string ecosystem,
        Infrastructure.CacheArtifactServeFacts caFacts,
        string? userId,
        string? actorKind,
        string? actorLabel,
        string? sourceIp,
        double maxOsvScoreTolerance,
        int? minReleaseAgeHours,
        string? blockDeprecatedMode,
        string? blockMaliciousMode,
        string? blockKevMode,
        double? maxEpssTolerance,
        string? blockInstallScriptsMode,
        string? verifyProvenanceMode,
        string? blockRevokedMode,
        string? licenseEnforcementMode,
        string? ownProvenanceStatus = null) =>
        new(orgId, ecosystem, caFacts.Purl ?? string.Empty, string.Empty,
            // OSV findings are keyed by package coordinate, not by bytes — see EvaluateAsync's
            // remark on VulnCheckedAt — so this is the shared row's real stamp, unmasked.
            caFacts.ManualBlockState, caFacts.VulnCheckedAt,
            userId, maxOsvScoreTolerance, sourceIp,
            MinReleaseAgeHours: minReleaseAgeHours,
            PublishedAt: caFacts.PublishedAt,
            ActorKind: actorKind,
            AuditActorLabel: actorLabel,
            Deprecated: caFacts.Deprecated,
            BlockDeprecatedMode: blockDeprecatedMode,
            BlockMaliciousMode: blockMaliciousMode,
            BlockKevMode: blockKevMode,
            MaxEpssTolerance: maxEpssTolerance,
            Origin: "proxy",
            HasInstallScript: caFacts.EffectiveHasInstallScript,
            InstallScriptKind: caFacts.EffectiveInstallScriptKind,
            BlockInstallScriptsMode: blockInstallScriptsMode,
            ProvenanceStatus: ownProvenanceStatus ?? caFacts.EffectiveProvenanceStatus,
            VerifyProvenanceMode: verifyProvenanceMode,
            RevokedAt: caFacts.RevokedAt,
            BlockRevokedMode: blockRevokedMode,
            LicenseEnforcementMode: licenseEnforcementMode,
            CacheArtifactId: caFacts.Id,
            ContentDiverges: caFacts.ContentDivergesFromSharedFacts);

    /// <summary>
    /// Constructs the request for the pre-record first-fetch DEPRECATION gate. This one runs before
    /// any cache-plane row exists, so it carries no facts — only the coordinate and the two values
    /// the deprecation arm reads. Kept here beside the others so every <see cref="BlockGateRequest"/>
    /// in the codebase is built in this file.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "A BlockGateRequest factory: BlockGateRequestConstructionComplianceTests requires the request " +
            "be built here rather than field-by-field at a call site, precisely because a dropped field defaults to " +
            "null and reads as \"policy off\". Collapsing this parameter list into a wrapper type is the same silent-hole " +
            "shape the factory exists to prevent.")]
    public static BlockGateRequest ForFirstFetchDeprecation(
        string orgId, string ecosystem, string purl, string? userId, string? actorKind, string? actorLabel,
        double maxOsvScoreTolerance, string? sourceIp, string? deprecated, string? blockDeprecatedMode) =>
        new(orgId, ecosystem, purl, string.Empty, null, null,
            userId, maxOsvScoreTolerance, sourceIp,
            ActorKind: actorKind,
            AuditActorLabel: actorLabel,
            Deprecated: deprecated,
            BlockDeprecatedMode: blockDeprecatedMode);

    /// <summary>
    /// Constructs the request for the pre-record first-fetch PROVENANCE gate, which refuses a
    /// version that failed signature verification before it is adopted into the cache catalogue.
    /// Like the deprecation twin it precedes the facts row, so the verdict is the one the ecosystem
    /// handler just computed rather than one read back from storage.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "A BlockGateRequest factory: BlockGateRequestConstructionComplianceTests requires the request " +
            "be built here rather than field-by-field at a call site, precisely because a dropped field defaults to " +
            "null and reads as \"policy off\". Collapsing this parameter list into a wrapper type is the same silent-hole " +
            "shape the factory exists to prevent.")]
    public static BlockGateRequest ForFirstFetchProvenance(
        string orgId, string ecosystem, string purl, string? userId, string? actorKind, string? actorLabel,
        double maxOsvScoreTolerance, string? sourceIp, string provenanceStatus, string? verifyProvenanceMode) =>
        new(orgId, ecosystem, purl, string.Empty, null, null,
            userId, maxOsvScoreTolerance, sourceIp,
            ActorKind: actorKind,
            AuditActorLabel: actorLabel,
            ProvenanceStatus: provenanceStatus,
            VerifyProvenanceMode: verifyProvenanceMode);
}
