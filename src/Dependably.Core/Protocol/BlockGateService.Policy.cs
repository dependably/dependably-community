using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol.Provenance;

namespace Dependably.Protocol;

/// <summary>The pure, I/O-free policy core and stored-state predicates of <see cref="BlockGateService"/>.</summary>
public sealed partial class BlockGateService
{
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
            BlockMaliciousLiveMode: settings.BlockMaliciousLive,
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
            BlockMaliciousLiveMode: settings.BlockMaliciousLive,
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

    /// <summary>
    /// The pure verdict the OCI pull gate would reach for an image, with no side effects: the
    /// same fact projection <see cref="EvaluateAsync"/> builds for a <see cref="BlockGateRequest.ForOciImage"/>
    /// request, evaluated against the org's arm modes and its <c>oci_scan_enforcement</c> posture.
    /// Read by the moving-tag promotion gate, which may promote a held digest onto its tag only
    /// once this verdict is servable. The licence arm is not part of it: the serve path still runs
    /// that arm on the promoted digest, as it does on every manifest.
    /// </summary>
    public static BlockVerdict PreviewOciImage(
        Infrastructure.OciScan.OciGateFacts facts, string? manualState, OrgSettings settings, DateTimeOffset now)
    {
        var vf = new VersionFacts(
            ManualState: manualState,
            Deprecated: null,
            PublishedAt: null,
            Scanned: facts.HasEvidence,
            Vulnerability: ProjectVulnFacts(facts.HasEvidence ? facts.Signals : null),
            Origin: "proxy",
            ScanRequired: IsOciScanEnforced(settings.OciScanEnforcement),
            ScanComplete: facts.IsComplete);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockMaliciousLiveMode: settings.BlockMaliciousLive,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            BlockKevRansomwareMode: settings.BlockKevRansomware,
            BlockSsvcExploitationMode: settings.BlockSsvcExploitation,
            MaxEpssPercentileTolerance: settings.MaxEpssPercentileTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            VerifyProvenanceMode: settings.VerifyProvenanceMode("oci"),
            BlockRevokedMode: settings.BlockRevoked,
            OciScanEnforcementMode: settings.OciScanEnforcement);

        return Evaluate(vf, policy, now);
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
        if (InstallScriptTriggers(facts) && policy.BlockInstallScriptsMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.InstallScript);
        }

        // Arm 10: unscanned. Only an OCI image under oci_scan_enforcement sets ScanRequired, so
        // every other ecosystem's normal unscanned window stays fail-open. Evaluated here rather
        // than inside EvaluateVulnArms, whose no-signal short-circuit returns servable for exactly
        // the case this arm exists to refuse; and after every advisory arm, so an image a partial
        // scan found a KEV in reports kev rather than unscanned.
        return UnscannedTriggers(facts) && policy.OciScanEnforcementMode == "block"
            ? new BlockVerdict(Servable: false, Arm: BlockArm.Unscanned)
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

    // Deliberately NO staleness gating, unlike SsvcExploitationTriggers' dual staleness handling
    // below: a positive still-live result does not go stale into "safe" the way an exploitation
    // ASSESSMENT can. The malware does not un-flag itself with the passage of time — only a fresh
    // probe finding the version actually removed changes the answer, and that arrives as a new
    // `false` on VulnFacts.MalStillLive, not a stale `true` that needs a horizon to discount. This
    // is a divergence from the SSVC precedent by design, not an omission.
    private static bool MalStillLiveTriggers(VersionFacts f) => f.Scanned && f.Vulnerability.MalStillLive;

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

    // Deliberately not keyed on !Scanned: that is true for every ecosystem's ordinary unscanned
    // window, which stays fail-open. Only a request that requires a scan can trip this arm.
    private static bool UnscannedTriggers(VersionFacts f) => f.ScanRequired && !f.ScanComplete;

    private static bool IsWarn(string? mode) => mode == "warn";

    /// <summary>
    /// The highest-priority arm whose fact is present and whose tenant mode is <c>warn</c>, or
    /// <see cref="BlockArm.None"/>. Walks the blocking pass's order and trigger predicates, so an arm
    /// cannot be enforced-but-not-warned or the reverse, with one deliberate exception:
    /// <see cref="BlockArm.Unscanned"/> leads here, so a missing-scan warning is not masked by a
    /// lower-priority advisory warning.
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
            // Priority order: the blocking pass's, except that Unscanned leads (see above). Written as a null-coalescing
            // chain rather than a sequence of ifs so the order is one readable list, and rather
            // than an array so the serve path allocates nothing per evaluation.
            : Warned(UnscannedTriggers(facts), policy.OciScanEnforcementMode, BlockArm.Unscanned)
              ?? Warned(DeprecatedTriggers(facts), policy.BlockDeprecatedMode, BlockArm.Deprecated)
              ?? Warned(RevokedTriggers(facts), policy.BlockRevokedMode, BlockArm.Revoked)
              ?? Warned(MalStillLiveTriggers(facts), policy.BlockMaliciousLiveMode, BlockArm.MaliciousLive)
              ?? Warned(MaliciousTriggers(facts), policy.BlockMaliciousMode, BlockArm.Malicious)
              ?? Warned(KevRansomwareTriggers(facts), policy.BlockKevRansomwareMode, BlockArm.KevRansomware)
              ?? Warned(KevTriggers(facts), policy.BlockKevMode, BlockArm.Kev)
              ?? Warned(SsvcExploitationTriggers(facts), policy.BlockSsvcExploitationMode, BlockArm.SsvcExploitation)
              ?? Warned(ProvenanceTriggers(facts), policy.VerifyProvenanceMode, BlockArm.Provenance)
              ?? Warned(InstallScriptTriggers(facts), policy.BlockInstallScriptsMode, BlockArm.InstallScript)
              ?? BlockArm.None;

    /// <summary>
    /// Every advisory arm whose fact is present and whose tenant mode is <c>warn</c>, in ladder
    /// order, by reason token. Recorded on an unscanned refusal: a partial result's warn-mode
    /// findings are not a pass, and since the refusal subsumes the warning no separate
    /// <c>gate_warned</c> row is written, so the refusal's own detail is where they are kept.
    /// </summary>
    private static List<string> WarnedArms(VersionFacts facts, BlockPolicy policy)
    {
        var arms = new List<string>();
        void Add(bool triggered, string? mode, BlockArm arm)
        {
            if (Warned(triggered, mode, arm) is { } warned
                && new BlockOutcome(BlockDecision.Blocked, warned).ReasonToken is { } token)
            {
                arms.Add(token);
            }
        }

        Add(MalStillLiveTriggers(facts), policy.BlockMaliciousLiveMode, BlockArm.MaliciousLive);
        Add(MaliciousTriggers(facts), policy.BlockMaliciousMode, BlockArm.Malicious);
        Add(KevRansomwareTriggers(facts), policy.BlockKevRansomwareMode, BlockArm.KevRansomware);
        Add(KevTriggers(facts), policy.BlockKevMode, BlockArm.Kev);
        Add(SsvcExploitationTriggers(facts), policy.BlockSsvcExploitationMode, BlockArm.SsvcExploitation);
        return arms;
    }

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
    [SuppressMessage("Critical Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "A flat, ordered sequence of independent policy arms, every branch at nesting "
                        + "depth zero — the complexity is the arm COUNT, not nested logic. The order is "
                        + "load-bearing and each arm's comment states why it must sit where it does "
                        + "(a narrow arm before its broad twin, so a 'warn' on the broad one cannot "
                        + "swallow the narrow one's attribution). Splitting the arms across helpers "
                        + "moves that ordering out of the one place a reviewer reads it, which is how "
                        + "arm 4a became unreachable-but-plausible once already.")]
    private static BlockVerdict EvaluateVulnArms(VersionFacts facts, BlockPolicy policy)
    {
        if (!facts.Scanned)
        {
            return new BlockVerdict(Servable: true, Arm: BlockArm.None);
        }

        // Arm 4a: the narrow still-live-malicious gate, evaluated BEFORE the broad malicious arm
        // (arm 4) — same reasoning as the KEV-ransomware/KEV pair below: the two settings are
        // independent, and the useful combination is block_malicious='warn' with this at 'block',
        // which only produces a block if the narrow arm is reached first. Ordering it after arm 4
        // would let the broad arm's 'warn' fall through and lose the still-live attribution
        // entirely. See MalStillLiveTriggers for why this arm carries no staleness gating.
        if (MalStillLiveTriggers(facts) && policy.BlockMaliciousLiveMode == "block")
        {
            return new BlockVerdict(Servable: false, Arm: BlockArm.MaliciousLive);
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
        // MalStillLive is included for the same defensive reason even though arm 4a's own check
        // above already runs unconditionally before this guard is reached: a signal this guard
        // does not name is exactly the failure mode that made arm 4a unreachable look correct at
        // its own call site while doing nothing, and this guard must never be the thing that
        // silently reintroduces that bug if the arms above it are ever reordered.
        if (!facts.Vulnerability.IsKev && facts.Vulnerability.IsKevRansomware != true
            && facts.Vulnerability.SsvcExploitation != "active" && !facts.Vulnerability.HasStaleEnrichment
            && facts.Vulnerability.Epss is null && facts.Vulnerability.EpssPercentile is null
            && facts.Vulnerability.Cvss is null && !facts.Vulnerability.MalStillLive)
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
