using System.Diagnostics.CodeAnalysis;

namespace Dependably.Protocol;

// The block gate's vocabulary: which arm fired, what the pure policy core decided, and how that
// decision is reported outward. Split out of BlockGateService.cs purely for file size (S104) —
// these are leaf declarations no compliance gate reads out of that file by name, unlike
// VersionFacts (whose ForUpstreamOnly factory VulnFactsConstructionComplianceTests requires there)
// and BlockGateRequest (whose factories the two BlockGateRequest gates locate there).
// BlockArmSideEffectComplianceTests enumerates BlockArm through Enum.GetValues, not the file, so
// the enum is safe to declare here.

/// <summary>
/// Identifies which policy arm triggered a block verdict. <see cref="None"/> means the
/// version is servable (no arm fired).
/// </summary>
public enum BlockArm
{
    None, Manual, Deprecated, Revoked, ReleaseAge, MaliciousLive, Malicious, Provenance,
    Kev, KevRansomware, SsvcExploitation, Epss, EpssPercentile, VulnScore, InstallScript, License,
}

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
        BlockArm.MaliciousLive => "malicious_live",
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
    string? BlockSsvcExploitationMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_malicious_live</c>: 'off' (default) | 'warn' |
    /// 'block'. The narrow companion to <see cref="BlockMaliciousMode"/>, matching only the
    /// tracker's version-precise still-live-malicious signal. Independent rather than a mode on
    /// the broad arm, so <c>BlockMaliciousMode = "warn"</c> with this at <c>"block"</c> is
    /// expressible.
    /// </summary>
    string? BlockMaliciousLiveMode = null);
