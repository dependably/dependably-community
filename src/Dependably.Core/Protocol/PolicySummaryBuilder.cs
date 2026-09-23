using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;

namespace Dependably.Protocol;

// ── Control DTOs ─────────────────────────────────────────────────────────────────────────────
//
// Each record is a leaf of PolicySummary.Controls, keyed by the BlockOutcome.ReasonToken the
// same arm reports in the X-Dependably-Block-Reason header. Controls holds them as `object`
// (System.Text.Json serializes an object-typed dictionary value by its runtime type, not the
// declared one) purely so the per-arm shapes below — which carry different fields (Mode vs
// MinHours vs MaxScore) — can share one dictionary without a lossy common base type.

/// <summary>An off/warn/block gate with no numeric threshold of its own.</summary>
public sealed record TriStateControl(string Mode, string Effect, bool Active);

/// <summary>The release-age hold: no tri-state mode, just a threshold that is either set or off.</summary>
public sealed record ReleaseAgeControl(int? MinHours, string Effect, bool Active);

/// <summary>The CVSS ceiling. Always "active" — nothing external can leave it unbacked.</summary>
public sealed record VulnScoreControl(double MaxScore, string Effect, bool Active);

/// <summary>The EPSS probability ceiling.</summary>
public sealed record EpssControl(double? MaxProbability, string Effect, bool Active);

/// <summary>The EPSS percentile ceiling — the rank sibling of <see cref="EpssControl"/>.</summary>
public sealed record EpssPercentileControl(double? MaxPercentile, string Effect, bool Active);

/// <summary>One ecosystem's signature/attestation-verification gate.</summary>
public sealed record ProvenanceEcosystemControl(string Mode, string Effect, bool AnchorsConfigured);

/// <summary>
/// The full <c>GET /api/v1/policies</c> payload. <see cref="Controls"/> deliberately excludes
/// upstream URLs, credentials, anchor material, PURL allow/blocklist patterns, and the
/// install-script allowlist — see <see cref="PolicySummaryBuilder"/>'s doc comment for why.
/// </summary>
public sealed record PolicySummary(
    string AllowlistMode,
    bool ProxyPassthroughEnabled,
    IReadOnlyDictionary<string, object> Controls);

/// <summary>
/// Pure derivation of the member-visible policy summary from an org's stored settings. Computes,
/// for every gate: the raw stored <c>mode</c>, a normalized <c>effect</c> (<c>off|warn|block</c> —
/// <c>block_new</c>/<c>block_all</c> both read as <c>block</c>, and a threshold sitting at its
/// "allow everything" value reads as <c>off</c>), and whether the gate's underlying <c>active</c>
/// data source is currently refreshing.
///
/// <c>active</c> is deliberately NOT "can this control fire" — a control with <c>active=false</c>
/// still enforces against whatever it last recorded; it simply is not learning anything new.
/// <see cref="BlockGateService"/>'s malicious-live and SSVC-exploitation arms read a signal the
/// vulnerability tracker last wrote and keep acting on it after the tracker connection pauses;
/// the SSVC arm additionally fires on <c>HasStaleEnrichment</c> — an enrichment gone stale is
/// itself a trigger, not a reason to stop enforcing. KEV/EPSS read the shared <c>vulnerabilities</c>
/// table the threat-feed job maintains, and a disabled job leaves that table's last values in
/// place rather than clearing them. Reporting "can't fire" here would read a paused refresh as a
/// safety net that does not exist — the wrong direction for a security control.
///
/// Deliberately excludes anything an attacker could use as a roadmap around a control: upstream
/// registry URLs/credentials, trust-anchor key material, the PURL allow/blocklist patterns
/// themselves (only their governing mode), and the install-script allowlist. Those stay behind
/// <c>read:tenant</c> on <c>GET /api/v1/proxy-settings</c>; this endpoint carries only posture.
/// </summary>
public static class PolicySummaryBuilder
{
    // Same ceiling OrgSettingsController.MaxOsvScore uses — a tolerance at (or above) the CVSS
    // scale's maximum accepts every score, so the gate never fires.
    private const double MaxOsvScore = 10.0;

    // EPSS is a 0.0-1.0 probability/percentile; the block arms compare with a strict `>`
    // (BlockGateService.EvaluateBlocking), so a tolerance at or above 1.0 can never be exceeded.
    private const double MaxEpssTolerance = 1.0;

    public static PolicySummary Build(
        OrgSettings? settings,
        // ResolvedVulnTrackerConfig.IsActive (Enabled && Configured): true only while the
        // vulnerability-tracker connection is live and actually refreshing malicious-live/SSVC
        // enrichment. False does not mean the malicious_live/ssvc_exploitation arms stop
        // enforcing — see the class doc comment.
        bool vulnTrackerActive,
        // !IAirGapMode.IsJobDisabled("threat-feed"): true while the background job that refreshes
        // the shared KEV/EPSS columns is running. False does not mean kev/kev_ransomware/epss/
        // epss_percentile stop enforcing — they act on whatever the table last recorded.
        bool threatFeedActive,
        ProvenanceAnchorStatus anchors)
    {
        bool allowlistMode = settings?.AllowlistMode ?? false;
        bool proxyPassthroughEnabled = settings?.ProxyPassthroughEnabled ?? true;
        double maxOsvScoreTolerance = settings?.MaxOsvScoreTolerance ?? MaxOsvScore;
        int? minReleaseAgeHours = settings?.MinReleaseAgeHours;
        string blockDeprecated = settings?.BlockDeprecated ?? "off";
        string blockRevoked = settings?.BlockRevoked ?? "warn";
        string blockMalicious = settings?.BlockMalicious ?? "block";
        string blockMaliciousLive = settings?.BlockMaliciousLive ?? "off";
        string blockKev = settings?.BlockKev ?? "off";
        string blockKevRansomware = settings?.BlockKevRansomware ?? "off";
        string blockSsvcExploitation = settings?.BlockSsvcExploitation ?? "off";
        double? maxEpssPercentileTolerance = settings?.MaxEpssPercentileTolerance;
        double? maxEpssTolerance = settings?.MaxEpssTolerance;
        string blockInstallScripts = settings?.BlockInstallScripts ?? "off";
        string verifyNpmSignatures = settings?.VerifyNpmSignatures ?? "off";
        string verifyNuGetSignatures = settings?.VerifyNuGetSignatures ?? "off";
        string verifyPyPiAttestations = settings?.VerifyPyPiAttestations ?? "off";
        string verifyRpmSignatures = settings?.VerifyRpmSignatures ?? "off";
        string verifyMavenSignatures = settings?.VerifyMavenSignatures ?? "off";
        string verifyTerraformSignatures = settings?.VerifyTerraformSignatures ?? "off";
        string licenseMode = settings?.LicenseEnforcementMode ?? "off";

        var controls = new Dictionary<string, object>
        {
            ["malicious"] = new TriStateControl(
                blockMalicious, TriStateEffect(blockMalicious), true),
            ["malicious_live"] = new TriStateControl(
                blockMaliciousLive, TriStateEffect(blockMaliciousLive), vulnTrackerActive),
            ["kev"] = new TriStateControl(blockKev, TriStateEffect(blockKev), threatFeedActive),
            ["kev_ransomware"] = new TriStateControl(
                blockKevRansomware, TriStateEffect(blockKevRansomware), threatFeedActive),
            ["deprecated"] = new TriStateControl(
                blockDeprecated, DeprecatedEffect(blockDeprecated), true),
            ["revoked"] = new TriStateControl(blockRevoked, TriStateEffect(blockRevoked), true),
            ["install_script"] = new TriStateControl(
                blockInstallScripts, TriStateEffect(blockInstallScripts), true),
            ["ssvc_exploitation"] = new TriStateControl(
                blockSsvcExploitation, TriStateEffect(blockSsvcExploitation), vulnTrackerActive),
            ["release_age"] = new ReleaseAgeControl(
                minReleaseAgeHours, ReleaseAgeEffect(minReleaseAgeHours), true),
            ["vuln_score"] = new VulnScoreControl(
                maxOsvScoreTolerance, VulnScoreEffect(maxOsvScoreTolerance), true),
            ["epss"] = new EpssControl(
                maxEpssTolerance, EpssEffect(maxEpssTolerance), threatFeedActive),
            ["epss_percentile"] = new EpssPercentileControl(
                maxEpssPercentileTolerance, EpssEffect(maxEpssPercentileTolerance), threatFeedActive),
            ["provenance"] = new Dictionary<string, ProvenanceEcosystemControl>
            {
                ["npm"] = new(
                    verifyNpmSignatures, TriStateEffect(verifyNpmSignatures), anchors.Npm),
                ["nuget"] = new(
                    verifyNuGetSignatures, TriStateEffect(verifyNuGetSignatures), anchors.NuGet),
                ["pypi"] = new(
                    verifyPyPiAttestations, TriStateEffect(verifyPyPiAttestations), anchors.PyPi),
                ["rpm"] = new(
                    verifyRpmSignatures, TriStateEffect(verifyRpmSignatures), anchors.Rpm),
                ["maven"] = new(
                    verifyMavenSignatures, TriStateEffect(verifyMavenSignatures), anchors.Maven),
                ["terraform"] = new(
                    verifyTerraformSignatures, TriStateEffect(verifyTerraformSignatures),
                    anchors.Terraform),
            },
            ["license"] = new TriStateControl(licenseMode, TriStateEffect(licenseMode), true),
        };

        return new PolicySummary(
            allowlistMode ? "on" : "off", proxyPassthroughEnabled, controls);
    }

    // off/warn/block gates map straight through.
    private static string TriStateEffect(string mode) => mode switch
    {
        "block" => "block",
        "warn" => "warn",
        _ => "off",
    };

    // block_deprecated carries a fourth raw value ('block_new'), which only refuses a deprecated
    // version on its first fetch — an already-cached deprecated version keeps serving and stays
    // listed (BlockGateService's deprecated arm explicitly excludes block_new from its check).
    // 'block_new' and 'block_all' both still collapse to effect "block" here: the distinction
    // between them lives in the raw `mode` this control also carries, which the frontend renders
    // verbatim (the same Settings -> Gates option labels), not in this normalized effect.
    private static string DeprecatedEffect(string mode) => mode switch
    {
        "block_new" or "block_all" => "block",
        "warn" => "warn",
        _ => "off",
    };

    // Mirrors BlockGateService.IsReleaseAgeBlocked: null or non-positive is off.
    private static string ReleaseAgeEffect(int? minHours) =>
        minHours is null or <= 0 ? "off" : "block";

    // A tolerance at or above the CVSS scale's own ceiling accepts every score.
    private static string VulnScoreEffect(double maxScore) =>
        maxScore >= MaxOsvScore ? "off" : "block";

    // EPSS probability/percentile ceilings: NULL is the gate's own "off" value, and so is a
    // tolerance at or above 1.0 — the block arms compare with a strict `>` against a value that
    // can never exceed 1.0, so a tolerance that high accepts everything.
    private static string EpssEffect(double? tolerance) =>
        tolerance is null or >= MaxEpssTolerance ? "off" : "block";
}
