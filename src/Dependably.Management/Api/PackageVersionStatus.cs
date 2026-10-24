using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Protocol;

namespace Dependably.Api;

/// <summary>
/// The status label a package version carries in the package views: <c>blocked</c>,
/// <c>allowed</c>, <c>deprecated</c>, <c>no_feed</c>, <c>unscanned</c>, <c>vulnerable</c>,
/// <c>partial</c> or <c>clean</c>, derived from its block state and screening signals.
/// </summary>
internal static class PackageVersionStatus
{
    internal static string ComputeVersionStatus(
        PackageVersion v, string ecosystem, double? maxScore, double tolerance, string blockDeprecatedMode = "off")
        => ComputeStatus(v, new ScanSignals(
            Scanned: v.VulnCheckedAt is not null,
            HasAdvisory: v.HasAdvisory,
            HasFeed: OsvFeedCoverage.HasAdvisoryFeed(ecosystem),
            HasGaps: false,
            MaxScore: maxScore), tolerance, blockDeprecatedMode);

    /// <summary>Scanned with coverage gaps and no advisories: OCI images only.</summary>
    internal const string PartialStatus = "partial";

    /// <summary>
    /// An OCI image's status from the org's own scan facts (<paramref name="facts"/> is null when
    /// the org has no result for it). OCI has a feed for an image only when the org has a stored
    /// result or a live scanner, so without either it stays <c>no_feed</c>. A stored result keeps
    /// its status after the scanner stops. A result with coverage gaps and no advisories is
    /// <c>partial</c>, never clean. A score above the org's tolerance reads <c>blocked</c> only
    /// when <paramref name="scoreEnforced"/> (the org's <c>oci_scan_enforcement</c> is
    /// <c>block</c>, so the pull gate refuses it); otherwise it reads <c>vulnerable</c>, since the
    /// image still pulls and a <c>blocked</c> label would claim a refusal that never happens.
    /// </summary>
    internal static string ComputeOciVersionStatus(
        PackageVersion v, OciScanFacts? facts, bool covered,
        double tolerance, string blockDeprecatedMode, bool scoreEnforced = false)
        => ComputeStatus(v, new ScanSignals(
            Scanned: facts is not null,
            HasAdvisory: facts is { AdvisoryCount: > 0 },
            HasFeed: facts is not null || covered,
            HasGaps: facts is { GapCount: > 0 },
            MaxScore: facts?.MaxScore,
            ScoreEnforced: scoreEnforced), tolerance, blockDeprecatedMode);

    /// <summary>
    /// What the status rules read about a version's vulnerability screening.
    /// <c>ScoreEnforced</c> says whether the serve path refuses a version whose score is above the
    /// tolerance; only then does such a score read <c>blocked</c>.
    /// </summary>
    private readonly record struct ScanSignals(
        bool Scanned, bool HasAdvisory, bool HasFeed, bool HasGaps, double? MaxScore, bool ScoreEnforced = true);

    private static string ComputeStatus(
        PackageVersion v, ScanSignals scan, double tolerance, string blockDeprecatedMode)
    {
        double? maxScore = scan.MaxScore;
        if (v.ManualBlockState == "blocked")
        {
            return "blocked";
        }
        // Only block_all denies an already-cached deprecated version; under block_new the cached
        // version keeps serving, so it surfaces as "deprecated" below. Legacy 'block' == block_all.
        if (v.Deprecated is not null && blockDeprecatedMode is "block_all" or "block")
        {
            return "blocked";
        }

        bool autoBlocked = scan.ScoreEnforced && scan.Scanned && maxScore.HasValue && maxScore.Value > tolerance;
        return (v.ManualBlockState, autoBlocked) switch
        {
            // Manual allow over an advisory the gate would otherwise auto-block.
            ("allowed", true) => "allowed",
            // Any non-allowed version above tolerance is auto-blocked.
            (_, true) => "blocked",
            _ when v.Deprecated is not null => "deprecated",
            // OSV publishes no feed this ecosystem's artefacts could match, so neither a stamped
            // nor an absent vuln_checked_at says anything about them: an empty advisory list is
            // the only answer a lookup can return. Reported as its own state so the absence of
            // coverage is visible instead of reading as a clean screening — "nothing to scan
            // against" and "not scanned yet" call for different operator action. Conditioned on
            // HasAdvisory so a row that did acquire advisory links keeps its vulnerable label.
            _ when !scan.HasAdvisory && !scan.HasFeed
                => OsvFeedCoverage.NoFeedStatus,
            _ when !scan.Scanned => "unscanned",
            // Scanned and servable, but carries at least one advisory below the block
            // tolerance (or an unscored/MAL advisory the score aggregate never saw). Reported
            // distinctly so it is never labelled "clean" — only an advisory-free scanned
            // version earns that label.
            _ when scan.HasAdvisory => "vulnerable",
            // Scanned, no advisories, but the scan could not inventory or match part of the
            // image (an OCI coverage gap): the absence of advisories covers only what was read.
            _ when scan.HasGaps => PartialStatus,
            _ => "clean",
        };
    }
}
