using System.Text.Json;

namespace Dependably.Infrastructure.OciScan;

/// <summary>The body of <c>POST /api/v1/oci-scan/claim</c>.</summary>
public sealed record OciScanClaimRequest(int? Max, OciScannerReport? Scanner);

/// <summary>What a scanner says about itself on each call; every field is optional.</summary>
public sealed record OciScannerReport(string? Version, string? OsvSource, JsonElement? OsvState);

/// <summary>One leased job, as the scanner receives it.</summary>
public sealed record OciScanClaimedJob(
    string Id, string Kind, string OwnerKind, string Repository, string Digest, string LeaseExpiresAt, int Attempt);

/// <summary>The body of <c>POST /api/v1/oci-scan/{job}/fail</c>.</summary>
public sealed record OciScanFailRequest(string? Reason, bool Retryable);

/// <summary>
/// The body of <c>POST /api/v1/oci-scan/{job}/result</c>: one entry per scanned platform, and
/// every advisory any component references as its complete OSV record.
/// </summary>
public sealed record OciScanResultRequest(
    IReadOnlyList<OciScanPlatformResult>? Platforms,
    IReadOnlyList<JsonElement>? Advisories,
    OciScannerReport? Scanner);

/// <summary>One platform of the image (an index fans out to several).</summary>
public sealed record OciScanPlatformResult(
    string? Platform,
    string? ScannerVersion,
    string? ExtractionVersion,
    string? OsvSource,
    IReadOnlyList<string>? Gaps,
    string? EntrypointKind,
    bool ClosureBounded,
    IReadOnlyList<OciScanComponent>? Components,
    IReadOnlyList<string>? ContentGaps = null);

/// <summary>A package found in the image's layers.</summary>
public sealed record OciScanComponent(
    string? Purl,
    string? Ecosystem,
    string? Name,
    string? Version,
    string? SourceName,
    string? SourceVersion,
    int? LayerIndex,
    string? LayerDiffId,
    string? LayerInstruction,
    int? FilesPresent,
    int? FilesRemoved,
    bool? InEntrypointClosure,
    string? OwnedByPurl,
    IReadOnlyList<OciScanComponentVuln>? Vulns,
    OciScanComponentVerdict? Verdict = null);

/// <summary>
/// A component's own reachability verdict. It depends on the component, not on any advisory, so
/// it is stored with the component and a rematch copies it onto whatever advisory it finds.
/// </summary>
public sealed record OciScanComponentVerdict(string? Status, string? NotObservedBasis, string? Confidence);

/// <summary>An advisory matched to a component, with its reachability verdict.</summary>
public sealed record OciScanComponentVuln(
    string? Id, string? Reachability, string? NotObservedBasis, string? Confidence);

/// <summary>
/// The body of <c>POST /api/v1/oci-scan/{job}/matches</c>: a rematch job's new findings for the
/// stored inventory it read from <c>inventory</c>, one entry per stored platform, and every
/// advisory a finding names as its complete OSV record.
/// </summary>
public sealed record OciScanMatchRequest(
    IReadOnlyList<OciScanMatchPlatform>? Platforms,
    IReadOnlyList<JsonElement>? Advisories,
    OciScannerReport? Scanner);

/// <summary>
/// One stored platform re-matched. <c>CoverageId</c> is the inventory token the inventory read
/// returned; a re-extraction replaces it, and the result is then refused.
/// </summary>
public sealed record OciScanMatchPlatform(
    string? Platform,
    string? CoverageId,
    string? OsvSource,
    string? ScannerVersion,
    IReadOnlyList<string>? MatchGaps,
    IReadOnlyList<OciScanMatchFinding>? Findings);

/// <summary>The advisories one stored component matched, by the component id the inventory read returned.</summary>
public sealed record OciScanMatchFinding(string? ComponentId, IReadOnlyList<string>? Vulns);

/// <summary>The body of <c>POST /api/v1/oci-scan/{job}/reextract</c>.</summary>
public sealed record OciScanReextractRequest(string? Reason, OciScannerReport? Scanner);

/// <summary>The job kinds a scanner may ask a claim for, and what the server can do with them.</summary>
public static class OciScanKinds
{
    public const string Scan = "scan";
    public const string Rematch = "rematch";

    /// <summary>
    /// What the claim response advertises: <c>rematch</c> (the inventory, matches and reextract
    /// routes) and <c>contentGaps</c> (the optional result fields <c>platforms[].contentGaps</c> and
    /// <c>components[].verdict</c>). A scanner sends those fields and takes the rematch path only
    /// after a claim has advertised them, so it keeps speaking the old shape to an older server.
    /// </summary>
    public static readonly IReadOnlyList<string> Capabilities = ["rematch", "contentGaps"];

    /// <summary>
    /// True when the claim's <c>kinds</c> query parameter names <c>rematch</c>. Absent, blank, or
    /// naming only other kinds means scan jobs only; an unknown kind is ignored, so a later
    /// scanner's new kind never makes an older server refuse the claim.
    /// </summary>
    public static bool IncludesRematch(string? kinds) =>
        !string.IsNullOrWhiteSpace(kinds)
        && kinds.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Contains(Rematch, StringComparer.OrdinalIgnoreCase);
}

/// <summary>The bounds a result must stay inside; anything beyond is refused as a whole.</summary>
public static class OciScanLimits
{
    public const int MaxClaim = 16;
    public const int MaxPlatforms = 16;
    public const int MaxComponents = 100_000;
    public const int MaxVulnsPerComponent = 2_000;

    /// <summary>
    /// The most findings (advisory ids, summed over every component) one result or match may
    /// carry. Each is a row written in the result's one transaction, so the per-component cap
    /// alone would still let a single body hold the database's writer for millions of rows.
    /// </summary>
    public const int MaxFindings = 250_000;
    public const int MaxAdvisories = 50_000;
    public const int MaxGapsPerPlatform = 1_000;
    public const int MaxTextLength = 4_096;
    public const int MaxReasonLength = 2_000;
    public const long MaxResultBytes = 128L * 1024 * 1024;

    public static readonly IReadOnlySet<string> Reachability =
        new HashSet<string>(StringComparer.Ordinal) { "reachable", "not_observed", "unknown" };
}
