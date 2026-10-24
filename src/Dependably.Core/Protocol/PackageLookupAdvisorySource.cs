using System.Text.Json.Serialization;

namespace Dependably.Protocol;

/// <summary>
/// Which advisory source answered a lookup, or why none did. It is what lets a client tell three
/// things apart that an empty advisory list cannot: <c>checked</c> (the source was consulted and
/// the empty list is a real answer), <c>unavailable</c> (it could not be consulted, so the empty
/// list says nothing) and <c>not_applicable</c> (the ecosystem has no advisory source at all).
/// </summary>
/// <param name="Status"><c>checked</c> | <c>unavailable</c> | <c>not_applicable</c>.</param>
/// <param name="Source"><c>osv</c> or <c>oci_scan</c>; null when no source exists for the ecosystem.</param>
/// <param name="Reason">Machine-readable cause when <paramref name="Status"/> is not <c>checked</c>:
/// <c>osv_unreachable</c>, <c>distro_required</c>, <c>no_osv_coverage</c>, <c>origin_unknown</c>
/// (an apk name the release's feed has never listed, which may be a sub-package of an origin the
/// feed does list), <c>name_unknown</c> (an rpm name the release's feed has never listed: a typo,
/// a package from a repository the feed does not cover, or a Red Hat package asked of the other
/// stream), <c>no_scan_result</c>, <c>scan_incomplete</c> or <c>no_advisory_source</c>.
/// A <c>not_applicable</c> answer is not a failure to check, so a lookup that otherwise passes
/// keeps the verdict <c>allowed</c>.</param>
/// <param name="Distro">The OSV ecosystem an apk or rpm lookup was scoped to (<c>Alpine:v3.20</c>).</param>
/// <param name="DistroInferred">True when <paramref name="Distro"/> came from the org's upstream
/// configuration rather than the request.</param>
/// <param name="MatchedAt">For an <c>oci_scan</c> answer, when the org's stored scan of the image
/// was last matched against OSV (the oldest across its platforms): how stale its findings may be.
/// Omitted from the response for every other source.</param>
public sealed record AdvisorySourceInfo(
    string Status, string? Source, string? Reason, string? Distro = null, bool DistroInferred = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? MatchedAt = null)
{
    public const string CheckedStatus = "checked";
    public const string UnavailableStatus = "unavailable";
    public const string NotApplicableStatus = "not_applicable";

    private const string Osv = "osv";
    private const string OciScan = "oci_scan";

    public static AdvisorySourceInfo OsvChecked(DistroScope? scope = null, bool inferred = false) =>
        new(CheckedStatus, Osv, null, scope?.OsvEcosystem, inferred);

    public static AdvisorySourceInfo OsvUnreachable(DistroScope? scope = null, bool inferred = false) =>
        new(UnavailableStatus, Osv, "osv_unreachable", scope?.OsvEcosystem, inferred);

    public static AdvisorySourceInfo NoOsvCoverage(DistroScope scope, bool inferred) =>
        new(UnavailableStatus, Osv, "no_osv_coverage", scope.OsvEcosystem, inferred);

    /// <summary>The source holds no advisory feed for a PURL ecosystem (a local dump loaded without it).</summary>
    public static AdvisorySourceInfo NoOsvCoverage() =>
        new(UnavailableStatus, Osv, "no_osv_coverage");

    public static AdvisorySourceInfo OriginUnknown(DistroScope scope, bool inferred) =>
        new(UnavailableStatus, Osv, "origin_unknown", scope.OsvEcosystem, inferred);

    public static AdvisorySourceInfo NameUnknown(DistroScope scope, bool inferred) =>
        new(UnavailableStatus, Osv, "name_unknown", scope.OsvEcosystem, inferred);

    public static AdvisorySourceInfo DistroRequired() =>
        new(UnavailableStatus, Osv, "distro_required");

    /// <summary>The ecosystem has no advisory source: terraform providers are not an OSV ecosystem.</summary>
    public static AdvisorySourceInfo NotApplicable() =>
        new(NotApplicableStatus, null, "no_advisory_source");

    public static AdvisorySourceInfo OciChecked(string? matchedAt = null) =>
        new(CheckedStatus, OciScan, null, MatchedAt: matchedAt);

    public static AdvisorySourceInfo OciNoScanResult() => new(UnavailableStatus, OciScan, "no_scan_result");

    public static AdvisorySourceInfo OciScanIncomplete(string? matchedAt = null) =>
        new(UnavailableStatus, OciScan, "scan_incomplete", MatchedAt: matchedAt);
}
