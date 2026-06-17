using System.Text.RegularExpressions;
using NuGet.Versioning;

namespace Dependably.Protocol;

public static partial class PurlNormalizer
{
    [GeneratedRegex(@"[-_.]+")]
    private static partial Regex PyPiSeparatorRegex();

    /// <summary>
    /// Normalizes a PyPI package name per PEP 503: runs of <c>-</c>, <c>_</c>, or <c>.</c>
    /// collapse to a single <c>-</c>, and the result is lowercased. Use this as the canonical
    /// key wherever a PyPI name is stored or compared (cache keys, purl_name column, etc.).
    /// </summary>
    public static string PyPiName(string name)
        => PyPiSeparatorRegex().Replace(name, "-").ToLowerInvariant();

    public static string PyPi(string name, string version)
    {
        string normalized = PyPiName(name);
        return $"pkg:pypi/{normalized}@{version}";
    }

    public static string Npm(string name, string version)
        => $"pkg:npm/{name}@{version}";

    /// <summary>
    /// Canonical Maven PURL: <c>pkg:maven/{groupId}/{artifactId}@{version}</c>
    /// per the PURL spec. Group/artifact stay as-is (Maven coordinates are case-sensitive);
    /// the path-style separator matches the on-disk repo layout Maven/Gradle clients walk.
    /// </summary>
    public static string Maven(string groupId, string artifactId, string version)
        => $"pkg:maven/{groupId}/{artifactId}@{version}";

    /// <summary>
    /// Canonical RPM PURL: <c>pkg:rpm/{name}@{version}-{release}?arch={arch}[&amp;epoch={n}]</c>.
    /// Name is lowercased (rpm package names are case-insensitive); epoch is omitted from
    /// the qualifier list when zero so the most common (non-epoch) form stays terse.
    /// </summary>
    public static string Rpm(string name, string version, string release, string arch, int epoch = 0)
    {
        string normalizedName = name.ToLowerInvariant();
        string versionRelease = $"{version}-{release}";
        string qualifiers = epoch != 0
            ? $"arch={arch}&epoch={epoch}"
            : $"arch={arch}";
        return $"pkg:rpm/{normalizedName}@{versionRelease}?{qualifiers}";
    }

    /// <summary>
    /// Canonical OCI PURL (purl-spec <c>oci</c> type): <c>pkg:oci/{name}@{digest}?repository_url={repo}[&amp;tag={tag}]</c>.
    /// <para>
    /// Name is the lowercased final path segment of the repository (<c>library/ubuntu</c> → <c>ubuntu</c>);
    /// the digest is the content-addressed identity, so its <c>algo:hex</c> colon is percent-encoded
    /// (<c>sha256%3A…</c>) per the spec. <c>repository_url</c> carries the full repository path so the
    /// same short name in different repos stays distinguishable; <c>tag</c> records the tag that
    /// resolved to this digest (omitted on pure by-digest pulls).
    /// </para>
    /// </summary>
    public static string Oci(string repository, string digest, string? tag = null)
    {
        int slash = repository.LastIndexOf('/');
        string name = (slash >= 0 ? repository[(slash + 1)..] : repository).ToLowerInvariant();
        string encodedDigest = digest.Replace(":", "%3A");
        string qualifiers = $"repository_url={repository}";
        if (!string.IsNullOrEmpty(tag))
        {
            qualifiers += $"&tag={tag}";
        }

        return $"pkg:oci/{name}@{encodedDigest}?{qualifiers}";
    }

    /// <summary>
    /// Canonical Cargo PURL: <c>pkg:cargo/{name}@{version}</c>.
    /// Cargo crate names are case-sensitive in the index but conventionally lowercase.
    /// Names are stored as-published; no case normalisation is applied here.
    /// </summary>
    public static string Cargo(string name, string version)
        => $"pkg:cargo/{name}@{version}";

    public static string NuGet(string id, string version)
    {
        string normalized = NuGetVersion.TryParse(version, out var parsed)
            ? NormalizeNuGetVersion(parsed)
            : version;
        return $"pkg:nuget/{id}@{normalized}";
    }

    /// <summary>
    /// Canonical Go module PURL: <c>pkg:golang/{module}@{version}</c>.
    /// Module paths are stored as-is (Go module paths are case-sensitive);
    /// versions carry the leading <c>v</c> prefix as Go clients use it on the wire.
    /// </summary>
    public static string Golang(string module, string version)
        => $"pkg:golang/{module}@{version}";

    public static string NormalizeNuGetVersionString(string version)
    {
        return NuGetVersion.TryParse(version, out var parsed)
            ? NormalizeNuGetVersion(parsed)
            : version;
    }

    private static string NormalizeNuGetVersion(NuGetVersion v)
    {
        // Collapse 4-part version with zero revision to 3-part: 1.0.0.0 → 1.0.0
        return v.Revision == 0 && !v.IsPrerelease && string.IsNullOrEmpty(v.Metadata)
            ? $"{v.Major}.{v.Minor}.{v.Patch}"
            : v.ToNormalizedString();
    }
}
