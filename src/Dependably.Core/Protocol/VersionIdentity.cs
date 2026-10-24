namespace Dependably.Protocol;

/// <summary>
/// Whether two version strings of an ecosystem name the same version, decided in one place.
///
/// NuGet (NuGetVersion) normalizes case, so <c>1.0.0-RC1</c> and <c>1.0.0-rc1</c> are one version
/// there. PyPI compares PEP 440 canonical forms (<see cref="Pep440Canonical"/>): case, separators,
/// a leading <c>v</c>, implicit zeros and spelling variants all collapse, so <c>1.0.0-rc1</c>,
/// <c>1.0.0.rc1</c> and <c>1.0.0RC1</c> are one version. Every other ecosystem treats the string as
/// the identity: npm compares SemVer prerelease identifiers case-sensitively, Go module versions are
/// case-sensitive tags, Cargo, Hex and Terraform versions are exact strings, and Maven versions
/// are repository path segments on a case-sensitive path. Folding case there would hide a real,
/// distinct version (and its advisories) behind a look-alike.
///
/// Any site that merges, shadows, dedupes or looks up versions across the uploaded and proxied
/// planes asks this rather than hard-coding a comparer. The stored version string is never
/// rewritten: the canonical form is only the comparison key, so what a client is served keeps the
/// spelling it asked for. The SQL version count in <c>PackageRepository.Query</c> follows the same
/// rule for NuGet in SQL and for PyPI by recounting canonical forms after the query.
/// </summary>
public static class VersionIdentity
{
    /// <summary>True when versions of <paramref name="ecosystem"/> compare without regard to case.</summary>
    public static bool IsCaseInsensitive(string ecosystem) =>
        ecosystem is "nuget" or "pypi";

    /// <summary>The comparer for hash sets and groupings of <paramref name="ecosystem"/> versions.</summary>
    public static IEqualityComparer<string> Comparer(string ecosystem) => ecosystem switch
    {
        "pypi" => Pep440Comparer.Instance,
        "nuget" => StringComparer.OrdinalIgnoreCase,
        _ => StringComparer.Ordinal,
    };

    /// <summary>True when the two version strings are the same version of <paramref name="ecosystem"/>.</summary>
    public static bool Equal(string ecosystem, string? left, string? right) =>
        left is null || right is null
            ? left is null && right is null
            : Comparer(ecosystem).Equals(left, right);

    private sealed class Pep440Comparer : IEqualityComparer<string>
    {
        public static readonly Pep440Comparer Instance = new();

        public bool Equals(string? x, string? y) =>
            ReferenceEquals(x, y)
            || (x is not null && y is not null
                && string.Equals(Pep440Canonical.Canonicalize(x), Pep440Canonical.Canonicalize(y), StringComparison.Ordinal));

        public int GetHashCode(string obj) =>
            Pep440Canonical.Canonicalize(obj).GetHashCode(StringComparison.Ordinal);
    }
}
