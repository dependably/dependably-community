namespace Dependably.Protocol;

/// <summary>
/// Total ordering over raw Maven version strings, for the places that must reduce a Maven
/// version set to a single newest entry or render it in a reproducible order — the
/// <c>&lt;latest&gt;</c>/<c>&lt;release&gt;</c> elements and the <c>&lt;versions&gt;</c> list of
/// <c>maven-metadata.xml</c>.
///
/// The comparison itself is <see cref="EcosystemVersionOrdering"/>'s Maven scheme, a
/// ComparableVersion-style segment walk. That scheme is the deliberate choice over a SemVer
/// comparer (<c>NuGet.Versioning</c>) because Maven versions are not SemVer: numeric segments
/// compare numerically (<c>1.9 &lt; 1.10</c>, which any text sort inverts), a qualifier segment
/// always ranks below a numeric one, and the qualifier ladder runs
/// alpha &lt; beta &lt; milestone &lt; rc &lt; snapshot &lt; release &lt; sp — so
/// <c>1.0-SNAPSHOT &lt; 1.0 &lt; 1.0-sp1</c>, where SemVer puts every qualifier below the
/// release. Common Maven forms (<c>1.0-alpha-1</c>, <c>1.2.3.4.5</c>, <c>20040616</c>) do not
/// parse as SemVer at all, and a parse failure that degrades to a text sort reintroduces the
/// <c>1.10 &lt; 1.9</c> inversion on exactly the coordinates that need the ordering.
///
/// Versions Maven considers equal but spells differently (<c>1.0</c> vs <c>1.0.0</c>), and
/// version strings that carry no comparable segment at all, fall back to an ordinal compare of
/// the raw text. That fallback is what makes this a <i>total</i> order rather than a partial
/// one, and callers depend on it: the rendered metadata body feeds a content-derived ETag and
/// its generated <c>.sha1</c>/<c>.md5</c> sidecars, so the same version set must always render
/// to the same bytes no matter what order the rows arrive in.
/// </summary>
public sealed class MavenVersionComparer : IComparer<string>
{
    /// <summary>Shared stateless instance.</summary>
    public static MavenVersionComparer Instance { get; } = new();

    private MavenVersionComparer()
    {
    }

    /// <summary>
    /// Orders <paramref name="x"/> against <paramref name="y"/> under Maven's version rules,
    /// falling back to an ordinal text compare when the two are Maven-equal or unparseable.
    /// Null sorts below any value.
    /// </summary>
    public int Compare(string? x, string? y)
    {
        if (ReferenceEquals(x, y))
        {
            return 0;
        }
        if (x is null)
        {
            return -1;
        }
        if (y is null)
        {
            return 1;
        }

        int? maven = EcosystemVersionOrdering.Compare("maven", x, y);
        return maven is int c && c != 0 ? c : string.CompareOrdinal(x, y);
    }
}
