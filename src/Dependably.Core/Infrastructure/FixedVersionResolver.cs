using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolves the fixed version an installed version should upgrade to from an OSV advisory's
/// <c>affected[]</c> ranges, under the ecosystem's native version ordering
/// (<see cref="EcosystemVersionOrdering.Compare"/>). Strictly best-effort and fail-safe: any
/// unsupported ecosystem, unparseable version, or malformed range yields null — never a guess —
/// and a caller falls back to showing the raw ranges.
/// Shared by the vulnerability detail endpoint, the package lookup, and the npm bulk audit.
/// </summary>
public static class FixedVersionResolver
{
    /// <summary>
    /// Returns the <c>fixed</c> version of the affected interval containing
    /// <paramref name="installedVersion"/>, or null when no interval contains it, the containing
    /// interval has no fix, or nothing parses. Entries whose package name matches
    /// <paramref name="packageName"/> are preferred. When none match (OSV name spellings can
    /// diverge from ours) and the record lists one package, its entries are considered so
    /// resolution degrades rather than vanishes. When none match and the record lists several
    /// packages, the answer is null: picking whichever package's range contains the version
    /// would be a guess.
    /// </summary>
    /// <param name="distroScope">The OSV distro ecosystem (<c>Alpine:v3.20</c>, <c>Rocky Linux:9</c>)
    /// a release-scoped apk or rpm lookup was answered from. When set, only entries filed under that
    /// release are considered (a record can carry several releases, each with its own fix), and
    /// versions are ordered by the distro's own scheme instead of being left unordered.</param>
    public static string? Resolve(
        OsvAffectedDetail[]? affected, string ecosystem, string packageName, string installedVersion,
        string? distroScope = null)
    {
        if (distroScope is not null && affected is not null)
        {
            affected = affected.Where(a => DistroScopes.Covers(distroScope, a.Package?.Ecosystem)).ToArray();
        }

        if (affected is null || affected.Length == 0)
        {
            return null;
        }

        var matching = affected.Where(a => MatchesPackage(a.Package, ecosystem, packageName)).ToList();
        if (matching.Count == 0 && ListsSeveralPackages(affected, ecosystem))
        {
            return null;
        }

        var candidates = matching.Count > 0 ? matching : affected.ToList();
        bool ordered = distroScope is not null;

        foreach (var entry in candidates)
        {
            string? fix = FixFromEntry(entry, ecosystem, installedVersion, ordered);
            if (fix is not null)
            {
                return fix;
            }
        }

        return null;
    }

    private static string? FixFromEntry(
        OsvAffectedDetail entry, string ecosystem, string installedVersion, bool ordered)
    {
        foreach (var range in entry.Ranges ?? [])
        {
            if (range.Events is not { Length: > 0 } || IsGitRange(range.Type))
            {
                continue;
            }

            string? fix = FixForContainingInterval(range.Events, ecosystem, installedVersion, ordered);
            if (fix is not null)
            {
                return fix;
            }
        }

        return null;
    }

    // Whether the entries name more than one package, compared by the ecosystem's canonical name
    // (jupyter_server and jupyter-server are one PyPI package). With one package listed, an entry
    // whose name spelling differs from ours is still ours; with several, nothing says which is.
    private static bool ListsSeveralPackages(OsvAffectedDetail[] affected, string ecosystem) =>
        affected
            .Select(a => (
                Ecosystem: a.Package?.Ecosystem?.ToUpperInvariant(),
                Name: CanonicalOrNull(ecosystem, a.Package?.Name ?? PurlName(a.Package?.Purl))?.ToUpperInvariant()))
            .Distinct()
            .Skip(1)
            .Any();

    // GIT ranges hold commit hashes, not package versions — never comparable here.
    private static bool IsGitRange(string? type) =>
        string.Equals(type, "GIT", StringComparison.OrdinalIgnoreCase);

    // Names are compared by the ecosystem's canonical form on both sides: OSV spells a PyPI
    // package as published (zope.interface) while a caller sends the PEP 503 name
    // (zope-interface), and the two are one package.
    private static bool MatchesPackage(OsvAffectedPackageRef? pkg, string ecosystem, string packageName)
    {
        if (pkg is null)
        {
            return false;
        }

        string wanted = PurlNormalizer.CanonicalName(ecosystem, packageName);
        if (pkg.Name is not null
            && string.Equals(PurlNormalizer.CanonicalName(ecosystem, pkg.Name), wanted, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // OSV purls are versionless base purls (pkg:npm/left-pad); match on the name tail.
        if (pkg.Purl is null)
        {
            return false;
        }

        string purl = PurlNormalizer.CanonicalName(ecosystem, pkg.Purl);
        return purl.EndsWith("/" + wanted, StringComparison.OrdinalIgnoreCase)
            || purl.EndsWith(":" + wanted, StringComparison.OrdinalIgnoreCase);
    }

    private static string? CanonicalOrNull(string ecosystem, string? name) =>
        name is null ? null : PurlNormalizer.CanonicalName(ecosystem, name);

    // The name part of a versionless purl: everything after "pkg:<type>/", without a version or
    // qualifiers.
    private static string? PurlName(string? purl)
    {
        if (purl is null)
        {
            return null;
        }

        int slash = purl.IndexOf('/');
        string rest = slash < 0 ? purl : purl[(slash + 1)..];
        int end = rest.IndexOfAny(['@', '?', '#']);
        return end < 0 ? rest : rest[..end];
    }

    /// <summary>
    /// Walks the range's event list (OSV orders events ascending): each <c>introduced</c> opens
    /// an interval, the next <c>fixed</c>/<c>last_affected</c> closes it. Returns the closing
    /// <c>fixed</c> when the installed version falls in [introduced, fixed); a containing
    /// interval closed by <c>last_affected</c> or left open carries no fix and yields null.
    /// </summary>
    private static string? FixForContainingInterval(
        OsvRangeEvent[] events, string ecosystem, string installedVersion, bool distro)
    {
        string? introduced = null;
        foreach (var ev in events)
        {
            if (ev.Introduced is not null)
            {
                introduced = ev.Introduced;
                continue;
            }

            if (introduced is null)
            {
                continue; // closing event before any introduced — malformed; skip it
            }

            if (ev.Fixed is not null)
            {
                if (AboveLowerBound(ecosystem, installedVersion, introduced, distro)
                    && Compare(ecosystem, installedVersion, ev.Fixed, distro) is < 0)
                {
                    return ev.Fixed;
                }

                introduced = null;
            }
            else if (ev.LastAffected is not null)
            {
                introduced = null; // interval closes without a fix — nothing to upgrade to
            }
            // `limit` events only bound GIT ranges; irrelevant here.
        }

        return null;
    }

    // OSV uses introduced: "0" for "since the beginning" — always below any real version, and
    // deliberately not parsed ("0" is not a valid version in every ecosystem's scheme).
    private static bool AboveLowerBound(string ecosystem, string installedVersion, string introduced, bool distro) =>
        introduced == "0"
        || Compare(ecosystem, installedVersion, introduced, distro) is >= 0;

    // apk and rpm have no place in EcosystemVersionOrdering, whose callers need a stable-release
    // filter they cannot answer; a release-scoped lookup orders them with the distro comparers.
    private static int? Compare(string ecosystem, string left, string right, bool distro) =>
        distro && ecosystem == "apk" ? DistroVersionComparer.CompareApk(left, right)
        : distro && ecosystem == "rpm" ? DistroVersionComparer.CompareRpm(left, right)
        : EcosystemVersionOrdering.Compare(ecosystem, left, right);
}
