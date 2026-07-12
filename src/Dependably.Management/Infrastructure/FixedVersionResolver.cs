using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolves the fixed version an installed version should upgrade to from an OSV advisory's
/// <c>affected[]</c> ranges, under the ecosystem's native version ordering
/// (<see cref="EcosystemVersionOrdering.Compare"/>). Strictly best-effort and fail-safe: any
/// unsupported ecosystem, unparseable version, or malformed range yields null — never a guess —
/// and the caller (the Vulnerabilities detail panel) falls back to showing the raw ranges.
/// Lives in Management, not Core, for the same reason as <see cref="RemediationCatalog"/>: only
/// the vulnerability detail endpoint needs it, and the Edge composition root never serves that.
/// </summary>
public static class FixedVersionResolver
{
    /// <summary>
    /// Returns the <c>fixed</c> version of the affected interval containing
    /// <paramref name="installedVersion"/>, or null when no interval contains it, the containing
    /// interval has no fix, or nothing parses. Entries whose package name matches
    /// <paramref name="packageName"/> are preferred; when none match (OSV name spellings can
    /// diverge from ours), every entry is considered so resolution degrades rather than vanishes.
    /// </summary>
    public static string? Resolve(
        OsvAffectedDetail[]? affected, string ecosystem, string packageName, string installedVersion)
    {
        if (affected is null || affected.Length == 0)
        {
            return null;
        }

        var matching = affected.Where(a => MatchesPackage(a.Package, packageName)).ToList();
        var candidates = matching.Count > 0 ? matching : affected.ToList();

        foreach (var entry in candidates)
        {
            foreach (var range in entry.Ranges ?? [])
            {
                if (range.Events is not { Length: > 0 } || IsGitRange(range.Type))
                {
                    continue;
                }

                string? fix = FixForContainingInterval(range.Events, ecosystem, installedVersion);
                if (fix is not null)
                {
                    return fix;
                }
            }
        }

        return null;
    }

    // GIT ranges hold commit hashes, not package versions — never comparable here.
    private static bool IsGitRange(string? type) =>
        string.Equals(type, "GIT", StringComparison.OrdinalIgnoreCase);

    private static bool MatchesPackage(OsvAffectedPackageRef? pkg, string packageName)
    {
        if (pkg is null)
        {
            return false;
        }

        if (string.Equals(pkg.Name, packageName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // OSV purls are versionless base purls (pkg:npm/left-pad); match on the name tail.
        return pkg.Purl is not null
            && (pkg.Purl.EndsWith("/" + packageName, StringComparison.OrdinalIgnoreCase)
                || pkg.Purl.EndsWith(":" + packageName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Walks the range's event list (OSV orders events ascending): each <c>introduced</c> opens
    /// an interval, the next <c>fixed</c>/<c>last_affected</c> closes it. Returns the closing
    /// <c>fixed</c> when the installed version falls in [introduced, fixed); a containing
    /// interval closed by <c>last_affected</c> or left open carries no fix and yields null.
    /// </summary>
    private static string? FixForContainingInterval(
        OsvRangeEvent[] events, string ecosystem, string installedVersion)
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
                if (AboveLowerBound(ecosystem, installedVersion, introduced)
                    && EcosystemVersionOrdering.Compare(ecosystem, installedVersion, ev.Fixed) is < 0)
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
    private static bool AboveLowerBound(string ecosystem, string installedVersion, string introduced) =>
        introduced == "0"
        || EcosystemVersionOrdering.Compare(ecosystem, installedVersion, introduced) is >= 0;
}
