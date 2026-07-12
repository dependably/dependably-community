using System.Globalization;
using System.Text.RegularExpressions;
using NuGet.Versioning;

namespace Dependably.Protocol;

/// <summary>
/// Per-ecosystem "is this a stable release" filter and native-ordering comparison, used to build
/// the versions-behind operational-risk count. Applies the same latest=STABLE convention
/// <see cref="IUpstreamLatestVersionResolver"/> already uses when picking a package's single
/// "latest" version — npm/PyPI/NuGet/Maven each get their own native version scheme (semver, PEP
/// 440, <see cref="NuGetVersion"/>, and a Maven-ComparableVersion-style comparer respectively)
/// rather than a single generic ordering.
/// </summary>
public static partial class EcosystemVersionOrdering
{
    /// <summary>
    /// Filters <paramref name="rawVersions"/> down to the STABLE releases for
    /// <paramref name="ecosystem"/> and orders them newest-first in their native scheme. Returns
    /// an empty list for an unsupported ecosystem or when nothing parses as stable — callers treat
    /// an empty list the same as "no upstream version data" (unknown, not zero).
    /// </summary>
    public static IReadOnlyList<string> OrderStableDescending(string ecosystem, IEnumerable<string> rawVersions) =>
        ecosystem switch
        {
            "npm" => OrderNpm(rawVersions),
            "pypi" => OrderPyPi(rawVersions),
            "nuget" => OrderNuGet(rawVersions),
            "maven" => OrderMaven(rawVersions),
            _ => Array.Empty<string>(),
        };

    /// <summary>
    /// Counts how many entries in <paramref name="stableVersionsDescending"/> compare strictly
    /// newer than <paramref name="heldVersion"/> under <paramref name="ecosystem"/>'s native
    /// ordering. Returns null (unknown — never 0) when the ecosystem is unsupported, the list is
    /// null/empty, or <paramref name="heldVersion"/> fails to parse under that ecosystem's scheme.
    /// </summary>
    public static int? CountNewerStable(string ecosystem, IReadOnlyList<string>? stableVersionsDescending, string heldVersion)
    {
        return stableVersionsDescending is null || stableVersionsDescending.Count == 0
            ? null
            : ecosystem switch
            {
                "npm" => CountNewer<NpmSemver>(stableVersionsDescending, heldVersion, TryParseNpm, CompareNpm),
                "pypi" => CountNewer<Pep440>(stableVersionsDescending, heldVersion, TryParsePep440, ComparePep440),
                "nuget" => CountNewer<NuGetVersion>(stableVersionsDescending, heldVersion,
                    (string s, out NuGetVersion? v) => NuGetVersion.TryParse(s, out v),
                    (a, b) => VersionComparer.Default.Compare(a, b)),
                "maven" => CountNewer<IReadOnlyList<MavenToken>>(stableVersionsDescending, heldVersion, TryParseMaven, CompareMaven),
                _ => null,
            };
    }

    private delegate bool TryParse<T>(string raw, out T? parsed);

    private static int? CountNewer<T>(
        IReadOnlyList<string> stableVersionsDescending, string heldVersion, TryParse<T> tryParse, Comparison<T> compare)
    {
        if (!tryParse(heldVersion, out var held) || held is null)
        {
            return null;
        }

        int count = 0;
        foreach (string candidate in stableVersionsDescending)
        {
            if (tryParse(candidate, out var parsed) && parsed is not null && compare(parsed, held) > 0)
            {
                count++;
            }
        }
        return count;
    }

    // ── npm (semver.org precedence) ───────────────────────────────────────────

    private readonly record struct NpmSemver(int Major, int Minor, int Patch, IReadOnlyList<string> Prerelease);

    private static List<string> OrderNpm(IEnumerable<string> rawVersions) =>
        rawVersions
            .Select(raw => (Raw: raw, Ok: TryParseNpm(raw, out var v), Parsed: v))
            .Where(r => r.Ok && r.Parsed.Prerelease.Count == 0)
            .OrderByDescending(r => r.Parsed, Comparer<NpmSemver>.Create(CompareNpm))
            .Select(r => r.Raw)
            .ToList();

    private static bool TryParseNpm(string raw, out NpmSemver version)
    {
        version = default;
        string s = raw.Trim();
        if (s.Length == 0)
        {
            return false;
        }
        if (s[0] is 'v' or 'V')
        {
            s = s[1..];
        }

        int plus = s.IndexOf('+');
        if (plus >= 0)
        {
            s = s[..plus];
        }

        int dash = s.IndexOf('-');
        string core = dash >= 0 ? s[..dash] : s;
        string pre = dash >= 0 ? s[(dash + 1)..] : "";

        string[] parts = core.Split('.');
        if (parts.Length != 3
            || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out int major)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int minor)
            || !int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out int patch))
        {
            return false;
        }

        string[] prerelease = pre.Length == 0 ? Array.Empty<string>() : pre.Split('.');
        version = new NpmSemver(major, minor, patch, prerelease);
        return true;
    }

    private static int CompareNpm(NpmSemver a, NpmSemver b)
    {
        int c = a.Major.CompareTo(b.Major);
        if (c != 0)
        {
            return c;
        }
        c = a.Minor.CompareTo(b.Minor);
        if (c != 0)
        {
            return c;
        }
        c = a.Patch.CompareTo(b.Patch);
        return c != 0 ? c : CompareNpmPrerelease(a.Prerelease, b.Prerelease);
    }

    // Compares the dot-separated prerelease identifier lists per semver.org precedence:
    // no-prerelease outranks any prerelease at the same major.minor.patch; otherwise identifiers
    // compare pairwise left-to-right, and a shorter list that's a prefix of the longer one loses.
    private static int CompareNpmPrerelease(IReadOnlyList<string> aPre, IReadOnlyList<string> bPre)
    {
        if (aPre.Count == 0 && bPre.Count == 0)
        {
            return 0;
        }
        if (aPre.Count == 0)
        {
            return 1;
        }
        if (bPre.Count == 0)
        {
            return -1;
        }

        int n = Math.Min(aPre.Count, bPre.Count);
        for (int i = 0; i < n; i++)
        {
            int cc = CompareNpmPrereleaseIdentifier(aPre[i], bPre[i]);
            if (cc != 0)
            {
                return cc;
            }
        }
        return aPre.Count.CompareTo(bPre.Count);
    }

    // Semver precedence for a single dot-separated prerelease identifier: numeric identifiers
    // always sort lower than alphanumeric ones; same-kind identifiers compare numerically or
    // ordinally respectively.
    private static int CompareNpmPrereleaseIdentifier(string pa, string pb)
    {
        bool numericA = pa.Length > 0 && pa.All(char.IsAsciiDigit);
        bool numericB = pb.Length > 0 && pb.All(char.IsAsciiDigit);

        return numericA && numericB
            ? CompareNumericStrings(pa, pb)
            : numericA != numericB
                ? numericA ? -1 : 1
                : string.CompareOrdinal(pa, pb);
    }

    // Compares two digit-only strings numerically without risking integer overflow on
    // pathologically long identifiers: shorter (after trimming leading zeros) is smaller;
    // same length compares lexically (digits compare the same as numeric value at equal length).
    private static int CompareNumericStrings(string a, string b)
    {
        string ta = a.TrimStart('0');
        string tb = b.TrimStart('0');
        return ta.Length != tb.Length ? ta.Length.CompareTo(tb.Length) : string.CompareOrdinal(ta, tb);
    }

    // ── PyPI (PEP 440) ────────────────────────────────────────────────────────

    // Simplified PEP 440 grammar covering epoch, release segments, pre-release (a/b/rc, with the
    // c/alpha/beta/pre/preview spellings folded to the same three ranks), post-release, and
    // dev-release. Local version identifiers (+local) are intentionally ignored for ordering —
    // they only disambiguate builds of the same public version, which never changes a
    // versions-behind count.
    [GeneratedRegex(
        @"^\s*(?:(?<epoch>[0-9]+)!)?(?<release>[0-9]+(?:\.[0-9]+)*)" +
        @"(?:[-_.]?(?<preL>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?<preN>[0-9]+)?)?" +
        @"(?:(?:-(?<postImplicit>[0-9]+))|(?:[-_.]?(?:post|rev|r)[-_.]?(?<postN>[0-9]+)?))?" +
        @"(?:[-_.]?dev[-_.]?(?<devN>[0-9]+)?)?" +
        @"(?:\+[a-zA-Z0-9]+(?:[-_.][a-zA-Z0-9]+)*)?\s*$",
        RegexOptions.IgnoreCase)]
    private static partial Regex Pep440Regex();

    // Phase ordering within a release: dev < pre-release < final < post-release.
    private const int PhaseDev = 0;
    private const int PhasePre = 1;
    private const int PhaseFinal = 2;
    private const int PhasePost = 3;

    private sealed record Pep440(int Epoch, IReadOnlyList<int> Release, int Phase, int SubRank, int Number);

    private static List<string> OrderPyPi(IEnumerable<string> rawVersions) =>
        rawVersions
            .Select(raw => (Raw: raw, Ok: TryParsePep440(raw, out var v), Parsed: v))
            .Where(r => r.Ok && r.Parsed!.Phase is PhaseFinal or PhasePost)
            .OrderByDescending(r => r.Parsed, Comparer<Pep440?>.Create((x, y) => ComparePep440(x!, y!)))
            .Select(r => r.Raw)
            .ToList();

    private static bool TryParsePep440(string raw, out Pep440? version)
    {
        version = null;
        var m = Pep440Regex().Match(raw.Trim());
        if (!m.Success)
        {
            return false;
        }

        int epoch = m.Groups["epoch"].Success ? int.Parse(m.Groups["epoch"].Value, CultureInfo.InvariantCulture) : 0;
        var release = m.Groups["release"].Value
            .Split('.')
            .Select(p => int.Parse(p, CultureInfo.InvariantCulture))
            .ToList();

        version = BuildPep440Phase(m, raw, epoch, release);
        return true;
    }

    // Resolves the dev/pre/post/final phase rank from the regex match groups, per PEP 440's
    // precedence ordering: dev < pre < final < post at the same release segment.
    private static Pep440 BuildPep440Phase(Match m, string raw, int epoch, List<int> release)
    {
        bool isDev = m.Groups["devN"].Success || raw.Contains("dev", StringComparison.OrdinalIgnoreCase);
        if (isDev)
        {
            int devN = m.Groups["devN"].Success ? int.Parse(m.Groups["devN"].Value, CultureInfo.InvariantCulture) : 0;
            return new Pep440(epoch, release, PhaseDev, 0, devN);
        }

        if (m.Groups["preL"].Success)
        {
            return BuildPep440Pre(m, epoch, release);
        }

        bool isPost = m.Groups["postN"].Success || m.Groups["postImplicit"].Success;
        if (isPost)
        {
            string postValue = m.Groups["postN"].Success ? m.Groups["postN"].Value : m.Groups["postImplicit"].Value;
            int postN = postValue.Length > 0 ? int.Parse(postValue, CultureInfo.InvariantCulture) : 0;
            return new Pep440(epoch, release, PhasePost, 0, postN);
        }

        return new Pep440(epoch, release, PhaseFinal, 0, 0);
    }

    // Ranks a PEP 440 pre-release segment: alpha < beta < (rc/c/pre/preview), each with its
    // numeric suffix.
    private static Pep440 BuildPep440Pre(Match m, int epoch, List<int> release)
    {
        int subRank = m.Groups["preL"].Value.ToLowerInvariant() switch
        {
            "a" or "alpha" => 0,
            "b" or "beta" => 1,
            _ => 2, // c, rc, pre, preview
        };
        int preN = m.Groups["preN"].Success ? int.Parse(m.Groups["preN"].Value, CultureInfo.InvariantCulture) : 0;
        return new Pep440(epoch, release, PhasePre, subRank, preN);
    }

    private static int ComparePep440(Pep440 a, Pep440 b)
    {
        int c = a.Epoch.CompareTo(b.Epoch);
        if (c != 0)
        {
            return c;
        }

        int n = Math.Max(a.Release.Count, b.Release.Count);
        for (int i = 0; i < n; i++)
        {
            int ra = i < a.Release.Count ? a.Release[i] : 0;
            int rb = i < b.Release.Count ? b.Release[i] : 0;
            c = ra.CompareTo(rb);
            if (c != 0)
            {
                return c;
            }
        }

        c = a.Phase.CompareTo(b.Phase);
        if (c != 0)
        {
            return c;
        }
        c = a.SubRank.CompareTo(b.SubRank);
        return c != 0 ? c : a.Number.CompareTo(b.Number);
    }

    // ── NuGet (NuGet.Versioning) ──────────────────────────────────────────────

    private static List<string> OrderNuGet(IEnumerable<string> rawVersions) =>
        rawVersions
            .Select(raw => NuGetVersion.TryParse(raw, out var v) ? v : null)
            .OfType<NuGetVersion>()
            .Where(v => !v.IsPrerelease)
            .OrderByDescending(v => v, VersionComparer.Default)
            .Select(v => v.ToNormalizedString().ToLowerInvariant())
            .ToList();

    // ── Maven (ComparableVersion-style) ───────────────────────────────────────

    private static List<string> OrderMaven(IEnumerable<string> rawVersions) =>
        rawVersions
            .Where(raw => !raw.Contains("SNAPSHOT", StringComparison.OrdinalIgnoreCase))
            .Select(raw => (Raw: raw, Ok: TryParseMaven(raw, out var tokens), Tokens: tokens))
            .Where(r => r.Ok)
            .OrderByDescending(r => r.Tokens, Comparer<IReadOnlyList<MavenToken>?>.Create((x, y) => CompareMaven(x!, y!)))
            .Select(r => r.Raw)
            .ToList();

    // A version segment is either numeric (compared as an integer) or a qualifier string
    // (compared via MavenQualifierRank, falling back to ordinal for unrecognized qualifiers).
    // This mirrors the shape (not the full generality) of Maven's
    // org.apache.maven.artifact.versioning.ComparableVersion: numeric segments always outrank
    // qualifier segments at the same position, and a shorter numeric tail pads with zero while a
    // shorter qualifier tail pads with the "release" rank (empty string).
    private readonly record struct MavenToken(bool IsNumeric, long Numeric, string Qualifier);

    [GeneratedRegex(@"[0-9]+|[^0-9.\-]+")]
    private static partial Regex MavenTokenRegex();

    private static bool TryParseMaven(string raw, out IReadOnlyList<MavenToken> tokens)
    {
        string s = raw.Trim();
        if (s.Length == 0)
        {
            tokens = Array.Empty<MavenToken>();
            return false;
        }

        var list = MavenTokenRegex().Matches(s)
            .Select(m => long.TryParse(m.Value, NumberStyles.None, CultureInfo.InvariantCulture, out long num)
                ? new MavenToken(true, num, "")
                : new MavenToken(false, 0, m.Value.ToLowerInvariant()))
            .ToList();
        tokens = list;
        return list.Count > 0;
    }

    private static readonly Dictionary<string, int> MavenQualifierRank = new()
    {
        ["alpha"] = 0,
        ["beta"] = 1,
        ["milestone"] = 2,
        ["m"] = 2,
        ["rc"] = 3,
        ["cr"] = 3,
        ["snapshot"] = 4,
        [""] = 5, // "release"/"final"/"ga" normalize to empty and rank here
        ["ga"] = 5,
        ["final"] = 5,
        ["sp"] = 6,
    };

    private static int CompareMaven(IReadOnlyList<MavenToken> a, IReadOnlyList<MavenToken> b)
    {
        int n = Math.Max(a.Count, b.Count);
        for (int i = 0; i < n; i++)
        {
            bool hasA = i < a.Count;
            bool hasB = i < b.Count;
            var ta = hasA ? a[i] : new MavenToken(true, 0, "");
            var tb = hasB ? b[i] : new MavenToken(true, 0, "");
            // A missing trailing token pads as numeric 0 only when its counterpart is also
            // numeric; against a qualifier it pads as the "release" qualifier so e.g. "1.0" ranks
            // above "1.0-beta" (a numeric tail always outranks a qualifier tail).
            if (!hasA && hasB && !tb.IsNumeric)
            {
                ta = new MavenToken(false, 0, "");
            }
            if (!hasB && hasA && !ta.IsNumeric)
            {
                tb = new MavenToken(false, 0, "");
            }

            int c = CompareMavenToken(ta, tb);
            if (c != 0)
            {
                return c;
            }
        }
        return 0;
    }

    private static int CompareMavenToken(MavenToken a, MavenToken b)
    {
        if (a.IsNumeric && b.IsNumeric)
        {
            return a.Numeric.CompareTo(b.Numeric);
        }
        if (a.IsNumeric != b.IsNumeric)
        {
            // Maven rule: a numeric item is always newer than a non-numeric (qualifier) item.
            return a.IsNumeric ? 1 : -1;
        }

        bool rankedA = MavenQualifierRank.TryGetValue(a.Qualifier, out int ra);
        bool rankedB = MavenQualifierRank.TryGetValue(b.Qualifier, out int rb);
        if (rankedA && rankedB)
        {
            return ra.CompareTo(rb);
        }
        if (rankedA != rankedB)
        {
            // An unrecognized qualifier ranks above every known qualifier (Maven treats an
            // unknown string as newer than the known alpha/beta/milestone/rc/snapshot/ga/sp set).
            return rankedA ? -1 : 1;
        }
        return string.CompareOrdinal(a.Qualifier, b.Qualifier);
    }
}
