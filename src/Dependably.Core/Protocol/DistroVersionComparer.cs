using System.Numerics;

namespace Dependably.Protocol;

/// <summary>
/// Native version ordering for the two distro package schemes lookup answers from OSV's
/// release-scoped feeds: RPM (<c>[epoch:]version[-release]</c>, compared by <c>rpmvercmp</c>) and
/// Alpine apk (<c>1.2.3a_rc1-r2</c>). Both comparers are total and never throw: a string that does
/// not fit the grammar is ordered by the same segment rules as any other, so a malformed version
/// can neither crash a lookup nor silently compare equal to everything.
/// </summary>
public static class DistroVersionComparer
{
    /// <summary>
    /// Orders two RPM EVR strings. A missing epoch is 0. A version with no release sorts below the
    /// same version with any release, so a bare version can never read as having reached a fixed
    /// build.
    /// </summary>
    public static int CompareRpm(string left, string right)
    {
        var (le, lv, lr) = SplitEvr(left);
        var (re, rv, rr) = SplitEvr(right);

        int epoch = le.CompareTo(re);
        if (epoch != 0)
        {
            return Math.Sign(epoch);
        }

        int version = RpmVerCmp(lv, rv);
        return version != 0
            ? version
            : lr is null || rr is null ? (lr is null ? 0 : 1) - (rr is null ? 0 : 1) : RpmVerCmp(lr, rr);
    }

    private static (BigInteger Epoch, string Version, string? Release) SplitEvr(string evr)
    {
        var epoch = BigInteger.Zero;
        string rest = evr;
        int colon = evr.IndexOf(':');
        if (colon >= 0)
        {
            string epochText = evr[..colon];
            if (epochText.Length > 0 && epochText.All(char.IsAsciiDigit))
            {
                epoch = BigInteger.Parse(epochText, System.Globalization.CultureInfo.InvariantCulture);
            }

            rest = evr[(colon + 1)..];
        }

        int dash = rest.LastIndexOf('-');
        return dash < 0
            ? (epoch, rest, null)
            : (epoch, rest[..dash], rest[(dash + 1)..]);
    }

    // rpm's rpmvercmp: alternating digit/alpha runs, separators skipped, '~' sorts before
    // everything (even the end of the string), '^' sorts after the end but before any other run.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Critical Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "Faithful port of rpmvercmp: correctness is correspondence with the reference algorithm, so a "
                        + "restructure would trade a diffable port for an unverified rewrite.")]
    private static int RpmVerCmp(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.Ordinal))
        {
            return 0;
        }

        int i = 0;
        int j = 0;
        while (i < a.Length || j < b.Length)
        {
            SkipSeparators(a, ref i);
            SkipSeparators(b, ref j);

            char ca = i < a.Length ? a[i] : '\0';
            char cb = j < b.Length ? b[j] : '\0';

            if (ca == '~' || cb == '~')
            {
                if (ca != '~')
                {
                    return 1;
                }

                if (cb != '~')
                {
                    return -1;
                }

                i++;
                j++;
                continue;
            }

            if (ca == '^' || cb == '^')
            {
                if (i >= a.Length)
                {
                    return -1;
                }

                if (j >= b.Length)
                {
                    return 1;
                }

                if (ca != '^')
                {
                    return 1;
                }

                if (cb != '^')
                {
                    return -1;
                }

                i++;
                j++;
                continue;
            }

            if (i >= a.Length || j >= b.Length)
            {
                break;
            }

            int segment = CompareSegment(a, ref i, b, ref j);
            if (segment != 0)
            {
                return segment;
            }
        }

        return i >= a.Length && j >= b.Length ? 0 : i >= a.Length ? -1 : 1;
    }

    private static void SkipSeparators(string s, ref int i)
    {
        while (i < s.Length && !char.IsAsciiLetterOrDigit(s[i]) && s[i] != '~' && s[i] != '^')
        {
            i++;
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Critical Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "Faithful port of rpmvercmp: correctness is correspondence with the reference algorithm, so a "
                        + "restructure would trade a diffable port for an unverified rewrite.")]
    private static int CompareSegment(string a, ref int i, string b, ref int j)
    {
        bool numeric = char.IsAsciiDigit(a[i]);
        int startA = i;
        int startB = j;
        if (numeric)
        {
            while (i < a.Length && char.IsAsciiDigit(a[i]))
            {
                i++;
            }

            while (j < b.Length && char.IsAsciiDigit(b[j]))
            {
                j++;
            }
        }
        else
        {
            while (i < a.Length && char.IsAsciiLetter(a[i]))
            {
                i++;
            }

            while (j < b.Length && char.IsAsciiLetter(b[j]))
            {
                j++;
            }
        }

        string segA = a[startA..i];
        string segB = b[startB..j];
        if (segB.Length == 0)
        {
            // The runs are of different kinds: a numeric run is newer than an alphabetic one.
            return numeric ? 1 : -1;
        }

        if (!numeric)
        {
            return Math.Sign(string.CompareOrdinal(segA, segB));
        }

        segA = segA.TrimStart('0');
        segB = segB.TrimStart('0');
        return segA.Length != segB.Length
            ? Math.Sign(segA.Length - segB.Length)
            : Math.Sign(string.CompareOrdinal(segA, segB));
    }

    /// <summary>
    /// Orders two Alpine apk versions: dotted numbers, an optional trailing letter, pre/post
    /// suffixes (<c>_alpha &lt; _beta &lt; _pre &lt; _rc &lt; (none) &lt; _cvs &lt; _svn &lt; _git &lt; _hg &lt; _p</c>),
    /// then the <c>-r</c> package revision. A version with no revision sorts below the same version
    /// at <c>-r0</c>, as apk-tools orders it.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Critical Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "Faithful port of apk-tools version.c: correctness is correspondence with the reference "
                        + "ordering, so a restructure would trade a diffable port for an unverified rewrite.")]
    public static int CompareApk(string left, string right)
    {
        var l = ApkVersion.Parse(left);
        var r = ApkVersion.Parse(right);

        int count = Math.Max(l.Numbers.Count, r.Numbers.Count);
        for (int k = 0; k < count; k++)
        {
            int part = CompareApkNumber(
                k < l.Numbers.Count ? l.Numbers[k] : null,
                k < r.Numbers.Count ? r.Numbers[k] : null,
                first: k == 0);
            if (part != 0)
            {
                return part;
            }
        }

        int letter = l.Letter.CompareTo(r.Letter);
        if (letter != 0)
        {
            return Math.Sign(letter);
        }

        int suffixCount = Math.Max(l.Suffixes.Count, r.Suffixes.Count);
        for (int k = 0; k < suffixCount; k++)
        {
            var (lr, ln) = k < l.Suffixes.Count ? l.Suffixes[k] : (0, BigInteger.Zero);
            var (rr, rn) = k < r.Suffixes.Count ? r.Suffixes[k] : (0, BigInteger.Zero);
            if (lr != rr)
            {
                return Math.Sign(lr - rr);
            }

            if (ln != rn)
            {
                return ln > rn ? 1 : -1;
            }
        }

        return Math.Sign(l.Revision.CompareTo(r.Revision));
    }

    // A missing component sorts below any present one. After the leading component, a component
    // with a leading zero is a fraction (1.01 < 1.1), compared as text.
    private static int CompareApkNumber(string? a, string? b, bool first)
    {
        if (a is null || b is null)
        {
            return a is null && b is null ? 0 : a is null ? -1 : 1;
        }

        if (!first && (a.StartsWith('0') || b.StartsWith('0')))
        {
            return Math.Sign(string.CompareOrdinal(a.TrimEnd('0'), b.TrimEnd('0')));
        }

        var na = BigInteger.Parse(a, System.Globalization.CultureInfo.InvariantCulture);
        var nb = BigInteger.Parse(b, System.Globalization.CultureInfo.InvariantCulture);
        return na.CompareTo(nb);
    }

    private static readonly (string Name, int Rank)[] ApkSuffixes =
    [
        ("alpha", -4), ("beta", -3), ("pre", -2), ("rc", -1),
        ("cvs", 1), ("svn", 2), ("git", 3), ("hg", 4), ("p", 5),
    ];

    private sealed record ApkVersion(
        List<string> Numbers, char Letter, List<(int Rank, BigInteger Number)> Suffixes, BigInteger Revision)
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Critical Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
            Justification = "Faithful port of apk-tools version.c: correctness is correspondence with the reference "
                            + "ordering, so a restructure would trade a diffable port for an unverified rewrite.")]
        public static ApkVersion Parse(string raw)
        {
            var numbers = new List<string>();
            var suffixes = new List<(int, BigInteger)>();
            char letter = '\0';
            var revision = BigInteger.MinusOne;
            int i = 0;

            while (true)
            {
                int start = i;
                while (i < raw.Length && char.IsAsciiDigit(raw[i]))
                {
                    i++;
                }

                if (i == start)
                {
                    break;
                }

                numbers.Add(raw[start..i]);
                if (i < raw.Length && raw[i] == '.')
                {
                    i++;
                    continue;
                }

                break;
            }

            if (i < raw.Length && char.IsAsciiLetterLower(raw[i]))
            {
                letter = raw[i];
                i++;
            }

            while (i < raw.Length && raw[i] == '_')
            {
                i++;
                int at = i;
                var (suffixName, suffixRank) = ApkSuffixes.FirstOrDefault(
                    s => string.CompareOrdinal(raw, at, s.Name, 0, s.Name.Length) == 0);
                if (suffixName is null)
                {
                    break;
                }

                i += suffixName.Length;
                int ns = i;
                while (i < raw.Length && char.IsAsciiDigit(raw[i]))
                {
                    i++;
                }

                suffixes.Add((suffixRank, i > ns ? BigInteger.Parse(raw[ns..i], System.Globalization.CultureInfo.InvariantCulture) : BigInteger.Zero));
            }

            int rev = raw.IndexOf("-r", i, StringComparison.Ordinal);
            if (rev >= 0)
            {
                string digits = new(raw[(rev + 2)..].TakeWhile(char.IsAsciiDigit).ToArray());
                if (digits.Length > 0)
                {
                    revision = BigInteger.Parse(digits, System.Globalization.CultureInfo.InvariantCulture);
                }
            }

            return new ApkVersion(numbers, letter, suffixes, revision);
        }
    }
}
