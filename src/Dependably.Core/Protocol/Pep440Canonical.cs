using System.Text;
using System.Text.RegularExpressions;

namespace Dependably.Protocol;

/// <summary>
/// The PEP 440 canonical spelling of a PyPI version, the single rule behind PyPI version identity.
///
/// Normalization folds case, drops a leading <c>v</c>, unifies the pre-release, post-release and
/// dev-release separators and spellings (<c>alpha</c> to <c>a</c>, <c>beta</c> to <c>b</c>,
/// <c>c</c>/<c>pre</c>/<c>preview</c> to <c>rc</c>, <c>rev</c>/<c>r</c> and the implicit
/// <c>-N</c> form to <c>.postN</c>), supplies the implicit zero in <c>a</c>/<c>b</c>/<c>rc</c>/
/// <c>post</c>/<c>dev</c> segments, strips leading zeros from numeric segments, and keeps a
/// non-zero epoch. Trailing release zeros are kept: <c>1.0</c> and <c>1.0.0</c> are distinct
/// canonical strings, exactly as the index treats them.
///
/// The grammar is the one in PEP 440 Appendix B, so the form is a pure string function: it needs no
/// database and is applied to uploaded and proxied versions alike. A string that is not a PEP 440
/// version falls back to its trimmed, lower-cased form, which is the identity PyPI versions had
/// before normalization and so never merges two values that were distinct.
/// </summary>
public static partial class Pep440Canonical
{
    [GeneratedRegex(
        @"^v?(?:(?<epoch>[0-9]+)!)?(?<release>[0-9]+(?:\.[0-9]+)*)" +
        @"(?:[-_.]?(?<preL>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?<preN>[0-9]+)?)?" +
        @"(?:(?:-(?<postN1>[0-9]+))|(?:[-_.]?(?<postL>post|rev|r)[-_.]?(?<postN2>[0-9]+)?))?" +
        @"(?:[-_.]?(?<devL>dev)[-_.]?(?<devN>[0-9]+)?)?" +
        @"(?:\+(?<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex Pep440Regex();

    /// <summary>The canonical form of <paramref name="version"/>, or its trimmed lower-case form when it is not PEP 440.</summary>
    public static string Canonicalize(string version) =>
        TryCanonicalize(version, out string canonical) ? canonical : version.Trim().ToLowerInvariant();

    /// <summary>True, with the canonical form, when <paramref name="version"/> is a PEP 440 version.</summary>
    public static bool TryCanonicalize(string version, out string canonical)
    {
        canonical = "";
        Match m;
        try
        {
            m = Pep440Regex().Match(version.Trim());
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }

        if (!m.Success)
        {
            return false;
        }

        canonical = Render(m);
        return true;
    }

    private static string Render(Match m)
    {
        var sb = new StringBuilder();
        AppendEpoch(sb, m);
        sb.Append(string.Join('.', m.Groups["release"].Value.Split('.').Select(Number)));
        AppendPreRelease(sb, m);
        AppendPost(sb, m);
        if (m.Groups["devL"].Success)
        {
            sb.Append(".dev").Append(Number(m.Groups["devN"].Value));
        }

        AppendLocal(sb, m);
        return sb.ToString();
    }

    private static void AppendEpoch(StringBuilder sb, Match m)
    {
        if (!m.Groups["epoch"].Success)
        {
            return;
        }

        string epoch = Number(m.Groups["epoch"].Value);
        if (epoch != "0")
        {
            sb.Append(epoch).Append('!');
        }
    }

    private static void AppendPreRelease(StringBuilder sb, Match m)
    {
        if (!m.Groups["preL"].Success)
        {
            return;
        }

        sb.Append(m.Groups["preL"].Value.ToLowerInvariant() switch
        {
            "alpha" or "a" => "a",
            "beta" or "b" => "b",
            _ => "rc",
        }).Append(Number(m.Groups["preN"].Value));
    }

    private static void AppendPost(StringBuilder sb, Match m)
    {
        if (!m.Groups["postN1"].Success && !m.Groups["postL"].Success)
        {
            return;
        }

        string post = m.Groups["postN1"].Success ? m.Groups["postN1"].Value : m.Groups["postN2"].Value;
        sb.Append(".post").Append(Number(post));
    }

    private static void AppendLocal(StringBuilder sb, Match m)
    {
        if (!m.Groups["local"].Success)
        {
            return;
        }

        var segments = m.Groups["local"].Value.ToLowerInvariant().Split('-', '_', '.')
            .Select(s => s.All(char.IsAsciiDigit) ? Number(s) : s);
        sb.Append('+').Append(string.Join('.', segments));
    }

    // A numeric segment without leading zeros; an absent number is the implicit zero.
    private static string Number(string digits)
    {
        string trimmed = digits.TrimStart('0');
        return trimmed.Length == 0 ? "0" : trimmed;
    }
}
