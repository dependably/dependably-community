using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the regex end-anchor invariant: a pattern that validates a whole string
/// ends with <c>\z</c>, never <c>$</c>.
///
/// <para>
/// Without <c>RegexOptions.Multiline</c>, .NET's <c>$</c> matches end-of-string <em>or</em> the
/// position immediately before a single trailing <c>\n</c>. So <c>^[a-z0-9]+$</c> — which reads as
/// "lowercase alphanumerics only" — accepts <c>"pkg\n"</c>. Every coordinate-shape validator in this
/// repo was written that way, and a route value arrives already URL-decoded, so <c>%0A</c> on the
/// wire is a literal newline by the time the action sees it. The character then rides into whatever
/// the validated value feeds: a blob key that becomes an on-disk path segment, a database identity
/// column, a response header Kestrel will reject <em>after</em> the write has committed.
/// </para>
///
/// <para>
/// This is a textbook green-but-blind failure: the validator is present, looks correct, has tests,
/// and passes them — because no test thought to append a newline. Nothing but this gate distinguishes
/// <c>$</c> from <c>\z</c> at review time; the two are visually interchangeable and the difference
/// only shows on one input nobody types by hand.
/// </para>
///
/// <para>
/// A pattern that genuinely wants line-anchored semantics (a multi-line scan, a log parser) opts out
/// with <c>// regex-anchor-ok: &lt;reason&gt;</c> in the 5 lines above, matching the
/// <c>// xtenant:</c> / <c>// rawsql:</c> / <c>// blobkey-ok:</c> convention. A bare marker with no
/// stated reason is malformed and is never honoured.
/// </para>
///
/// <para>
/// <b>Known limitations, stated plainly:</b> this scans pattern <em>literals</em> passed to
/// <c>[GeneratedRegex(…)]</c> and <c>new Regex(…)</c>. A pattern built at runtime, read from
/// configuration, composed from constants, or passed to a static <c>Regex.IsMatch(input, pattern)</c>
/// overload is invisible to it. It skips a <c>$</c> that is escaped (<c>\$</c>, a literal dollar) or
/// that sits inside a character class (<c>[$]</c>), but it does not parse the full regex grammar — a
/// <c>$</c> inside a nested or exotic construct could in principle be misjudged. It reasons purely
/// about the anchor character and cannot tell whether the value being validated ever reaches a
/// security-relevant sink; it treats every <c>$</c> in a pattern literal as suspect, which is the
/// fail-closed trade the rest of this family makes.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class RegexAnchorComplianceTests
{
    private const string Marker = "regex-anchor-ok:";
    private const int MarkerWindow = 5;

    // [GeneratedRegex(@"…")] / [GeneratedRegex("…")] / new Regex(@"…") / new Regex("…").
    // Group 'verbatim' tells us whether backslashes in the body are regex escapes or C# ones;
    // group 'body' is the pattern text.
    [GeneratedRegex(@"(?:GeneratedRegex|new\s+Regex)\s*\(\s*(?<verbatim>@)?""(?<body>(?:[^""\\]|\\.|"""")*)""")]
    private static partial Regex PatternLiteral();

    private readonly ITestOutputHelper _output;
    public RegexAnchorComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void NoRegexPatternUsesTheDollarEndAnchor()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string text = File.ReadAllText(file);
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);

            foreach (Match m in PatternLiteral().Matches(text))
            {
                if (HasMarkerAbove(text, m.Index))
                {
                    continue;
                }

                string body = m.Groups["body"].Value;
                if (!ContainsAnchorDollar(body, verbatim: m.Groups["verbatim"].Success))
                {
                    continue;
                }

                violations.Add(
                    $"{rel}:{LineOf(text, m.Index)}: regex pattern uses the '$' end anchor, which " +
                    $"also matches before a single trailing newline — use '\\z'. Pattern: {body}");
            }
        }

        Assert.True(violations.Count == 0, Report(violations,
            "Regex pattern(s) using the newline-permissive '$' anchor"));
    }

    [Fact]
    public void EveryRegexAnchorOkMarkerCarriesAStatedReason()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);
            string[] lines = File.ReadAllLines(file);

            for (int i = 0; i < lines.Length; i++)
            {
                int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
                if (at >= 0 && lines[i][(at + Marker.Length)..].Trim().Length == 0)
                {
                    violations.Add($"{rel}:{i + 1}: bare '{Marker}' marker with no stated reason.");
                }
            }
        }

        Assert.True(violations.Count == 0, Report(violations, "Malformed regex-anchor-ok marker(s)"));
    }

    /// <summary>
    /// Does the pattern body use <c>$</c> as an anchor — i.e. a <c>$</c> that is neither escaped to
    /// mean a literal dollar nor sitting inside a character class?
    /// </summary>
    private static bool ContainsAnchorDollar(string body, bool verbatim)
    {
        bool inClass = false;

        for (int i = 0; i < body.Length; i++)
        {
            char c = body[i];

            // In a non-verbatim C# literal a regex backslash is written '\\', so consume the pair.
            if (c == '\\')
            {
                i += verbatim ? 1 : 2;
                continue;
            }

            if (c == '[')
            {
                inClass = true;
            }
            else if (c == ']')
            {
                inClass = false;
            }
            else if (c == '$' && !inClass)
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasMarkerAbove(string text, int index)
    {
        int line = LineOf(text, index);
        string[] lines = text.Split('\n');
        int first = Math.Max(0, line - 1 - MarkerWindow);

        for (int i = first; i < line && i < lines.Length; i++)
        {
            int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
            if (at >= 0 && lines[i][(at + Marker.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static int LineOf(string text, int index) => 1 + text.AsSpan(0, index).Count('\n');

    private string Report(List<string> violations, string headline)
    {
        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        return $"{headline} ({violations.Count}):{Environment.NewLine}" +
               string.Join(Environment.NewLine, violations);
    }
}
