using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the coordinate-header invariant: every write to
/// <c>X-Dependably-PURL</c> passes its value through <see cref="Dependably.Security.HeaderSanitizer"/>.
///
/// <para>
/// A PURL is assembled from package coordinates — an RPM <c>Vendor</c>/<c>Name</c> tag read out of
/// uploaded bytes, Maven <c>groupId</c>/<c>artifactId</c> taken from URL path segments. Those are the
/// values most likely to carry a CR or LF, and <c>HeaderSanitizer</c>'s own doc comment names this
/// header as the reason it exists. 14 of 16 call sites used it; two did not, which is drift rather
/// than a decision — nothing marked the two as deliberate and no test covered them.
/// </para>
///
/// <para>
/// <b>Why this gate is scoped to one header rather than to every header write.</b> There are ~26
/// non-literal <c>Response.Headers[…] = …</c> assignments in <c>src/</c>, and nearly all of them are
/// a <c>long.ToString()</c>, a closed-set literal (<c>isHit ? "HIT" : "MISS"</c>), a server-computed
/// digest, or a generated upload UUID — none of which can carry a control character. Requiring a
/// marker on all of them would mean ~24 rubber-stamp opt-outs, which is how a gate stops being read.
/// The narrow rule holds where the risk actually is; the broader "sanitise anything caller-derived"
/// rule stays a reviewer judgment, as it must, since no regex can tell a coordinate-derived string
/// from a numeric one.
/// </para>
///
/// <para>
/// A deliberate exception opts out with <c>// header-raw-ok: &lt;reason&gt;</c> in the 5 lines above.
/// A bare marker with no stated reason is malformed and is never honoured.
/// </para>
///
/// <para>
/// <b>Known limitation:</b> this proves the sanitiser is <em>called</em>, not that the value reaching
/// it is the untrusted one, and it matches the literal header name — a write through a constant or a
/// computed header name is invisible to it.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class PurlHeaderSanitizationComplianceTests
{
    private const string Marker = "header-raw-ok:";
    private const int MarkerWindow = 5;
    private const string PurlHeader = "X-Dependably-PURL";

    /// <summary>An assignment into the PURL header, capturing the assigned expression.</summary>
    private static readonly Regex PurlHeaderWrite = new(
        @"Headers\[""" + Regex.Escape(PurlHeader) + @"""\]\s*=\s*(?<value>[^;]+);",
        RegexOptions.Compiled);

    private readonly ITestOutputHelper _output;
    public PurlHeaderSanitizationComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryPurlHeaderWriteIsSanitized()
    {
        var violations = new List<string>();
        int checkedWrites = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string text = File.ReadAllText(file);
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);

            foreach (Match m in PurlHeaderWrite.Matches(text))
            {
                checkedWrites++;
                string value = m.Groups["value"].Value;

                if (value.Contains("HeaderSanitizer.Sanitize", StringComparison.Ordinal)
                    || HasMarkerAbove(text, m.Index))
                {
                    continue;
                }

                violations.Add(
                    $"{rel}:{LineOf(text, m.Index)}: writes {PurlHeader} without " +
                    $"HeaderSanitizer.Sanitize(...). Value: {value.Trim()}");
            }
        }

        // A refactor that renamed the header or changed the assignment shape would silently reduce
        // this gate to a no-op, so assert it still found the call sites it is meant to police.
        Assert.True(checkedWrites > 0,
            $"found no {PurlHeader} writes at all — the gate has gone blind, not clean.");

        Assert.True(violations.Count == 0, Report(violations,
            $"{PurlHeader} write(s) bypassing HeaderSanitizer"));
    }

    [Fact]
    public void EveryHeaderRawOkMarkerCarriesAStatedReason()
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

        Assert.True(violations.Count == 0, Report(violations, "Malformed header-raw-ok marker(s)"));
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
