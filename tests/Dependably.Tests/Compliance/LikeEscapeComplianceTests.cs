using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the LIKE-escaping invariant: a <c>LIKE</c> predicate bound to a parameter
/// also declares <c>ESCAPE</c>.
///
/// <para>
/// These searches are parameterized, so this is not an injection rule — the search term never
/// becomes SQL. It is a correctness rule. <c>%</c> and <c>_</c> are LIKE metacharacters, so an
/// unescaped term silently changes what the query means: <c>_</c> matches any single character
/// (PyPI and NuGet names routinely contain one, so <c>my_pkg</c> also matches <c>myXpkg</c>), and a
/// term of just <c>%</c> matches every row, turning a filtered lookup into a full scan over a
/// leading-wildcard predicate no index can serve.
/// </para>
///
/// <para>
/// The rule exists because the two halves live apart and fail silently. <c>LikePattern</c> inserts
/// backslashes; the SQL must declare <c>ESCAPE '\'</c> for them to mean anything. Escape without the
/// clause matches the backslashes literally — a term containing <c>_</c> stops matching itself.
/// Clause without escaping is the original bug. Neither raises an error; both just return the wrong
/// rows, which is why review did not catch that six call sites had one half and not the other while
/// five had both.
/// </para>
///
/// <para>
/// A deliberate exception opts out with <c>// like-escape-ok: &lt;reason&gt;</c> in the 5 lines above.
/// A bare marker with no stated reason is malformed and is never honoured.
/// </para>
///
/// <para>
/// <b>Known limitations, stated plainly:</b> a line-oriented source scan. It requires <c>ESCAPE</c>
/// on the same line as the <c>LIKE</c>, so a predicate wrapped across lines would false-flag and need
/// a marker. It skips single-line comments so prose mentioning a predicate does not trip it, and it
/// ignores <c>LIKE 'literal'</c> forms, where the pattern is a compile-time constant with no caller
/// input. It proves the clause is present, not that the bound value was built by
/// <c>LikePattern</c> — the other half of the pair stays a reviewer judgment.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class LikeEscapeComplianceTests
{
    private const string Marker = "like-escape-ok:";
    private const int MarkerWindow = 5;

    /// <summary>A LIKE bound to a parameter — <c>LIKE @foo</c>, or <c>LIKE LOWER(@foo)</c>.</summary>
    [GeneratedRegex(@"\bLIKE\s+(?:LOWER\s*\(\s*)?@\w+", RegexOptions.IgnoreCase)]
    private static partial Regex ParameterizedLike();

    private readonly ITestOutputHelper _output;
    public LikeEscapeComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryParameterizedLikeDeclaresItsEscapeCharacter()
    {
        var violations = new List<string>();
        int checkedPredicates = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);
            string[] lines = File.ReadAllLines(file);

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];

                // Prose about a predicate is not a predicate.
                if (line.TrimStart().StartsWith("//", StringComparison.Ordinal)
                    || line.TrimStart().StartsWith("///", StringComparison.Ordinal))
                {
                    continue;
                }

                if (!ParameterizedLike().IsMatch(line))
                {
                    continue;
                }

                checkedPredicates++;

                if (line.Contains("ESCAPE", StringComparison.OrdinalIgnoreCase)
                    || HasMarkerAbove(lines, i))
                {
                    continue;
                }

                violations.Add(
                    $"{rel}:{i + 1}: parameterized LIKE with no ESCAPE clause, so a '%' or '_' in the " +
                    $"caller's term acts as a wildcard: {line.Trim()}");
            }
        }

        // A refactor that moved the SQL or changed the predicate shape would reduce this gate to a
        // no-op; assert it still sees the predicates it is meant to police.
        Assert.True(checkedPredicates > 0,
            "found no parameterized LIKE predicates at all — the gate has gone blind, not clean.");

        Assert.True(violations.Count == 0, Report(violations,
            "Parameterized LIKE predicate(s) missing ESCAPE"));
    }

    [Fact]
    public void EveryLikeEscapeOkMarkerCarriesAStatedReason()
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

        Assert.True(violations.Count == 0, Report(violations, "Malformed like-escape-ok marker(s)"));
    }

    private static bool HasMarkerAbove(string[] lines, int index)
    {
        for (int i = Math.Max(0, index - MarkerWindow); i < index; i++)
        {
            int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
            if (at >= 0 && lines[i][(at + Marker.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

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
