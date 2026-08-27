using System.Text;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every <see cref="System.Data.Common.DbCommand"/> mint in <c>src/**</c> — <c>new
/// SqliteCommand(</c>, <c>new NpgsqlCommand(</c>, or <c>.CreateCommand()</c> — is bound by a
/// <c>using</c> / <c>await using</c> declaration or statement, or opts out with a reasoned
/// <c>// dbcommand-ok: &lt;reason&gt;</c> marker in the <see cref="MarkerWindow"/> lines above.
///
/// <para>
/// A command owns prepared <c>sqlite3_stmt</c> handles. Abandoning one does not fail to compile
/// and does not fail a test: the statements are released by the GC and the finalizer thread
/// instead of by the scope that created them, so their lifetime stops being bounded by anything
/// the source states. The shape this gate exists for was on the hottest path in the codebase —
/// <c>SqliteMetadataStore.OpenAsync</c> ran <c>await new SqliteCommand(pragmas, conn)
/// .ExecuteNonQueryAsync(ct)</c> on <b>every single connection open</b>, in production and in
/// every test — and the whole class of defect is invisible to the eye precisely because the
/// abandoned object never appears again in the source.
/// </para>
///
/// <para>
/// <b>Blind spots</b>, stated plainly rather than left implicit, same as every other regex gate
/// in this family. This proves the mint's <i>binding form</i>, not its lifetime:
/// </para>
/// <list type="bullet">
///   <item>A command reached through a helper (<c>BuildCommand(conn)</c>) or a factory delegate
///     is structurally invisible — the gate keys on the three mint tokens and nothing else.</item>
///   <item>A <c>using</c>-bound command whose handle escapes the scope (stored in a field, handed
///     to a longer-lived object) passes: binding form is not escape analysis.</item>
///   <item>A command assigned to a field and disposed correctly in <c>DisposeAsync</c> would
///     <i>fail</i> this gate and need a marker. No such site exists in this repo today, which is
///     what keeps the rule absolute rather than heuristic; the marker is the escape hatch if one
///     ever does.</item>
///   <item>Only <c>src/**</c> is scanned. Tests mint commands freely and are not covered — a
///     leaked handle in a test process is the failure mode this rule guards against, but tests
///     also deliberately construct half-broken shapes, so gating them would be noise.</item>
/// </list>
///
/// <para>
/// The scan resolves its roots through <see cref="SourceRoots"/> rather than naming a project
/// directory, so a source root added later is covered the moment it lands.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class DbCommandDisposalComplianceTests
{
    private const string OptOutMarker = "dbcommand-ok:";
    private const int MarkerWindow = 5;

    private static readonly string[] MintTokens =
    [
        "new SqliteCommand(",
        "new NpgsqlCommand(",
        "new SqlCommand(",
        ".CreateCommand()",
    ];

    private readonly ITestOutputHelper _output;
    public DbCommandDisposalComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryDbCommandMintIsUsingBound()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var violations = new List<string>();

        foreach (string root in SourceRoots.All())
        {
            foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
            {
                string rel = Path.GetRelativePath(repoRoot, file);
                if (rel.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                       .Any(s => s is "bin" or "obj"))
                {
                    continue;
                }

                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];
                    if (IsCommentLine(line) || !MintTokens.Any(t => line.Contains(t, StringComparison.Ordinal)))
                    {
                        continue;
                    }

                    if (IsUsingBound(lines, i) || HasMarker(lines, i))
                    {
                        continue;
                    }

                    violations.Add($"{rel}:{i + 1}: DbCommand minted without a using binding: {line.Trim()}");
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} DbCommand mint(s) not bound by using/await using. " +
                        $"A command owns prepared statement handles; an unbound one leaves them to " +
                        $"the finalizer thread. Bind it with `await using var cmd = …`, or opt out " +
                        $"a deliberate exception with `// {OptOutMarker} <reason>`.");
        }
    }

    /// <summary>
    /// True when the statement the mint belongs to opens with <c>using</c> / <c>await using</c>.
    /// The statement is reconstructed by walking backwards from the mint line to the previous
    /// statement boundary, so a mint whose declaration was wrapped across lines still resolves.
    /// </summary>
    private static bool IsUsingBound(string[] lines, int index)
    {
        var statement = new StringBuilder();
        for (int i = Math.Max(0, index - JoinWindow); i <= index; i++)
        {
            string trimmed = lines[i].Trim();
            if (i < index && (trimmed.Length == 0 || EndsStatement(trimmed) || IsCommentLine(lines[i])))
            {
                statement.Clear();
                continue;
            }

            statement.Append(trimmed).Append(' ');
        }

        string text = statement.ToString().TrimStart();
        return text.StartsWith("using ", StringComparison.Ordinal)
            || text.StartsWith("using(", StringComparison.Ordinal)
            || text.StartsWith("await using ", StringComparison.Ordinal)
            || text.StartsWith("await using(", StringComparison.Ordinal);
    }

    // How many lines a single mint statement may span. Every site in this repo is one line;
    // this is headroom for a wrapped declaration, not an observed need.
    private const int JoinWindow = 3;

    private static bool EndsStatement(string trimmed) =>
        trimmed.EndsWith(';') || trimmed.EndsWith('{') || trimmed.EndsWith('}');

    private static bool IsCommentLine(string line)
    {
        string t = line.TrimStart();
        return t.StartsWith("//", StringComparison.Ordinal)
            || t.StartsWith("///", StringComparison.Ordinal)
            || t.StartsWith('*');
    }

    private static bool HasMarker(string[] lines, int index)
    {
        for (int i = Math.Max(0, index - MarkerWindow); i < index; i++)
        {
            int at = lines[i].IndexOf(OptOutMarker, StringComparison.Ordinal);
            if (at >= 0 && lines[i][(at + OptOutMarker.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }
}
