using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: runtime SQL never calls a provider-specific clock function. <c>strftime()</c>
/// is SQLite-only and <c>to_char()/now()</c> is Postgres-only, so a statement embedding either
/// runs on one provider and throws on the other — and because these sit in proxy and push
/// paths that the SQLite-backed test suite covers happily, the failure only ever appears on a
/// Postgres deployment.
///
/// The fix is not to branch the statement but to remove the clock from it: pass the instant as
/// a parameter from the injected <see cref="TimeProvider"/>
/// (<c>new { now = UtcTimestamp.Now(_time) }</c>). That is portable by construction, and it
/// also makes the write deterministic under <c>FakeTimeProvider</c> instead of reading the
/// database's wall clock.
///
/// Exempt: the <c>SchemaInitializer</c> partials, whose DDL is provider-branched by
/// construction (<c>_db.Provider == DbProvider.Postgres ? … : …</c>) and whose SQLite arm must
/// name the SQLite function. Column DEFAULTs in the two <c>.sql</c> files are likewise correct
/// — each file is already provider-specific.
///
/// Opt-out: <c>// sqlonly-ok: &lt;reason&gt;</c> on the same line or within the 5 lines above.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class PortableSqlTimestampComplianceTests
{
    private readonly ITestOutputHelper _output;
    public PortableSqlTimestampComplianceTests(ITestOutputHelper output) => _output = output;

    [GeneratedRegex(@"\b(strftime|to_char)\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex ProviderClockRegex();

    [Fact]
    public void RuntimeSqlUsesParameterizedTimestampsNotProviderClocks()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var violations = new List<string>();

        foreach (string root in SourceRoots.All())
        {
            foreach (string file in EnumerateSource(root))
            {
                // Provider-branched by construction; its SQLite arm must name strftime.
                if (Path.GetFileName(file).StartsWith("SchemaInitializer", StringComparison.Ordinal))
                {
                    continue;
                }

                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].TrimStart().StartsWith("//"))
                    {
                        continue;
                    }

                    if (ProviderClockRegex().IsMatch(lines[i]) && !HasOptOut(lines, i))
                    {
                        violations.Add(
                            $"{Path.GetRelativePath(repoRoot, file)}:{i + 1}: provider-specific clock in SQL — " +
                            $"pass the instant as a parameter (UtcTimestamp.Now(_time)), or annotate " +
                            $"`// sqlonly-ok: <reason>`. {lines[i].Trim()}");
                    }
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} provider-specific clock call(s) in runtime SQL. strftime() is " +
                        "SQLite-only and to_char()/now() is Postgres-only, so the statement throws on the " +
                        "other provider — invisibly, because the test suite runs on SQLite. Pass the " +
                        "timestamp as a parameter instead. See test output.");
        }
    }

    private static bool HasOptOut(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("sqlonly-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<string> EnumerateSource(string root)
    {
        foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            string p = file.Replace('\\', '/');
            if (p.Contains("/obj/") || p.Contains("/bin/"))
            {
                continue;
            }

            yield return file;
        }
    }
}
