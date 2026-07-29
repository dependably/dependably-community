using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: no schema file declares a native temporal column type. Every instant is stored
/// as TEXT holding canonical ISO-8601 UTC (see <c>UtcTimestamp</c>), on both providers.
///
/// This is the rule <see cref="SchemaParityComplianceTests"/> deliberately does not cover — it
/// compares column NAMES only, because type spellings legitimately differ between providers
/// (INTEGER↔BIGINT). That gap is exactly how three <c>TIMESTAMPTZ</c> columns shipped in
/// <c>Schema.pg.sql</c> while their SQLite counterparts were TEXT, leaving every Postgres read,
/// write, and comparison against them broken and undetected — the SQLite-backed suite never
/// exercised them.
///
/// Why TEXT rather than the richer type, given TIMESTAMPTZ would typecheck:
///   - It would typecheck on ONE provider. SQLite has no native date/time type and is the
///     default, so the invariant has to hold above the database regardless — and it does, via
///     TimeProvider → UtcTimestamp.ToUtcIso(), policed by UtcTimestampFormatComplianceTests.
///   - TIMESTAMPTZ does not enforce UTC. It accepts any offset and renders in the session's
///     TimeZone, so "stored in UTC" is an application invariant either way.
///   - One statement runs against both engines. Fixed-format ISO-8601 UTC TEXT is the only
///     representation whose comparison semantics are identical under both, which is what the
///     lexicographic <c>WHERE starts_at &lt;= @now</c> comparisons and the <c>substr()</c> date
///     bucketing in PackageAnalyticsRepository depend on.
///
/// Opt-out: <c>-- timestamptype-ok: &lt;reason&gt;</c> on the same line or within the 5 lines above.
/// </summary>
[Trait("Category", "Schema")]
public sealed partial class TimestampColumnTypeComplianceTests
{
    private readonly ITestOutputHelper _output;
    public TimestampColumnTypeComplianceTests(ITestOutputHelper output) => _output = output;

    // A column declaration whose type is a native temporal type. Anchored on the column-name +
    // type shape so it does not match the same words inside a comment or a to_char format.
    [GeneratedRegex(
        @"^\s*[a-z_][a-z0-9_]*\s+(TIMESTAMPTZ|TIMESTAMP\b|DATETIME\b|\bDATE\b|TIME\s+WITH|TIMESTAMP\s+WITH)",
        RegexOptions.IgnoreCase)]
    private static partial Regex TemporalColumnRegex();

    [Theory]
    [InlineData("Schema.sql")]
    [InlineData("Schema.pg.sql")]
    public void SchemaFilesStoreInstantsAsUtcText(string fileName)
    {
        string path = Path.Combine(
            SourceRoots.RepoRoot(),
            "src", "Dependably.Core", "Infrastructure", "schema", fileName);

        string[] lines = File.ReadAllLines(path);
        var violations = new List<string>();

        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];
            if (line.TrimStart().StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            if (TemporalColumnRegex().IsMatch(line) && !HasOptOut(lines, i))
            {
                violations.Add($"{fileName}:{i + 1}: native temporal column type — store the instant " +
                               $"as TEXT (canonical ISO-8601 UTC), or annotate " +
                               $"`-- timestamptype-ok: <reason>`. {line.Trim()}");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} native temporal column type(s) in {fileName}. Instants are " +
                        "stored as TEXT ISO-8601 UTC on both providers; a native type exists on only one " +
                        "of them, does not itself enforce UTC, and breaks the lexicographic comparisons " +
                        "and substr() bucketing that run against both engines. See test output.");
        }
    }

    private static bool HasOptOut(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("timestamptype-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
