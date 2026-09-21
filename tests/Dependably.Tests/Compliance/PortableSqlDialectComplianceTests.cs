using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: runtime SQL in a shared code path uses no construct that exists on only one of
/// the two supported engines. The companion to <see cref="PortableSqlTimestampComplianceTests"/>,
/// which covers the clock functions (<c>strftime</c> / <c>to_char</c>) specifically; this one
/// covers the rest of the dialect surface, in both directions.
///
/// <para>
/// The failure mode this exists for is silent by construction. The unit and compliance suites run
/// on SQLite, so a SQLite-only construct passes every gate and throws only on a Postgres
/// deployment — which is the production topology — and it throws at <em>request</em> time, not at
/// boot, so nothing degrades visibly until someone exercises the path. The SIEM auth feed shipped
/// in exactly that state: it unfolded its action-prefix list with a SQLite-only table-valued JSON
/// function, worked perfectly against the SQLite dogfood instance, and had never once worked on
/// Postgres. A Postgres-only construct is the mirror image, and fails the same way on SQLite.
/// </para>
///
/// <para>
/// The fix for a flagged line is almost never a provider branch: it is to move the work out of SQL
/// (compute the id or the timestamp in C# and bind it) or to express the predicate with the
/// constructs both engines share (a parameterized <c>LIKE</c> disjunction via
/// <c>DapperInClause.ExpandLikeAny</c> instead of an in-SQL array unfold).
/// </para>
///
/// <para><b>Scope and its stated limits.</b> Two classes of file are exempt because they are
/// provider-specific by construction and saying so per line would be noise: the
/// <c>SchemaInitializer</c> partials, whose DDL is already branched on
/// <c>_db.Provider == DbProvider.Postgres</c>, and files whose name carries a provider
/// (<c>*Sqlite*</c>, <c>*Npgsql*</c>, <c>*Postgres*</c>). That exemption is the gate's main blind
/// spot: a shared query that happens to live in a provider-named file is not scanned. Comment
/// lines are skipped, so prose describing a construct is not a violation — which is also why the
/// scan cannot see a construct assembled across several lines. And the rule set is a curated
/// denylist, not a proof of portability: it catches the named constructs, not every possible
/// divergence. Two shapes are deliberately left out because their false-positive rate exceeds
/// their value in C# source — <c>now()</c> and <c>typeof()</c> (both collide with ordinary C#
/// calls: <c>UtcTimestamp.Now(_time)</c>, <c>typeof(Program)</c>), and <c>= ANY(</c>, which this
/// repository names repeatedly in analyzer-suppression justifications explaining why
/// <c>DapperInClause</c> exists.
/// </para>
///
/// <para>Opt-out: <c>// sqlonly-ok: &lt;reason&gt;</c> on the line or within the 5 lines above —
/// the same marker <see cref="PortableSqlTimestampComplianceTests"/> uses. A bare marker with no
/// stated reason is malformed and is never honoured.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class PortableSqlDialectComplianceTests
{
    private const string Marker = "sqlonly-ok:";
    private const int MarkerWindow = 5;

    private readonly ITestOutputHelper _output;
    public PortableSqlDialectComplianceTests(ITestOutputHelper output) => _output = output;

    // SQLite's JSON1 table-valued/extraction functions. Postgres has same-named functions with
    // different argument types and different semantics (json_each unfolds an object, not an array),
    // so the statement does not merely underperform — it errors at bind time.
    [GeneratedRegex(@"\bjson_(each|tree|extract|group_array|group_object|array_length|patch|quote)\s*\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex SqliteJsonRegex();

    // SQLite's GLOB operator. Postgres's equivalent is the `~` POSIX-regex operator.
    [GeneratedRegex(@"\bGLOB\b")]
    private static partial Regex SqliteGlobRegex();

    // SQLite-only scalar functions. randomblob()/hex() as an in-SQL id generator is the one that
    // has actually shipped here; the rest are the neighbours a reader reaches for next.
    [GeneratedRegex(@"\b(ifnull|group_concat|julianday|unixepoch|last_insert_rowid|randomblob|total_changes)\s*\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex SqliteScalarRegex();

    // SQLite's engine catalogue.
    [GeneratedRegex(@"\bsqlite_(master|schema|sequence)\b", RegexOptions.IgnoreCase)]
    private static partial Regex SqliteCatalogRegex();

    // SQLite's conflict-resolution INSERT prefix; Postgres expresses this as ON CONFLICT, which
    // both engines accept.
    [GeneratedRegex(@"\bINSERT\s+OR\s+(IGNORE|REPLACE|ABORT|FAIL|ROLLBACK)\b", RegexOptions.IgnoreCase)]
    private static partial Regex SqliteInsertOrRegex();

    // SQLite PRAGMA statements.
    [GeneratedRegex(@"\bPRAGMA\s+\w+")]
    private static partial Regex SqlitePragmaRegex();

    // Postgres-only operators and functions, the mirror image of the SQLite set.
    [GeneratedRegex(@"\b(ILIKE\b|string_agg\s*\(|array_agg\s*\(|unnest\s*\(|to_timestamp\s*\(|gen_random_uuid\s*\(|jsonb_\w+\s*\(|DISTINCT\s+ON\b)",
        RegexOptions.IgnoreCase)]
    private static partial Regex PostgresFunctionRegex();

    // Postgres's `::type` cast syntax. Matched case-sensitively against lowercase type names so
    // C#'s own `global::`/alias-qualified names cannot collide with it.
    [GeneratedRegex(@"::(text|int|int4|int8|integer|bigint|smallint|boolean|bool|numeric|real|timestamptz|timestamp|date|uuid|jsonb|json|bytea)\b")]
    private static partial Regex PostgresCastRegex();

    private static (string Rule, Regex Pattern, string Remedy)[] Rules() =>
    [
        ("SQLite JSON1 function", SqliteJsonRegex(),
            "unfold the list into bound parameters instead (DapperInClause.ExpandLikeAny / .Expand)"),
        ("SQLite GLOB operator", SqliteGlobRegex(), "use LIKE, or branch the predicate per provider"),
        ("SQLite-only scalar function", SqliteScalarRegex(),
            "compute the value in C# and bind it (ids: Guid.NewGuid().ToString(\"N\"))"),
        ("SQLite engine catalogue", SqliteCatalogRegex(), "query the schema through a provider-neutral path"),
        ("SQLite INSERT OR <action>", SqliteInsertOrRegex(), "use ON CONFLICT, which both engines accept"),
        ("SQLite PRAGMA", SqlitePragmaRegex(), "issue it from the SQLite-specific store, not a shared path"),
        ("Postgres-only function/operator", PostgresFunctionRegex(),
            "use a construct both engines share, or compute it in C#"),
        ("Postgres :: cast", PostgresCastRegex(), "use CAST(x AS t) or bind an already-typed parameter"),
    ];

    [Fact]
    public void SharedRuntimeSqlUsesNoSingleEngineConstruct()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var violations = new List<string>();
        var rules = Rules();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            if (IsProviderSpecificFile(file))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string trimmed = lines[i].TrimStart();
                if (trimmed.StartsWith("//", StringComparison.Ordinal)
                    || trimmed.StartsWith('*'))
                {
                    continue;
                }

                foreach (var (rule, pattern, remedy) in rules)
                {
                    if (!pattern.IsMatch(lines[i]) || HasOptOut(lines, i))
                    {
                        continue;
                    }

                    violations.Add(
                        $"{Path.GetRelativePath(repoRoot, file)}:{i + 1}: {rule} in shared SQL — " +
                        $"{remedy}, or annotate `// {Marker} <reason>`. {lines[i].Trim()}");
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} single-engine SQL construct(s) in shared code. Each one " +
                        "runs on one provider and throws on the other — invisibly, because the test " +
                        "suite runs on SQLite while production runs on Postgres. See test output.");
        }
    }

    [Fact]
    public void EverySqlOnlyMarkerCarriesAStatedReason()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var malformed = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                int at = lines[i].IndexOf(Marker, StringComparison.OrdinalIgnoreCase);
                if (at < 0)
                {
                    continue;
                }

                if (lines[i][(at + Marker.Length)..].Trim().Length < 10)
                {
                    malformed.Add($"{Path.GetRelativePath(repoRoot, file)}:{i + 1}: {lines[i].Trim()}");
                }
            }
        }

        Assert.True(
            malformed.Count == 0,
            $"{malformed.Count} `{Marker}` marker(s) with no stated reason. A marker is a reviewed " +
            $"decision, not a mute button:{Environment.NewLine}{string.Join(Environment.NewLine, malformed)}");
    }

    // ── Self-tests: the scanner sees the real shapes and not the prose about them. ──

    [Fact]
    public void Scanner_FlagsTheJsonUnfoldThatBrokeTheAuthFeed()
    {
        const string line = @"WHERE EXISTS (SELECT 1 FROM json_each(@patternsJson) j WHERE al.action LIKE j.value)";
        Assert.Contains(Rules(), r => r.Pattern.IsMatch(line));
    }

    [Fact]
    public void Scanner_FlagsAnInSqlIdGenerator()
    {
        const string line = @"VALUES (lower(hex(randomblob(16))), @caId, 'cache_artifact',";
        Assert.Contains(Rules(), r => r.Pattern.IsMatch(line));
    }

    [Fact]
    public void Scanner_FlagsAPostgresOnlyConstruct()
    {
        Assert.Contains(Rules(), r => r.Pattern.IsMatch("SELECT string_agg(name, ',') FROM packages"));
        Assert.Contains(Rules(), r => r.Pattern.IsMatch("SELECT id FROM packages WHERE name ILIKE @q"));
        Assert.Contains(Rules(), r => r.Pattern.IsMatch("SELECT md5(random()::text)"));
    }

    [Fact]
    public void Scanner_IgnoresPortableSqlAndOrdinaryCSharp()
    {
        foreach (string line in new[]
                 {
                     "            WHERE (al.action LIKE @actionPrefix0 OR al.action LIKE @actionPrefix1)",
                     "        ON CONFLICT(package_version_id) DO UPDATE SET rpm_name = excluded.rpm_name",
                     "        var now = UtcTimestamp.Now(_time);",
                     "        typeof(Program).Assembly.GetName();",
                     "        string version = global::System.Environment.Version.ToString();",
                     "        foreach (string file in Directory.EnumerateFiles(root, globPattern))",
                 })
        {
            Assert.DoesNotContain(Rules(), r => r.Pattern.IsMatch(line));
        }
    }

    private static bool IsProviderSpecificFile(string file)
    {
        string name = Path.GetFileName(file);
        return name.StartsWith("SchemaInitializer", StringComparison.Ordinal)
            || name.Contains("Sqlite", StringComparison.Ordinal)
            || name.Contains("Npgsql", StringComparison.Ordinal)
            || name.Contains("Postgres", StringComparison.Ordinal);
    }

    private static bool HasOptOut(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - MarkerWindow); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains(Marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
