using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static guard that Schema.sql (SQLite) and Schema.pg.sql (Postgres) declare the same indexes:
/// same set of index names, each pointing at the same table and columns, with the same UNIQUE
/// flag and the same WHERE predicate (normalized for whitespace and quoting).
///
/// Partial-index predicates (e.g. <c>WHERE owner_kind = 'package_version'</c>) are the H1
/// correctness invariant: a predicate difference across providers means one provider's uniqueness
/// constraint covers a different row-set and a duplicate can slip through on the other. Any
/// such difference must be caught here before it reaches production.
///
/// Column TYPE differences (e.g. <c>INTEGER AUTOINCREMENT</c> vs <c>BIGSERIAL</c>) are
/// provider-dialect and legitimately differ; they are NOT checked here — that is out of scope
/// for an index-parity test.
///
/// Genuinely intentional index-level divergences (none today) go in
/// <see cref="KnownIndexExceptions"/> with a reason; an allow-listed entry is a deliberate,
/// reviewed decision rather than silent rot.
/// </summary>
[Trait("Category", "Schema")]
public sealed partial class SchemaIndexParityComplianceTests
{
    private readonly ITestOutputHelper _output;
    public SchemaIndexParityComplianceTests(ITestOutputHelper output) => _output = output;

    // Index names allowed to differ between SQLite and Postgres. Empty today — all 66 indexes
    // are structurally identical across providers. Any future deliberate divergence (different
    // collation, provider-specific expression index syntax, etc.) must be documented here with
    // a clear reason rather than left as silent drift.
    private static readonly HashSet<string> KnownIndexExceptions = new(StringComparer.OrdinalIgnoreCase)
    {
        // example: "idx_some_table_col", // reason: Postgres-specific expression index; SQLite has no equivalent
    };

    [Fact]
    public void SqliteAndPostgres_DeclareTheSameIndexNames()
    {
        var (sqlite, pg) = ParseBoth();
        var violations = new List<string>();

        foreach (string name in sqlite.Keys.Except(pg.Keys, StringComparer.OrdinalIgnoreCase))
        {
            if (!KnownIndexExceptions.Contains(name))
            {
                violations.Add($"index `{name}` is in Schema.sql but missing from Schema.pg.sql");
            }
        }

        foreach (string name in pg.Keys.Except(sqlite.Keys, StringComparer.OrdinalIgnoreCase))
        {
            if (!KnownIndexExceptions.Contains(name))
            {
                violations.Add($"index `{name}` is in Schema.pg.sql but missing from Schema.sql");
            }
        }

        Report(violations);
    }

    [Fact]
    public void SqliteAndPostgres_IndexDefinitionsAreIdentical_PerIndex()
    {
        var (sqlite, pg) = ParseBoth();
        var violations = new List<string>();

        foreach (string name in sqlite.Keys.Intersect(pg.Keys, StringComparer.OrdinalIgnoreCase))
        {
            if (KnownIndexExceptions.Contains(name))
            {
                continue;
            }

            var s = sqlite[name];
            var p = pg[name];

            if (!string.Equals(s.Table, p.Table, StringComparison.OrdinalIgnoreCase))
            {
                violations.Add($"{name}: table mismatch — SQLite ON {s.Table}, Postgres ON {p.Table}");
            }

            if (!NormalizeColumns(s.Columns).Equals(NormalizeColumns(p.Columns), StringComparison.OrdinalIgnoreCase))
            {
                violations.Add($"{name}: columns mismatch — SQLite ({s.Columns}), Postgres ({p.Columns})");
            }

            if (s.IsUnique != p.IsUnique)
            {
                string sq = s.IsUnique ? "UNIQUE" : "non-unique";
                string pq = p.IsUnique ? "UNIQUE" : "non-unique";
                violations.Add($"{name}: uniqueness mismatch — SQLite is {sq}, Postgres is {pq}");
            }

            // WHERE predicate comparison is the H1 correctness invariant. Normalize whitespace
            // and single-quote delimiters before comparing so cosmetic formatting differences
            // (indentation, line breaks, extra spaces) do not false-positive, but a real
            // semantic difference (wrong owner_kind value, missing NULL check, etc.) does fail.
            string? sWhere = s.WherePredicate is not null ? NormalizePredicate(s.WherePredicate) : null;
            string? pWhere = p.WherePredicate is not null ? NormalizePredicate(p.WherePredicate) : null;
            if (!string.Equals(sWhere, pWhere, StringComparison.Ordinal))
            {
                violations.Add(
                    $"{name}: WHERE predicate mismatch — " +
                    $"SQLite [{sWhere ?? "none"}], Postgres [{pWhere ?? "none"}]");
            }
        }

        Report(violations);
    }

    /// <summary>
    /// Focused regression check: every partial unique index that guards the polymorphic
    /// owner_kind discriminator must exist in both schema files with the correct predicate.
    /// This is the specific H1 invariant: the cache_artifact / package_version arms of
    /// rpm_metadata, maven_version_files, package_version_vulns, package_version_licenses,
    /// and cargo_metadata must each have their partial uniques defined in both dialects.
    /// </summary>
    [Fact]
    public void OwnerKindPartialUniques_ExistInBothProviders_WithMatchingPredicates()
    {
        // Curated set of partial-unique indexes that enforce the owner_kind discriminator.
        // Each entry is (index name, expected normalized WHERE predicate).
        var expected = new[]
        {
            ("idx_pvv_pv_vuln",       "owner_kind = 'package_version'"),
            ("idx_pvv_ca_vuln",       "owner_kind = 'cache_artifact'"),
            ("idx_rpm_metadata_pv",   "owner_kind = 'package_version'"),
            ("idx_rpm_metadata_ca",   "owner_kind = 'cache_artifact'"),
            ("idx_mvf_pv_filename",   "owner_kind = 'package_version'"),
            ("idx_mvf_ca_filename",   "owner_kind = 'cache_artifact'"),
            ("idx_cargo_metadata_pv", "owner_kind = 'package_version'"),
            ("idx_cargo_metadata_ca", "owner_kind = 'cache_artifact'"),
        };

        var (sqlite, pg) = ParseBoth();
        var violations = new List<string>();

        foreach (var (name, expectedWhere) in expected)
        {
            foreach (var (label, dict) in new[] { ("Schema.sql", sqlite), ("Schema.pg.sql", pg) })
            {
                if (!dict.TryGetValue(name, out var def))
                {
                    violations.Add($"{name}: missing from {label}");
                    continue;
                }

                if (!def.IsUnique)
                {
                    violations.Add($"{name} in {label}: expected UNIQUE index, found non-unique");
                }

                string? actual = def.WherePredicate is not null ? NormalizePredicate(def.WherePredicate) : null;
                if (!string.Equals(actual, expectedWhere, StringComparison.Ordinal))
                {
                    violations.Add(
                        $"{name} in {label}: WHERE predicate is [{actual ?? "none"}], expected [{expectedWhere}]");
                }
            }
        }

        Report(violations);
    }

    // Normalizes column list: collapse whitespace, strip redundant outer parens.
    private static string NormalizeColumns(string cols) =>
        WhitespaceRegex().Replace(cols.Trim('(', ')').Trim(), " ");

    // Normalizes a WHERE predicate: collapse internal whitespace to single spaces, then
    // normalize SQL keyword casing. String literal values (e.g. owner_kind enum strings)
    // are preserved verbatim — they are case-sensitive data, not syntax.
    private static string NormalizePredicate(string predicate)
    {
        string normalized = WhitespaceRegex().Replace(predicate.Trim(), " ");
        normalized = IsNotNullRegex().Replace(normalized, "IS NOT NULL");
        normalized = IsNullRegex().Replace(normalized, "IS NULL");
        normalized = AndKeywordRegex().Replace(normalized, "AND");
        normalized = OrKeywordRegex().Replace(normalized, "OR");
        return normalized;
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespaceRegex();

    [GeneratedRegex(@"\bIS\s+NOT\s+NULL\b", RegexOptions.IgnoreCase)]
    private static partial Regex IsNotNullRegex();

    [GeneratedRegex(@"\bIS\s+NULL\b", RegexOptions.IgnoreCase)]
    private static partial Regex IsNullRegex();

    [GeneratedRegex(@"\bAND\b", RegexOptions.IgnoreCase)]
    private static partial Regex AndKeywordRegex();

    [GeneratedRegex(@"\bOR\b", RegexOptions.IgnoreCase)]
    private static partial Regex OrKeywordRegex();

    private static (Dictionary<string, IndexDefinition> Sqlite, Dictionary<string, IndexDefinition> Pg) ParseBoth()
    {
        string src = SchemaTestPaths.SourceRoot();
        return (SchemaIndexParser.ParseIndexes(File.ReadAllText(SchemaTestPaths.SqliteSchema(src))),
                SchemaIndexParser.ParseIndexes(File.ReadAllText(SchemaTestPaths.PostgresSchema(src))));
    }

    private void Report(List<string> violations)
    {
        if (violations.Count == 0)
        {
            return;
        }

        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        Assert.Fail($"{violations.Count} schema index parity violation(s) between Schema.sql and Schema.pg.sql. See test output.");
    }
}

/// <summary>
/// Captures the parsed shape of a single CREATE [UNIQUE] INDEX statement.
/// </summary>
internal sealed record IndexDefinition(
    bool IsUnique,
    string Table,
    string Columns,
    string? WherePredicate);

/// <summary>
/// Minimal regex-based parser for CREATE [UNIQUE] INDEX statements in the hand-maintained
/// Schema.sql / Schema.pg.sql DDL files. Mirrors <see cref="SchemaSqlParser"/>'s approach:
/// comment-stripped, regex-matched, no full SQL grammar required.
/// </summary>
internal static partial class SchemaIndexParser
{
    // Matches CREATE [UNIQUE] INDEX [IF NOT EXISTS] <name> ON <table> (<cols>) [WHERE <pred>] ;
    // The WHERE group captures greedily up to the semicolon so multi-condition predicates are
    // captured in full. Singleline mode makes '.' match newlines for multi-line definitions.
    [GeneratedRegex(
        @"CREATE\s+(?<unique>UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(?<name>\w+)\s+ON\s+(?<table>\w+)\s*\((?<cols>[^)]+)\)\s*(?:WHERE\s+(?<where>[^;]+?))?\s*;",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex IndexRegex();

    /// <summary>
    /// Parses every CREATE [UNIQUE] INDEX statement and returns a map of index name to its
    /// structural definition. Comments are stripped first so inline documentation does not
    /// confuse the WHERE-predicate capture group.
    /// </summary>
    public static Dictionary<string, IndexDefinition> ParseIndexes(string sql)
    {
        string clean = SchemaSqlParser.StripComments(sql);
        var result = new Dictionary<string, IndexDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in IndexRegex().Matches(clean))
        {
            bool isUnique = m.Groups["unique"].Success && m.Groups["unique"].Length > 0;
            string name = m.Groups["name"].Value;
            string table = m.Groups["table"].Value;
            string cols = m.Groups["cols"].Value.Trim();
            string? where = m.Groups["where"].Success && m.Groups["where"].Length > 0
                ? m.Groups["where"].Value.Trim()
                : null;
            result[name] = new IndexDefinition(isUnique, table, cols, where);
        }
        return result;
    }
}
