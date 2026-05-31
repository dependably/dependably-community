using Xunit;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static guard that Schema.sql (SQLite) and Schema.pg.sql (Postgres) declare the same tables and,
/// per table, the same column NAMES. Type spellings legitimately differ between providers
/// (INTEGER↔BIGINT, TEXT↔TIMESTAMPTZ), so this compares names only — never types.
///
/// This catches the drift the runtime path masks: a column present in one provider's CREATE TABLE
/// but absent from the other is silently backfilled on the lagging provider by
/// RunAdditiveMigrationsAsync, so only a static comparison of the CREATE blocks surfaces it.
///
/// Genuinely intentional divergences (none today) go in <see cref="KnownColumnExceptions"/> with a
/// reason, so an allow-listed entry is a deliberate, reviewed decision rather than silent rot.
/// </summary>
[Trait("Category", "Schema")]
public sealed class SchemaParityComplianceTests
{
    private readonly ITestOutputHelper _output;
    public SchemaParityComplianceTests(ITestOutputHelper output) => _output = output;

    // table → columns allowed to exist in one provider's CREATE but not the other. Empty today.
    private static readonly Dictionary<string, HashSet<string>> KnownColumnExceptions =
        new(StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void SqliteAndPostgres_DeclareTheSameTables()
    {
        var (sqlite, pg) = ParseBoth();
        var violations = new List<string>();
        foreach (var t in sqlite.Keys.Except(pg.Keys, StringComparer.OrdinalIgnoreCase))
            violations.Add($"table `{t}` is in Schema.sql but missing from Schema.pg.sql");
        foreach (var t in pg.Keys.Except(sqlite.Keys, StringComparer.OrdinalIgnoreCase))
            violations.Add($"table `{t}` is in Schema.pg.sql but missing from Schema.sql");
        Report(violations);
    }

    [Fact]
    public void SqliteAndPostgres_DeclareTheSameColumns_PerTable()
    {
        var (sqlite, pg) = ParseBoth();
        var violations = new List<string>();
        foreach (var table in sqlite.Keys.Intersect(pg.Keys, StringComparer.OrdinalIgnoreCase))
        {
            var s = new HashSet<string>(sqlite[table], StringComparer.OrdinalIgnoreCase);
            var p = new HashSet<string>(pg[table], StringComparer.OrdinalIgnoreCase);
            foreach (var c in s.Except(p))
                if (!IsAllowed(table, c)) violations.Add($"{table}.{c}: declared in Schema.sql, missing from Schema.pg.sql");
            foreach (var c in p.Except(s))
                if (!IsAllowed(table, c)) violations.Add($"{table}.{c}: declared in Schema.pg.sql, missing from Schema.sql");
        }
        Report(violations);
    }

    private static bool IsAllowed(string table, string column) =>
        KnownColumnExceptions.TryGetValue(table, out var set) && set.Contains(column);

    private static (Dictionary<string, List<string>> Sqlite, Dictionary<string, List<string>> Pg) ParseBoth()
    {
        var src = SchemaTestPaths.SourceRoot();
        return (SchemaSqlParser.ParseTables(File.ReadAllText(SchemaTestPaths.SqliteSchema(src))),
                SchemaSqlParser.ParseTables(File.ReadAllText(SchemaTestPaths.PostgresSchema(src))));
    }

    private void Report(List<string> violations)
    {
        if (violations.Count == 0) return;
        foreach (var v in violations) _output.WriteLine(v);
        Assert.Fail($"{violations.Count} schema parity violation(s) between Schema.sql and Schema.pg.sql. See test output.");
    }
}
