using Dependably.Infrastructure;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static guard over the canonical-timestamp CHECK constraint. Every TEXT column whose name
/// matches the temporal naming convention (<see cref="SchemaInitializer.IsTemporalColumnName"/> —
/// <c>*_at</c> / <c>*_since</c>, plus the small set of established non-suffixed exceptions) must
/// carry the exact <see cref="TemporalCheckPredicate"/> text in its <c>CREATE TABLE</c> declaration,
/// in BOTH <c>Schema.sql</c> and <c>Schema.pg.sql</c> — this is what fresh installs on both
/// providers get the constraint from, and (on Postgres) what
/// <c>SchemaInitializer.TemporalCheckRetrofit.cs</c> parses to decide which columns to retrofit
/// onto an existing database. Existing SQLite databases are never retrofitted — see
/// <c>SchemaInitializer.TemporalColumnNaming.cs</c>.
///
/// The column list is derived structurally from each schema file via
/// <see cref="SchemaSqlParser.ParseTableDefinitions"/> and the shared naming-convention test, not
/// hand-maintained — mirroring <see cref="OrgIdFilteringComplianceTests"/>'s derivation of its own
/// table set from <c>Schema.sql</c>.
/// </summary>
[Trait("Category", "Schema")]
public sealed class TemporalCheckConstraintComplianceTests
{
    private readonly ITestOutputHelper _output;
    public TemporalCheckConstraintComplianceTests(ITestOutputHelper output) => _output = output;

    [Theory]
    [InlineData("Schema.sql")]
    [InlineData("Schema.pg.sql")]
    public void EveryTemporalTextColumn_CarriesTheCanonicalCheck(string fileName)
    {
        string src = SchemaTestPaths.SourceRoot();
        string path = fileName == "Schema.sql" ? SchemaTestPaths.SqliteSchema(src) : SchemaTestPaths.PostgresSchema(src);
        string sql = File.ReadAllText(path);
        var tables = SchemaSqlParser.ParseTableDefinitions(sql);

        bool isSqlite = fileName == "Schema.sql";
        var violations = new List<string>();
        int temporalColumnCount = 0;

        foreach (var (table, def) in tables)
        {
            foreach (var column in def.Columns)
            {
                if (!SchemaInitializer.IsTemporalColumnName(column.Name))
                {
                    continue;
                }

                // Only a TEXT column is in scope — a non-TEXT column happening to match the
                // naming convention (none exist today, but the check stays honest) is not this
                // constraint's business.
                if (!IsTextColumn(column.Declaration))
                {
                    continue;
                }

                temporalColumnCount++;
                string expected = isSqlite
                    ? TemporalCheckPredicate.ForSqlite(column.Name)
                    : TemporalCheckPredicate.ForPostgres(column.Name);

                if (!column.Declaration.Contains(expected, StringComparison.Ordinal))
                {
                    violations.Add($"{fileName}: {table}.{column.Name} is missing the canonical " +
                                    $"temporal CHECK — expected to find: {expected}");
                }
            }
        }

        // Guard: the derivation itself must actually find columns, or a broken parser/regex would
        // report a vacuous pass.
        Assert.True(temporalColumnCount > 100,
            $"expected well over 100 structurally-derived temporal columns in {fileName}, found {temporalColumnCount} " +
            "— the naming-convention derivation may be broken");

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} temporal column(s) in {fileName} missing the canonical CHECK. See test output.");
        }
    }

    /// <summary>
    /// The Postgres retrofit's column set (<see cref="SchemaInitializer.DeclaredTemporalCheckColumns"/>,
    /// which looks for the CHECK literal) and this gate's column set (which looks for the naming
    /// convention) are two independent derivations from the same file. They must agree exactly.
    /// A column in only the naming set means the schema is missing a CHECK the gate above already
    /// reports; a column in only the retrofit set would mean the retrofit constrains something the
    /// fresh install does not — the more dangerous direction, and the one nothing else catches.
    /// </summary>
    [Fact]
    public void RetrofitColumnSet_MatchesTheSchemaDeclaredTemporalColumns()
    {
        string sql = File.ReadAllText(SchemaTestPaths.PostgresSchema(SchemaTestPaths.SourceRoot()));

        var byNamingConvention = SchemaSqlParser.ParseTableDefinitions(sql)
            .SelectMany(t => t.Value.Columns.Select(c => (Table: t.Key, Column: c)))
            .Where(x => SchemaInitializer.IsTemporalColumnName(x.Column.Name) && IsTextColumn(x.Column.Declaration))
            .Select(x => $"{x.Table}.{x.Column.Name}")
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToList();

        var byCheckLiteral = SchemaInitializer.DeclaredTemporalCheckColumns(sql)
            .Select(c => $"{c.Table}.{c.Column}")
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToList();

        _output.WriteLine($"{byCheckLiteral.Count} temporal columns derived from Schema.pg.sql");
        Assert.Equal(byNamingConvention, byCheckLiteral);
        Assert.True(byCheckLiteral.Count > 100,
            $"expected well over 100 derived temporal columns, found {byCheckLiteral.Count}");

        // _applied_migrations is created by EnsureMigrationsTableAsync, not by Schema.pg.sql, and
        // carries no CHECK on a fresh install. It is the concrete reason the retrofit derives its
        // set from the schema text rather than scanning information_schema for *_at TEXT columns:
        // that scan would sweep this in and constrain a column no fresh install constrains.
        Assert.DoesNotContain("_applied_migrations.applied_at", byCheckLiteral);
    }

    // Column type is the first whitespace-delimited token after the name in the raw declaration
    // text (SchemaColumn.Declaration starts with "<name> <type> ..."). All temporal columns in
    // this schema are TEXT; this guard just keeps the derivation honest if that ever changes.
    private static bool IsTextColumn(string declaration)
    {
        string[] parts = declaration.TrimStart().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && string.Equals(parts[1], "TEXT", StringComparison.OrdinalIgnoreCase);
    }
}
