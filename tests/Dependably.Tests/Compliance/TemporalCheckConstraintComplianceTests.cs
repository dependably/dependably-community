using Dependably.Infrastructure;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static guard over the canonical-timestamp CHECK constraint. Every TEXT column whose name
/// matches the temporal naming convention (<see cref="SchemaInitializer.IsTemporalColumnName"/> —
/// <c>*_at</c> / <c>*_since</c>, plus the small set of established non-suffixed exceptions) must
/// carry the exact <see cref="TemporalCheckPredicate"/> text in its <c>CREATE TABLE</c> declaration,
/// in BOTH <c>Schema.sql</c> and <c>Schema.pg.sql</c> — this is what fresh installs on both
/// providers get the constraint from. Neither provider retrofits it onto an existing database
/// this release (see <c>SchemaInitializer.TemporalColumnNaming.cs</c> for the sequencing).
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

    // Column type is the first whitespace-delimited token after the name in the raw declaration
    // text (SchemaColumn.Declaration starts with "<name> <type> ..."). All temporal columns in
    // this schema are TEXT; this guard just keeps the derivation honest if that ever changes.
    private static bool IsTextColumn(string declaration)
    {
        string[] parts = declaration.TrimStart().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && string.Equals(parts[1], "TEXT", StringComparison.OrdinalIgnoreCase);
    }
}
