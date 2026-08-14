using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// The upgrade-boot gate over the declarative schema files.
///
/// <para><c>SchemaInitializer.ApplySchemaAsync</c> executes the whole of <c>Schema.sql</c> /
/// <c>Schema.pg.sql</c> and only then runs <c>RunAdditiveMigrationsAsync</c>. On an existing
/// database every <c>CREATE TABLE IF NOT EXISTS</c> in that file is a no-op, so any other statement
/// in it resolves against the table shape the database already has — the shape that predates this
/// release's <c>ALTER TABLE … ADD COLUMN</c>. A <c>CREATE INDEX</c> naming a column that only
/// arrives in the additive pass therefore fails on every upgrade boot: Postgres raises
/// <c>42703 column … does not exist</c> and the app crash-loops, while SQLite is worse — the batch
/// is truncated at the failing statement and every table declared later in the file is silently
/// never created, with initialization still reporting success.</para>
///
/// <para>The safe condition is release-relative, not textual: a column an index names must already
/// have existed in the PREVIOUS release's <c>CREATE TABLE</c> block, because that is what every
/// live database booting this build was created or migrated to. A column introduced in this release
/// gets its index created next to its <c>ALTER</c> in <c>RunAdditiveMigrationsAsync</c> instead —
/// which also covers fresh installs, since that pass runs unconditionally. The declaration may move
/// into the schema files one release later.</para>
///
/// <para><c>CREATE TABLE</c> and <c>CREATE INDEX</c> are the only statement kinds these files
/// contain, and a no-op <c>CREATE TABLE</c> references nothing, so indexes are the whole exposure.
/// A repository with no release tag has no upgrade path and passes; a repository whose baseline
/// could not be read is a broken signal — set <c>SCHEMA_BACKCOMPAT_REQUIRE_BASELINE=true</c> (as the
/// CI schema job does) to fail on it rather than let the gate quietly stop checking.</para>
/// </summary>
[Trait("Category", "Schema")]
public sealed partial class SchemaUpgradeOrderComplianceTests
{
    private const string RequireBaselineVariable = "SCHEMA_BACKCOMPAT_REQUIRE_BASELINE";

    private readonly ITestOutputHelper _output;
    public SchemaUpgradeOrderComplianceTests(ITestOutputHelper output) => _output = output;

    [GeneratedRegex(@"[A-Za-z_][A-Za-z0-9_]*")]
    private static partial Regex IdentifierRegex();

    [Fact]
    public void NoSchemaFileIndex_NamesAColumnThatOnlyArrivesInTheAdditivePass()
    {
        var resolution = SchemaBaselineResolver.Resolve();
        _output.WriteLine(resolution.Log);

        if (resolution.Baseline is null)
        {
            Assert.True(
                SchemaBaselineResolver.IsTolerable(
                    resolution,
                    string.Equals(
                        Environment.GetEnvironmentVariable(RequireBaselineVariable),
                        "true",
                        StringComparison.OrdinalIgnoreCase)),
                $"{RequireBaselineVariable} is set, but the previous release's schema could not be "
                + $"resolved ({resolution.Absence}) — the upgrade-boot gate compared nothing. See "
                + "test output for the resolution log.");
            return;
        }

        string src = SchemaTestPaths.SourceRoot();
        var violations = new List<string>();
        Analyze(
            violations, "Schema.sql",
            File.ReadAllText(SchemaTestPaths.SqliteSchema(src)), resolution.Baseline.SqliteSql);
        Analyze(
            violations, "Schema.pg.sql",
            File.ReadAllText(SchemaTestPaths.PostgresSchema(src)), resolution.Baseline.PostgresSql);

        if (violations.Count == 0)
        {
            return;
        }

        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        Assert.Fail(
            $"{violations.Count} index declaration(s) in the schema files name a column that release "
            + $"{resolution.Baseline.Tag} did not have, so they resolve against the pre-ALTER table "
            + "shape on every upgrade boot. Declare the index in "
            + "SchemaInitializer.RunAdditiveMigrationsAsync next to the ALTER that adds the column "
            + "instead; move it into the schema files a release later. See test output.");
    }

    private static void Analyze(List<string> violations, string file, string currentSql, string baselineSql)
    {
        var currentTables = SchemaSqlParser.ParseTables(currentSql);
        var baselineTables = SchemaSqlParser.ParseTables(baselineSql);
        var indexes = SchemaIndexParser.ParseIndexes(currentSql);

        foreach ((string name, var index) in indexes)
        {
            if (!baselineTables.TryGetValue(index.Table, out var baselineColumns))
            {
                // The table itself is new in this release, so this file's own CREATE TABLE — which
                // precedes the index in the same batch — is what the index resolves against.
                continue;
            }

            if (!currentTables.TryGetValue(index.Table, out var currentColumns))
            {
                continue;
            }

            var baseline = new HashSet<string>(baselineColumns, StringComparer.OrdinalIgnoreCase);
            var current = new HashSet<string>(currentColumns, StringComparer.OrdinalIgnoreCase);

            string referenced = index.Columns + " " + (index.WherePredicate ?? string.Empty);
            foreach (string token in IdentifierRegex().Matches(referenced).Select(m => m.Value).Distinct(
                         StringComparer.OrdinalIgnoreCase))
            {
                // Only identifiers that are genuinely columns of this table are checked; SQL
                // keywords, function names and literal values in a partial-index predicate are not.
                if (current.Contains(token) && !baseline.Contains(token))
                {
                    violations.Add(
                        $"{file}: index `{name}` ON {index.Table} names column `{token}`, which the "
                        + "previous release's CREATE TABLE block does not declare");
                }
            }
        }
    }
}
