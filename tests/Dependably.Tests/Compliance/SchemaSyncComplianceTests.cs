using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static guard over the schema source files. Enforces the migration convention documented in
/// <c>src/Dependably/Infrastructure/schema/schema-migrations.md</c>:
///
///   1. Every additive <c>ALTER TABLE x ADD COLUMN y</c> in
///      <c>SchemaInitializer.RunAdditiveMigrationsAsync</c> must ALSO be declared in the
///      <c>CREATE TABLE</c> block of BOTH Schema.sql and Schema.pg.sql — so fresh installs get the
///      column from CREATE (not only from the upgrade-path ALTER) and the two providers stay in step.
///   2. No additive <c>ADD COLUMN</c> may be <c>NOT NULL</c> without a <c>DEFAULT</c> — that fails on
///      any table that already holds rows. (This is the check the retired scripts/schema-lint.sh
///      claimed to perform; it now lives here.)
///   3. No <c>CREATE TABLE</c> / <c>CREATE INDEX</c> object name is declared twice within a file.
///
/// Mirrors the static-scan style of <see cref="OrgIdFilteringComplianceTests"/>: read source, regex,
/// collect violations, fail with the full list.
/// </summary>
[Trait("Category", "Schema")]
public sealed partial class SchemaSyncComplianceTests
{
    private readonly ITestOutputHelper _output;
    public SchemaSyncComplianceTests(ITestOutputHelper output) => _output = output;

    // Matches the one-line additive statements in the RunAdditiveMigrationsAsync array. The rest of
    // the column definition runs to the closing quote of the C# string literal ([^"]*), which is
    // enough to inspect NOT NULL / DEFAULT. DROP COLUMN and RENAME statements are not matched.
    [GeneratedRegex(@"ALTER\s+TABLE\s+(?<table>\w+)\s+ADD\s+COLUMN\s+(?<col>\w+)(?<rest>[^""]*)", RegexOptions.IgnoreCase)]
    private static partial Regex AddColumnRegex();

    [GeneratedRegex(@"\bNOT\s+NULL\b", RegexOptions.IgnoreCase)]
    private static partial Regex NotNullRegex();

    [GeneratedRegex(@"\bDEFAULT\b", RegexOptions.IgnoreCase)]
    private static partial Regex DefaultRegex();

    private sealed record AddColumn(string Table, string Column, string Rest);

    [Fact]
    public void EveryAdditiveColumn_IsDeclaredInBothCreateTableBlocks()
    {
        var src = SchemaTestPaths.SourceRoot();
        var adds = ParseAdditiveColumns(src);
        Assert.NotEmpty(adds); // guard: the regex + path must actually find the migration array

        var sqlite = SchemaSqlParser.ParseTables(File.ReadAllText(SchemaTestPaths.SqliteSchema(src)));
        var pg = SchemaSqlParser.ParseTables(File.ReadAllText(SchemaTestPaths.PostgresSchema(src)));

        var violations = new List<string>();
        foreach (var add in adds)
        {
            CheckPresence(violations, "Schema.sql", sqlite, add);
            CheckPresence(violations, "Schema.pg.sql", pg, add);
        }
        Report(violations, "additive column(s) missing from a CREATE TABLE block");
    }

    [Fact]
    public void NoAdditiveColumn_IsNotNullWithoutDefault()
    {
        var violations = new List<string>();
        foreach (var add in ParseAdditiveColumns(SchemaTestPaths.SourceRoot()))
        {
            bool notNull = NotNullRegex().IsMatch(add.Rest);
            bool hasDefault = DefaultRegex().IsMatch(add.Rest);
            if (notNull && !hasDefault)
                violations.Add($"{add.Table}.{add.Column}: NOT NULL ADD COLUMN without DEFAULT — fails on a populated table");
        }
        Report(violations, "NOT NULL additive column(s) without DEFAULT");
    }

    [Theory]
    [InlineData("Schema.sql")]
    [InlineData("Schema.pg.sql")]
    public void NoDuplicateObjectNames_WithinSchemaFile(string file)
    {
        var src = SchemaTestPaths.SourceRoot();
        var sql = File.ReadAllText(Path.Combine(src, "Infrastructure", "schema", file));
        var violations = new List<string>();
        AppendDuplicates(violations, file, "TABLE", SchemaSqlParser.CreatedTableNames(sql));
        AppendDuplicates(violations, file, "INDEX", SchemaSqlParser.CreatedIndexNames(sql));
        Report(violations, $"duplicate object declaration(s) in {file}");
    }

    private static List<AddColumn> ParseAdditiveColumns(string src)
    {
        var initializer = File.ReadAllText(SchemaTestPaths.SchemaInitializer(src));
        return AddColumnRegex().Matches(initializer)
            .Select(m => new AddColumn(m.Groups["table"].Value, m.Groups["col"].Value, m.Groups["rest"].Value))
            .ToList();
    }

    private static void CheckPresence(List<string> violations, string file,
        Dictionary<string, List<string>> schema, AddColumn add)
    {
        if (!schema.TryGetValue(add.Table, out var cols)
            || !cols.Contains(add.Column, StringComparer.OrdinalIgnoreCase))
            violations.Add($"{file}: `{add.Column}` (added via ALTER TABLE {add.Table}) is not declared in its CREATE TABLE block");
    }

    private static void AppendDuplicates(List<string> violations, string file, string kind, List<string> names)
    {
        foreach (var g in names.GroupBy(n => n, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
            violations.Add($"{file}: {kind} `{g.Key}` declared {g.Count()} times");
    }

    private void Report(List<string> violations, string what)
    {
        if (violations.Count == 0) return;
        foreach (var v in violations) _output.WriteLine(v);
        Assert.Fail($"{violations.Count} {what}. See test output for the full list.");
    }
}
