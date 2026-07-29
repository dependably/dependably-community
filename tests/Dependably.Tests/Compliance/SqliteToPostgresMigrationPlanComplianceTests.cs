using System.Text.RegularExpressions;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Migration;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Anti-rot gate for the SQLite → Postgres migration plan. The migrator derives its table list from
/// the live source catalogue rather than from a literal list, and this proves the derivation
/// actually covers the schema: every <c>CREATE TABLE</c> in <c>Schema.sql</c> must appear in the
/// plan, in an order that puts parents before children.
///
/// <para>Without this, the exclusion sets are the rot surface — a table added to
/// <see cref="MigrationTablePlan.ExcludedTables"/> or a narrowed discovery query would silently drop
/// a table's worth of data from every migration and still pass every other gate.</para>
///
/// <para>Tagged <c>Category=Schema</c> alongside the rest of the schema-integrity suite: it applies
/// the real embedded schema to a fresh in-memory SQLite database and needs no external service.</para>
/// </summary>
[Trait("Category", "Schema")]
public sealed partial class SqliteToPostgresMigrationPlanComplianceTests
{
    [GeneratedRegex(@"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)",
        RegexOptions.IgnoreCase)]
    private static partial Regex CreateTableRegex();

    private static IReadOnlyList<string> SchemaTableNames()
    {
        // Resolved by discovery (the root that owns Infrastructure/schema/) rather than by a
        // hard-coded project directory, so moving the schema between source roots cannot leave
        // this gate reading a stale path.
        string path = SchemaTestPaths.SqliteSchema(SchemaTestPaths.SourceRoot());
        // Strip `--` comments first: the schema's own prose talks about "the CREATE TABLE blocks",
        // which a naive scan would read as a table named `blocks`.
        string sql = string.Join(
            '\n',
            File.ReadAllLines(path).Select(line =>
            {
                int comment = line.IndexOf("--", StringComparison.Ordinal);
                return comment >= 0 ? line[..comment] : line;
            }));
        var names = CreateTableRegex().Matches(sql).Select(m => m.Groups[1].Value).ToList();
        Assert.NotEmpty(names);
        return names;
    }

    private static async Task<TestMetadataStore> FreshDatabaseAsync()
    {
        var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();
        return db;
    }

    [Fact]
    public async Task EverySchemaTable_IsCoveredByTheMigrationPlan()
    {
        await using var db = await FreshDatabaseAsync();
        await using var conn = await db.OpenAsync();
        var plan = await MigrationTablePlan.DiscoverAsync(conn);
        var planned = new HashSet<string>(plan.Tables, StringComparer.OrdinalIgnoreCase);

        var missing = SchemaTableNames().Where(t => !planned.Contains(t)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        Assert.True(missing.Count == 0,
            $"{missing.Count} table(s) declared in Schema.sql are absent from the SQLite → Postgres " +
            $"migration plan, so their rows would be silently dropped by a migration: " +
            $"{string.Join(", ", missing)}. Fix the discovery in MigrationTablePlan (or, if the omission " +
            $"is deliberate, state why in MigrationTablePlan.ExcludedTables).");
    }

    [Fact]
    public async Task MigrationPlan_ContainsNoTableThatIsNotInTheDatabase()
    {
        await using var db = await FreshDatabaseAsync();
        await using var conn = await db.OpenAsync();
        var plan = await MigrationTablePlan.DiscoverAsync(conn);

        var live = new HashSet<string>(
            await conn.QueryAsync<string>(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"),
            StringComparer.OrdinalIgnoreCase);

        var phantom = plan.Tables.Where(t => !live.Contains(t)).ToList();
        Assert.True(phantom.Count == 0, "Plan names tables that do not exist: " + string.Join(", ", phantom));
        Assert.Equal(plan.Tables.Count, plan.Tables.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public async Task MigrationPlan_OrdersEveryParentBeforeItsChildren()
    {
        await using var db = await FreshDatabaseAsync();
        await using var conn = await db.OpenAsync();
        var plan = await MigrationTablePlan.DiscoverAsync(conn);

        Assert.False(plan.HasCycle, "The schema's foreign-key graph could not be topologically ordered.");

        var position = plan.Tables
            .Select((t, i) => (Table: t, Index: i))
            .ToDictionary(x => x.Table, x => x.Index, StringComparer.OrdinalIgnoreCase);

        var violations = new List<string>();
        foreach (string table in plan.Tables)
        {
            var parents = await conn.QueryAsync<string>(
                "SELECT CAST(\"table\" AS TEXT) FROM pragma_foreign_key_list(@table)", new { table });
            foreach (string parent in parents.Where(p => p is not null && position.ContainsKey(p)))
            {
                if (!string.Equals(parent, table, StringComparison.OrdinalIgnoreCase)
                    && position[parent] > position[table])
                {
                    violations.Add($"{table} (index {position[table]}) is copied before its parent {parent} " +
                                   $"(index {position[parent]})");
                }
            }
        }

        Assert.True(violations.Count == 0,
            "Migration order would violate foreign keys:\n" + string.Join("\n", violations));
    }

    /// <summary>
    /// The pre-flight "is this target already in use?" refusal ignores the tables the schema apply
    /// populates by itself. That exemption is only sound while it names exactly those tables, so
    /// this pins it: a freshly initialised database must have rows in the declared seed tables and
    /// nowhere else. A new seeder writing somewhere new fails here rather than quietly turning the
    /// refusal into a no-op for that table.
    /// </summary>
    [Fact]
    public async Task SeedPopulatedTables_ExactlyMatchesAFreshlyInitialisedDatabase()
    {
        await using var db = await FreshDatabaseAsync();
        await using var conn = await db.OpenAsync();
        var plan = await MigrationTablePlan.DiscoverAsync(conn);

        var populated = new List<string>();
        foreach (string table in plan.Tables)
        {
            // rawsql: the table name comes from the live SQLite catalogue via MigrationTablePlan.
            long rows = await conn.ExecuteScalarAsync<long>(
                $"SELECT COUNT(*) FROM {MigrationColumnPlanner.Quote(table)}");
            if (rows > 0)
            {
                populated.Add(table);
            }
        }

        Assert.Equal(
            MigrationTablePlan.SeedPopulatedTables.OrderBy(t => t, StringComparer.Ordinal),
            populated.OrderBy(t => t, StringComparer.Ordinal));
    }
}
