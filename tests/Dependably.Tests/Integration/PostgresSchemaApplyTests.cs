using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Npgsql;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// Applies the real Postgres schema (Schema.pg.sql + every additive ALTER + the one-time migrations)
/// against a LIVE Postgres server through the production <see cref="NpgsqlMetadataStore"/>, proving
/// the Postgres path actually boots, is idempotent, and lands the same logical shape as the SQLite
/// path. The static SchemaParityComplianceTests compares the source files; this proves the server
/// accepts the DDL — the runtime complement no static check can give.
///
/// Tagged <c>Category=SchemaPostgres</c> (distinct from the no-dependency <c>Category=Schema</c>
/// suite) so it runs only in the dedicated <c>schema-integrity</c> CI job, which attaches a postgres
/// service and sets <c>TEST_POSTGRES_CONNECTION</c>. Ordinary offline runs don't select this
/// category, so the suite stays green without Postgres; running it without a connection fails loudly
/// with a clear message rather than skipping silently.
///
/// The target database is treated as disposable: each test resets the <c>public</c> schema so runs
/// are deterministic and order-independent. Point <c>TEST_POSTGRES_CONNECTION</c> only at a
/// throwaway database (the CI service container, or a local docker postgres).
/// </summary>
[Trait("Category", "SchemaPostgres")]
public sealed class PostgresSchemaApplyTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private static async Task<NpgsqlMetadataStore> FreshPostgresAsync()
    {
        var store = new NpgsqlMetadataStore(ConnectionString);
        await using var conn = await store.OpenAsync();
        // Pristine slate: drop everything from a prior run so the apply starts from zero.
        await conn.ExecuteAsync("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
        return store;
    }

    [Fact]
    public async Task Schema_AppliesAgainstLivePostgres_AndIsIdempotent()
    {
        var store = await FreshPostgresAsync();
        var initializer = new SchemaInitializer(store);

        // First apply must succeed (this is the path that aborted on a fresh PG before the
        // EnsureMigrationsTableAsync strftime fix), and a second apply must be a clean no-op.
        await initializer.InitializeAsync();
        var ex = await Record.ExceptionAsync(() => initializer.InitializeAsync());
        Assert.Null(ex);

        await using var conn = await store.OpenAsync();
        var ledger = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM _applied_migrations");
        Assert.True(ledger > 0, "one-time migrations did not record themselves in _applied_migrations");
    }

    [Fact]
    public async Task LivePostgresShape_MatchesFreshSqlite()
    {
        var pgStore = await FreshPostgresAsync();
        await new SchemaInitializer(pgStore).InitializeAsync();

        await using var sqliteStore = new TestMetadataStore();
        await new SchemaInitializer(sqliteStore).InitializeAsync();

        var pgShape = await PostgresShapeAsync(pgStore);
        var sqliteShape = await SqliteShapeAsync(sqliteStore);

        var violations = new List<string>();
        foreach (var t in pgShape.Keys.Except(sqliteShape.Keys, StringComparer.OrdinalIgnoreCase))
            violations.Add($"table `{t}` exists in live Postgres but not in SQLite");
        foreach (var t in sqliteShape.Keys.Except(pgShape.Keys, StringComparer.OrdinalIgnoreCase))
            violations.Add($"table `{t}` exists in SQLite but not in live Postgres");
        foreach (var table in pgShape.Keys.Intersect(sqliteShape.Keys, StringComparer.OrdinalIgnoreCase))
        {
            foreach (var c in pgShape[table].Except(sqliteShape[table], StringComparer.OrdinalIgnoreCase))
                violations.Add($"{table}.{c}: in live Postgres, missing from SQLite");
            foreach (var c in sqliteShape[table].Except(pgShape[table], StringComparer.OrdinalIgnoreCase))
                violations.Add($"{table}.{c}: in SQLite, missing from live Postgres");
        }

        Assert.True(violations.Count == 0,
            "Live Postgres / SQLite schema shape mismatch:\n" + string.Join("\n", violations));
    }

    private static async Task<Dictionary<string, HashSet<string>>> PostgresShapeAsync(NpgsqlMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        var rows = await conn.QueryAsync<(string Table, string Column)>(
            """
            SELECT table_name AS Table, column_name AS Column
            FROM information_schema.columns
            WHERE table_schema = 'public'
            """);
        return Group(rows);
    }

    private static async Task<Dictionary<string, HashSet<string>>> SqliteShapeAsync(TestMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        var tables = (await conn.QueryAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")).ToList();
        var rows = new List<(string Table, string Column)>();
        foreach (var table in tables)
            foreach (var col in await conn.QueryAsync<string>("SELECT name FROM pragma_table_info(@table)", new { table }))
                rows.Add((table, col));
        return Group(rows);
    }

    private static Dictionary<string, HashSet<string>> Group(IEnumerable<(string Table, string Column)> rows)
    {
        var shape = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (table, column) in rows)
        {
            if (!shape.TryGetValue(table, out var cols))
                shape[table] = cols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            cols.Add(column);
        }
        return shape;
    }
}
