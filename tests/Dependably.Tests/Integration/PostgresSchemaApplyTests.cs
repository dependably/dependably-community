using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

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
        long ledger = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM _applied_migrations");
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
        foreach (string? t in pgShape.Keys.Except(sqliteShape.Keys, StringComparer.OrdinalIgnoreCase))
        {
            violations.Add($"table `{t}` exists in live Postgres but not in SQLite");
        }

        foreach (string? t in sqliteShape.Keys.Except(pgShape.Keys, StringComparer.OrdinalIgnoreCase))
        {
            violations.Add($"table `{t}` exists in SQLite but not in live Postgres");
        }

        foreach (string? table in pgShape.Keys.Intersect(sqliteShape.Keys, StringComparer.OrdinalIgnoreCase))
        {
            foreach (string? c in pgShape[table].Except(sqliteShape[table], StringComparer.OrdinalIgnoreCase))
            {
                violations.Add($"{table}.{c}: in live Postgres, missing from SQLite");
            }

            foreach (string? c in sqliteShape[table].Except(pgShape[table], StringComparer.OrdinalIgnoreCase))
            {
                violations.Add($"{table}.{c}: in SQLite, missing from live Postgres");
            }
        }

        Assert.True(violations.Count == 0,
            "Live Postgres / SQLite schema shape mismatch:\n" + string.Join("\n", violations));
    }

    // ── SAML replay-guard semantics on live Postgres ─────────────────────────
    // SamlReplayGuardTests proves the one-shot/replay/tenant-isolation semantics on SQLite; these
    // re-run the security-critical paths through the production NpgsqlMetadataStore so the
    // INSERT ... ON CONFLICT DO NOTHING (rows==1-only-on-insert) and the atomic
    // UPDATE ... WHERE consumed_at IS NULL one-shot are proven on the engine enterprise deploys on,
    // not just SQLite. Kept in this class so they share the serialized live-Postgres lifecycle.

    private static async Task<NpgsqlMetadataStore> InitializedPostgresAsync()
    {
        var store = await FreshPostgresAsync();
        await new SchemaInitializer(store).InitializeAsync();
        return store;
    }

    private static async Task<string> SeedOrgAsync(NpgsqlMetadataStore store)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id, slug = "pg-replay-" + id[..8] });
        return id;
    }

    [Fact]
    public async Task AssertionReplayGuard_OnLivePostgres_FirstAccepts_ReplayRejected()
    {
        // Frozen clock + fixed expiry: the repository prunes/compares expiry against its
        // injected TimeProvider, so KnownNow-relative instants stay on the right side of
        // the window regardless of when the CI job runs.
        var store = await InitializedPostgresAsync();
        var repo = new SamlConfigRepository(store, TestTime.Frozen());
        string org = await SeedOrgAsync(store);
        string assertionId = "_" + Guid.NewGuid().ToString("N");
        var expiry = TestTime.KnownNow.AddMinutes(5);

        // ON CONFLICT DO NOTHING must report rows==1 on first insert, rows==0 on the replay.
        Assert.True(await repo.TryConsumeAssertionAsync(org, "https://idp/x", assertionId, expiry));
        Assert.False(await repo.TryConsumeAssertionAsync(org, "https://idp/x", assertionId, expiry));
    }

    [Fact]
    public async Task AssertionReplayGuard_OnLivePostgres_SameIdDistinctTenants_Independent()
    {
        var store = await InitializedPostgresAsync();
        // Frozen clock + fixed expiry — same determinism rationale as the replay test above.
        var repo = new SamlConfigRepository(store, TestTime.Frozen());
        string orgA = await SeedOrgAsync(store);
        string orgB = await SeedOrgAsync(store);
        string assertionId = "_" + Guid.NewGuid().ToString("N");
        var expiry = TestTime.KnownNow.AddMinutes(5);

        Assert.True(await repo.TryConsumeAssertionAsync(orgA, "idp", assertionId, expiry));
        Assert.True(await repo.TryConsumeAssertionAsync(orgB, "idp", assertionId, expiry)); // different PK
        Assert.False(await repo.TryConsumeAssertionAsync(orgA, "idp", assertionId, expiry)); // still one-shot
    }

    [Fact]
    public async Task PendingRequest_OnLivePostgres_ConsumedExactlyOnce()
    {
        var store = await InitializedPostgresAsync();
        // Frozen clock + fixed expiry — same determinism rationale as the replay test above.
        var repo = new SamlConfigRepository(store, TestTime.Frozen());
        string org = await SeedOrgAsync(store);
        string reqId = "_" + Guid.NewGuid().ToString("N");
        await repo.IssuePendingRequestAsync(reqId, org, TestTime.KnownNow.AddMinutes(10));

        // Atomic UPDATE...WHERE consumed_at IS NULL must return rows==1 once, then rows==0.
        Assert.True(await repo.TryConsumePendingRequestAsync(reqId, org));
        Assert.False(await repo.TryConsumePendingRequestAsync(reqId, org));
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
        foreach (string? table in tables)
        {
            foreach (string col in await conn.QueryAsync<string>("SELECT name FROM pragma_table_info(@table)", new { table }))
            {
                rows.Add((table, col));
            }
        }

        return Group(rows);
    }

    private static Dictionary<string, HashSet<string>> Group(IEnumerable<(string Table, string Column)> rows)
    {
        var shape = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (table, column) in rows)
        {
            if (!shape.TryGetValue(table, out var cols))
            {
                shape[table] = cols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            cols.Add(column);
        }
        return shape;
    }
}
