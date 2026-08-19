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
[Collection("LivePostgres")]
public sealed class PostgresSchemaApplyTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task Schema_AppliesAgainstLivePostgres_AndIsIdempotent()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
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
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var pgStore = pg.Store;
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

    private static async Task<LivePostgresHandle> InitializedPostgresAsync()
    {
        var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        return pg;
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
        await using var pg = await InitializedPostgresAsync();
        var store = pg.Store;
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
        await using var pg = await InitializedPostgresAsync();
        var store = pg.Store;
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
        await using var pg = await InitializedPostgresAsync();
        var store = pg.Store;
        // Frozen clock + fixed expiry — same determinism rationale as the replay test above.
        var repo = new SamlConfigRepository(store, TestTime.Frozen());
        string org = await SeedOrgAsync(store);
        string reqId = "_" + Guid.NewGuid().ToString("N");
        await repo.IssuePendingRequestAsync(reqId, org, TestTime.KnownNow.AddMinutes(10));

        // Atomic UPDATE...WHERE consumed_at IS NULL must return rows==1 once, then rows==0.
        Assert.True(await repo.TryConsumePendingRequestAsync(reqId, org));
        Assert.False(await repo.TryConsumePendingRequestAsync(reqId, org));
    }

    // ── Reshape row-preservation on live Postgres ──────────────────────────────────────────
    // The Postgres branch of make_pvv_package_version_id_nullable uses in-place ALTER TABLE
    // statements (not a recreate-table). This test seeds rows including a dangling one
    // (inserted while FK enforcement is bypassed via session_replication_role), resets the
    // ledger, re-runs InitializeAsync, and confirms no row was lost. The in-place ALTER is
    // inherently row-preserving, but this catches future regressions where a DELETE or
    // TRUNCATE is accidentally introduced.
    // Unverified locally (requires TEST_POSTGRES_CONNECTION / CI postgres service).
    /// <summary>
    /// The per-org SMTP transport columns on <c>alert_settings</c> are dropped, and the drop
    /// repeats on every boot so a database an older slot re-populated converges back.
    ///
    /// <para>
    /// Worth proving on a live server rather than only on SQLite: the drop is provider-branched
    /// only through <c>ColumnExistsAsync</c> (information_schema on Postgres, pragma on SQLite), so
    /// the probe that decides whether each <c>DROP COLUMN</c> runs is a different query here, and a
    /// probe that silently answered "absent" would turn the whole pass into a no-op that no SQLite
    /// test could see. This also pins that the live delivery channel survives the drop.
    /// </para>
    /// </summary>
    [Fact]
    public async Task DropAlertSettingsRetiredSmtpColumns_OnLivePostgres_DropsThemAndRepeats()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await using var conn = await store.OpenAsync();

        string orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = "pg-smtp-drop-" + orgId[..8] });

        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, email_enabled, email_recipients, email_last_status, email_consecutive_failures)
            VALUES (@orgId, 1, 'ops@example.com', 'failed', 3)
            """, new { orgId });

        // A fresh install never had the columns, so assert that first — otherwise the re-drop below
        // could pass against a schema that simply never declared them.
        Assert.Equal(0, await RetiredColumnCountAsync(conn));

        // An older release's slot boots against this database and re-adds its own columns, exactly
        // as its additive-migration list does — including the CHECK-bearing one.
        await conn.ExecuteAsync(
            """
            ALTER TABLE alert_settings ADD COLUMN email_inherit_instance INTEGER NOT NULL DEFAULT 1;
            ALTER TABLE alert_settings ADD COLUMN email_smtp_host TEXT;
            ALTER TABLE alert_settings ADD COLUMN email_smtp_port INTEGER;
            ALTER TABLE alert_settings ADD COLUMN email_smtp_security TEXT
                CHECK (email_smtp_security IS NULL OR email_smtp_security IN ('starttls','ssl','none'));
            ALTER TABLE alert_settings ADD COLUMN email_smtp_username TEXT;
            ALTER TABLE alert_settings ADD COLUMN email_smtp_password TEXT;
            ALTER TABLE alert_settings ADD COLUMN email_smtp_from TEXT;
            """);
        await conn.ExecuteAsync(
            "UPDATE alert_settings SET email_smtp_host = 'own.example.com', "
            + "email_smtp_password = 'enc:v1:own-secret' WHERE org_id = @orgId", new { orgId });

        Assert.Equal(7, await RetiredColumnCountAsync(conn));

        // The current release boots again. No ledger rewind: the drop is deliberately not ledgered,
        // and that is exactly the property under test here.
        await new SchemaInitializer(store).InitializeAsync();

        Assert.Equal(0, await RetiredColumnCountAsync(conn));

        // The live delivery channel is untouched — dropping it would silently disable the tenant.
        var (enabled, recipients) = await conn.QuerySingleAsync<(bool Enabled, string Recipients)>(
            "SELECT email_enabled, email_recipients FROM alert_settings WHERE org_id = @orgId",
            new { orgId });
        Assert.True(enabled);
        Assert.Equal("ops@example.com", recipients);
    }

    private static async Task<int> RetiredColumnCountAsync(System.Data.Common.DbConnection conn) =>
        (await conn.QueryAsync<string>(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'alert_settings'
              AND column_name IN ('email_inherit_instance', 'email_smtp_host', 'email_smtp_port',
                                  'email_smtp_security', 'email_smtp_username', 'email_smtp_password',
                                  'email_smtp_from')
            """)).Count();

    [Fact]
    public async Task MakePvvPackageVersionIdNullable_OnLivePostgres_AllRowsSurviveReshape()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        var initializer = new SchemaInitializer(store);
        await initializer.InitializeAsync();

        await using var conn = await store.OpenAsync();

        // Seed org, package, and a real package_version to own the valid child row.
        string orgId = Guid.NewGuid().ToString("N");
        string pkgId = Guid.NewGuid().ToString("N");
        string pvId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = "pg-reshape-" + orgId[..8] });
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@pkgId, @orgId, 'npm', 'test', 'test', 0)",
            new { pkgId, orgId });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key) VALUES (@pvId, @pkgId, '1.0.0', 'pkg:npm/test@1.0.0', 'npm/r/test/1.0.0/test-1.0.0.tgz')",
            new { pvId, pkgId });

        // Seed a vulnerability so the FK on vuln_id can be satisfied.
        string vulnId = "GHSA-pg-reshape-test01";
        await conn.ExecuteAsync("""
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name)
            VALUES (@vulnId, @vulnId, 'npm', 'test')
            ON CONFLICT (id) DO NOTHING
            """, new { vulnId });

        // Insert via session_replication_role = replica to bypass FK enforcement,
        // so we can plant a dangling row (parent package_version_id does not exist).
        await conn.ExecuteAsync("SET session_replication_role = replica");
        await conn.ExecuteAsync("""
            INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind)
            VALUES (@id1, @pvId, @vulnId, 'package_version'),
                   (@id2, 'pv-DANGLING-PG-GONE', @vulnId, 'package_version')
            """,
            new
            {
                id1 = Guid.NewGuid().ToString("N"),
                pvId,
                id2 = Guid.NewGuid().ToString("N"),
                vulnId,
            });
        await conn.ExecuteAsync("SET session_replication_role = DEFAULT");

        long beforeCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns");
        Assert.Equal(2, beforeCount);

        // Reset the migration ledger entry so InitializeAsync re-runs the reshape.
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = 'make_pvv_package_version_id_nullable'");

        // Re-run: the Postgres branch uses in-place ALTER TABLE, which preserves all rows.
        await initializer.InitializeAsync();

        long afterCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns");
        Assert.Equal(beforeCount, afterCount);

        // The dangling row must still be present.
        long danglingCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns WHERE package_version_id = 'pv-DANGLING-PG-GONE'");
        Assert.Equal(1, danglingCount);
    }

    /// <summary>
    /// The read-model views are defined once and executed verbatim against both engines, so there is
    /// no SQLite/Postgres pair to drift — but there is still one body that has to compile and expose
    /// the same columns on each. That is what this asserts. It is the only gate on the views: the
    /// static schema-parity tests regex CREATE TABLE / CREATE INDEX and never see a CREATE VIEW.
    /// </summary>
    [Fact]
    [Trait("Category", "SchemaPostgres")]
    public async Task LivePostgresViews_HaveTheSameColumnsAsSqlite()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        await using var sqliteStore = new TestMetadataStore();
        await new SchemaInitializer(sqliteStore).InitializeAsync();

        var pgViews = await PostgresViewShapeAsync(pg.Store);
        var sqliteViews = await SqliteViewShapeAsync(sqliteStore);

        Assert.NotEmpty(pgViews);
        Assert.Equal(
            sqliteViews.Keys.OrderBy(k => k, StringComparer.Ordinal),
            pgViews.Keys.OrderBy(k => k, StringComparer.Ordinal));

        foreach (string view in pgViews.Keys)
        {
            Assert.Equal(
                sqliteViews[view].OrderBy(c => c, StringComparer.OrdinalIgnoreCase),
                pgViews[view].OrderBy(c => c, StringComparer.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// A replica boot must not remove an object a serving replica is querying. On Postgres that is
    /// <c>CREATE OR REPLACE VIEW</c>, which swaps the body in place and never leaves the name
    /// unresolvable — so a second apply changes nothing observable, and in particular the view's OID
    /// survives. A drop+create would mint a new OID; equality here is what proves the replace path
    /// (not the fallback) is the one a steady-state boot takes.
    /// </summary>
    [Fact]
    public async Task SecondApply_ReplacesViewsInPlace_WithoutDroppingThem()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        var before = await ViewOidsAsync(pg.Store);
        Assert.NotEmpty(before);

        await initializer.InitializeAsync();

        Assert.Equal(before, await ViewOidsAsync(pg.Store));
    }

    /// <summary>
    /// The deliberate escape hatch. <c>CREATE OR REPLACE VIEW</c> refuses to remove, rename, or
    /// retype an output column — which is exactly the blue-green rule for view shape — so a genuine
    /// shape change has to fall back to a guarded drop+create. Planting a view with the right name
    /// and a wrong column list forces that refusal and proves the fallback recovers instead of
    /// crash-looping the boot.
    /// </summary>
    [Fact]
    public async Task ViewWithAnIncompatibleColumnList_FallsBackToDropAndCreate()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            await conn.ExecuteAsync("DROP VIEW org_storage_bytes");
            // xtenant: stand-in view body for the test; its column list deliberately differs from the
            // real one so CREATE OR REPLACE VIEW must refuse it.
            await conn.ExecuteAsync(
                "CREATE VIEW org_storage_bytes AS SELECT o.id AS a_different_column FROM orgs o");
        }

        var ex = await Record.ExceptionAsync(() => initializer.InitializeAsync());
        Assert.Null(ex);

        await using (var conn = await pg.Store.OpenAsync())
        {
            var columns = (await conn.QueryAsync<string>(
                """
                SELECT column_name FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'org_storage_bytes'
                """)).ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.Contains("total_bytes", columns);
            Assert.DoesNotContain("a_different_column", columns);
        }
    }

    private static async Task<Dictionary<string, long>> ViewOidsAsync(NpgsqlMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        var rows = await conn.QueryAsync<(string Name, long Oid)>(
            """
            SELECT c.relname AS Name, c.oid::bigint AS Oid
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'v' AND n.nspname = 'public'
            """);
        return rows.ToDictionary(r => r.Name, r => r.Oid, StringComparer.Ordinal);
    }

    private static async Task<Dictionary<string, HashSet<string>>> PostgresViewShapeAsync(NpgsqlMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        var rows = await conn.QueryAsync<(string Table, string Column)>(
            """
            SELECT c.table_name AS Table, c.column_name AS Column
            FROM information_schema.columns c
            JOIN information_schema.tables t
              ON t.table_schema = c.table_schema AND t.table_name = c.table_name
            WHERE c.table_schema = 'public' AND t.table_type = 'VIEW'
            """);
        return Group(rows);
    }

    private static async Task<Dictionary<string, HashSet<string>>> SqliteViewShapeAsync(TestMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        var views = (await conn.QueryAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='view'")).ToList();
        var rows = new List<(string Table, string Column)>();
        foreach (string view in views)
        {
            foreach (string col in await conn.QueryAsync<string>(
                "SELECT name FROM pragma_table_info(@view)", new { view }))
            {
                rows.Add((view, col));
            }
        }

        return Group(rows);
    }

    private static async Task<Dictionary<string, HashSet<string>>> PostgresShapeAsync(NpgsqlMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        // information_schema.columns includes VIEW columns; sqlite_master WHERE type='table' does
        // not. Restrict to base tables so this stays a comparison of table shape — view parity is
        // asserted separately below, where a typo in a view body reports as a view failure rather
        // than a phantom missing table.
        var rows = await conn.QueryAsync<(string Table, string Column)>(
            """
            SELECT c.table_name AS Table, c.column_name AS Column
            FROM information_schema.columns c
            JOIN information_schema.tables t
              ON t.table_schema = c.table_schema AND t.table_name = c.table_name
            WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
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
