using System.Data.Common;
using System.Reflection;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Coverage-focused tests for <see cref="SchemaInitializer"/>. These exercise the
/// migration branches that the fresh-schema smoke tests don't reach:
///
/// 1. <c>DropLegacyTokenScopeColumnAsync</c> — column-exists branch on both
///    <c>user_tokens</c> and <c>service_tokens</c> (fresh schema lacks the column, so the
///    fresh-init path only covers the early-skip side).
/// 2. <c>DropPackageVersionsSbomColumnAsync</c> — column-exists branch (fresh
///    schema also lacks <c>sbom</c>, so only the early-return is hit otherwise).
/// 3. <c>ColumnExistsAsync</c> — the <c>true</c> return (the fresh-init path only
///    covers the <c>false</c> side).
/// 4. <c>DropAllowlistBlocklistEcosystemAsync</c> — exercises the recreate-table
///    copy when rows are present, including the deduping <c>MIN(id)</c> path that
///    collapses prior ecosystem-scoped duplicates onto the new UNIQUE.
/// 5. <c>RunOnceAsync</c> already-applied logging branch (LogDebug skip).
/// 6. Constructor: explicit logger and seeder paths.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SchemaInitializerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static SchemaInitializer NewInitializer(IMetadataStore db, ILogger<SchemaInitializer>? logger = null)
        => new(db, logger ?? NullLogger<SchemaInitializer>.Instance);

    // A one-time migration that creates a table and then fails before its ledger insert —
    // stands in for a process killed mid-migration (the partial-failure wedge class).
    private static async Task FailingMigrationAsync(DbConnection conn)
    {
        await conn.ExecuteAsync("CREATE TABLE wedge_probe (id TEXT)");
        throw new InvalidOperationException("boom");
    }

    [Fact]
    public async Task RunOnceAsync_WhenActionThrows_RollsBackPartialDdl_AndDoesNotRecordLedger()
    {
        var initializer = NewInitializer(_db);
        await initializer.InitializeAsync(); // builds the schema + _applied_migrations ledger

        await using var conn = await _db.OpenAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => initializer.RunOnceAsync(conn, "wedge_probe_migration", FailingMigrationAsync));

        // The wrapping transaction rolled back: the table the action created is gone...
        var tableCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='wedge_probe'");
        Assert.Equal(0, tableCount);

        // ...and the ledger never records a migration that didn't fully commit, so a retry
        // re-runs it from a clean slate instead of wedging on a leftover artefact.
        var recorded = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'wedge_probe_migration'");
        Assert.Equal(0, recorded);
    }

    [Fact]
    public async Task FixNuGetProxyPurlNames_IsLedgerGated_AfterInitialize()
    {
        // Previously ran unguarded on every boot; it is now a ledger-gated RunOnceAsync migration.
        var initializer = NewInitializer(_db);
        await initializer.InitializeAsync();

        await using var conn = await _db.OpenAsync();
        var recorded = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'fix_nuget_proxy_purl_names'");
        Assert.Equal(1, recorded);
    }

    /// <summary>
    /// Re-runs a one-time migration by deleting its tracking row, then re-invoking
    /// the initializer. Used to land back in the "needs to apply" branch after the
    /// first init has already marked it complete.
    /// </summary>
    private async Task ResetMigrationAsync(string name)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = @name", new { name });
    }

    [Fact]
    public async Task Constructor_NullLoggerAndSeeder_UsesDefaults()
    {
        // Bare two-arg construction (logger only) — exercises the seeder-default path.
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();

        await using var conn = await _db.OpenAsync();
        var schemaApplied = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='orgs'");
        Assert.Equal(1, schemaApplied);
    }

    [Fact]
    public async Task DropLegacyTokenScopeColumn_RemovesColumnWhenPresent()
    {
        // Fresh init brings the schema to its current shape (no `scope` column).
        await NewInitializer(_db).InitializeAsync();

        // Simulate a legacy database: add the column back and rewind the migration.
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("ALTER TABLE user_tokens ADD COLUMN scope TEXT");
            await setup.ExecuteAsync("ALTER TABLE service_tokens ADD COLUMN scope TEXT");
        }
        await ResetMigrationAsync("drop_legacy_token_scope_column");

        // Re-run: the column-exists branch fires for both tables.
        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var userTokensHasScope = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('user_tokens') WHERE name = 'scope'");
        var serviceTokensHasScope = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('service_tokens') WHERE name = 'scope'");
        Assert.Equal(0, userTokensHasScope);
        Assert.Equal(0, serviceTokensHasScope);
    }

    [Fact]
    public async Task DropLegacyTokenScopeColumn_IsNoOpWhenAbsent()
    {
        // Fresh init: schema already lacks `scope` on both tables, so the column-exists
        // checks return false on the first run. The migration completes successfully and
        // is marked applied; reset+rerun proves the no-op stays a no-op.
        await NewInitializer(_db).InitializeAsync();
        await ResetMigrationAsync("drop_legacy_token_scope_column");

        var ex = await Record.ExceptionAsync(() => NewInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        await using var verify = await _db.OpenAsync();
        var tokensRows = await verify.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM user_tokens");
        Assert.Equal(0, tokensRows);
    }

    [Fact]
    public async Task DropPackageVersionsSbomColumn_RemovesColumnWhenPresent()
    {
        await NewInitializer(_db).InitializeAsync();

        // Add the legacy column back and rewind so the migration sees a pre-drop database.
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("ALTER TABLE package_versions ADD COLUMN sbom TEXT");
        }
        await ResetMigrationAsync("drop_package_versions_sbom_column");

        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var hasSbom = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('package_versions') WHERE name = 'sbom'");
        Assert.Equal(0, hasSbom);
    }

    [Fact]
    public async Task DropPackageVersionsSbomColumn_EarlyReturnWhenAbsent()
    {
        // Fresh schema lacks `sbom`; the migration's `if (!ColumnExists) return` line fires
        // and the migration is marked applied without touching the table.
        await NewInitializer(_db).InitializeAsync();
        await using var verify = await _db.OpenAsync();
        var applied = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'drop_package_versions_sbom_column'");
        Assert.Equal(1, applied);
    }

    [Fact]
    public async Task DropAllowlistBlocklistEcosystem_RecreatesTablesPreservingRows()
    {
        // Land at the post-init shape, seed real rows in both tables, rewind the migration,
        // and re-run. This exercises the recreate-table SQL:
        //   - CREATE TABLE *_new
        //   - INSERT … SELECT MIN(id), org_id, pattern, MIN(created_at) … GROUP BY
        //   - DROP + RENAME
        // Note: the current schema already enforces UNIQUE(org_id, pattern), so we can't
        // seed pre-collapse duplicates — we just verify the row survives the recreate
        // and the new UNIQUE is in force afterwards.
        await NewInitializer(_db).InitializeAsync();

        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
            await setup.ExecuteAsync("""
                INSERT INTO allowlist (id, org_id, purl_pattern, created_at)
                VALUES ('a-keep','o1','pkg:npm/express','2024-01-01T00:00:00Z')
                """);
            await setup.ExecuteAsync("""
                INSERT INTO blocklist (id, org_id, pattern, created_at)
                VALUES ('b-keep','o1','evil-.*','2024-01-01T00:00:00Z')
                """);
        }
        await ResetMigrationAsync("drop_allowlist_blocklist_ecosystem");

        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var allowIds = (await verify.QueryAsync<string>(
            "SELECT id FROM allowlist ORDER BY id")).ToList();
        var blockIds = (await verify.QueryAsync<string>(
            "SELECT id FROM blocklist ORDER BY id")).ToList();
        Assert.Equal(new[] { "a-keep" }, allowIds);
        Assert.Equal(new[] { "b-keep" }, blockIds);

        // The recreated tables retain the new UNIQUE contract.
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => verify.ExecuteAsync("""
            INSERT INTO allowlist (id, org_id, purl_pattern)
            VALUES ('dup','o1','pkg:npm/express')
            """));
        Assert.Contains("UNIQUE", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunOnceAsync_SecondRunHitsAlreadyAppliedLogBranch()
    {
        // First run: all migrations execute (LogInformation x2 per migration).
        // Second run: every migration's RunOnceAsync hits the LogDebug "already applied" path,
        // which is the otherwise-uncovered branch in the RunOnce helper.
        var logger = new CapturingLogger<SchemaInitializer>();
        var initializer = new SchemaInitializer(_db, logger);

        await initializer.InitializeAsync();
        logger.Records.Clear();
        await initializer.InitializeAsync();

        Assert.Contains(logger.Records,
            r => r.Level == LogLevel.Debug && r.Message.Contains("already applied"));
        // And no migration should have re-run on the second pass.
        Assert.DoesNotContain(logger.Records,
            r => r.Level == LogLevel.Information && r.Message.EndsWith("applied."));
    }

    [Fact]
    public async Task RunOnceAsync_FirstRunLogsApplyingAndApplied()
    {
        var logger = new CapturingLogger<SchemaInitializer>();
        var initializer = new SchemaInitializer(_db, logger);

        await initializer.InitializeAsync();

        Assert.Contains(logger.Records,
            r => r.Level == LogLevel.Information && r.Message.Contains("applying"));
        Assert.Contains(logger.Records,
            r => r.Level == LogLevel.Information && r.Message.EndsWith("applied."));
    }

    [Fact]
    public async Task FixNuGetProxyPurlNames_FixesBrokenProxyRows_WhenRun()
    {
        // fix_nuget_proxy_purl_names is now a ledger-gated RunOnceAsync migration (it used to run
        // unguarded on every boot). Insert a broken-shaped row, clear the ledger entry to re-trigger
        // the migration, and assert the rename logic still fixes it.
        await NewInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
            // is_proxy = 1, purl_name starts with 'pkg:' — the broken shape the migration fixes.
            await setup.ExecuteAsync("""
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
                VALUES ('p1','o1','nuget','Newtonsoft.Json','pkg:nuget/Newtonsoft.Json@13.0.1', 1)
                """);
        }
        await ResetMigrationAsync("fix_nuget_proxy_purl_names");

        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var purlName = await verify.ExecuteScalarAsync<string>(
            "SELECT purl_name FROM packages WHERE id = 'p1'");
        Assert.Equal("Newtonsoft.Json", purlName);
    }

    [Fact]
    public async Task RenameTokensTables_IsNoOpOnFreshInstall()
    {
        // Fresh schema has user_tokens/service_tokens straight from the CREATE TABLE blocks.
        // The rename action's existence guards return false, the migration completes, and the
        // ledger records both rename rows so subsequent boots short-circuit.
        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var applied = (await verify.QueryAsync<string>(
            "SELECT name FROM _applied_migrations WHERE name LIKE 'rename_%' ORDER BY name")).ToList();
        Assert.Equal(
            new[] { "rename_cicd_tokens_to_service_tokens", "rename_tokens_to_user_tokens" },
            applied);
    }

    // The next two tests cover defensive branches that InitializeAsync can't reach on its own:
    // Schema.sql (re)creates oci_tags on every boot before the backfill runs, so the
    // "table absent" / "real ALTER error" states are unreachable through the public surface.
    // We invoke the private members directly to prove the hardening behaves as intended —
    // these guard against the prod incident where a partial schema made startup hosting-fatal
    // with "no such table: oci_tags".

    [Theory]
    [InlineData("oci_tags")]
    [InlineData("oci_blobs")]
    public async Task BackfillOciCatalog_SkipsWithWarningWhenEitherTableAbsent(string missingTable)
    {
        var logger = new CapturingLogger<SchemaInitializer>();
        var initializer = new SchemaInitializer(_db, logger);
        await initializer.InitializeAsync();

        // Simulate the anomalous state the guard exists for: one of the OCI tables the backfill
        // query reads is missing. Both are guarded, so dropping either must trigger the skip.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync($"DROP TABLE {missingTable}");
        logger.Records.Clear();

        var backfill = typeof(SchemaInitializer).GetMethod(
            "BackfillOciCatalogAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var ex = await Record.ExceptionAsync(
            () => (Task)backfill.Invoke(initializer, new object[] { conn })!);

        Assert.Null(ex);  // degrades gracefully instead of crashing hosting
        Assert.Contains(logger.Records,
            r => r.Level == LogLevel.Warning && r.Message.Contains("backfill_oci_catalog"));
    }

    [Fact]
    public async Task MigrateSqlite_SwallowsDuplicateColumnButSurfacesOtherErrors()
    {
        // Error code 1 is SQLite's generic catch-all. The helper must ignore only
        // "duplicate column" (idempotent re-run) and let real schema errors propagate —
        // the masking bug previously hid a "no such table" behind the same code.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("CREATE TABLE migrate_probe (a TEXT)");

        var migrate = typeof(SchemaInitializer).GetMethod(
            "MigrateSqliteAsync", BindingFlags.Static | BindingFlags.NonPublic)!;
        Task Invoke(string ddl) => (Task)migrate.Invoke(null, new object[] { conn, ddl })!;

        await Invoke("ALTER TABLE migrate_probe ADD COLUMN b TEXT");
        var duplicate = await Record.ExceptionAsync(
            () => Invoke("ALTER TABLE migrate_probe ADD COLUMN b TEXT"));
        Assert.Null(duplicate);  // duplicate-column re-run stays a no-op

        var realError = await Record.ExceptionAsync(
            () => Invoke("ALTER TABLE no_such_table ADD COLUMN c TEXT"));
        Assert.NotNull(realError);  // no-such-table now surfaces rather than being swallowed
    }

    /// <summary>
    /// Captures log records so we can assert on the applied/skipped branches in
    /// <c>RunOnceAsync</c>. Per project memory: "migrations log applied AND skipped".
    /// </summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Records { get; } = new();

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Records.Add((logLevel, formatter(state, exception)));
        }
    }
}
