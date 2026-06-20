using System.Data.Common;
using System.Reflection;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

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
        long tableCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='wedge_probe'");
        Assert.Equal(0, tableCount);

        // ...and the ledger never records a migration that didn't fully commit, so a retry
        // re-runs it from a clean slate instead of wedging on a leftover artefact.
        long recorded = await conn.ExecuteScalarAsync<long>(
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
        long recorded = await conn.ExecuteScalarAsync<long>(
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
        long schemaApplied = await conn.ExecuteScalarAsync<long>(
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
        long userTokensHasScope = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('user_tokens') WHERE name = 'scope'");
        long serviceTokensHasScope = await verify.ExecuteScalarAsync<long>(
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
        long tokensRows = await verify.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM user_tokens");
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
        long hasSbom = await verify.ExecuteScalarAsync<long>(
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
        long applied = await verify.ExecuteScalarAsync<long>(
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
        string? purlName = await verify.ExecuteScalarAsync<string>(
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

    [Fact]
    public async Task SeedGoCargoUpstreamRegistries_SeedsBothDefaultsForOrgWithNoRows()
    {
        // A pre-existing org that has no golang/cargo upstream rows (because the original
        // seed_default_upstream_registries backfill predated those ecosystems) receives both
        // defaults when the targeted backfill re-runs.
        await NewInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        }
        await ResetMigrationAsync("seed_go_cargo_upstream_registries");

        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        string? golang = await verify.ExecuteScalarAsync<string>(
            "SELECT url FROM upstream_registry WHERE org_id = 'o1' AND ecosystem = 'golang'");
        string? cargo = await verify.ExecuteScalarAsync<string>(
            "SELECT url FROM upstream_registry WHERE org_id = 'o1' AND ecosystem = 'cargo'");
        Assert.Equal("https://proxy.golang.org", golang);
        Assert.Equal("https://index.crates.io", cargo);
    }

    [Fact]
    public async Task SeedGoCargoUpstreamRegistries_DoesNotDuplicateExistingRows()
    {
        // An org that already has a golang/cargo row (e.g. an operator-customised mirror) is not
        // touched: the per-(org, ecosystem) existence check skips it, so no second row appears.
        await NewInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
            await setup.ExecuteAsync("""
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
                VALUES ('g-custom','o1','golang','https://mirror.internal/go',0)
                """);
            await setup.ExecuteAsync("""
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
                VALUES ('c-custom','o1','cargo','https://mirror.internal/cargo',0)
                """);
        }
        await ResetMigrationAsync("seed_go_cargo_upstream_registries");

        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        var golangIds = (await verify.QueryAsync<string>(
            "SELECT id FROM upstream_registry WHERE org_id = 'o1' AND ecosystem = 'golang'")).ToList();
        var cargoIds = (await verify.QueryAsync<string>(
            "SELECT id FROM upstream_registry WHERE org_id = 'o1' AND ecosystem = 'cargo'")).ToList();
        Assert.Equal(new[] { "g-custom" }, golangIds);
        Assert.Equal(new[] { "c-custom" }, cargoIds);
    }

    [Fact]
    public async Task SeedGoCargoUpstreamRegistries_DoesNotResurrectDeliberatelyRemovedOtherEcosystem()
    {
        // The targeted-backfill safety property: an org that has deliberately zero rows for an
        // OTHER ecosystem (e.g. npm proxying disabled by deleting its upstream) must NOT have that
        // ecosystem re-seeded by this migration — it touches only golang and cargo. Re-running the
        // full backfill would resurrect the removed npm row; the restricted scope prevents that.
        await NewInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
            // o1 has rows for everything EXCEPT npm and golang/cargo: npm was deliberately removed.
        }
        await ResetMigrationAsync("seed_go_cargo_upstream_registries");

        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        long npmRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = 'o1' AND ecosystem = 'npm'");
        long golangRows = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = 'o1' AND ecosystem = 'golang'");
        Assert.Equal(0, npmRows);   // deliberately-removed npm stays removed
        Assert.Equal(1, golangRows); // golang/cargo are the only ecosystems seeded
    }

    [Fact]
    public async Task DropPackageVersionsPurlUnique_RemovesUniqueConstraint_OnExistingDb()
    {
        // Simulate a pre-migration database where package_versions.purl carries a UNIQUE
        // constraint. Initialize normally first to get the base schema, then manually add
        // the purl UNIQUE back (recreating the old state) and rewind the migration ledger.
        await NewInitializer(_db).InitializeAsync();

        // Re-create the old package_versions schema with purl UNIQUE to simulate an upgrade.
        // Drop the current table and recreate it in its pre-migration form.
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("""
                CREATE TABLE package_versions_old_shape (
                    id          TEXT PRIMARY KEY,
                    package_id  TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                    version     TEXT NOT NULL,
                    purl        TEXT NOT NULL UNIQUE,
                    blob_key    TEXT NOT NULL,
                    size_bytes  INTEGER NOT NULL DEFAULT 0,
                    checksum_sha256 TEXT,
                    yanked      INTEGER NOT NULL DEFAULT 0,
                    yank_reason TEXT,
                    first_fetch INTEGER NOT NULL DEFAULT 0,
                    last_used   TEXT,
                    download_count INTEGER NOT NULL DEFAULT 0,
                    vuln_checked_at TEXT,
                    manual_block_state TEXT,
                    deprecated  TEXT,
                    origin      TEXT NOT NULL DEFAULT 'proxy',
                    published_at TEXT,
                    checksum_sha1 TEXT,
                    upstream_integrity_value TEXT,
                    upstream_integrity_algorithm TEXT,
                    filename    TEXT,
                    deprecation_checked_at TEXT,
                    has_install_script INTEGER NOT NULL DEFAULT 0,
                    install_script_kind TEXT,
                    provenance_status TEXT,
                    provenance_signer TEXT,
                    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                    UNIQUE (package_id, version)
                )
                """);
            // Copy any existing rows across.
            await setup.ExecuteAsync("""
                INSERT INTO package_versions_old_shape
                SELECT id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, yanked,
                       yank_reason, first_fetch, last_used, download_count, vuln_checked_at,
                       manual_block_state, deprecated, origin, published_at, checksum_sha1,
                       upstream_integrity_value, upstream_integrity_algorithm, filename,
                       deprecation_checked_at, has_install_script, install_script_kind,
                       provenance_status, provenance_signer, created_at
                FROM package_versions
                """);
            await setup.ExecuteAsync("DROP TABLE package_versions");
            await setup.ExecuteAsync("ALTER TABLE package_versions_old_shape RENAME TO package_versions");
        }
        await ResetMigrationAsync("drop_package_versions_purl_unique");

        // Re-run: the purl-unique detection fires and the recreate removes the constraint.
        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        // The purl UNIQUE must be gone: two tenants can now share the same purl.
        // packages.UNIQUE(org_id, ecosystem, purl_name) means two orgs get separate package rows.
        await verify.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme'),('o2','beta')");
        await verify.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('p1','o1','npm','express','express',1),
                   ('p2','o2','npm','express','express',1)
            """);
        await verify.ExecuteAsync("""
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key)
            VALUES ('v1','p1','4.18.2','pkg:npm/express@4.18.2','proxy/express/4.18.2.tgz')
            """);
        // Tenant 2 pulls the same package version (same purl, different package_id): must succeed.
        var ex = await Record.ExceptionAsync(() => verify.ExecuteAsync("""
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key)
            VALUES ('v2','p2','4.18.2','pkg:npm/express@4.18.2','proxy/express/4.18.2b.tgz')
            """));
        Assert.Null(ex);

        // UNIQUE(package_id, version) is still enforced.
        var dupEx = await Assert.ThrowsAnyAsync<Exception>(() => verify.ExecuteAsync("""
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key)
            VALUES ('v3','p1','4.18.2','pkg:npm/express@4.18.2','proxy/express/4.18.2c.tgz')
            """));
        Assert.Contains("UNIQUE", dupEx.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DropPackageVersionsPurlUnique_IsNoOpOnFreshInstall()
    {
        // Fresh schema has no purl UNIQUE (Schema.sql already emits it without UNIQUE).
        // The migration's purl-detection returns false and the migration records itself
        // without doing any DDL, leaving the schema stable.
        await NewInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        long applied = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'drop_package_versions_purl_unique'");
        Assert.Equal(1, applied);

        // Schema is stable: re-running does not change anything.
        await ResetMigrationAsync("drop_package_versions_purl_unique");
        await NewInitializer(_db).InitializeAsync();

        // Still no purl unique — UNIQUE(package_id, version) remains the only unique on the table.
        // Two tenants can hold the same purl via separate package rows (one per org).
        await using var verify2 = await _db.OpenAsync();
        await verify2.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme'),('o2','beta')");
        await verify2.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('p1','o1','npm','express','express',1),
                   ('p2','o2','npm','express','express',1)
            """);
        await verify2.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('v1','p1','4.18.2','pkg:npm/express@4.18.2','proxy/e1.tgz')
            """);
        // Tenant 2 pulls the same version — must succeed on a fresh install too.
        var ex = await Record.ExceptionAsync(() => verify2.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('v2','p2','4.18.2','pkg:npm/express@4.18.2','proxy/e2.tgz')
            """));
        Assert.Null(ex);
    }

    [Fact]
    public async Task DropPackageVersionsPurlUnique_MixedRows_SomeSucceedSomeFail()
    {
        // Mixed partial-failure scenario: after the migration, rows that share a purl across
        // different (package_id) contexts succeed, while rows that violate UNIQUE(package_id,
        // version) still fail — the constraint drop is precise, not a wholesale relaxation.
        await NewInitializer(_db).InitializeAsync();

        await using var setup = await _db.OpenAsync();
        await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme'),('o2','beta')");
        await setup.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('p1','o1','npm','lodash','lodash',1),
                   ('p2','o2','npm','lodash','lodash',1)
            """);

        // Tenant 1 pulls lodash 4.17.21 — allowed.
        await setup.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('v1','p1','4.17.21','pkg:npm/lodash@4.17.21','proxy/lodash/4.17.21.tgz')
            """);

        // Tenant 2 pulls the SAME lodash 4.17.21 (same purl) — must also succeed because
        // purl is no longer globally unique; only (package_id, version) is unique per-tenant.
        var crossTenantEx = await Record.ExceptionAsync(() => setup.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('v2','p2','4.17.21','pkg:npm/lodash@4.17.21','proxy/lodash/4.17.21b.tgz')
            """));
        Assert.Null(crossTenantEx);

        // Within the SAME tenant, inserting the same (package_id, version) must still fail.
        var sameVersionEx = await Assert.ThrowsAnyAsync<Exception>(() => setup.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('v3','p1','4.17.21','pkg:npm/lodash@4.17.21','proxy/lodash/4.17.21c.tgz')
            """));
        Assert.Contains("UNIQUE", sameVersionEx.Message, StringComparison.OrdinalIgnoreCase);

        // A NEW version for the same tenant succeeds normally.
        var newVersionEx = await Record.ExceptionAsync(() => setup.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('v4','p1','4.17.22','pkg:npm/lodash@4.17.22','proxy/lodash/4.17.22.tgz')
            """));
        Assert.Null(newVersionEx);
    }

    // ── rpm_metadata restructure ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task MakeRpmMetadataPvNullable_FreshInstall_IsIdempotent()
    {
        // Fresh schema already has the new shape; running the migration twice must be a no-op.
        await NewInitializer(_db).InitializeAsync();
        await ResetMigrationAsync("make_rpm_metadata_pv_nullable");
        var ex = await Record.ExceptionAsync(() => NewInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        await using var verify = await _db.OpenAsync();
        long applied = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'make_rpm_metadata_pv_nullable'");
        Assert.Equal(1, applied);
    }

    [Fact]
    public async Task MakeRpmMetadataPvNullable_CacheArtifactOwnedRowCanBeInserted()
    {
        // After migration, a row with owner_kind='cache_artifact' and NULL package_version_id
        // must be insertable; the partial unique index on cache_artifact_id enforces per-CA dedup.
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                 first_cached_at, last_accessed_at)
            VALUES ('ca1', 'rpm', 'hello', '2.10-1.el9', 'hello-2.10-1.el9.x86_64.rpm',
                    'proxy/abc123', 'abc123', 1024,
                    '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
            """);

        // Insert a cache_artifact-owned row with NULL package_version_id.
        var insertEx = await Record.ExceptionAsync(() => conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, cache_artifact_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 installed_size, archive_size, header_start, header_end)
            VALUES ('rid1', 'ca1', 'cache_artifact',
                    'hello', 0, '2.10', '1.el9', 'x86_64',
                    65536, 60000, 440, 2048)
            """));
        Assert.Null(insertEx);

        long rowCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM rpm_metadata WHERE cache_artifact_id = 'ca1' AND package_version_id IS NULL");
        Assert.Equal(1, rowCount);
    }

    [Fact]
    public async Task MakeRpmMetadataPvNullable_PartialUniqueEnforcesPerArmDedup()
    {
        // Mixed partial-failure scenario: a second cache_artifact-arm row for the same CA must
        // conflict; a package_version-arm row for a different package_version_id must succeed.
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                 first_cached_at, last_accessed_at)
            VALUES ('ca1', 'rpm', 'hello', '2.10-1.el9', 'hello.rpm', 'proxy/a', 'a', 1,
                    '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'),
                   ('ca2', 'rpm', 'world', '1.0-1.el9', 'world.rpm', 'proxy/b', 'b', 1,
                    '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
            """);

        // First CA-arm row — succeeds.
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, cache_artifact_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 installed_size, archive_size, header_start, header_end)
            VALUES ('r1', 'ca1', 'cache_artifact', 'hello', 0, '2.10', '1', 'x86_64', 1, 1, 0, 1)
            """);

        // Duplicate CA-arm for same cache_artifact_id — must violate partial unique.
        var dupEx = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, cache_artifact_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 installed_size, archive_size, header_start, header_end)
            VALUES ('r2', 'ca1', 'cache_artifact', 'hello', 0, '2.10', '1', 'x86_64', 1, 1, 0, 1)
            """));
        Assert.Contains("UNIQUE", dupEx.Message, StringComparison.OrdinalIgnoreCase);

        // Different CA — succeeds (different cache_artifact_id, no conflict).
        var okEx = await Record.ExceptionAsync(() => conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, cache_artifact_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 installed_size, archive_size, header_start, header_end)
            VALUES ('r3', 'ca2', 'cache_artifact', 'world', 0, '1.0', '1', 'x86_64', 1, 1, 0, 1)
            """));
        Assert.Null(okEx);
    }

    // ── maven_version_files restructure ───────────────────────────────────────────────────────────

    [Fact]
    public async Task MakeMvfPvNullable_FreshInstall_IsIdempotent()
    {
        await NewInitializer(_db).InitializeAsync();
        await ResetMigrationAsync("make_mvf_pv_nullable");
        var ex = await Record.ExceptionAsync(() => NewInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        await using var verify = await _db.OpenAsync();
        long applied = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'make_mvf_pv_nullable'");
        Assert.Equal(1, applied);
    }

    [Fact]
    public async Task MakeMvfPvNullable_CacheArtifactOwnedRowCanBeInserted()
    {
        // After migration, a row with owner_kind='cache_artifact' and NULL package_version_id
        // must be insertable; per-CA/filename dedup is enforced by the partial unique index.
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                 first_cached_at, last_accessed_at)
            VALUES ('ca1', 'maven', 'com.example:lib', '1.0.0', 'lib-1.0.0.jar',
                    'proxy/abc', 'abc', 1024,
                    '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
            """);

        var insertEx = await Record.ExceptionAsync(() => conn.ExecuteAsync("""
            INSERT INTO maven_version_files
                (id, cache_artifact_id, filename, extension, blob_key, size_bytes, owner_kind)
            VALUES ('mvf1', 'ca1', 'lib-1.0.0.jar', 'jar', 'proxy/abc', 1024, 'cache_artifact')
            """));
        Assert.Null(insertEx);

        long rowCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM maven_version_files WHERE cache_artifact_id = 'ca1' AND package_version_id IS NULL");
        Assert.Equal(1, rowCount);
    }

    [Fact]
    public async Task MakeMvfPvNullable_PartialUniqueEnforcesPerArmDedup_MixedScenario()
    {
        // Mixed partial-failure: duplicate (CA, filename) in cache_artifact arm fails;
        // same filename under package_version arm succeeds (different arm, no conflict).
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                 first_cached_at, last_accessed_at)
            VALUES ('ca1', 'maven', 'g:a', '1.0', 'a-1.0.jar', 'proxy/x', 'x', 1,
                    '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
            """);
        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('p1', 'o1', 'maven', 'g:a', 'g:a', 1)
            """);
        await conn.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('pv1', 'p1', '1.0', 'pkg:maven/g/a@1.0', 'proxy/x')
            """);

        // CA-arm row — succeeds.
        await conn.ExecuteAsync("""
            INSERT INTO maven_version_files
                (id, cache_artifact_id, filename, extension, blob_key, size_bytes, owner_kind)
            VALUES ('f1', 'ca1', 'a-1.0.jar', 'jar', 'proxy/x', 1, 'cache_artifact')
            """);

        // Duplicate CA-arm row for same (CA, filename) — must conflict.
        var dupEx = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync("""
            INSERT INTO maven_version_files
                (id, cache_artifact_id, filename, extension, blob_key, size_bytes, owner_kind)
            VALUES ('f2', 'ca1', 'a-1.0.jar', 'jar', 'proxy/x', 1, 'cache_artifact')
            """));
        Assert.Contains("UNIQUE", dupEx.Message, StringComparison.OrdinalIgnoreCase);

        // PV-arm row for same filename — must succeed (different arm).
        var pvEx = await Record.ExceptionAsync(() => conn.ExecuteAsync("""
            INSERT INTO maven_version_files
                (id, package_version_id, filename, extension, blob_key, size_bytes, owner_kind)
            VALUES ('f3', 'pv1', 'a-1.0.jar', 'jar', 'proxy/x', 1, 'package_version')
            """));
        Assert.Null(pvEx);
    }

    // ── cargo_metadata restructure ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task MakeCargoMetadataVidNullable_FreshInstall_IsIdempotent()
    {
        await NewInitializer(_db).InitializeAsync();
        await ResetMigrationAsync("make_cargo_metadata_vid_nullable");
        var ex = await Record.ExceptionAsync(() => NewInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        await using var verify = await _db.OpenAsync();
        long applied = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'make_cargo_metadata_vid_nullable'");
        Assert.Equal(1, applied);
    }

    [Fact]
    public async Task MakeCargoMetadataVidNullable_CacheArtifactOwnedRowCanBeInserted()
    {
        // After migration, a row with owner_kind='cache_artifact' and NULL version_id
        // must be insertable; per-CA dedup is enforced by the partial unique index.
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                 first_cached_at, last_accessed_at)
            VALUES ('ca1', 'cargo', 'serde', '1.0.0', 'serde-1.0.0.crate',
                    'proxy/abc', 'abc', 1024,
                    '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
            """);

        var insertEx = await Record.ExceptionAsync(() => conn.ExecuteAsync("""
            INSERT INTO cargo_metadata (cache_artifact_id, index_line, owner_kind)
            VALUES ('ca1', '{"name":"serde","vers":"1.0.0","deps":[],"cksum":"abc","features":{},"yanked":false}', 'cache_artifact')
            """));
        Assert.Null(insertEx);

        long rowCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cargo_metadata WHERE cache_artifact_id = 'ca1' AND version_id IS NULL");
        Assert.Equal(1, rowCount);
    }

    [Fact]
    public async Task MakeCargoMetadataVidNullable_PartialUniqueEnforcesPerArmDedup_MixedScenario()
    {
        // Mixed partial-failure: duplicate CA-arm row for same cache_artifact_id fails;
        // PV-arm row for same version_id after conflict resolution works via ON CONFLICT.
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                 first_cached_at, last_accessed_at)
            VALUES ('ca1', 'cargo', 'serde', '1.0.0', 'serde-1.0.0.crate',
                    'proxy/x', 'x', 1,
                    '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
            """);
        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('p1', 'o1', 'cargo', 'serde', 'serde', 0)
            """);
        await conn.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('pv1', 'p1', '1.0.0', 'pkg:cargo/serde@1.0.0', 'cargo/o1/serde/1.0.0.crate')
            """);

        const string indexLine = """{"name":"serde","vers":"1.0.0","deps":[],"cksum":"x","features":{},"yanked":false}""";

        // CA-arm row — succeeds.
        await conn.ExecuteAsync(
            "INSERT INTO cargo_metadata (cache_artifact_id, index_line, owner_kind) VALUES ('ca1', @line, 'cache_artifact')",
            new { line = indexLine });

        // Duplicate CA-arm row for same CA — must conflict.
        var dupEx = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync(
            "INSERT INTO cargo_metadata (cache_artifact_id, index_line, owner_kind) VALUES ('ca1', @line, 'cache_artifact')",
            new { line = indexLine }));
        Assert.Contains("UNIQUE", dupEx.Message, StringComparison.OrdinalIgnoreCase);

        // PV-arm row (different arm) for the same crate version — must succeed.
        var pvEx = await Record.ExceptionAsync(() => conn.ExecuteAsync("""
            INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
            VALUES ('pv1', @line, 'package_version')
            ON CONFLICT (version_id) WHERE owner_kind = 'package_version' DO UPDATE SET index_line = excluded.index_line
            """,
            new { line = indexLine }));
        Assert.Null(pvEx);
    }

    // ── Owner-invariant CHECK tests ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Verifies that the owner-invariant CHECK on each polymorphic metadata table rejects an
    /// INSERT where owner_kind='cache_artifact' but cache_artifact_id is NULL (the mismatch the
    /// invariant was designed to prevent). Fresh-install shape — the constraint is in the CREATE
    /// TABLE block — so no migration reset needed.
    /// </summary>

    [Fact]
    public async Task OwnerInvariantCheck_PvvRejectsMismatch_CacheArtifactArmWithNullCaId()
    {
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        // Mismatched row: owner_kind='cache_artifact' but cache_artifact_id IS NULL — violates invariant.
        // vuln_id must reference a real vulnerabilities row; use a sentinel that bypasses the vuln FK
        // by seeding it inline so only the owner-invariant CHECK is under test.
        await conn.ExecuteAsync("""
            INSERT OR IGNORE INTO vulnerabilities (id, osv_id, ecosystem, package_name)
            VALUES ('GHSA-0000-0000-0002', 'GHSA-0000-0000-0002', 'npm', 'test')
            """);
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync("""
            INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind)
            VALUES ('pvv-bad', NULL, 'GHSA-0000-0000-0002', 'cache_artifact')
            """));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OwnerInvariantCheck_PvlRejectsMismatch_CacheArtifactArmWithNullCaId()
    {
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedMinimalPackageVersionAsync(conn, "org-ckl", "pv-ckl1");

        // Mismatched row: owner_kind='cache_artifact' but cache_artifact_id IS NULL.
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync("""
            INSERT INTO package_version_licenses (id, cache_artifact_id, owner_kind, license_spdx, source)
            VALUES ('pvl-bad', NULL, 'cache_artifact', 'MIT', 'upstream')
            """));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OwnerInvariantCheck_RpmMetadataRejectsMismatch_CacheArtifactArmWithNullCaId()
    {
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        // Mismatched row: owner_kind='cache_artifact' but cache_artifact_id IS NULL.
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, cache_artifact_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch)
            VALUES ('rm-bad', NULL, 'cache_artifact',
                    'test', 0, '1.0', '1.el9', 'x86_64')
            """));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OwnerInvariantCheck_MvfRejectsMismatch_CacheArtifactArmWithNullCaId()
    {
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        // Mismatched row: owner_kind='cache_artifact' but cache_artifact_id IS NULL.
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync("""
            INSERT INTO maven_version_files
                (id, cache_artifact_id, owner_kind, filename, extension, blob_key)
            VALUES ('mvf-bad', NULL, 'cache_artifact', 'a.jar', 'jar', 'k')
            """));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OwnerInvariantCheck_CargoMetadataRejectsMismatch_CacheArtifactArmWithNullCaId()
    {
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        // Mismatched row: owner_kind='cache_artifact' but cache_artifact_id IS NULL.
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => conn.ExecuteAsync("""
            INSERT INTO cargo_metadata (cache_artifact_id, index_line, owner_kind)
            VALUES (NULL, '{"name":"x"}', 'cache_artifact')
            """));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── delete_migrated_proxy_package_versions tests ───────────────────────────────────────────

    [Fact]
    public async Task DeleteMigratedProxyPackageVersions_RemovesProxyRows_LeavesUploadedIntact()
    {
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedMinimalOrgAsync(conn, "org-del");

        // Seed a package, one proxy version, and one uploaded version.
        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('pkg-del', 'org-del', 'npm', 'lodash', 'lodash', 1)
            """);
        await conn.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin)
            VALUES ('pv-proxy', 'pkg-del', '4.0.0', 'pkg:npm/lodash@4.0.0', 'proxy/abc123/lodash-4.0.0.tgz', 'proxy'),
                   ('pv-upload', 'pkg-del', '3.0.0', 'pkg:npm/lodash@3.0.0', 'npm/registry/lodash/3.0.0/lodash-3.0.0.tgz', 'uploaded')
            """);

        // Reset so the migration fires again.
        await ResetMigrationAsync("delete_migrated_proxy_package_versions");
        await NewInitializer(_db).InitializeAsync();

        long proxyCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE origin = 'proxy'");
        long uploadCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE origin = 'uploaded'");
        Assert.Equal(0, proxyCount);
        Assert.Equal(1, uploadCount);
    }

    [Fact]
    public async Task DeleteMigratedProxyPackageVersions_IsIdempotent_SecondRunNoOp()
    {
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        // No proxy rows on a fresh DB — the migration recorded itself and future re-runs
        // (via ledger) are no-ops. Reset and re-run: no exception.
        await ResetMigrationAsync("delete_migrated_proxy_package_versions");
        var ex = await Record.ExceptionAsync(() => NewInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        // Ledger re-records it.
        long recorded = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'delete_migrated_proxy_package_versions'");
        Assert.Equal(1, recorded);
    }

    [Fact]
    public async Task DeleteMigratedProxyPackageVersions_CascadeDropsOnlyPvMetadata_CaMetadataSurvives()
    {
        // Mixed partial scenario: one proxy PV row with a metadata twin (pvv pv arm + pvv ca arm),
        // one uploaded PV row. After delete: proxy PV + its pv-arm vulns are gone; ca-arm vulns
        // and the uploaded PV + its pv-arm vulns both survive.
        await NewInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedMinimalOrgAsync(conn, "org-cas");

        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('pkg-cas', 'org-cas', 'npm', 'react', 'react', 1)
            """);

        // Seed a vulnerability so we can reference it.
        await conn.ExecuteAsync("""
            INSERT INTO vulnerabilities
                (id, osv_id, ecosystem, package_name, affected_versions, osv_json,
                 published_at, modified_at, fetched_at)
            VALUES ('GHSA-1111-1111-1111', 'GHSA-1111-1111-1111', 'npm', 'react', '[]', '{}',
                    '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
            """);

        await conn.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin)
            VALUES ('pv-proxy2', 'pkg-cas', '18.0.0', 'pkg:npm/react@18.0.0', 'proxy/x/react-18.0.0.tgz', 'proxy'),
                   ('pv-upload2', 'pkg-cas', '17.0.0', 'pkg:npm/react@17.0.0', 'npm/registry/react/17.0.0/react-17.0.0.tgz', 'uploaded')
            """);

        // Seed a cache_artifact row to simulate the global plane twin.
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
            VALUES ('ca-cas', 'npm', 'react', '18.0.0', 'react-18.0.0.tgz', 'proxy/x', 'x', 0)
            """);

        // pv-arm vuln for the proxy version (will be cascade-deleted with pv-proxy2).
        await conn.ExecuteAsync("""
            INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind)
            VALUES ('pvv-pv', 'pv-proxy2', 'GHSA-1111-1111-1111', 'package_version')
            """);

        // ca-arm vuln for the same vuln (the global-plane twin; must survive the delete).
        await conn.ExecuteAsync("""
            INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind)
            VALUES ('pvv-ca', 'ca-cas', 'GHSA-1111-1111-1111', 'cache_artifact')
            """);

        // pv-arm vuln for the uploaded version (must survive).
        await conn.ExecuteAsync("""
            INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind)
            VALUES ('pvv-up', 'pv-upload2', 'GHSA-1111-1111-1111', 'package_version')
            """);

        await ResetMigrationAsync("delete_migrated_proxy_package_versions");
        await NewInitializer(_db).InitializeAsync();

        // Proxy PV and its pv-arm vuln are gone.
        long proxyPvCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE id = 'pv-proxy2'");
        long pvvPvCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns WHERE id = 'pvv-pv'");
        Assert.Equal(0, proxyPvCount);
        Assert.Equal(0, pvvPvCount);

        // ca-arm vuln (global plane twin) survives.
        long pvvCaCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns WHERE id = 'pvv-ca'");
        Assert.Equal(1, pvvCaCount);

        // Uploaded PV and its pv-arm vuln survive.
        long uploadPvCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE id = 'pv-upload2'");
        long pvvUpCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns WHERE id = 'pvv-up'");
        Assert.Equal(1, uploadPvCount);
        Assert.Equal(1, pvvUpCount);
    }

    // ── Seed helpers ─────────────────────────────────────────────────────────────────────────────

    private static async Task SeedMinimalOrgAsync(DbConnection conn, string orgId)
    {
        await conn.ExecuteAsync("""
            INSERT OR IGNORE INTO orgs (id, slug)
            VALUES (@id, @id)
            """, new { id = orgId });
    }

    private static async Task SeedMinimalPackageVersionAsync(DbConnection conn, string orgId, string pvId)
    {
        await SeedMinimalOrgAsync(conn, orgId);
        string pkgId = $"pkg-{pvId}";
        await conn.ExecuteAsync("""
            INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@pkgId, @orgId, 'npm', 'test', 'test', 0)
            """, new { pkgId, orgId });
        await conn.ExecuteAsync("""
            INSERT OR IGNORE INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES (@pvId, @pkgId, '1.0.0', 'pkg:npm/test@1.0.0', 'npm/registry/test/1.0.0/test-1.0.0.tgz')
            """, new { pvId, pkgId });
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
