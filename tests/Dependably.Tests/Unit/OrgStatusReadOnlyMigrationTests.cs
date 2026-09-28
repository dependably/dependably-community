using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit;

/// <summary>
/// Schema migration: <c>read_only</c> must be a permitted value of <c>orgs.status</c> on both
/// fresh and existing databases, and the one-time CHECK rewrite must be safe to run again on
/// every subsequent boot (the ledger records it once; a re-init after that must not fail or
/// double-apply). Mirrors <see cref="AuditorRoleMigrationTests"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgStatusReadOnlyMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task FreshSchema_AcceptsReadOnlyStatus()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES ('o1', 'acme', 'read_only')");

        string? status = await conn.ExecuteScalarAsync<string>(
            "SELECT status FROM orgs WHERE id = 'o1'");
        Assert.Equal("read_only", status);
    }

    [Fact]
    public async Task LegacySchemaWithOldCheck_MigratedInPlace_AcceptsReadOnly()
    {
        // Simulate a database that pre-dates this migration: recreate orgs with the OLD 4-value
        // CHECK, then re-run the schema initializer and assert the widen took.
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("DROP TABLE IF EXISTS orgs");
            // Minimal stand-in carrying the exact legacy CHECK text the SQLite rewrite targets.
            await setup.ExecuteAsync(
                "CREATE TABLE orgs (\n" +
                "    id TEXT PRIMARY KEY,\n" +
                "    slug TEXT NOT NULL UNIQUE,\n" +
                "    status TEXT NOT NULL DEFAULT 'active'\n" +
                "        CHECK (status IN ('active','suspended','archived','deleting'))\n" +
                ")");

            // Mark the migration as not-yet-applied so re-init runs it.
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_org_status_check_with_read_only'");

            // Sanity: legacy CHECK rejects 'read_only'.
            var ex = await Assert.ThrowsAsync<SqliteException>(() => setup.ExecuteAsync(
                "INSERT INTO orgs (id, slug, status) VALUES ('o-legacy','legacy','read_only')"));
            Assert.Contains("CHECK", ex.Message);
        }

        // Re-run initializer; the one-time migration should rewrite the CHECK.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await verify.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES ('o-after','after','read_only')");
        string? status = await verify.ExecuteScalarAsync<string>(
            "SELECT status FROM orgs WHERE id = 'o-after'");
        Assert.Equal("read_only", status);
    }

    /// <summary>
    /// The shape a long-lived SQLite database actually has: orgs.status was added by the additive
    /// ALTER ADD COLUMN, which cannot carry a CHECK, so there is nothing to widen. The migration
    /// must complete (the value is validated at the API) rather than fail startup.
    /// </summary>
    [Fact]
    public async Task LegacySchemaWhereStatusWasAddedWithoutACheck_BootsAndAcceptsReadOnly()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await TestSchemaViews.DropAsync(setup);
            await setup.ExecuteAsync("PRAGMA foreign_keys = OFF");
            await setup.ExecuteAsync("DROP TABLE IF EXISTS orgs");
            await setup.ExecuteAsync(
                "CREATE TABLE orgs (\n" +
                "    id          TEXT PRIMARY KEY,\n" +
                "    slug        TEXT NOT NULL UNIQUE,\n" +
                "    deleted_at  TEXT,\n" +
                "    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))\n" +
                ")");
            await setup.ExecuteAsync("ALTER TABLE orgs ADD COLUMN status TEXT NOT NULL DEFAULT 'active'");
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_org_status_check_with_read_only'");
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await verify.ExecuteAsync("INSERT INTO orgs (id, slug, status) VALUES ('o-alter', 'altered', 'read_only')");
        Assert.Equal("read_only", await verify.ExecuteScalarAsync<string>("SELECT status FROM orgs WHERE id = 'o-alter'"));
        Assert.Equal(1, await verify.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'expand_org_status_check_with_read_only'"));
    }

    [Fact]
    public async Task Migration_IsIdempotent_AcrossRepeatedBoots()
    {
        // Same legacy-shape setup as above, but re-run InitializeAsync three times after the
        // widen has already been recorded in the ledger — a reboot loop must not fail or
        // silently re-narrow the constraint.
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("DROP TABLE IF EXISTS orgs");
            await setup.ExecuteAsync(
                "CREATE TABLE orgs (\n" +
                "    id TEXT PRIMARY KEY,\n" +
                "    slug TEXT NOT NULL UNIQUE,\n" +
                "    status TEXT NOT NULL DEFAULT 'active'\n" +
                "        CHECK (status IN ('active','suspended','archived','deleting'))\n" +
                ")");
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_org_status_check_with_read_only'");
        }

        // Boot 1: applies the widen and records it.
        await new SchemaInitializer(_db).InitializeAsync();
        // Boots 2 and 3: the ledger already records the migration as applied — these must be
        // pure no-ops, not re-throw or re-narrow the constraint.
        await new SchemaInitializer(_db).InitializeAsync();
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await verify.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES ('o-reboot','reboot','read_only')");
        string? status = await verify.ExecuteScalarAsync<string>(
            "SELECT status FROM orgs WHERE id = 'o-reboot'");
        Assert.Equal("read_only", status);
    }
}
