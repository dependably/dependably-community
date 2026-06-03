using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Schema migration for the deprecated-package policy split: <c>org_settings.block_deprecated</c>
/// must permit the new <c>block_new</c> / <c>block_all</c> values on both fresh and existing
/// databases, and any legacy <c>block</c> row must be rewritten to <c>block_all</c> (its
/// behaviour-preserving successor). Mirrors <see cref="AuditorRoleMigrationTests"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlockDeprecatedMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Theory]
    [InlineData("block_new")]
    [InlineData("block_all")]
    public async Task FreshSchema_AcceptsNewBlockDeprecatedValues(string mode)
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");

        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, block_deprecated) VALUES ('o1', @mode)",
            new { mode });

        var stored = await conn.ExecuteScalarAsync<string>(
            "SELECT block_deprecated FROM org_settings WHERE org_id = 'o1'");
        Assert.Equal(mode, stored);
    }

    [Fact]
    public async Task LegacySchemaWithOldCheck_MigratedInPlace_WidensCheckAndRewritesBlock()
    {
        // Simulate a database that pre-dates the split: recreate org_settings with the OLD
        // 3-value CHECK and a row holding the retired 'block' value, then re-run the initializer.
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-legacy','legacy')");
            await setup.ExecuteAsync("DROP TABLE IF EXISTS org_settings");
            // Minimal stand-in carrying the exact legacy CHECK text the SQLite rewrite targets;
            // the additive ALTERs re-add the remaining columns on re-init.
            await setup.ExecuteAsync(
                "CREATE TABLE org_settings (\n" +
                "    org_id TEXT PRIMARY KEY,\n" +
                "    block_deprecated TEXT NOT NULL DEFAULT 'off' CHECK (block_deprecated IN ('off', 'warn', 'block'))\n" +
                ")");
            await setup.ExecuteAsync(
                "INSERT INTO org_settings (org_id, block_deprecated) VALUES ('o-legacy', 'block')");

            // Mark both one-shots as not-yet-applied so re-init runs them.
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name IN ('expand_block_deprecated_check','migrate_block_deprecated_to_block_all')");

            // Sanity: the legacy CHECK rejects the new value.
            var ex = await Assert.ThrowsAsync<SqliteException>(() => setup.ExecuteAsync(
                "INSERT INTO org_settings (org_id, block_deprecated) VALUES ('o-x', 'block_all')"));
            Assert.Contains("CHECK", ex.Message);
        }

        // Re-run initializer; the CHECK widen + data rewrite should both apply.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        // Legacy 'block' row rewritten to 'block_all'.
        var migrated = await verify.ExecuteScalarAsync<string>(
            "SELECT block_deprecated FROM org_settings WHERE org_id = 'o-legacy'");
        Assert.Equal("block_all", migrated);

        // Widened CHECK now accepts block_new / block_all.
        await verify.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2','two')");
        await verify.ExecuteAsync(
            "INSERT INTO org_settings (org_id, block_deprecated) VALUES ('o2', 'block_new')");
        var stored = await verify.ExecuteScalarAsync<string>(
            "SELECT block_deprecated FROM org_settings WHERE org_id = 'o2'");
        Assert.Equal("block_new", stored);
    }
}
