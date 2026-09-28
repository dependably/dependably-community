using Dapper;
using Dependably.Infrastructure;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves the Postgres side of widening <c>usage_daily.meter</c>'s CHECK for
/// <c>cache_storage_bytes</c> against a LIVE server: dropping the auto-named constraint a fresh
/// install creates reproduces a database created before the widen shipped, and re-running
/// <see cref="SchemaInitializer"/> must both restore a constraint and admit the new value.
/// <c>org_usage_caps.meter</c> deliberately never widens for it — proxy-cache storage is billed
/// but not cappable. <see cref="Unit.UsageCacheStorageCheckMigrationTests"/> pins the same
/// behaviour on SQLite.
///
/// Tagged <c>Category=SchemaPostgres</c> — see <c>PostgresSchemaApplyTests</c> for why this only
/// runs where a live Postgres is attached.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class UsageCacheStorageCheckMigrationPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task Dropped_usage_daily_meter_check_is_restored_and_admits_cache_storage_bytes()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var initializer = new SchemaInitializer(pg.Store);
        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
            await conn.ExecuteAsync("ALTER TABLE usage_daily DROP CONSTRAINT usage_daily_meter_check");

            // Sanity: with the constraint gone entirely, the new value is (still) admitted, so
            // dropping the constraint is not itself the thing under test — restoring a NARROW one
            // is. Recreate the pre-widen constraint explicitly.
            await conn.ExecuteAsync(
                "ALTER TABLE usage_daily ADD CONSTRAINT usage_daily_meter_check " +
                "CHECK (meter IN ('egress_bytes', 'egress_metadata_bytes', 'storage_bytes'))");
            var ex = await Assert.ThrowsAsync<PostgresException>(() => conn.ExecuteAsync(
                "INSERT INTO usage_daily (org_id, meter, bucket, computed_at) " +
                "VALUES ('o1', 'cache_storage_bytes', '2026-09-24', '2026-09-24T00:00:00Z')"));
            Assert.Equal("23514", ex.SqlState); // check_violation
        }

        // Re-running the initializer must not fail on the ledger already recording this migration
        // applied on the earlier InitializeAsync call above — it must re-widen unconditionally via
        // drop-and-re-add, since the ledger only prevents a repeat run, not a manually re-narrowed
        // constraint. Reset the ledger to force the widen to run again against this narrowed state.
        await using (var conn = await pg.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_usage_daily_meter_check_cache_storage'");
        }

        await initializer.InitializeAsync();

        await using (var conn = await pg.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO usage_daily (org_id, meter, bucket, computed_at) " +
                "VALUES ('o1', 'cache_storage_bytes', '2026-09-24', '2026-09-24T00:00:00Z')");
            Assert.Equal(1L, await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM usage_daily WHERE meter = 'cache_storage_bytes'"));

            await Assert.ThrowsAsync<PostgresException>(() => conn.ExecuteAsync(
                "INSERT INTO usage_daily (org_id, meter, bucket, computed_at) " +
                "VALUES ('o1', 'made_up_meter', '2026-09-25', '2026-09-25T00:00:00Z')"));
        }
    }

    /// <summary>
    /// Proxy-cache storage is billed but never cappable: a fresh install's
    /// <c>org_usage_caps.meter</c> CHECK never admits <c>cache_storage_bytes</c> on Postgres either.
    /// </summary>
    [Fact]
    public async Task FreshInstall_OrgUsageCaps_NeverAdmitsCacheStorageBytes()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();

        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        var ex = await Assert.ThrowsAsync<PostgresException>(() => conn.ExecuteAsync(
            "INSERT INTO org_usage_caps (org_id, meter, cap_quantity) VALUES ('o1', 'cache_storage_bytes', 1000)"));
        Assert.Equal("23514", ex.SqlState); // check_violation
    }
}
