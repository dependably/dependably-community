using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit;

/// <summary>
/// Widening <c>usage_daily.meter</c>'s closed CHECK for <c>cache_storage_bytes</c>. Fresh installs
/// pick the wider set up from the <c>CREATE TABLE</c> block; a database created before it needs
/// the stored constraint rewritten, or the first cache-storage mark an upgraded instance writes
/// fails its INSERT. <c>org_usage_caps.meter</c> deliberately does NOT widen: proxy-cache storage
/// is billed but not cappable, so <c>cache_storage_bytes</c> stays an unknown meter there on both
/// a fresh install and an upgraded database. Mirrors <see cref="AlertTypeCheckMigrationTests"/> and
/// <see cref="OrgStatusReadOnlyMigrationTests"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageCacheStorageCheckMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task LegacyUsageDailyCheck_IsWidenedInPlace_AndStillRefusesUnknownMeters()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("DROP TABLE IF EXISTS usage_daily");
            // Stand-in carrying the exact narrow CHECK text the SQLite rewrite targets.
            await setup.ExecuteAsync(
                "CREATE TABLE usage_daily (\n" +
                "    org_id            TEXT NOT NULL,\n" +
                "    meter             TEXT NOT NULL CHECK (meter IN ('egress_bytes', 'egress_metadata_bytes', 'storage_bytes')),\n" +
                "    bucket            TEXT NOT NULL,\n" +
                "    quantity          INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),\n" +
                "    redirect_quantity INTEGER NOT NULL DEFAULT 0 CHECK (redirect_quantity >= 0),\n" +
                "    request_count     INTEGER NOT NULL DEFAULT 0,\n" +
                "    computed_at       TEXT NOT NULL,\n" +
                "    PRIMARY KEY (org_id, meter, bucket)\n" +
                ")");
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_usage_daily_meter_check_cache_storage'");

            // Sanity: without the widen, the new meter is refused.
            var ex = await Assert.ThrowsAsync<SqliteException>(() => setup.ExecuteAsync(
                "INSERT INTO usage_daily (org_id, meter, bucket, computed_at) " +
                "VALUES ('o1', 'cache_storage_bytes', '2026-09-24', '2026-09-24T00:00:00Z')"));
            Assert.Contains("CHECK", ex.Message);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await verify.ExecuteAsync(
            "INSERT INTO usage_daily (org_id, meter, bucket, computed_at) " +
            "VALUES ('o1', 'cache_storage_bytes', '2026-09-24', '2026-09-24T00:00:00Z')");
        Assert.Equal(1, await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM usage_daily WHERE meter = 'cache_storage_bytes'"));

        // Widening is not the same as removing: an unregistered meter is still refused.
        await Assert.ThrowsAsync<SqliteException>(() => verify.ExecuteAsync(
            "INSERT INTO usage_daily (org_id, meter, bucket, computed_at) " +
            "VALUES ('o1', 'made_up_meter', '2026-09-25', '2026-09-25T00:00:00Z')"));
    }

    /// <summary>
    /// The one-shot is idempotent, so a second boot after a crash that lost the ledger entry
    /// repeats it harmlessly rather than corrupting the stored CREATE text.
    /// </summary>
    [Fact]
    public async Task ReRunningTheWiden_IsANoOp()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var reset = await _db.OpenAsync())
        {
            await reset.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_usage_daily_meter_check_cache_storage'");
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await verify.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await verify.ExecuteAsync(
            "INSERT INTO usage_daily (org_id, meter, bucket, computed_at) " +
            "VALUES ('o1', 'cache_storage_bytes', '2026-09-24', '2026-09-24T00:00:00Z')");
        Assert.Equal("ok", await verify.ExecuteScalarAsync<string>("PRAGMA integrity_check"));
    }

    /// <summary>
    /// Proxy-cache storage is billed but never cappable: <c>org_usage_caps.meter</c> has no widen
    /// migration for <c>cache_storage_bytes</c>, on a fresh install or an upgraded database alike.
    /// </summary>
    [Fact]
    public async Task OrgUsageCaps_NeverAdmitsCacheStorageBytes()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "INSERT INTO org_usage_caps (org_id, meter, cap_quantity) VALUES ('o1', 'cache_storage_bytes', 1000)"));
    }
}
