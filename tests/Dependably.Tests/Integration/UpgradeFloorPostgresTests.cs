using Dapper;
using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;
using static Dependably.Tests.Integration.ConstraintRetrofitLockBoundPostgresTests;

namespace Dependably.Tests.Integration;

/// <summary>
/// The upgrade floor on Postgres, including its one documented exception: a database created by
/// 0.2.2 to 0.4.4 upgrades directly, because no release between it and the floor can start on it.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class UpgradeFloorPostgresTests
{
    private static async Task ForgetFloorAsync(System.Data.Common.DbConnection conn) =>
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN ('expand_usage_daily_meter_check_cache_storage', 'upgrade_floor_0_13_3')");

    [Fact]
    public async Task DatabaseBelowTheFloor_IsRefused()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await using var conn = await pg.Store.OpenAsync();
        await ForgetFloorAsync(conn);

        await Assert.ThrowsAsync<UpgradeFloorException>(() => new SchemaInitializer(pg.Store).InitializeAsync());
    }

    // A 0.2.2-0.4.4 database on which a 0.14.x boot got through the additive pass (which adds
    // nuget_symbol_index.cache_artifact_id) and then failed before recording the sentinel or the marker.
    private static async Task SeedPrePlaneDatabaseAfterAFailedLaterBootAsync(System.Data.Common.DbConnection conn)
    {
        await ForgetFloorAsync(conn);
        await conn.ExecuteAsync("ALTER TABLE nuget_symbol_index DROP COLUMN cache_artifact_id CASCADE");
        await conn.ExecuteAsync("ALTER TABLE nuget_symbol_index ADD COLUMN cache_artifact_id TEXT");
    }

    [Fact]
    public async Task PrePlaneDatabaseAfterAFailedLaterBoot_IsRefused_WithTheOverrideNamedForThatCase()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await using var conn = await pg.Store.OpenAsync();
        await SeedPrePlaneDatabaseAfterAFailedLaterBootAsync(conn);

        var ex = await Assert.ThrowsAsync<UpgradeFloorException>(() => new SchemaInitializer(pg.Store).InitializeAsync());

        Assert.Contains("created by 0.2.2 to 0.4.4", ex.Message, StringComparison.Ordinal);
        Assert.Contains("UPGRADE_FLOOR_OVERRIDE=true for one boot", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'upgrade_floor_0_13_3'"));
    }

    [Fact]
    public async Task PrePlaneDatabaseAfterAFailedLaterBoot_BootsWithTheOverride_AndRecordsTheMarker()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await using var conn = await pg.Store.OpenAsync();
        await SeedPrePlaneDatabaseAfterAFailedLaterBootAsync(conn);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["UPGRADE_FLOOR_OVERRIDE"] = "true" })
            .Build();

        await new SchemaInitializer(pg.Store, config: config).InitializeAsync();

        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'upgrade_floor_0_13_3'"));

        // Recorded, so the next boot needs no override.
        await new SchemaInitializer(pg.Store).InitializeAsync();
    }

    [Fact]
    public async Task DatabaseCreatedBeforeTheOwnerPlane_UpgradesDirectly()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await using var conn = await pg.Store.OpenAsync();
        await ForgetFloorAsync(conn);
        await conn.ExecuteAsync("ALTER TABLE nuget_symbol_index DROP COLUMN cache_artifact_id CASCADE");

        var ex = await Record.ExceptionAsync(() => new SchemaInitializer(pg.Store).EnforceUpgradeFloorAsync(conn));

        Assert.Null(ex);
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'upgrade_floor_0_13_3'"));
    }
}
