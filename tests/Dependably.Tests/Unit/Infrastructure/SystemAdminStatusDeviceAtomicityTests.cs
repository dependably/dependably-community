using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Disabling a system admin and dropping their remembered devices are one atomic change. A device
/// row left behind by a fault between the two would skip the second factor once the admin is
/// re-activated. A trigger makes the device delete fail, so the test observes whether the status
/// write survives it: it must roll back with the failed delete.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemAdminStatusDeviceAtomicityTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task FailedDeviceDelete_RollsBackTheStatusWrite()
    {
        await SystemAdminSeeder.InsertAsync(_db, "peer@x.test");
        string adminId = await SystemAdminSeeder.InsertAsync(_db, "target@x.test");
        var devices = new TrustedDeviceService(_db, TestTime.Frozen(), new ConfigurationBuilder().Build());
        await devices.CreateAsync(adminId, "system", null, "ua");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "CREATE TRIGGER fail_device_delete BEFORE DELETE ON mfa_trusted_devices BEGIN SELECT RAISE(ABORT, 'injected'); END");
        }

        var sut = new SystemAdminRepository(_db, trustedDevices: devices);
        await Assert.ThrowsAsync<SqliteException>(() => sut.SetAccountStatusAsync(adminId, "disabled"));

        await using var check = await _db.OpenAsync();
        Assert.Equal("active", await check.ExecuteScalarAsync<string>(
            "SELECT account_status FROM system_admins WHERE id = @adminId", new { adminId }));
        Assert.Equal(1, await check.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @adminId", new { adminId }));
    }

    [Fact]
    public async Task Disabling_CommitsTheStatusAndTheDeviceDeleteTogether()
    {
        await SystemAdminSeeder.InsertAsync(_db, "peer@x.test");
        string adminId = await SystemAdminSeeder.InsertAsync(_db, "target@x.test");
        var devices = new TrustedDeviceService(_db, TestTime.Frozen(), new ConfigurationBuilder().Build());
        await devices.CreateAsync(adminId, "system", null, "ua");

        var sut = new SystemAdminRepository(_db, trustedDevices: devices);
        Assert.Equal(AdminAccountStatusChange.Updated, await sut.SetAccountStatusAsync(adminId, "disabled"));

        await using var check = await _db.OpenAsync();
        Assert.Equal("disabled", await check.ExecuteScalarAsync<string>(
            "SELECT account_status FROM system_admins WHERE id = @adminId", new { adminId }));
        Assert.Equal(0, await check.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @adminId", new { adminId }));
    }
}
