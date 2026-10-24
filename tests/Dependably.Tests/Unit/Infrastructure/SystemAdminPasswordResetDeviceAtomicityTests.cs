using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// An operator's password reset (of a tenant user, or of another system admin) and the drop of
/// that account's remembered devices are one atomic change. A device row left behind by a fault
/// between the two would skip the second factor the next time the account signs in with the new
/// password. A trigger makes the device delete fail, so each test observes whether the password
/// write survives it: it must roll back with the failed delete.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemAdminPasswordResetDeviceAtomicityTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private TrustedDeviceService Devices() =>
        new(_db, TestTime.Frozen(), new ConfigurationBuilder().Build());

    private async Task FailDeviceDeletesAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "CREATE TRIGGER fail_device_delete BEFORE DELETE ON mfa_trusted_devices BEGIN SELECT RAISE(ABORT, 'injected'); END");
    }

    private async Task<(string Hash, long Version)> UserCredentialAsync(string userId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<(string, long)>(
            "SELECT password_hash, token_version FROM users WHERE id = @userId", new { userId });
    }

    private async Task<(string Hash, long Version)> AdminCredentialAsync(string adminId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<(string, long)>(
            "SELECT password_hash, token_version FROM system_admins WHERE id = @adminId", new { adminId });
    }

    private async Task<long> DeviceCountAsync(string userId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId", new { userId });
    }

    private async Task<long> UserTokenCountAsync(string userId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM user_tokens WHERE user_id = @userId", new { userId });
    }

    [Fact]
    public async Task TenantUserReset_FailedDeviceDelete_RollsBackThePasswordWrite()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "reset-atomic");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "target@reset-atomic.test");
        var devices = Devices();
        await devices.CreateAsync(userId, "tenant", orgId, "ua");
        await new TokenRepository(_db, TestTime.Frozen()).CreateUserTokenAsync(
            orgId, userId, Capabilities.ReaderCapsCanonicalJson, expiresAt: null);
        var before = await UserCredentialAsync(userId);
        await FailDeviceDeletesAsync();

        var sut = new SystemAdminRepository(_db, TestTime.Frozen(), trustedDevices: devices);
        await Assert.ThrowsAsync<SqliteException>(() =>
            sut.IssuePasswordResetAsync("target@reset-atomic.test", "reset-atomic"));

        Assert.Equal(before, await UserCredentialAsync(userId));
        Assert.Equal(1, await DeviceCountAsync(userId));
        Assert.Equal(1, await UserTokenCountAsync(userId));
    }

    [Fact]
    public async Task TenantUserReset_CommitsThePasswordAndTheDeviceDeleteTogether()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "reset-commit");
        string userId = await UserSeeder.InsertAsync(_db, orgId, "target@reset-commit.test");
        var devices = Devices();
        await devices.CreateAsync(userId, "tenant", orgId, "ua");
        var before = await UserCredentialAsync(userId);

        var sut = new SystemAdminRepository(_db, TestTime.Frozen(), trustedDevices: devices);
        Assert.NotNull(await sut.IssuePasswordResetAsync("target@reset-commit.test", "reset-commit"));

        var after = await UserCredentialAsync(userId);
        Assert.NotEqual(before.Hash, after.Hash);
        Assert.Equal(before.Version + 1, after.Version);
        Assert.Equal(0, await DeviceCountAsync(userId));
    }

    [Fact]
    public async Task SystemAdminReset_FailedDeviceDelete_RollsBackThePasswordWrite()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_db, "target@x.test");
        var devices = Devices();
        await devices.CreateAsync(adminId, "system", null, "ua");
        var before = await AdminCredentialAsync(adminId);
        await FailDeviceDeletesAsync();

        var sut = new SystemAdminRepository(_db, TestTime.Frozen(), trustedDevices: devices);
        await Assert.ThrowsAsync<SqliteException>(() => sut.ResetPasswordAsync(
            adminId, BCrypt.Net.BCrypt.HashPassword("Fresh-Passw0rd!", workFactor: 4), TestTime.Frozen().GetUtcNow()));

        Assert.Equal(before, await AdminCredentialAsync(adminId));
        Assert.Equal(1, await DeviceCountAsync(adminId));
    }

    [Fact]
    public async Task SystemAdminReset_CommitsThePasswordAndTheDeviceDeleteTogether()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_db, "target@x.test");
        var devices = Devices();
        await devices.CreateAsync(adminId, "system", null, "ua");
        var before = await AdminCredentialAsync(adminId);

        var sut = new SystemAdminRepository(_db, TestTime.Frozen(), trustedDevices: devices);
        Assert.True(await sut.ResetPasswordAsync(
            adminId, BCrypt.Net.BCrypt.HashPassword("Fresh-Passw0rd!", workFactor: 4), TestTime.Frozen().GetUtcNow()));

        var after = await AdminCredentialAsync(adminId);
        Assert.NotEqual(before.Hash, after.Hash);
        Assert.Equal(before.Version + 1, after.Version);
        Assert.Equal(0, await DeviceCountAsync(adminId));
    }

    [Fact]
    public async Task SystemAdminReset_UnknownAdmin_IsFalse_AndWritesNothing()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_db, "bystander@x.test");
        var devices = Devices();
        await devices.CreateAsync(adminId, "system", null, "ua");

        var sut = new SystemAdminRepository(_db, TestTime.Frozen(), trustedDevices: devices);
        Assert.False(await sut.ResetPasswordAsync(
            "no-such-admin", BCrypt.Net.BCrypt.HashPassword("Fresh-Passw0rd!", workFactor: 4), TestTime.Frozen().GetUtcNow()));

        Assert.Equal(1, await DeviceCountAsync(adminId));
    }
}
