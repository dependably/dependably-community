using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// A signed-in user's (or system admin's) own password change and the drop of that account's
/// remembered devices are one atomic change. A device row left behind by a fault between the two
/// would skip the second factor under the new password. A trigger makes the device delete fail,
/// so each test observes whether the password write survives it: it must roll back.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SelfServicePasswordChangeDeviceAtomicityTests : IAsyncLifetime
{
    private const string OldPassword = "Password12345";
    private const string NewPassword = "Fresh-Passw0rd!";

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

    private async Task<(string Hash, long Version)> CredentialAsync(string table, string id)
    {
        await using var conn = await _db.OpenAsync();
        // rawsql: table is a literal supplied by this test, never user input
        return await conn.QuerySingleAsync<(string, long)>(
            $"SELECT password_hash, token_version FROM {table} WHERE id = @id", new { id });
    }

    private async Task<long> DeviceCountAsync(string userId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId", new { userId });
    }

    private async Task<(string UserId, TrustedDeviceService Devices, UserService Sut)> SeedUserAsync(string slug)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, slug);
        string userId = await UserSeeder.InsertAsync(_db, orgId, $"me@{slug}.test", password: OldPassword);
        var devices = Devices();
        await devices.CreateAsync(userId, "tenant", orgId, "ua");
        return (userId, devices, new UserService(_db, new OrgRepository(_db), trustedDevices: devices));
    }

    [Fact]
    public async Task UserChange_FailedDeviceDelete_RollsBackThePasswordWrite()
    {
        var (userId, _, sut) = await SeedUserAsync("chg-atomic");
        var before = await CredentialAsync("users", userId);
        await FailDeviceDeletesAsync();

        await Assert.ThrowsAsync<SqliteException>(() => sut.ChangePasswordAsync(userId, OldPassword, NewPassword));

        Assert.Equal(before, await CredentialAsync("users", userId));
        Assert.Equal(1, await DeviceCountAsync(userId));
    }

    [Fact]
    public async Task UserChange_CommitsThePasswordAndTheDeviceDeleteTogether()
    {
        var (userId, _, sut) = await SeedUserAsync("chg-commit");
        var before = await CredentialAsync("users", userId);

        var result = await sut.ChangePasswordAsync(userId, OldPassword, NewPassword);

        Assert.Equal(PasswordChangeOutcome.Success, result.Outcome);
        var after = await CredentialAsync("users", userId);
        Assert.NotEqual(before.Hash, after.Hash);
        Assert.Equal(before.Version + 1, after.Version);
        Assert.Equal(after.Version, result.NewTokenVersion);
        Assert.Equal(0, await DeviceCountAsync(userId));
    }

    [Fact]
    public async Task UserChange_WrongCurrentPassword_LeavesTheDevicesAlone()
    {
        var (userId, _, sut) = await SeedUserAsync("chg-wrong");

        var result = await sut.ChangePasswordAsync(userId, "not-the-password", NewPassword);

        Assert.Equal(PasswordChangeOutcome.CurrentPasswordIncorrect, result.Outcome);
        Assert.Equal(1, await DeviceCountAsync(userId));
    }

    [Fact]
    public async Task SystemAdminChange_FailedDeviceDelete_RollsBackThePasswordWrite()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_db, "self@x.test", OldPassword);
        var devices = Devices();
        await devices.CreateAsync(adminId, "system", null, "ua");
        var before = await CredentialAsync("system_admins", adminId);
        await FailDeviceDeletesAsync();

        var sut = new SystemAdminRepository(_db, TestTime.Frozen(), trustedDevices: devices);
        await Assert.ThrowsAsync<SqliteException>(() => sut.RotatePasswordAsync(
            adminId, OldPassword, BCrypt.Net.BCrypt.HashPassword(NewPassword, workFactor: 4)));

        Assert.Equal(before, await CredentialAsync("system_admins", adminId));
        Assert.Equal(1, await DeviceCountAsync(adminId));
    }

    [Fact]
    public async Task SystemAdminChange_CommitsThePasswordAndTheDeviceDeleteTogether()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_db, "self2@x.test", OldPassword);
        var devices = Devices();
        await devices.CreateAsync(adminId, "system", null, "ua");
        var before = await CredentialAsync("system_admins", adminId);

        var sut = new SystemAdminRepository(_db, TestTime.Frozen(), trustedDevices: devices);
        long? version = await sut.RotatePasswordAsync(
            adminId, OldPassword, BCrypt.Net.BCrypt.HashPassword(NewPassword, workFactor: 4));

        var after = await CredentialAsync("system_admins", adminId);
        Assert.Equal(after.Version, version);
        Assert.NotEqual(before.Hash, after.Hash);
        Assert.Equal(0, await DeviceCountAsync(adminId));
    }

    [Fact]
    public async Task SystemAdminChange_WrongCurrentPassword_LeavesTheDevicesAlone()
    {
        string adminId = await SystemAdminSeeder.InsertAsync(_db, "self3@x.test", OldPassword);
        var devices = Devices();
        await devices.CreateAsync(adminId, "system", null, "ua");

        var sut = new SystemAdminRepository(_db, TestTime.Frozen(), trustedDevices: devices);
        Assert.Null(await sut.RotatePasswordAsync(adminId, "wrong", "hash"));

        Assert.Equal(1, await DeviceCountAsync(adminId));
    }
}
