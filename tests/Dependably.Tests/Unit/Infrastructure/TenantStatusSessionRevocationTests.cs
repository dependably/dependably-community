using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Session revocation on a tenant lifecycle change. <see cref="OrgRepository.UpdateOrgStatusAsync"/>
/// must, whenever a tenant enters or leaves a lockout status (every status but <c>active</c> and
/// <c>read_only</c>), bump <c>token_version</c> and rotate <c>security_stamp</c> for every member,
/// drop their tenant-realm remembered devices in the same transaction, and evict each cached
/// version after the commit. <see cref="OrgRepository.SoftDeleteOrgAsync"/> and
/// <see cref="OrgRepository.RestoreOrgAsync"/> do the same. Other tenants are never touched.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantStatusSessionRevocationTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TenantStatusSessionRevocationTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private sealed record Tenant(string OrgId, string UserA, string UserB);

    private async Task<Tenant> SeedTenantAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"tsr-{Guid.NewGuid():N}");
        string a = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"a-{Guid.NewGuid():N}@x.test");
        string b = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"b-{Guid.NewGuid():N}@x.test");
        return new Tenant(orgId, a, b);
    }

    private OrgRepository Repo(UserTokenVersionStore? versions = null) =>
        new(_fixture.Store, time: TestTime.Frozen(), tokenVersions: versions);

    private TrustedDeviceService TrustedDevices() =>
        new(_fixture.Store, TestTime.Frozen(), new ConfigurationBuilder().Build());

    // Written around the application: the mint gate refuses a device for a soft-deleted tenant, and
    // these cases exercise the lifecycle write's backstop for a row that got there anyway.
    private async Task InsertDeviceDirectAsync(string userId, string orgId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO mfa_trusted_devices (id, user_id, realm, tenant_id, token_hash, expires_at) VALUES (@id, @userId, 'tenant', @orgId, @hash, '2999-01-01T00:00:00Z')",
            new { id = Guid.NewGuid().ToString("N"), userId, orgId, hash = Guid.NewGuid().ToString("N") });
    }

    private async Task SeedDevicesAsync(Tenant t)
    {
        await InsertDeviceDirectAsync(t.UserA, t.OrgId);
        await InsertDeviceDirectAsync(t.UserB, t.OrgId);
        // A system-realm row that happens to share a member's id is a different principal.
        await TrustedDevices().CreateAsync(t.UserA, "system", null, "ua");
    }

    // ── Which transitions revoke ─────────────────────────────────────────────

    [Theory]
    [InlineData("active", "suspended", true)]
    [InlineData("read_only", "suspended", true)]
    [InlineData("suspended", "suspended", true)]
    [InlineData("suspended", "active", true)]
    [InlineData("suspended", "read_only", true)]
    [InlineData("archived", "active", true)]
    [InlineData("deleting", "active", true)]
    [InlineData("active", "read_only", false)]
    [InlineData("read_only", "active", false)]
    [InlineData("active", "active", false)]
    public async Task UpdateOrgStatus_RevokesEveryMemberExactlyWhenALockoutIsEnteredOrLeft(
        string from, string to, bool revokes)
    {
        // Mixed scenario: a second tenant with its own members and devices sits beside the target
        // and must come through every transition untouched.
        var target = await SeedTenantAsync();
        var other = await SeedTenantAsync();
        await SeedDevicesAsync(target);
        await SeedDevicesAsync(other);
        await SetOrgStatusRawAsync(target.OrgId, from);
        var a = await ReadUserAsync(target.UserA);
        var b = await ReadUserAsync(target.UserB);
        var otherA = await ReadUserAsync(other.UserA);

        Assert.True((await Repo().UpdateOrgStatusAsync(target.OrgId, to)).Applied);

        Assert.Equal(to, await ReadOrgStatusAsync(target.OrgId));
        var aAfter = await ReadUserAsync(target.UserA);
        var bAfter = await ReadUserAsync(target.UserB);
        if (revokes)
        {
            Assert.Equal(a.Version + 1, aAfter.Version);
            Assert.Equal(b.Version + 1, bAfter.Version);
            Assert.NotEqual(a.Stamp, aAfter.Stamp);
            Assert.NotNull(aAfter.Stamp);
            Assert.NotEqual(b.Stamp, bAfter.Stamp);
            Assert.Equal(0, await CountTenantDevicesAsync(target.OrgId));
        }
        else
        {
            Assert.Equal(a, aAfter);
            Assert.Equal(b, bAfter);
            Assert.Equal(2, await CountTenantDevicesAsync(target.OrgId));
        }

        Assert.Equal(1, await CountDevicesAsync(target.UserA, "system"));
        Assert.Equal(otherA, await ReadUserAsync(other.UserA));
        Assert.Equal(2, await CountTenantDevicesAsync(other.OrgId));
        Assert.Equal("active", await ReadOrgStatusAsync(other.OrgId));
    }

    [Theory]
    [InlineData("active", "suspended", true)]
    [InlineData("read_only", "suspended", true)]
    [InlineData("suspended", "active", true)]
    [InlineData("archived", "read_only", true)]
    [InlineData("deleting", "active", true)]
    [InlineData("read_only", "active", false)]
    [InlineData("active", "read_only", false)]
    [InlineData("active", "active", false)]
    public void RevokesAccess_OnEnteringOrLeavingALockout_ReadOnlyIsNotOne(string prior, string next, bool expected)
    {
        Assert.Equal(expected, OrgRepository.RevokesAccess(prior, next));
    }

    [Fact]
    public async Task SuspendThenRestore_LeavesPreSuspensionVersionsStale()
    {
        var t = await SeedTenantAsync();
        long issuedAt = (await ReadUserAsync(t.UserA)).Version;
        var sut = Repo();

        await sut.UpdateOrgStatusAsync(t.OrgId, "suspended");
        await sut.UpdateOrgStatusAsync(t.OrgId, "active");

        Assert.True(issuedAt < (await ReadUserAsync(t.UserA)).Version);
    }

    // ── Refused writes revoke nothing ────────────────────────────────────────

    [Fact]
    public async Task UpdateOrgStatus_OnASoftDeletedTenant_ChangesNothing()
    {
        var t = await SeedTenantAsync();
        var sut = Repo();
        await sut.SoftDeleteOrgAsync(t.OrgId);
        await SeedDevicesAsync(t);
        var a = await ReadUserAsync(t.UserA);

        Assert.False((await sut.UpdateOrgStatusAsync(t.OrgId, "suspended")).Applied);

        Assert.Equal(a, await ReadUserAsync(t.UserA));
        Assert.Equal(2, await CountTenantDevicesAsync(t.OrgId));
        Assert.Equal("active", await ReadOrgStatusAsync(t.OrgId));
    }

    [Theory]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task UpdateOrgStatus_RejectedStatus_ChangesNothing(string status)
    {
        var t = await SeedTenantAsync();
        await SeedDevicesAsync(t);
        var a = await ReadUserAsync(t.UserA);

        Assert.False((await Repo().UpdateOrgStatusAsync(t.OrgId, status)).Applied);

        Assert.Equal(a, await ReadUserAsync(t.UserA));
        Assert.Equal(2, await CountTenantDevicesAsync(t.OrgId));
    }

    // ── Soft-delete and restore ──────────────────────────────────────────────

    [Fact]
    public async Task SoftDeleteAndRestore_EachRevokeTheMembers_AndLeaveOtherTenantsAlone()
    {
        var target = await SeedTenantAsync();
        var other = await SeedTenantAsync();
        await SeedDevicesAsync(target);
        await SeedDevicesAsync(other);
        long issuedAt = (await ReadUserAsync(target.UserA)).Version;
        var otherA = await ReadUserAsync(other.UserA);
        var sut = Repo();

        await sut.SoftDeleteOrgAsync(target.OrgId);
        Assert.Equal(issuedAt + 1, (await ReadUserAsync(target.UserA)).Version);
        Assert.Equal(0, await CountTenantDevicesAsync(target.OrgId));

        await InsertDeviceDirectAsync(target.UserB, target.OrgId);
        Assert.True((await sut.RestoreOrgAsync(target.OrgId)).Applied);
        Assert.Equal(issuedAt + 2, (await ReadUserAsync(target.UserA)).Version);
        Assert.Equal(0, await CountTenantDevicesAsync(target.OrgId));

        Assert.Equal(otherA, await ReadUserAsync(other.UserA));
        Assert.Equal(2, await CountTenantDevicesAsync(other.OrgId));
    }

    [Fact]
    public async Task Restore_OfATenantThatIsNotSoftDeleted_RevokesNothing()
    {
        var t = await SeedTenantAsync();
        await SeedDevicesAsync(t);
        var a = await ReadUserAsync(t.UserA);

        Assert.False((await Repo().RestoreOrgAsync(t.OrgId)).Applied);

        Assert.Equal(a, await ReadUserAsync(t.UserA));
        Assert.Equal(2, await CountTenantDevicesAsync(t.OrgId));
    }

    // ── The cached version cannot keep a session alive ───────────────────────

    [Theory]
    [InlineData("suspend")]
    [InlineData("soft-delete")]
    public async Task Lockout_EvictsEveryMembersCachedVersion(string action)
    {
        var t = await SeedTenantAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new UserTokenVersionStore(_fixture.Store, cache);

        // Prime the cache the way each member's live session does.
        long a = (await versions.GetCurrentVersionAsync(t.UserA))!.Value;
        long b = (await versions.GetCurrentVersionAsync(t.UserB))!.Value;

        var sut = Repo(versions);
        if (action == "suspend")
        {
            await sut.UpdateOrgStatusAsync(t.OrgId, "suspended");
        }
        else
        {
            await sut.SoftDeleteOrgAsync(t.OrgId);
        }

        // The members stay active, so the store answers their new version, not the cached one.
        Assert.Equal((long?)(a + 1), await versions.GetCurrentVersionAsync(t.UserA));
        Assert.Equal((long?)(b + 1), await versions.GetCurrentVersionAsync(t.UserB));
    }

    [Fact]
    public async Task Restore_EvictsEveryMembersCachedVersion()
    {
        var t = await SeedTenantAsync();
        await SetOrgStatusRawAsync(t.OrgId, "suspended");
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new UserTokenVersionStore(_fixture.Store, cache);
        long a = (await versions.GetCurrentVersionAsync(t.UserA))!.Value;

        await Repo(versions).UpdateOrgStatusAsync(t.OrgId, "active");

        Assert.Equal((long?)(a + 1), await versions.GetCurrentVersionAsync(t.UserA));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task SetOrgStatusRawAsync(string orgId, string status)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("UPDATE orgs SET status = @status WHERE id = @orgId", new { orgId, status });
    }

    private async Task<string> ReadOrgStatusAsync(string orgId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<string>("SELECT status FROM orgs WHERE id = @orgId", new { orgId });
    }

    private async Task<(long Version, string? Stamp)> ReadUserAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<(long, string?)>(
            "SELECT token_version, security_stamp FROM users WHERE id = @userId", new { userId });
    }

    private async Task<int> CountTenantDevicesAsync(string orgId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE tenant_id = @orgId AND realm = 'tenant'",
            new { orgId });
    }

    private async Task<int> CountDevicesAsync(string userId, string realm)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId AND realm = @realm",
            new { userId, realm });
    }
}
