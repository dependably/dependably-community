using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Session revocation on a system admin's account-status change and deletion. Locking or
/// disabling an admin is how an operator cuts off a peer (offboarding, suspected compromise), so
/// <see cref="SystemAdminRepository.SetAccountStatusAsync"/> must stale every outstanding system
/// session (bump <c>token_version</c>, rotate <c>security_stamp</c>), evict the cached version
/// after the write, and drop remembered devices; <see cref="SystemAdminRepository.DeleteIfDisabledAsync"/>
/// must evict the cached version so a deleted admin's session has no TTL window.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemAdminAccountStatusRevocationTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public SystemAdminAccountStatusRevocationTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // Every seeded admin comes with an active peer, so the last-active guard never refuses the
    // status changes these tests make, whichever order the shared fixture runs them in.
    private async Task<string> SeedAdminAsync(string prefix = "sa")
    {
        await SystemAdminSeeder.InsertAsync(_fixture.Store, $"peer-{Guid.NewGuid():N}@x.test");
        return await SystemAdminSeeder.InsertAsync(_fixture.Store, $"{prefix}-{Guid.NewGuid():N}@x.test");
    }

    private TrustedDeviceService TrustedDevices() =>
        new(_fixture.Store, TestTime.Frozen(), new ConfigurationBuilder().Build());

    // ── Lock / disable: version bump and stamp rotation ──────────────────────

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task SetAccountStatus_NonActive_BumpsTokenVersionAndRotatesStamp(string status)
    {
        string adminId = await SeedAdminAsync();
        var (versionBefore, stampBefore) = await ReadAdminAsync(adminId);

        var sut = new SystemAdminRepository(_fixture.Store);
        Assert.Equal(AdminAccountStatusChange.Updated, await sut.SetAccountStatusAsync(adminId, status));

        var (versionAfter, stampAfter) = await ReadAdminAsync(adminId);
        Assert.Equal(versionBefore + 1, versionAfter);
        Assert.NotEqual(stampBefore, stampAfter);
    }

    // ── Lock / disable: the cached version cannot keep the session alive ─────

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task SetAccountStatus_NonActive_EvictsTheCachedVersion(string status)
    {
        string adminId = await SeedAdminAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new SystemAdminTokenVersionStore(_fixture.Store, cache);

        // Prime the cache the way a live session's request does.
        Assert.NotNull(await versions.GetCurrentVersionAsync(adminId));

        var sut = new SystemAdminRepository(_fixture.Store, adminTokenVersions: versions);
        await sut.SetAccountStatusAsync(adminId, status);

        // A non-active admin has no current version: every session fails on its next request.
        Assert.Null(await versions.GetCurrentVersionAsync(adminId));
    }

    // ── Re-activation never revives a session issued before the lock ─────────

    [Fact]
    public async Task SetAccountStatus_ReactivationAfterDisable_LeavesPreDisableSessionsStale()
    {
        string adminId = await SeedAdminAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new SystemAdminTokenVersionStore(_fixture.Store, cache);
        long issuedAt = (await versions.GetCurrentVersionAsync(adminId))!.Value;

        var sut = new SystemAdminRepository(_fixture.Store, adminTokenVersions: versions);
        await sut.SetAccountStatusAsync(adminId, "disabled");
        await sut.SetAccountStatusAsync(adminId, "active");

        long? current = await versions.GetCurrentVersionAsync(adminId);
        Assert.NotNull(current);
        Assert.True(issuedAt < current!.Value, "a pre-disable tver must stay below the current version");
    }

    [Fact]
    public async Task SetAccountStatus_ReactivatingAnAdminDisabledWithoutABump_StillStalesItsSessions()
    {
        // A status written without a bump (a write path that predates the revocation, or a direct
        // database edit) must not let re-activation revive the sessions issued before it.
        string adminId = await SeedAdminAsync();
        long issuedAt = (await ReadAdminAsync(adminId)).Version;
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_admins SET account_status = 'disabled' WHERE id = @adminId", new { adminId });
        }

        var sut = new SystemAdminRepository(_fixture.Store);
        await sut.SetAccountStatusAsync(adminId, "active");

        Assert.True(issuedAt < (await ReadAdminAsync(adminId)).Version);
    }

    [Fact]
    public async Task SetAccountStatus_ActiveToActive_IsANoOpForSessions()
    {
        string adminId = await SeedAdminAsync();
        var before = await ReadAdminAsync(adminId);

        var sut = new SystemAdminRepository(_fixture.Store);
        Assert.Equal(AdminAccountStatusChange.Updated, await sut.SetAccountStatusAsync(adminId, "active"));

        Assert.Equal(before, await ReadAdminAsync(adminId));
    }

    [Fact]
    public async Task SetAccountStatus_MissingAdmin_ReturnsNotFound()
    {
        await SeedAdminAsync();
        var sut = new SystemAdminRepository(_fixture.Store);
        Assert.Equal(AdminAccountStatusChange.NotFound,
            await sut.SetAccountStatusAsync($"missing-{Guid.NewGuid():N}", "disabled"));
    }

    // ── Last-active guard: refused in the same transaction, nothing revoked ──

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task SetAccountStatus_LastActiveAdmin_IsRefusedAndChangesNothing(string status)
    {
        // A store of its own: the shared fixture holds other tests' active admins.
        await using var store = new TestMetadataStore();
        await new SchemaInitializer(store).InitializeAsync();
        string adminId = await SystemAdminSeeder.InsertAsync(store, $"alone-{Guid.NewGuid():N}@x.test");
        var devices = new TrustedDeviceService(store, TestTime.Frozen(), new ConfigurationBuilder().Build());
        await devices.CreateAsync(adminId, "system", null, "ua");
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new SystemAdminTokenVersionStore(store, cache);
        long? cached = await versions.GetCurrentVersionAsync(adminId);
        string? stampBefore;
        await using (var conn = await store.OpenAsync())
        {
            stampBefore = await conn.ExecuteScalarAsync<string?>(
                "SELECT security_stamp FROM system_admins WHERE id = @adminId", new { adminId });
        }

        var sut = new SystemAdminRepository(store, trustedDevices: devices, adminTokenVersions: versions);
        Assert.Equal(AdminAccountStatusChange.LastActiveAdmin, await sut.SetAccountStatusAsync(adminId, status));

        await using var check = await store.OpenAsync();
        var (accountStatus, stamp) = await check.QuerySingleAsync<(string, string?)>(
            "SELECT account_status, security_stamp FROM system_admins WHERE id = @adminId", new { adminId });
        Assert.Equal("active", accountStatus);
        Assert.Equal(stampBefore, stamp);
        Assert.Equal(cached, await versions.GetCurrentVersionAsync(adminId));
        Assert.Equal(1, await check.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @adminId AND realm = 'system'", new { adminId }));
    }

    [Fact]
    public async Task SetAccountStatus_ActivatingWithNoActiveAdmin_IsAllowed()
    {
        // Re-activation only raises the active count, so the guard never applies to it — even
        // when the instance has no active admin at all.
        await using var store = new TestMetadataStore();
        await new SchemaInitializer(store).InitializeAsync();
        string adminId = await SystemAdminSeeder.InsertAsync(store, $"revive-{Guid.NewGuid():N}@x.test");
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE system_admins SET account_status = 'disabled'");
        }

        var sut = new SystemAdminRepository(store);
        Assert.Equal(AdminAccountStatusChange.Updated, await sut.SetAccountStatusAsync(adminId, "active"));
    }

    // ── Trusted devices — mixed scenario: only the target's are dropped ──────

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task SetAccountStatus_NonActive_DropsOnlyTheTargetsTrustedDevices(string status)
    {
        string targetId = await SeedAdminAsync("target");
        string bystanderId = await SeedAdminAsync("bystander");
        var devices = TrustedDevices();
        await devices.CreateAsync(targetId, "system", null, "ua");
        await devices.CreateAsync(targetId, "system", null, "ua");
        await devices.CreateAsync(bystanderId, "system", null, "ua");
        long bystanderVersion = (await ReadAdminAsync(bystanderId)).Version;

        var sut = new SystemAdminRepository(_fixture.Store, trustedDevices: devices);
        await sut.SetAccountStatusAsync(targetId, status);

        Assert.Equal(0, await CountDevicesAsync(targetId));
        Assert.Equal(1, await CountDevicesAsync(bystanderId));
        Assert.Equal(bystanderVersion, (await ReadAdminAsync(bystanderId)).Version);
    }

    [Fact]
    public async Task SetAccountStatus_Reactivation_DropsDevicesWrittenWhileNonActive()
    {
        // A device row can appear while the admin is disabled (a second factor completing against
        // a challenge issued before the disable). Re-activation bumps the version, and drops the
        // devices with it, so the admin's next login needs the second factor.
        string adminId = await SeedAdminAsync();
        var devices = TrustedDevices();
        var sut = new SystemAdminRepository(_fixture.Store, trustedDevices: devices);
        await sut.SetAccountStatusAsync(adminId, "disabled");
        await devices.CreateAsync(adminId, "system", null, "ua");

        await sut.SetAccountStatusAsync(adminId, "active");

        Assert.Equal(0, await CountDevicesAsync(adminId));
    }

    [Fact]
    public async Task SetAccountStatus_ActiveToActive_KeepsTrustedDevices()
    {
        string adminId = await SeedAdminAsync();
        var devices = TrustedDevices();
        await devices.CreateAsync(adminId, "system", null, "ua");

        var sut = new SystemAdminRepository(_fixture.Store, trustedDevices: devices);
        Assert.Equal(AdminAccountStatusChange.Updated, await sut.SetAccountStatusAsync(adminId, "active"));

        Assert.Equal(1, await CountDevicesAsync(adminId));
    }

    // ── Delete: no cached window after the row is gone ───────────────────────

    [Fact]
    public async Task DeleteIfDisabled_EvictsTheCachedVersion()
    {
        string adminId = await SeedAdminAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new SystemAdminTokenVersionStore(_fixture.Store, cache);

        // Cache populated while the admin was active, then the status flipped by a write that did
        // not evict it: only the delete's own eviction stands between that entry and a full TTL.
        Assert.NotNull(await versions.GetCurrentVersionAsync(adminId));
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_admins SET account_status = 'disabled' WHERE id = @adminId", new { adminId });
        }

        var sut = new SystemAdminRepository(_fixture.Store, adminTokenVersions: versions);
        Assert.Equal(1, await sut.DeleteIfDisabledAsync(adminId));

        Assert.Null(await versions.GetCurrentVersionAsync(adminId));
    }

    // ── Fill race: a lookup straddling the status change does not re-cache ───

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task FillThatReadTheActiveRow_FinishingAfterAStatusChange_DoesNotRecacheIt(string status)
    {
        // A session validation reads the admin's version while the admin is still active; the
        // status change commits and invalidates between that read and the cache write. The fill
        // must not install the pre-change version after the invalidation, or the session the
        // operator just cut off survives for a full TTL.
        string adminId = await SeedAdminAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var hooked = new AfterDbReadHookStore(_fixture.Store);
        var versions = new SystemAdminTokenVersionStore(hooked, cache);
        var sut = new SystemAdminRepository(_fixture.Store, adminTokenVersions: versions);
        long preChange = (await ReadAdminAsync(adminId)).Version;

        hooked.AfterRead = () => sut.SetAccountStatusAsync(adminId, status);

        Assert.Equal(preChange, await versions.GetCurrentVersionAsync(adminId));

        Assert.Null(await versions.GetCurrentVersionAsync(adminId));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<(long Version, string? Stamp)> ReadAdminAsync(string adminId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<(long, string?)>(
            "SELECT token_version, security_stamp FROM system_admins WHERE id = @adminId", new { adminId });
    }

    private async Task<int> CountDevicesAsync(string adminId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @adminId AND realm = 'system'",
            new { adminId });
    }
}
