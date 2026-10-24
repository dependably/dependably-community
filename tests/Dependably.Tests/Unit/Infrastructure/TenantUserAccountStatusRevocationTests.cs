using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Session revocation on a tenant user's account-status change.
/// <see cref="OrgRepository.SetUserAccountStatusAsync"/> must stale every outstanding tenant
/// session on every status change except active to active (bump <c>token_version</c>, rotate
/// <c>security_stamp</c>), evict the cached version after the write, and drop the user's
/// tenant-realm remembered devices whenever it bumps, re-activation included.
/// <see cref="UserTokenVersionStore"/> must answer null for a non-active user, so a status written
/// without the bump still ends the session on the next uncached read.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantUserAccountStatusRevocationTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TenantUserAccountStatusRevocationTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private sealed record SeededUser(string UserId, string OrgId, string Slug, string Email);

    private async Task<SeededUser> SeedUserAsync(string prefix = "u", string? slug = null, string? email = null)
    {
        slug ??= $"ts-{Guid.NewGuid():N}";
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, slug);
        email ??= $"{prefix}-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email);
        return new SeededUser(userId, orgId, slug, email);
    }

    private async Task<SeededUser> SeedUserInOrgAsync(SeededUser sibling, string prefix, string? email = null)
    {
        email ??= $"{prefix}-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, sibling.OrgId, email);
        return sibling with { UserId = userId, Email = email };
    }

    private OrgRepository Repo(UserTokenVersionStore? versions = null) =>
        new(_fixture.Store, time: TestTime.Frozen(), tokenVersions: versions);

    private TrustedDeviceService TrustedDevices() =>
        new(_fixture.Store, TestTime.Frozen(), new ConfigurationBuilder().Build());

    // ── Every status change except active to active bumps and rotates ────────

    [Theory]
    [InlineData("active", "locked")]
    [InlineData("active", "disabled")]
    [InlineData("disabled", "active")]
    [InlineData("locked", "active")]
    [InlineData("locked", "disabled")]
    public async Task SetUserAccountStatus_StatusChange_BumpsTokenVersionAndRotatesStamp(string from, string to)
    {
        var user = await SeedUserAsync();
        await SetStatusRawAsync(user.UserId, from);
        var (versionBefore, stampBefore) = await ReadUserAsync(user.UserId);

        Assert.True(await Repo().SetUserAccountStatusAsync(user.Email, user.Slug, to));

        var (versionAfter, stampAfter) = await ReadUserAsync(user.UserId);
        Assert.Equal(versionBefore + 1, versionAfter);
        Assert.NotEqual(stampBefore, stampAfter);
        Assert.NotNull(stampAfter);
    }

    [Fact]
    public async Task SetUserAccountStatus_ActiveToActive_IsANoOpForSessions()
    {
        var user = await SeedUserAsync();
        var before = await ReadUserAsync(user.UserId);

        Assert.True(await Repo().SetUserAccountStatusAsync(user.Email, user.Slug, "active"));

        Assert.Equal(before, await ReadUserAsync(user.UserId));
    }

    // ── The cached version cannot keep the session alive ─────────────────────

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task SetUserAccountStatus_NonActive_EvictsTheCachedVersion(string status)
    {
        var user = await SeedUserAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new UserTokenVersionStore(_fixture.Store, cache);

        // Prime the cache the way a live session's request does.
        Assert.NotNull(await versions.GetCurrentVersionAsync(user.UserId));

        await Repo(versions).SetUserAccountStatusAsync(user.Email, user.Slug, status);

        // A non-active user has no current version: every session fails on its next request.
        Assert.Null(await versions.GetCurrentVersionAsync(user.UserId));
    }

    // ── Re-activation never revives a session issued before the lock ─────────

    [Fact]
    public async Task SetUserAccountStatus_ReactivationAfterDisable_LeavesPreDisableSessionsStale()
    {
        var user = await SeedUserAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new UserTokenVersionStore(_fixture.Store, cache);
        long issuedAt = (await versions.GetCurrentVersionAsync(user.UserId))!.Value;

        var sut = Repo(versions);
        await sut.SetUserAccountStatusAsync(user.Email, user.Slug, "disabled");
        await sut.SetUserAccountStatusAsync(user.Email, user.Slug, "active");

        long? current = await versions.GetCurrentVersionAsync(user.UserId);
        Assert.NotNull(current);
        Assert.True(issuedAt < current!.Value, "a pre-disable tver must stay below the current version");
    }

    [Fact]
    public async Task SetUserAccountStatus_ReactivatingAUserDisabledWithoutABump_StillStalesItsSessions()
    {
        // A status written without a bump (a direct database edit, or any future write path that
        // forgets it) must not let re-activation revive the sessions issued before it.
        var user = await SeedUserAsync();
        long issuedAt = (await ReadUserAsync(user.UserId)).Version;
        await SetStatusRawAsync(user.UserId, "disabled");

        await Repo().SetUserAccountStatusAsync(user.Email, user.Slug, "active");

        Assert.True(issuedAt < (await ReadUserAsync(user.UserId)).Version);
    }

    // ── Sessions are bound to active status, not only to the version ─────────

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task StatusWrittenWithoutABump_EndsTheSessionOnTheNextUncachedRead(string status)
    {
        // The write skips both the bump and the eviction, so the cached entry serves until it
        // expires; the eviction below stands in for that TTL expiry. On the next read the
        // active-only lookup answers null, so the session fails even though tver still matches.
        var user = await SeedUserAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var versions = new UserTokenVersionStore(_fixture.Store, cache);
        long issuedAt = (await versions.GetCurrentVersionAsync(user.UserId))!.Value;

        await SetStatusRawAsync(user.UserId, status);
        Assert.Equal(issuedAt, (await ReadUserAsync(user.UserId)).Version);
        cache.Remove("user-token-version:" + user.UserId);

        Assert.Null(await versions.GetCurrentVersionAsync(user.UserId));
    }

    // ── Trusted devices — mixed scenario: only the target's are dropped ──────

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task SetUserAccountStatus_NonActive_DropsOnlyTheTargetsTenantDevices(string status)
    {
        // Bystanders: a colleague in the same tenant, a user with the same email in another
        // tenant (the status write is keyed by email + slug), and a system-realm row that happens
        // to share the target's id. None of them may lose a device or a session.
        var target = await SeedUserAsync("target");
        var colleague = await SeedUserInOrgAsync(target, "colleague");
        var namesake = await SeedUserAsync(email: target.Email);
        var devices = TrustedDevices();
        await devices.CreateAsync(target.UserId, "tenant", target.OrgId, "ua");
        await devices.CreateAsync(target.UserId, "tenant", target.OrgId, "ua");
        await devices.CreateAsync(target.UserId, "system", null, "ua");
        await devices.CreateAsync(colleague.UserId, "tenant", colleague.OrgId, "ua");
        await devices.CreateAsync(namesake.UserId, "tenant", namesake.OrgId, "ua");
        long colleagueVersion = (await ReadUserAsync(colleague.UserId)).Version;
        long namesakeVersion = (await ReadUserAsync(namesake.UserId)).Version;

        Assert.True(await Repo().SetUserAccountStatusAsync(target.Email, target.Slug, status));

        Assert.Equal(0, await CountDevicesAsync(target.UserId, "tenant"));
        Assert.Equal(1, await CountDevicesAsync(target.UserId, "system"));
        Assert.Equal(1, await CountDevicesAsync(colleague.UserId, "tenant"));
        Assert.Equal(1, await CountDevicesAsync(namesake.UserId, "tenant"));
        Assert.Equal(colleagueVersion, (await ReadUserAsync(colleague.UserId)).Version);
        Assert.Equal(namesakeVersion, (await ReadUserAsync(namesake.UserId)).Version);
        Assert.Equal("active", await ReadStatusAsync(namesake.UserId));
    }

    [Fact]
    public async Task SetUserAccountStatus_Reactivation_DropsDevicesWrittenWhileNonActive()
    {
        // A device row can appear while the user is disabled (a second factor completing against a
        // challenge issued before the disable, on code without the live re-check). Re-activation
        // bumps the version and drops the devices with it, so the next login needs the second
        // factor.
        var user = await SeedUserAsync();
        var devices = TrustedDevices();
        var sut = Repo();
        await sut.SetUserAccountStatusAsync(user.Email, user.Slug, "disabled");
        await devices.CreateAsync(user.UserId, "tenant", user.OrgId, "ua");

        await sut.SetUserAccountStatusAsync(user.Email, user.Slug, "active");

        Assert.Equal(0, await CountDevicesAsync(user.UserId, "tenant"));
    }

    [Fact]
    public async Task SetUserAccountStatus_ActiveToActive_KeepsTrustedDevices()
    {
        var user = await SeedUserAsync();
        await TrustedDevices().CreateAsync(user.UserId, "tenant", user.OrgId, "ua");

        Assert.True(await Repo().SetUserAccountStatusAsync(user.Email, user.Slug, "active"));

        Assert.Equal(1, await CountDevicesAsync(user.UserId, "tenant"));
    }

    // ── Fill race: a lookup straddling the status change does not re-cache ───

    [Theory]
    [InlineData("locked")]
    [InlineData("disabled")]
    public async Task FillThatReadTheActiveRow_FinishingAfterAStatusChange_DoesNotRecacheIt(string status)
    {
        // A session validation reads the user's version while the user is still active; the
        // status change commits and invalidates between that read and the cache write. The fill
        // must not install the pre-change version after the invalidation, or the session the
        // operator just cut off survives for a full TTL.
        var user = await SeedUserAsync();
        using var cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var hooked = new AfterDbReadHookStore(_fixture.Store);
        var versions = new UserTokenVersionStore(hooked, cache);
        var sut = Repo(versions);
        long preChange = (await ReadUserAsync(user.UserId)).Version;

        hooked.AfterRead = () => sut.SetUserAccountStatusAsync(user.Email, user.Slug, status);

        Assert.Equal(preChange, await versions.GetCurrentVersionAsync(user.UserId));

        Assert.Null(await versions.GetCurrentVersionAsync(user.UserId));
    }

    // ── Live second-factor re-check ──────────────────────────────────────────

    [Fact]
    public async Task IsUserActiveAtVersion_RequiresActiveStatusTheSameVersionAndTheSameTenant()
    {
        var user = await SeedUserAsync();
        var other = await SeedUserAsync("other");
        long version = (await ReadUserAsync(user.UserId)).Version;
        var sut = Repo();

        Assert.True(await sut.IsUserActiveAtVersionAsync(user.UserId, user.OrgId, version));
        Assert.False(await sut.IsUserActiveAtVersionAsync(user.UserId, user.OrgId, version - 1));
        Assert.False(await sut.IsUserActiveAtVersionAsync(user.UserId, other.OrgId, version));
        Assert.False(await sut.IsUserActiveAtVersionAsync($"missing-{Guid.NewGuid():N}", user.OrgId, version));

        // Not bumped, so only the status distinguishes this from the passing case above.
        await SetStatusRawAsync(user.UserId, "locked");
        Assert.False(await sut.IsUserActiveAtVersionAsync(user.UserId, user.OrgId, version));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task SetStatusRawAsync(string userId, string status)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE users SET account_status = @status WHERE id = @userId", new { userId, status });
    }

    private async Task<(long Version, string? Stamp)> ReadUserAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<(long, string?)>(
            "SELECT token_version, security_stamp FROM users WHERE id = @userId", new { userId });
    }

    private async Task<string> ReadStatusAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<string>(
            "SELECT account_status FROM users WHERE id = @userId", new { userId });
    }

    private async Task<int> CountDevicesAsync(string userId, string realm)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId AND realm = @realm",
            new { userId, realm });
    }
}
