using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Hard-deleting a tenant carries the same Art. 17 erasure obligation as removing one member
/// (<see cref="OrgRepository.RemoveOrgMemberAsync"/>), for every member of the tenant at once:
/// login_attempts/account_send_throttle rows are keyed by
/// <see cref="LoginService.HashLockoutKey"/> over (realm, tenantId, email), carry no FK to
/// <c>orgs</c>, and so are never reached by the FK cascade that removes the rest of a hard-deleted
/// tenant's data. Every seeded row here is written through the real
/// <see cref="SqliteLockoutStore"/>/<see cref="AccountSendThrottle"/> classes and the real
/// <see cref="LoginService.HashLockoutKey"/> — never a hash recomputed by hand in the test.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantHardDeleteServiceLockoutErasureTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TenantHardDeleteServiceLockoutErasureTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);

    private static TenantHardDeleteService BuildService(IMetadataStore db, TimeProvider clock)
    {
        var orgs = new OrgRepository(db, null, clock);
        var audit = new AuditRepository(db, null, clock);
        var banners = new BannerRepository(db, clock);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TENANT_HARD_DELETE_GRACE_DAYS"] = "0" })
            .Build();
        return new TenantHardDeleteService(
            orgs, audit, db, banners, config,
            new AirGapMode(config),
            new InProcessDistributedLock(clock),
            NullLogger<TenantHardDeleteService>.Instance,
            clock);
    }

    private async Task ExpireAsync(string orgId, DateTimeOffset clockNow)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
            new { dt = clockNow.AddDays(-60).ToUtcIso(), id = orgId });
    }

    private async Task<int> CountAsync(string sql, object p)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(sql, p);
    }

    private async Task SeedLockoutAsync(FakeTimeProvider clock, string lockoutKey, int failedCount)
    {
        var lockout = new SqliteLockoutStore(_fixture.Store, clock);
        await lockout.RecordFailureAsync(lockoutKey, failedCount, lockedUntil: null, ct: default);
    }

    private async Task SeedSendThrottleAsync(FakeTimeProvider clock, string lockoutKey)
    {
        var config = new ConfigurationBuilder().Build();
        var throttle = new AccountSendThrottle(_fixture.Store, clock, config, NullLogger<AccountSendThrottle>.Instance);
        await throttle.TryConsumeAsync(lockoutKey, AccountSendThrottle.PurposePasswordReset, default);
    }

    [Fact]
    public async Task RunPassAsync_HardDeletingATenant_ClearsEveryMembersLockoutAndSendThrottleRow()
    {
        var clock = TestTime.Frozen(KnownNow);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"hd-lockout-{Guid.NewGuid():N}");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "member1@hd.test");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "member2@hd.test");
        await ExpireAsync(orgId, clock.GetUtcNow());

        string key1 = LoginService.HashLockoutKey("tenant", orgId, "member1@hd.test");
        string key2 = LoginService.HashLockoutKey("tenant", orgId, "member2@hd.test");
        await SeedLockoutAsync(clock, key1, failedCount: 2);
        await SeedLockoutAsync(clock, key2, failedCount: 3);
        await SeedSendThrottleAsync(clock, key1);
        await SeedSendThrottleAsync(clock, key2);

        var svc = BuildService(_fixture.Store, clock);
        var ex = await Record.ExceptionAsync(() => svc.RunPassAsync(CancellationToken.None));
        Assert.Null(ex);

        // The tenant is actually gone.
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId }));

        // Both members' lockout and send-throttle rows went with it.
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = key1 }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = key2 }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = key1 }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = key2 }));
    }

    [Fact]
    public async Task RunPassAsync_HardDeletingOneTenant_DoesNotClearASurvivingTenantsRow_EvenAtTheSameEmail()
    {
        var clock = TestTime.Frozen(KnownNow);

        // The tenant being hard-deleted.
        string expiredOrgId = await OrgSeeder.InsertAsync(_fixture.Store, $"hd-expired-{Guid.NewGuid():N}");
        await UserSeeder.InsertAsync(_fixture.Store, expiredOrgId, "shared@hd.test");
        await ExpireAsync(expiredOrgId, clock.GetUtcNow());

        // A surviving tenant (never soft-deleted) with a user at the EXACT SAME address. A fix
        // that keyed the erasure on the bare email (instead of the tenant-scoped
        // LoginService.HashLockoutKey) would erase this row too — that cross-tenant leak is
        // exactly what this test exists to catch.
        string survivingOrgId = await OrgSeeder.InsertAsync(_fixture.Store, $"hd-surviving-{Guid.NewGuid():N}");
        await UserSeeder.InsertAsync(_fixture.Store, survivingOrgId, "shared@hd.test");

        string expiredKey = LoginService.HashLockoutKey("tenant", expiredOrgId, "shared@hd.test");
        string survivingKey = LoginService.HashLockoutKey("tenant", survivingOrgId, "shared@hd.test");
        await SeedLockoutAsync(clock, expiredKey, failedCount: 4);
        await SeedLockoutAsync(clock, survivingKey, failedCount: 1);
        await SeedSendThrottleAsync(clock, expiredKey);
        await SeedSendThrottleAsync(clock, survivingKey);

        var svc = BuildService(_fixture.Store, clock);
        var ex = await Record.ExceptionAsync(() => svc.RunPassAsync(CancellationToken.None));
        Assert.Null(ex);

        // The hard-deleted tenant's row is gone.
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = expiredKey }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = expiredKey }));

        // The surviving tenant's row at the same address is untouched, and so is its user and org.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = survivingKey }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = survivingKey }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = survivingOrgId }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM users WHERE tenant_id = @id AND email = 'shared@hd.test'", new { id = survivingOrgId }));
    }
}
