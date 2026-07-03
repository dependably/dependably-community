using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the Redis-blip fix for <see cref="TenantHardDeleteService.RunPassAsync"/>: a
/// distributed-lock backend failure (Redis connection exception/failover, not a clean
/// "lock held" null response) during the sweep-lock acquire must be treated as a skipped pass,
/// not an unhandled exception. Pre-fix, the acquire call sat outside any try/catch and
/// ExecuteAsync's cron loop has no catch around RunPassAsync at all, so this exception would
/// escape and — under BackgroundService's default StopHost behavior — take the whole replica
/// down on a routine Redis hiccup.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantHardDeleteServiceResilienceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TenantHardDeleteServiceResilienceTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);

    // Always throws on TryAcquireAsync (models a Redis connection blip/failover), distinct from
    // a clean "lock held" null response.
    private sealed class AlwaysThrowingLock : IDistributedLock
    {
        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default) =>
            throw new InvalidOperationException("simulated distributed-lock backend failure (e.g. Redis connection blip)");

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
            throw new InvalidOperationException("simulated distributed-lock backend failure (e.g. Redis connection blip)");
    }

    // Throws on the first attempt only (a transient blip), then delegates to a real in-process
    // lock so the next attempt succeeds — models the backend recovering before the next tick.
    private sealed class ThrowOnceThenGrantLock : IDistributedLock
    {
        private readonly InProcessDistributedLock _inner;
        private int _attempts;

        public ThrowOnceThenGrantLock(TimeProvider time) => _inner = new InProcessDistributedLock(time);

        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
        {
            _attempts++;
            return _attempts == 1
                ? throw new InvalidOperationException("simulated distributed-lock backend failure (e.g. Redis connection blip)")
                : _inner.TryAcquireAsync(name, ttl, ct);
        }

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
            _inner.AcquireAsync(name, ttl, wait, retryInterval, ct);
    }

    private static TenantHardDeleteService BuildService(IMetadataStore db, IDistributedLock locks, TimeProvider clock)
    {
        var orgs = new OrgRepository(db, null, clock);
        var audit = new AuditRepository(db, null, clock);
        var banners = new BannerRepository(db, clock);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TENANT_HARD_DELETE_GRACE_DAYS"] = "0",
            })
            .Build();
        return new TenantHardDeleteService(
            orgs, audit, db, banners, config,
            new AirGapMode(config),
            locks,
            NullLogger<TenantHardDeleteService>.Instance,
            clock);
    }

    [Fact]
    public async Task RunPassAsync_LockAcquireThrows_DoesNotPropagate()
    {
        // This test fails on the pre-fix code (the exception from TryAcquireAsync propagates
        // straight out of RunPassAsync — and, since ExecuteAsync's cron loop has no catch around
        // RunPassAsync at all, would escape all the way out and fault the hosted service) and
        // passes on the fix (the exception is caught, logged, and the pass returns as a skipped
        // sweep).
        var clock = TestTime.Frozen(KnownNow);
        var svc = BuildService(_fixture.Store, new AlwaysThrowingLock(), clock);

        var ex = await Record.ExceptionAsync(() => svc.RunPassAsync(CancellationToken.None));

        Assert.Null(ex);
    }

    [Fact]
    public async Task RunPassAsync_LockAcquireThrowsThenRecovers_NextPassStillHardDeletesExpiredTenant()
    {
        // "the next tick still runs" contract: a lock-acquire failure on one pass must not
        // prevent a subsequent pass (once the backend recovers) from doing its real work.
        var clock = TestTime.Frozen(KnownNow);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"blip-recover-{Guid.NewGuid():N}");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
                new { dt = KnownNow.AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ssZ"), id = orgId });
        }

        var recoveringLock = new ThrowOnceThenGrantLock(clock);
        var svc = BuildService(_fixture.Store, recoveringLock, clock);

        // First pass: the lock backend blips — skipped, no throw, org survives.
        var ex = await Record.ExceptionAsync(() => svc.RunPassAsync(CancellationToken.None));
        Assert.Null(ex);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            int survivingCount = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId });
            Assert.Equal(1, survivingCount);
        }

        // Second pass: the backend has recovered — the sweep runs and hard-deletes the org.
        await svc.RunPassAsync(CancellationToken.None);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            int deletedCount = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId });
            Assert.Equal(0, deletedCount);
        }
    }
}
