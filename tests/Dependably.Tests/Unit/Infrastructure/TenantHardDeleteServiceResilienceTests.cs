using System.Data.Common;
using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.SystemEvents;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

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

    private static TenantHardDeleteService BuildService(
        IMetadataStore db, IDistributedLock locks, TimeProvider clock, ISystemEventNotifier? systemEvents = null)
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
            clock,
            systemEvents);
    }

    // Throws on the first Notify call (models a transient failure in the per-tenant delete work),
    // then succeeds. Notify runs after the org row is already deleted, so this exercises the
    // per-iteration guard: the throw must be caught and the batch must continue to the next org.
    private sealed class ThrowOnFirstNotify : ISystemEventNotifier
    {
        private int _calls;
        public void Notify(SystemEventRecord record)
        {
            _calls++;
            if (_calls == 1)
            {
                throw new InvalidOperationException("simulated transient failure in per-tenant delete work");
            }
        }
    }

    // Delegates every open to the inner store, but on the Nth open it first clears the target org's
    // deleted_at — modelling a system_admin restore that lands between the expired-list snapshot
    // (open #1, inside ListExpiredSoftDeletedOrgIdsAsync) and the loop's guarded DELETE (which uses
    // the shared connection opened at open #2). Restoring on open #2 reproduces exactly that race.
    private sealed class RestoreOnNthOpenStore : IMetadataStore
    {
        private readonly IMetadataStore _inner;
        private readonly string _orgId;
        private readonly int _restoreOnOpen;
        private int _opens;

        public RestoreOnNthOpenStore(IMetadataStore inner, string orgId, int restoreOnOpen)
        {
            _inner = inner;
            _orgId = orgId;
            _restoreOnOpen = restoreOnOpen;
        }

        public DbProvider Provider => _inner.Provider;

        public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            _opens++;
            if (_opens == _restoreOnOpen)
            {
                await using var restoreConn = await _inner.OpenAsync(ct);
                await restoreConn.ExecuteAsync(
                    "UPDATE orgs SET deleted_at = NULL WHERE id = @id AND deleted_at IS NOT NULL",
                    new { id = _orgId });
            }
            return await _inner.OpenAsync(ct);
        }
    }

    // The sweep-lock name RunPassAsync contends on. Mirrored here because the service keeps it
    // private; the second-acquirer assertion below has to name the same key.
    private const string SweepLockName = "tenant-hard-delete:sweep";

    // The sweep-lock TTL RunPassAsync acquires with.
    private static readonly TimeSpan SweepLockTtl = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The hard-delete sweep is destructive and can run long on a large tenant set. While it runs,
    /// its sweep lock must be renewed so a second replica cannot acquire the same lock and start a
    /// concurrent hard-delete pass. Pre-fix the lock was acquired once with a fixed TTL and never
    /// extended, so a sweep that outran the TTL kept deleting while another replica took the lock;
    /// this test fails there (no renewal ever lands) and passes on the lease.
    /// </summary>
    [Fact]
    public async Task RunPassAsync_SweepOutrunsLockTtl_LeaseRenewed_SecondReplicaRefused()
    {
        var clock = TestTime.Frozen(KnownNow);
        var locks = new LeasedTestLock(clock);
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"lease-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"lease-b-{Guid.NewGuid():N}");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @dt WHERE id IN (@a, @b)",
                new { dt = KnownNow.AddDays(-60).ToUtcIso(), a = orgA, b = orgB });
        }

        // Open 1 lists the expired orgs, open 2 is the batch connection, open 3 is the first
        // tenant's own read — the sweep is mid-batch by then.
        var slowStore = new LeaseProbeStore(
            _fixture.Store, clock, locks, SweepLockName, SweepLockTtl, probeOnOpen: 3);
        var svc = BuildService(slowStore, locks, clock);

        await svc.RunPassAsync(CancellationToken.None);

        Assert.True(locks.ExtendSuccesses >= 4,
            $"expected the sweep to renew its lease while running; got {locks.ExtendSuccesses} renewal(s)");
        Assert.True(slowStore.SecondAcquirerRefusedMidPass,
            "a second replica must not be able to acquire the sweep lock while the sweep is still running");

        // The sweep still completed its work, and released the lock when it finished.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            int survivors = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM orgs WHERE id IN (@a, @b)", new { a = orgA, b = orgB });
            Assert.Equal(0, survivors);
        }

        Assert.False(locks.IsHeld(SweepLockName));
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
                new { dt = KnownNow.AddDays(-60).ToUtcIso(), id = orgId });
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

    [Fact]
    public async Task RunPassAsync_PerTenantWorkThrows_DoesNotPropagateAndBatchContinues()
    {
        // Two expired tenants; the per-tenant notify throws on the first one processed. Pre-fix the
        // loop body had no per-iteration catch, so the throw escaped RunPassAsync — leaving the
        // second tenant undeleted and, in production, faulting the hosted BackgroundService (whole
        // replica down). Post-fix the throw is caught and the batch finishes: both tenants deleted,
        // no exception.
        var clock = TestTime.Frozen(KnownNow);
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"batch-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"batch-b-{Guid.NewGuid():N}");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @dt WHERE id IN (@a, @b)",
                new { dt = KnownNow.AddDays(-60).ToUtcIso(), a = orgA, b = orgB });
        }

        var svc = BuildService(_fixture.Store, new InProcessDistributedLock(clock), clock, new ThrowOnFirstNotify());

        var ex = await Record.ExceptionAsync(() => svc.RunPassAsync(CancellationToken.None));
        Assert.Null(ex);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            int survivors = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM orgs WHERE id IN (@a, @b)", new { a = orgA, b = orgB });
            Assert.Equal(0, survivors);
        }
    }

    [Fact]
    public async Task RunPassAsync_ConcurrentRestoreBetweenListAndDelete_DoesNotHardDeleteRestoredTenant()
    {
        // A system_admin restores the tenant (clears deleted_at) after the sweep has listed it as
        // expired but before the loop's DELETE fires. Pre-fix the DELETE was an unconditional
        // `DELETE FROM orgs WHERE id = @id`, so the just-restored tenant was permanently hard-
        // deleted. Post-fix the DELETE re-asserts `deleted_at IS NOT NULL AND deleted_at < @cutoff`,
        // matches no row, and the tenant is left intact with no hard-delete audit row.
        var clock = TestTime.Frozen(KnownNow);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"restore-race-{Guid.NewGuid():N}");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
                new { dt = KnownNow.AddDays(-60).ToUtcIso(), id = orgId });
        }

        // Restore lands on the second open — after the expired-list snapshot, before the DELETE.
        var racingStore = new RestoreOnNthOpenStore(_fixture.Store, orgId, restoreOnOpen: 2);
        var svc = BuildService(racingStore, new InProcessDistributedLock(clock), clock);

        var ex = await Record.ExceptionAsync(() => svc.RunPassAsync(CancellationToken.None));
        Assert.Null(ex);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            int survivingCount = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId });
            Assert.Equal(1, survivingCount);

            string? deletedAt = await conn.ExecuteScalarAsync<string?>(
                "SELECT deleted_at FROM orgs WHERE id = @id", new { id = orgId });
            Assert.Null(deletedAt);

            int auditRows = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM audit_log WHERE org_id = @id AND action = 'tenant.hard_deleted'",
                new { id = orgId });
            Assert.Equal(0, auditRows);
        }
    }
}
