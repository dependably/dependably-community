using System.Data.Common;
using Cronos;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Resilience coverage for <see cref="SamlCertExpiryCheckService"/>: a database error in a
/// check pass must not tear down the background loop. The service catches exceptions at both
/// <c>RunCheckPassAsync</c> call sites (startup pass and in-loop pass) and keeps scheduling,
/// so one failing sweep does not silence cert-expiry alerting for the rest of the host's life.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SamlCertExpiryCheckServiceResilienceTests
{
    // A metadata store whose every connection attempt fails — models a transient DB outage
    // (file lock, connection-pool exhaustion, corruption) that surfaces as an exception out
    // of the first Dapper call inside RunCheckPassInnerAsync.
    private sealed class ThrowingMetadataStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException("simulated database outage");
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private static IConfiguration Config() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // A schedule far in the future keeps the in-loop pass from ever firing during
                // the test — the startup pass is what exercises the failure path; the loop is
                // stopped via cancellation before any cron tick.
                ["SAML_CERT_EXPIRY_SCHEDULE"] = "0 6 1 1 *",
                ["SAML_CERT_EXPIRY_JITTER_SECONDS"] = "0",
            })
            .Build();

    // A lock whose TryAcquireAsync always returns null — models another instance already
    // holding the sweep lock in a multi-replica deployment.
    private sealed class AlwaysHeldLock : IDistributedLock
    {
        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default) =>
            Task.FromResult<ILockHandle?>(null);

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
            throw new TimeoutException("lock held");
    }

    private static SamlCertExpiryCheckService BuildService(
        IMetadataStore store, TimeProvider time, IDistributedLock? locks = null)
    {
        var samlConfig = new SamlConfigRepository(store, time);
        var audit = new AuditRepository(store, activityWriter: null, time);
        return new SamlCertExpiryCheckService(
            samlConfig,
            audit,
            Config(),
            new StubAirGap(),
            // Default: the in-process lock grants on first acquire, so the single instance
            // sweeps normally — identical to standalone behaviour.
            locks ?? new InProcessDistributedLock(time),
            NullLogger<SamlCertExpiryCheckService>.Instance,
            time);
    }

    [Fact]
    public async Task RunCheckPassAsync_DbError_Propagates()
    {
        // The internal pass honours its rethrow contract: a DB failure bubbles out so the
        // BackgroundJobScope can record the run as failed. ExecuteAsync is what swallows it.
        var time = TestTime.Frozen();
        var service = BuildService(new ThrowingMetadataStore(), time);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.RunCheckPassAsync(CancellationToken.None));
    }

    [Fact]
    public async Task RunCheckPassAsync_SweepLockHeld_SkipsWithoutTouchingDb()
    {
        // Another instance holds the sweep lock (TryAcquire returns null), so this instance must
        // skip the pass before any database work. The store throws on every connection attempt;
        // if the gate failed to short-circuit, the first Dapper call would surface that exception
        // out of RunCheckPassAsync. A clean return proves the DB was never opened.
        var time = TestTime.Frozen();
        var service = BuildService(new ThrowingMetadataStore(), time, new AlwaysHeldLock());

        // No throw — the skip path returns before GetAllCertRowsAsync opens a connection.
        await service.RunCheckPassAsync(CancellationToken.None);
    }

    [Fact]
    public async Task ExecuteAsync_StartupPassThrows_HostLoopSurvives()
    {
        // The startup pass throws (DB outage), but ExecuteAsync must not let that escape — the
        // host would otherwise crash on boot. The service then enters its scheduling loop, which
        // we stop deterministically: StopAsync signals the BackgroundService's internal stopping
        // token, the next-occurrence Task.Delay is cancelled, the loop ends, and the service
        // reaches a clean stopped state without ever waiting on the far-future cron tick.
        var time = TestTime.Frozen();
        var service = BuildService(new ThrowingMetadataStore(), time);

        // StartAsync kicks off ExecuteAsync; it returns once the service is running (the startup
        // pass has thrown-and-been-swallowed and the loop is parked on the next-occurrence wait).
        await service.StartAsync(CancellationToken.None);

        // StopAsync cancels the stopping token ExecuteAsync observes and awaits the loop drain.
        await service.StopAsync(CancellationToken.None);

        // The execute task completed without faulting — no unhandled exception escaped the loop.
        Assert.NotNull(service.ExecuteTask);
        Assert.True(service.ExecuteTask!.IsCompleted);
        Assert.False(service.ExecuteTask.IsFaulted);
    }

    [Fact]
    public async Task WaitForNextOccurrence_LongHorizonSchedule_DoesNotThrowArgumentOutOfRange()
    {
        // Regression pin for the Task.Delay uint.MaxValue-millisecond ceiling (~49.7 days).
        // A yearly cron like "0 6 1 1 *" fires ~200 days from TestTime.KnownNow (June 2026
        // → January 2027). The pre-fix code passed that full delay directly to Task.Delay,
        // which throws ArgumentOutOfRangeException synchronously before the cancellation token
        // is even checked. The fix sleeps in 1-hour chunks, so Task.Delay never sees a value
        // near the limit and the cancellation token correctly ends the wait with return false.
        var time = TestTime.Frozen();
        var service = BuildService(new ThrowingMetadataStore(), time);
        var schedule = CronExpression.Parse("0 6 1 1 *", CronFormat.Standard);

        // Pre-cancelled token makes the first chunk return immediately via OperationCanceledException,
        // which the method catches and translates to false. On the pre-fix code, Task.Delay throws
        // ArgumentOutOfRangeException before it can observe the token, so the method throws instead.
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        bool result = await service.WaitForNextOccurrenceAsync(schedule, cts.Token);

        Assert.False(result);
    }
}
