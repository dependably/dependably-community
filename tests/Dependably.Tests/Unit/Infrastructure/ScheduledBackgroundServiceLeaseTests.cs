using System.Diagnostics.Metrics;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Leader-lease behavior of <see cref="ScheduledBackgroundService"/> for jobs flagged
/// <c>RequiresLeaderLock</c> — the destructive/expensive ones (orphan-blob reconcile, retention,
/// tenant hard delete, vulnerability scan).
///
/// A tick acquires the lock with a finite TTL. Without renewal, a tick that runs longer than the
/// TTL keeps working while its lock lapses and the next replica to tick starts a concurrent second
/// pass. These tests pin that a running tick renews its lease, and that a tick which loses its
/// lease is cancelled rather than left running unleased.
///
/// The lock is <see cref="LeasedTestLock"/> — real expiry semantics on the fake clock — rather than
/// <see cref="InProcessDistributedLock"/>, which grants the first in-process acquirer regardless of
/// lease state and would let these tests pass without any renewal happening.
/// </summary>
// One test asserts the outcome recorded on dependably.background_job.duration via a MeterListener
// filtered by DependablyMeter.MeterName, so the class runs alone against the process-wide static
// meter. See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class ScheduledBackgroundServiceLeaseTests
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(60);

    // LeaderLease renews three times per TTL window: a renewal is due every 20s at this TTL.
    private static readonly TimeSpan RenewStep = TimeSpan.FromSeconds(20);

    // Real-time safety bound for the polls below; a healthy run satisfies them immediately.
    private static readonly TimeSpan PollTimeout = TimeSpan.FromSeconds(10);

    private static async Task WaitUntilAsync(Func<bool> condition, string because)
    {
        var deadline = Task.Delay(PollTimeout);
        while (!condition())
        {
            Assert.False(deadline.IsCompleted, $"timed out after {PollTimeout.TotalSeconds:0}s waiting for {because}");
            await Task.Delay(5);
        }
    }

    /// <summary>
    /// A leader-locked service whose single tick blocks until the test releases it (or until the
    /// tick's own token is cancelled), modelling a pass that runs longer than the lock TTL.
    ///
    /// <para>Both tick-error shapes are constructible. The default here is
    /// <c>ContinueOnTickError = false</c> with no scope, so an abort exception that escaped the
    /// base class would fault <c>ExecuteTask</c> and fail the test loudly rather than being
    /// swallowed. The <c>ContinueOnTickError = true</c> + scope shape is what the destructive jobs
    /// actually run with (orphan-blob reconcile, retention, cache eviction all take the base
    /// default), where the base class's catch-all is what an abort has to be distinguished
    /// from.</para>
    /// </summary>
    private sealed class LongRunningLeaderService : ScheduledBackgroundService
    {
        private readonly TaskCompletionSource _tickStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseTick = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _tickCount;
        private int _tickCancelled;
        private int _tickCompleted;

        public LongRunningLeaderService(
            IDistributedLock locks,
            TimeProvider time,
            bool continueOnTickError = false,
            string? scopeJobName = null,
            string? scopeMetricName = null)
            : base(new ConfigurationBuilder().Build(), NullLogger.Instance, time, locks)
        {
            ContinueOnTickError = continueOnTickError;
            ScopeJobName = scopeJobName;
            ScopeMetricName = scopeMetricName;
        }

        protected override string CronEnvKey => "TEST_SCHEDULE";
        protected override string DefaultCron => "* * * * *";
        protected override bool RequiresLeaderLock => true;
        protected override bool RunOnStartup => true;
        protected override bool ContinueOnTickError { get; }
        protected override string? ScopeJobName { get; }
        protected override string? ScopeMetricName { get; }
        protected override TimeSpan LeaderLockTtl => Ttl;

        /// <summary>The lock name the base class contends on, for the second-acquirer assertions.</summary>
        public string LockName => LeaderLockName;

        public Task TickStarted => _tickStarted.Task;
        public int TickCount => Volatile.Read(ref _tickCount);
        public bool TickObservedCancellation => Volatile.Read(ref _tickCancelled) == 1;
        public bool TickRanToCompletion => Volatile.Read(ref _tickCompleted) == 1;

        public void ReleaseTick() => _releaseTick.TrySetResult();

        // Only the startup tick runs: the scheduling delay never elapses until the host stops.
        protected override Task DelayAsync(TimeSpan delay, CancellationToken ct) =>
            Task.Delay(Timeout.Infinite, ct);

        protected override async Task RunTickAsync(CancellationToken ct)
        {
            Interlocked.Increment(ref _tickCount);
            _tickStarted.TrySetResult();

            await using var registration = ct.Register(() =>
            {
                Interlocked.Exchange(ref _tickCancelled, 1);
                _releaseTick.TrySetResult();
            });

            await _releaseTick.Task;

            // Real job bodies surface a cancelled token as an OperationCanceledException from the
            // repository/blob call they are in the middle of; do the same here.
            ct.ThrowIfCancellationRequested();
            Interlocked.Exchange(ref _tickCompleted, 1);
        }
    }

    // Lets the in-flight tick finish on its own terms before stopping the host, so the shutdown
    // cancellation cannot race the tick body and change what the test is asserting on.
    private static async Task StopAsync(LongRunningLeaderService svc, CancellationTokenSource cts)
    {
        svc.ReleaseTick();
        await WaitUntilAsync(
            () => svc.TickRanToCompletion || svc.TickObservedCancellation,
            "the in-flight tick to finish");
        await cts.CancelAsync();

        if (svc.ExecuteTask is { } execute)
        {
            var finished = await Task.WhenAny(execute, Task.Delay(PollTimeout));
            Assert.True(finished == execute, "the service did not terminate after cancellation");
            try
            {
                await execute;
            }
            catch (OperationCanceledException)
            {
                // Shutdown cancellation; each test asserts on ExecuteTask's final state instead.
            }
        }
    }

    /// <summary>
    /// The core regression: while a leader-locked tick is still running past the lock TTL, the lock
    /// is renewed and a second replica is still refused. Pre-fix the lock was acquired once per
    /// tick and never extended, so at TTL the key lapsed under the running tick and the next
    /// replica to tick acquired it and began a concurrent destructive pass.
    /// </summary>
    [Fact]
    public async Task LongTick_RenewsLease_SecondReplicaStillRefusedPastTtl()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock);
        var svc = new LongRunningLeaderService(locks, clock);
        using var cts = new CancellationTokenSource();

        await svc.StartAsync(cts.Token);
        await svc.TickStarted.WaitAsync(PollTimeout);

        // 6 x 20s = 120s inside the tick — twice the 60s TTL.
        for (int step = 1; step <= 6; step++)
        {
            clock.Advance(RenewStep);
            int expected = step;
            await WaitUntilAsync(() => locks.ExtendAttempts >= expected, $"renewal attempt {expected}");
        }

        Assert.True(locks.ExtendSuccesses >= 6, $"expected a renewal per interval; got {locks.ExtendSuccesses}");
        Assert.Null(await locks.TryAcquireAsync(svc.LockName, Ttl));
        Assert.False(svc.TickObservedCancellation, "a renewed lease must not cancel the running tick");

        await StopAsync(svc, cts);

        Assert.Equal(1, svc.TickCount);
        Assert.False(locks.IsHeld(svc.LockName), "the lease must release the lock when the tick finishes");
    }

    /// <summary>
    /// The abort half: when renewal is refused (another instance now holds the lock), the running
    /// tick's token is cancelled so the pass stops instead of continuing to delete without a lease.
    /// The abort must not fault the service — a lost lease is a skipped pass, not a dead replica.
    /// </summary>
    [Fact]
    public async Task RenewalRefused_RunningTickIsCancelled_ServiceSurvives()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock) { ExtendBehavior = _ => ExtendOutcome.Refuse };
        var svc = new LongRunningLeaderService(locks, clock);
        using var cts = new CancellationTokenSource();

        await svc.StartAsync(cts.Token);
        await svc.TickStarted.WaitAsync(PollTimeout);

        clock.Advance(RenewStep);
        await WaitUntilAsync(() => svc.TickObservedCancellation, "the running tick to observe its lost lease");

        Assert.False(svc.TickRanToCompletion, "a tick that lost its lease must abort, not run to completion");

        await StopAsync(svc, cts);

        Assert.NotNull(svc.ExecuteTask);
        Assert.False(svc.ExecuteTask!.IsFaulted,
            "a lost lease must not escape ExecuteAsync — under BackgroundService's default StopHost behavior a fault here takes the replica down");
    }

    // Captures the outcome tag recorded on dependably.background_job.duration for one job name.
    // Filtering by job name as well as instrument keeps the assertion honest even though the class
    // is already serialized against other meter-sensitive tests.
    private static MeterListener JobOutcomeListener(string jobName, Action<string> onOutcome)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName
                    && instrument.Name == "dependably.background_job.duration")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };

        listener.SetMeasurementEventCallback<double>((_, _, tags, _) =>
        {
            string? name = null;
            string? outcome = null;
            foreach (var tag in tags)
            {
                if (tag.Key == "job_name") { name = tag.Value as string; }
                else if (tag.Key == "outcome") { outcome = tag.Value as string; }
            }

            if (name == jobName && outcome is not null)
            {
                onOutcome(outcome);
            }
        });

        listener.Start();
        return listener;
    }

    /// <summary>
    /// The configuration the destructive jobs actually run in: <c>ContinueOnTickError = true</c>
    /// (the base default, which OrphanBlobReconcilerService, RetentionService and
    /// CacheEvictionService all take) plus an automatic job scope. The base class's catch-all for
    /// tick errors sits between the aborted tick and the lease-abort handling, so a lost lease has
    /// to be recognised *inside* that handler — otherwise it is swallowed as an ordinary tick
    /// failure and recorded as <c>server_error</c> with a "tick failed" error log on every
    /// leadership handover. This asserts the recorded outcome is <c>cancelled</c> and that the
    /// service survives.
    /// </summary>
    [Fact]
    public async Task RenewalRefused_ContinueOnTickErrorWithScope_RecordsCancelledNotFailure()
    {
        string jobName = $"lease-abort-{Guid.NewGuid():N}";
        var outcomes = new List<string>();
        using var listener = JobOutcomeListener(jobName, outcome => outcomes.Add(outcome));

        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock) { ExtendBehavior = _ => ExtendOutcome.Refuse };
        var svc = new LongRunningLeaderService(
            locks, clock,
            continueOnTickError: true,
            scopeJobName: jobName,
            scopeMetricName: "test.lease_abort");
        using var cts = new CancellationTokenSource();

        await svc.StartAsync(cts.Token);
        await svc.TickStarted.WaitAsync(PollTimeout);

        clock.Advance(RenewStep);
        await WaitUntilAsync(() => svc.TickObservedCancellation, "the running tick to observe its lost lease");

        await StopAsync(svc, cts);

        Assert.False(svc.TickRanToCompletion, "a tick that lost its lease must abort, not run to completion");
        Assert.NotNull(svc.ExecuteTask);
        Assert.False(svc.ExecuteTask!.IsFaulted);

        string recorded = Assert.Single(outcomes);
        Assert.Equal("cancelled", recorded);
    }

    /// <summary>
    /// Mixed partial-failure across one pass: some renewal attempts hit an unreachable lock backend
    /// and some succeed. The transient failures do not abort the tick, the lock stays held past its
    /// TTL, and the pass runs to completion.
    /// </summary>
    [Fact]
    public async Task RenewalThrowsThenSucceeds_TickNotAborted_AndCompletes()
    {
        var clock = TestTime.Frozen();
        var locks = new LeasedTestLock(clock)
        {
            ExtendBehavior = attempt => attempt is 1 or 4 ? ExtendOutcome.Throw : ExtendOutcome.Renew,
        };
        var svc = new LongRunningLeaderService(locks, clock);
        using var cts = new CancellationTokenSource();

        await svc.StartAsync(cts.Token);
        await svc.TickStarted.WaitAsync(PollTimeout);

        for (int step = 1; step <= 6; step++)
        {
            clock.Advance(RenewStep);
            int expected = step;
            await WaitUntilAsync(() => locks.ExtendAttempts >= expected, $"renewal attempt {expected}");
        }

        Assert.False(svc.TickObservedCancellation, "a transient renewal failure inside the lease window must not abort the pass");
        Assert.Null(await locks.TryAcquireAsync(svc.LockName, Ttl));

        await StopAsync(svc, cts);

        Assert.True(svc.TickRanToCompletion);
        Assert.Equal(1, svc.TickCount);
    }
}
