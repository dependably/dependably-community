using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for <see cref="ScheduledBackgroundService"/>. Each test uses a minimal
/// concrete subclass that overrides <see cref="ScheduledBackgroundService.DelayAsync"/>
/// to fire immediately, making the loop deterministic without real wall-clock waits.
///
/// Coverage:
///   - <see cref="ScheduledBackgroundService.RunOnStartup"/>: RunTickAsync fires once
///     before the cron loop begins.
///   - <see cref="ScheduledBackgroundService.DisableOnInvalidCron"/> = true: exits
///     silently when the cron expression is unparseable.
///   - <see cref="ScheduledBackgroundService.DisableOnInvalidCron"/> = false: propagates
///     the CronFormatException when the expression is unparseable.
///   - <see cref="ScheduledBackgroundService.ContinueOnTickError"/> = true: a tick that
///     throws is caught and the loop continues to the next occurrence.
///   - <see cref="ScheduledBackgroundService.ContinueOnTickError"/> = false: a tick that
///     throws propagates out of ExecuteAsync and terminates the service.
///   - Auto-scope wrapping: scope is opened and closed around RunTickAsync when
///     ScopeJobName/ScopeMetricName are set.
///   - Mixed partial-failure scenario: in a multi-tick run where some ticks succeed and
///     some fail, each tick is invoked — a prior failure does not abort subsequent ticks.
///     This is the regression guard for the pre-base hand-rolled loops.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ScheduledBackgroundServiceTests
{
    // ── helpers ───────────────────────────────────────────────────────────────────

    private static IConfiguration EmptyConfig() =>
        new ConfigurationBuilder().Build();

    private static IConfiguration Config(IDictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    /// <summary>
    /// Minimal concrete subclass. Overrides <see cref="DelayAsync"/> to resolve
    /// immediately, making loop tick-count assertions deterministic. A <see cref="maxTicks"/>
    /// cap cancels the token after N ticks so tests don't spin forever.
    /// </summary>
    private sealed class TrackingService : ScheduledBackgroundService
    {
        private readonly Queue<Exception?> _outcomes;
        private readonly int _maxTicks;
        private readonly CancellationTokenSource _cts;

        public int TickCount { get; private set; }
        public List<Exception?> OutcomeHistory { get; } = [];

        protected override string CronEnvKey { get; }
        protected override string DefaultCron { get; }
        protected override string? ScopeJobName { get; }
        protected override string? ScopeMetricName { get; }
        protected override bool ContinueOnTickError { get; }
        protected override bool RunOnStartup { get; }
        protected override string? JitterEnvKey { get; }
        protected override bool DisableOnInvalidCron { get; }
        protected override bool RequiresLeaderLock { get; }

        public TrackingService(
            IConfiguration config,
            CancellationTokenSource cts,
            Queue<Exception?> outcomes,
            int maxTicks,
            string cronEnvKey = "TEST_SCHEDULE",
            string defaultCron = "* * * * *",
            string? scopeJobName = null,
            string? scopeMetricName = null,
            bool continueOnTickError = true,
            bool runOnStartup = false,
            string? jitterEnvKey = null,
            bool disableOnInvalidCron = false,
            bool requiresLeaderLock = false,
            IDistributedLock? locks = null)
            : base(config, NullLogger.Instance, TestTime.Frozen(), locks ?? new InProcessDistributedLock(TestTime.Frozen()))
        {
            RequiresLeaderLock = requiresLeaderLock;
            _outcomes = outcomes;
            _maxTicks = maxTicks;
            _cts = cts;
            CronEnvKey = cronEnvKey;
            DefaultCron = defaultCron;
            ScopeJobName = scopeJobName;
            ScopeMetricName = scopeMetricName;
            ContinueOnTickError = continueOnTickError;
            RunOnStartup = runOnStartup;
            JitterEnvKey = jitterEnvKey;
            DisableOnInvalidCron = disableOnInvalidCron;
        }

        // Skip real delay so loop iterations fire immediately.
        protected override Task DelayAsync(TimeSpan delay, CancellationToken ct) =>
            Task.CompletedTask;

        protected override Task RunTickAsync(CancellationToken ct)
        {
            TickCount++;
            var ex = _outcomes.Count > 0 ? _outcomes.Dequeue() : null;
            OutcomeHistory.Add(ex);

            if (TickCount >= _maxTicks)
            {
                // Enough ticks reached; cancel the service to exit the loop.
                _cts.Cancel();
            }

            return ex is null ? Task.CompletedTask : throw ex;
        }
    }

    private static (TrackingService Service, CancellationTokenSource Cts) Build(
        Queue<Exception?> outcomes,
        int maxTicks,
        IConfiguration? config = null,
        string? scopeJobName = null,
        string? scopeMetricName = null,
        bool continueOnTickError = true,
        bool runOnStartup = false,
        string? jitterEnvKey = null,
        bool disableOnInvalidCron = false,
        string defaultCron = "* * * * *",
        bool requiresLeaderLock = false,
        IDistributedLock? locks = null)
    {
        var cts = new CancellationTokenSource();
        var svc = new TrackingService(
            config ?? EmptyConfig(),
            cts,
            outcomes,
            maxTicks,
            defaultCron: defaultCron,
            scopeJobName: scopeJobName,
            scopeMetricName: scopeMetricName,
            continueOnTickError: continueOnTickError,
            runOnStartup: runOnStartup,
            jitterEnvKey: jitterEnvKey,
            disableOnInvalidCron: disableOnInvalidCron,
            requiresLeaderLock: requiresLeaderLock,
            locks: locks);
        return (svc, cts);
    }

    // Generous safety bound for the deterministic wait below. Tests complete in
    // microseconds normally; this only caps a genuinely hung loop so it fails fast
    // instead of hanging the runner. It is never reached in a healthy run.
    private static readonly TimeSpan CompletionTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Awaits the service's background <c>ExecuteTask</c> to a terminal state, bounded by
    /// a safety timeout. Every test drives the service to termination — via the maxTicks
    /// cancel, a fatal tick exception, or the silent invalid-cron exit — so task completion
    /// is the deterministic "all expected ticks have run" signal. This replaces fixed
    /// <see cref="Task.Delay"/> sleeps, which guess at scheduling latency and flake under
    /// thread-pool starvation on shared CI runners (a starved loop ran zero ticks inside a
    /// 200&#160;ms window). Faults are swallowed here; each test asserts on the final state
    /// (<c>TickCount</c>, <c>OutcomeHistory</c>, or <c>ExecuteTask.IsFaulted</c>) instead.
    /// </summary>
    private static async Task WaitForServiceCompletionAsync(TrackingService svc)
    {
        Assert.NotNull(svc.ExecuteTask);
        var finished = await Task.WhenAny(svc.ExecuteTask!, Task.Delay(CompletionTimeout));
        Assert.True(finished == svc.ExecuteTask,
            $"ScheduledBackgroundService did not terminate within {CompletionTimeout.TotalSeconds:0}s; " +
            $"TickCount={svc.TickCount}.");
        // Observe the task so a fault is not left unobserved; tests assert on final state.
        try
        {
            await svc.ExecuteTask!;
        }
        catch
        {
            // Expected for the terminate-on-failure and invalid-cron-throws cases.
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RunOnStartup_InvokesTickBeforeFirstCronOccurrence()
    {
        // A startup tick fires before the cron loop begins.
        var outcomes = new Queue<Exception?>(new Exception?[] { null });
        var (svc, cts) = Build(outcomes, maxTicks: 1, runOnStartup: true);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.True(svc.TickCount >= 1, $"Expected at least one startup tick; got {svc.TickCount}");
        cts.Dispose();
    }

    [Fact]
    public async Task DisableOnInvalidCron_True_ExitsSilentlyWithZeroTicks()
    {
        // An unparseable cron with DisableOnInvalidCron = true must exit without throwing
        // and without calling RunTickAsync.
        var outcomes = new Queue<Exception?>();
        var (svc, cts) = Build(outcomes, maxTicks: 0,
            disableOnInvalidCron: true,
            defaultCron: "not-a-cron-expression");

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(0, svc.TickCount);
        cts.Dispose();
    }

    [Fact]
    public async Task DisableOnInvalidCron_False_ThrowsOnBadCron()
    {
        // When DisableOnInvalidCron is false, a bad cron expression surfaces as an
        // exception. BackgroundService wraps ExecuteAsync exceptions into a faulted task;
        // inspect the ExecuteTask directly.
        var outcomes = new Queue<Exception?>();
        var (svc, cts) = Build(outcomes, maxTicks: 0,
            disableOnInvalidCron: false,
            defaultCron: "not-a-cron-expression");

        // StartAsync returns immediately for BackgroundService (ExecuteAsync runs on
        // a background task). We need to await the inner ExecuteTask to observe the fault.
        await svc.StartAsync(cts.Token);

        // Drive ExecuteAsync to its terminal (faulted) state deterministically.
        await WaitForServiceCompletionAsync(svc);

        // The ExecuteTask should be faulted or the service should be stopped.
        Assert.NotNull(svc.ExecuteTask);
        // The task is either faulted, or (if StartAsync propagates it) we caught it above.
        bool isFaulted = svc.ExecuteTask!.IsFaulted;
        Assert.True(isFaulted, "Expected ExecuteTask to be faulted on an invalid cron");
        cts.Dispose();
    }

    [Fact]
    public async Task ContinueOnTickError_True_LoopContinuesAfterFailure()
    {
        // Three ticks: first fails, second and third succeed. The loop must not abort on
        // the first error.
        var outcomes = new Queue<Exception?>(new Exception?[]
        {
            new InvalidOperationException("tick 1 fails"),
            null,
            null,
        });
        var (svc, cts) = Build(outcomes, maxTicks: 3, continueOnTickError: true);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(3, svc.TickCount);
        Assert.IsType<InvalidOperationException>(svc.OutcomeHistory[0]);
        Assert.Null(svc.OutcomeHistory[1]);
        Assert.Null(svc.OutcomeHistory[2]);
        cts.Dispose();
    }

    [Fact]
    public async Task ContinueOnTickError_False_TerminatesOnFirstFailure()
    {
        // When ContinueOnTickError = false, the first exception from RunTickAsync must
        // propagate out and terminate the service without attempting further ticks.
        var outcomes = new Queue<Exception?>(new Exception?[]
        {
            new InvalidOperationException("fatal"),
            null,  // would be tick 2; must never be reached
        });
        // maxTicks=10 but we expect the service to stop after tick 1 due to the exception.
        var (svc, cts) = Build(outcomes, maxTicks: 10,
            continueOnTickError: false,
            runOnStartup: true);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        // Only one tick was attempted — the exception terminated the service.
        Assert.Equal(1, svc.TickCount);
        cts.Dispose();
    }

    [Fact]
    public async Task ScopeWrapping_SuccessfulTick_CompletesNormally()
    {
        // Auto-scope path (ScopeJobName/ScopeMetricName set): successful tick does not
        // interfere with normal completion.
        var outcomes = new Queue<Exception?>(new Exception?[] { null });
        var (svc, cts) = Build(outcomes, maxTicks: 1,
            scopeJobName: "test-job",
            scopeMetricName: "test.metric",
            runOnStartup: true);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(1, svc.TickCount);
        Assert.Null(svc.OutcomeHistory[0]);
        cts.Dispose();
    }

    [Fact]
    public async Task ScopeWrapping_FailingTick_ContinuesLoop()
    {
        // Scope path + ContinueOnTickError = true: a failing tick calls scope.Fail, logs
        // the error, and the loop continues for the next tick.
        var outcomes = new Queue<Exception?>(new Exception?[]
        {
            new("scope fail test"),
            null,
        });
        var (svc, cts) = Build(outcomes, maxTicks: 2,
            scopeJobName: "test-job",
            scopeMetricName: "test.metric",
            continueOnTickError: true);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(2, svc.TickCount);
        cts.Dispose();
    }

    [Fact]
    public async Task JitterEnvKey_Set_DoesNotBreakLoop()
    {
        // Jitter configured with zero max: loop still runs ticks normally.
        var outcomes = new Queue<Exception?>(new Exception?[] { null });
        var cfg = Config(new Dictionary<string, string?> { ["TEST_JITTER_SECONDS"] = "0" });
        var (svc, cts) = Build(outcomes, maxTicks: 1,
            config: cfg,
            jitterEnvKey: "TEST_JITTER_SECONDS");

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.True(svc.TickCount >= 1);
        cts.Dispose();
    }

    /// <summary>
    /// Regression for the partial-failure contract: across N ticks in a mixed-outcome run
    /// (some succeed, some fail), every scheduled tick is invoked — a prior failure does
    /// not abort subsequent occurrences.
    ///
    /// This test would FAIL on the old hand-rolled per-service loop if an exception were
    /// allowed to propagate out of the loop body, and PASSES on the base-class implementation
    /// that catches and logs errors when <see cref="ScheduledBackgroundService.ContinueOnTickError"/>
    /// is true.
    /// </summary>
    [Fact]
    public async Task MixedTickOutcomes_PartialFailure_AllTicksInvoked()
    {
        var outcomes = new Queue<Exception?>(new Exception?[]
        {
            null,                                             // tick 1: success
            new InvalidOperationException("tick 2 fails"),   // tick 2: failure
            new ArgumentException("tick 3 also fails"),      // tick 3: failure
            null,                                             // tick 4: success
        });
        var (svc, cts) = Build(outcomes, maxTicks: 4, continueOnTickError: true);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        // All 4 ticks must have been attempted regardless of intermediate failures.
        Assert.Equal(4, svc.TickCount);
        Assert.Null(svc.OutcomeHistory[0]);
        Assert.IsType<InvalidOperationException>(svc.OutcomeHistory[1]);
        Assert.IsType<ArgumentException>(svc.OutcomeHistory[2]);
        Assert.Null(svc.OutcomeHistory[3]);
        cts.Dispose();
    }

    // ── RequiresLeaderLock (multi-replica HA coordination) ─────────────────────────

    // Always denies the leader lock (models another replica already holding it) and
    // cancels the driving token once a caller-chosen number of attempts have been made, so
    // a test that expects the tick to never run still terminates deterministically instead
    // of spinning until the WaitForServiceCompletionAsync safety timeout.
    private sealed class CountingDenyLock : IDistributedLock
    {
        private readonly CancellationTokenSource _cts;
        private readonly int _cancelAfterAttempts;

        public int Attempts { get; private set; }

        public CountingDenyLock(CancellationTokenSource cts, int cancelAfterAttempts)
        {
            _cts = cts;
            _cancelAfterAttempts = cancelAfterAttempts;
        }

        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
        {
            Attempts++;
            if (Attempts >= _cancelAfterAttempts)
            {
                _cts.Cancel();
            }
            return Task.FromResult<ILockHandle?>(null);
        }

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
            throw new TimeoutException("lock held");
    }

    // Denies the first N attempts (another replica holds the lock), then delegates to a real
    // in-process lock so a subsequent attempt succeeds — models the leader lock becoming
    // available (the holder crashed / released) partway through this replica's polling.
    private sealed class DenyThenGrantLock : IDistributedLock
    {
        private readonly int _denyCount;
        private readonly IDistributedLock _inner;

        public int Attempts { get; private set; }

        public DenyThenGrantLock(int denyCount, TimeProvider time)
        {
            _denyCount = denyCount;
            _inner = new InProcessDistributedLock(time);
        }

        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
        {
            Attempts++;
            return Attempts <= _denyCount
                ? Task.FromResult<ILockHandle?>(null)
                : _inner.TryAcquireAsync(name, ttl, ct);
        }

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
            _inner.AcquireAsync(name, ttl, wait, retryInterval, ct);
    }

    /// <summary>
    /// Pins the HA fan-out fix: a job flagged <see cref="ScheduledBackgroundService.RequiresLeaderLock"/>
    /// must never invoke <c>RunTickAsync</c> while another replica holds the leader lock — this is
    /// what stops every replica in a multi-instance deployment from running the same destructive/
    /// expensive job on every tick. Pre-fix, RequiresLeaderLock did not exist and every tick ran
    /// unconditionally regardless of another instance's lock.
    /// </summary>
    [Fact]
    public async Task RequiresLeaderLock_LockHeldByAnotherInstance_TickNeverRuns()
    {
        var outcomes = new Queue<Exception?>();
        var cts = new CancellationTokenSource();
        var lockHeldElsewhere = new CountingDenyLock(cts, cancelAfterAttempts: 3);
        var (svc, _) = Build(outcomes, maxTicks: 100, requiresLeaderLock: true, locks: lockHeldElsewhere);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(0, svc.TickCount);
        Assert.True(lockHeldElsewhere.Attempts >= 3);
        cts.Dispose();
    }

    /// <summary>
    /// Mixed partial-failure shape for the leader-lock gate: some tick attempts are skipped
    /// (another replica holds the lock), and once this replica wins the lock the job runs
    /// exactly once — proving the gate is a per-tick check, not a one-time disable.
    /// </summary>
    [Fact]
    public async Task RequiresLeaderLock_LockAvailableAfterHeldAttempts_TickRunsOnceLockWon()
    {
        var outcomes = new Queue<Exception?>(new Exception?[] { null });
        var lockEventuallyAvailable = new DenyThenGrantLock(denyCount: 2, TestTime.Frozen());
        var (svc, cts) = Build(outcomes, maxTicks: 1, requiresLeaderLock: true, locks: lockEventuallyAvailable);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(1, svc.TickCount);
        Assert.True(lockEventuallyAvailable.Attempts >= 3, "expected 2 denied attempts then a grant");
        cts.Dispose();
    }

    /// <summary>
    /// Default (RequiresLeaderLock = false, the shape every job had before HA coordination):
    /// the in-process lock always grants, so standalone/non-coordinated jobs run every tick
    /// exactly as before — the leader-lock gate is opt-in per job, not a global behavior change.
    /// </summary>
    [Fact]
    public async Task RequiresLeaderLock_DefaultFalse_TicksRunWithoutLockCheck()
    {
        var outcomes = new Queue<Exception?>(new Exception?[] { null, null });
        var (svc, cts) = Build(outcomes, maxTicks: 2);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(2, svc.TickCount);
        cts.Dispose();
    }

    // Always throws on TryAcquireAsync (models a Redis connection blip/failover — the lock
    // backend itself is unreachable, distinct from a clean "lock held" null response) and
    // cancels the driving token once a caller-chosen number of attempts have been made, so a
    // test expecting the tick to never run still terminates deterministically.
    private sealed class CountingThrowLock : IDistributedLock
    {
        private readonly CancellationTokenSource _cts;
        private readonly int _cancelAfterAttempts;

        public int Attempts { get; private set; }

        public CountingThrowLock(CancellationTokenSource cts, int cancelAfterAttempts)
        {
            _cts = cts;
            _cancelAfterAttempts = cancelAfterAttempts;
        }

        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
        {
            Attempts++;
            if (Attempts >= _cancelAfterAttempts)
            {
                _cts.Cancel();
            }
            throw new InvalidOperationException("simulated distributed-lock backend failure (e.g. Redis connection blip)");
        }

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
            throw new InvalidOperationException("simulated distributed-lock backend failure (e.g. Redis connection blip)");
    }

    // Throws on TryAcquireAsync for the first N attempts (models a transient Redis blip/failover
    // that then recovers), then delegates to a real in-process lock so a later attempt succeeds.
    private sealed class ThrowThenGrantLock : IDistributedLock
    {
        private readonly int _throwCount;
        private readonly IDistributedLock _inner;

        public int Attempts { get; private set; }

        public ThrowThenGrantLock(int throwCount, TimeProvider time)
        {
            _throwCount = throwCount;
            _inner = new InProcessDistributedLock(time);
        }

        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
        {
            Attempts++;
            return Attempts <= _throwCount
                ? throw new InvalidOperationException("simulated distributed-lock backend failure (e.g. Redis connection blip)")
                : _inner.TryAcquireAsync(name, ttl, ct);
        }

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
            _inner.AcquireAsync(name, ttl, wait, retryInterval, ct);
    }

    /// <summary>
    /// Pins the Redis-blip fix: a distributed-lock backend failure (Redis connection
    /// exception/failover, not a clean "lock held" response) during
    /// <see cref="ScheduledBackgroundService.RequiresLeaderLock"/> acquire must be treated as a
    /// skipped tick, not an unhandled exception. Pre-fix, the acquire call sat outside any
    /// try/catch in RunTickGuardedAsync, so this exception escaped ExecuteAsync and — under
    /// BackgroundService's default StopHost behavior — would take the whole host down on a
    /// routine Redis hiccup. This test fails on the pre-fix code (ExecuteTask ends up faulted)
    /// and passes on the fix (ExecuteTask completes cleanly, RunTickAsync is never invoked).
    /// </summary>
    [Fact]
    public async Task RequiresLeaderLock_LockAcquireThrows_TickSkipped_ServiceSurvives()
    {
        var outcomes = new Queue<Exception?>();
        var cts = new CancellationTokenSource();
        var throwingLock = new CountingThrowLock(cts, cancelAfterAttempts: 3);
        var (svc, _) = Build(outcomes, maxTicks: 100, requiresLeaderLock: true, locks: throwingLock);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(0, svc.TickCount);
        Assert.True(throwingLock.Attempts >= 3);
        Assert.NotNull(svc.ExecuteTask);
        Assert.False(svc.ExecuteTask!.IsFaulted,
            "a distributed-lock acquire failure must not escape ExecuteAsync and fault the service — " +
            "under BackgroundService's default StopHost behavior a fault here would take the whole host down.");
        cts.Dispose();
    }

    /// <summary>
    /// Mixed partial-failure shape for the Redis-blip fix: some lock-acquire attempts throw
    /// (transient backend failure), and once the backend recovers the job runs exactly once —
    /// the next scheduled tick retries rather than the service staying down.
    /// </summary>
    [Fact]
    public async Task RequiresLeaderLock_LockAcquireThrowsThenRecovers_TickRunsOnceRecovered()
    {
        var outcomes = new Queue<Exception?>(new Exception?[] { null });
        var recoveringLock = new ThrowThenGrantLock(throwCount: 2, TestTime.Frozen());
        var (svc, cts) = Build(outcomes, maxTicks: 1, requiresLeaderLock: true, locks: recoveringLock);

        await svc.StartAsync(cts.Token);
        await WaitForServiceCompletionAsync(svc);

        Assert.Equal(1, svc.TickCount);
        Assert.True(recoveringLock.Attempts >= 3, "expected 2 throwing attempts then a successful grant");
        Assert.NotNull(svc.ExecuteTask);
        Assert.False(svc.ExecuteTask!.IsFaulted);
        cts.Dispose();
    }
}
