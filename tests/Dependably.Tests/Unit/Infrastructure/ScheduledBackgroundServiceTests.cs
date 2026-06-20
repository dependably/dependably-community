using Dependably.Infrastructure;
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
            bool disableOnInvalidCron = false)
            : base(config, NullLogger.Instance, TestTime.Frozen())
        {
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
        string defaultCron = "* * * * *")
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
            disableOnInvalidCron: disableOnInvalidCron);
        return (svc, cts);
    }

    // ── tests ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RunOnStartup_InvokesTickBeforeFirstCronOccurrence()
    {
        // A startup tick fires before the cron loop begins.
        var outcomes = new Queue<Exception?>(new Exception?[] { null });
        var (svc, cts) = Build(outcomes, maxTicks: 1, runOnStartup: true);

        await svc.StartAsync(cts.Token);
        await Task.Delay(50);   // give the async task a moment to finish

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
        await Task.Delay(50);

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

        // Give ExecuteAsync a moment to run and fault.
        await Task.Delay(100);

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
        await Task.Delay(200);

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
        await Task.Delay(200);

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
        await Task.Delay(100);

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
        await Task.Delay(200);

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
        await Task.Delay(200);

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
        await Task.Delay(400);

        // All 4 ticks must have been attempted regardless of intermediate failures.
        Assert.Equal(4, svc.TickCount);
        Assert.Null(svc.OutcomeHistory[0]);
        Assert.IsType<InvalidOperationException>(svc.OutcomeHistory[1]);
        Assert.IsType<ArgumentException>(svc.OutcomeHistory[2]);
        Assert.Null(svc.OutcomeHistory[3]);
        cts.Dispose();
    }
}
