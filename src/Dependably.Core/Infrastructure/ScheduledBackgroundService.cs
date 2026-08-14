using Cronos;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure;

/// <summary>
/// Abstract base for background services that run work on a cron schedule. Owns the
/// scheduling loop: cron parse, next-occurrence computation, optional jitter,
/// <see cref="Task.Delay"/> with cancellation, and the per-tick scope boundary.
///
/// Subclasses supply:
/// <list type="bullet">
///   <item><see cref="CronEnvKey"/> / <see cref="DefaultCron"/> — schedule configuration.</item>
///   <item><see cref="RunTickAsync"/> — the work performed each scheduled tick.</item>
///   <item>Optional <see cref="JitterEnvKey"/> / <see cref="DefaultJitterMaxSeconds"/> for
///         thundering-herd spreading (default: no jitter).</item>
///   <item>Optional <see cref="RunOnStartup"/> to run one pass immediately on host start
///         before the first scheduled tick (default: false).</item>
///   <item>Optional <see cref="ScopeJobName"/> / <see cref="ScopeMetricName"/> to have the
///         base wrap each tick in a <see cref="BackgroundJobScope"/> (default: null —
///         subclasses that manage their own scope set this to null).</item>
///   <item>Optional <see cref="DisableOnInvalidCron"/> when an unparseable schedule should
///         silently disable the service rather than throw (default: false).</item>
/// </list>
/// </summary>
public abstract class ScheduledBackgroundService : BackgroundService
{
    /// <summary>Name of the environment variable that supplies the cron expression.</summary>
    protected abstract string CronEnvKey { get; }

    /// <summary>Default cron expression when <see cref="CronEnvKey"/> is not set.</summary>
    protected abstract string DefaultCron { get; }

    /// <summary>
    /// Name of the environment variable that supplies the maximum jitter in seconds.
    /// When null (the default) no jitter is applied.
    /// </summary>
    protected virtual string? JitterEnvKey => null;

    // Seconds in one hour; the default maximum jitter window for thundering-herd spreading.
    private const int SecondsPerHour = 3600;

    /// <summary>
    /// Default maximum jitter in seconds when <see cref="JitterEnvKey"/> is set but the
    /// variable is absent. Ignored when <see cref="JitterEnvKey"/> is null.
    /// </summary>
    protected virtual int DefaultJitterMaxSeconds => SecondsPerHour;

    /// <summary>
    /// When true, <see cref="RunTickAsync"/> is called once on service startup before the
    /// cron loop begins. Default is false.
    /// </summary>
    protected virtual bool RunOnStartup => false;

    /// <summary>
    /// Job name passed to <see cref="BackgroundJobScope.Begin"/> for the automatic
    /// per-tick scope. When null (the default) the base does not open a scope — useful
    /// for subclasses that manage their own scope inside <see cref="RunTickAsync"/>.
    /// </summary>
    protected virtual string? ScopeJobName => null;

    /// <summary>
    /// Metric operation name passed to <see cref="BackgroundJobScope.Begin"/>.
    /// Required when <see cref="ScopeJobName"/> is set.
    /// </summary>
    protected virtual string? ScopeMetricName => null;

    /// <summary>
    /// When true, an exception thrown from <see cref="RunTickAsync"/> is caught, logged,
    /// and the loop continues. When false the exception propagates out of
    /// <see cref="ExecuteAsync"/> and terminates the service. Default is true.
    /// </summary>
    protected virtual bool ContinueOnTickError => true;

    /// <summary>
    /// When true and the configured cron expression cannot be parsed, the service logs an
    /// informational message and exits silently instead of throwing. Default is false.
    /// </summary>
    protected virtual bool DisableOnInvalidCron => false;

    /// <summary>
    /// When true, each tick first tries to acquire a distributed lock named
    /// <see cref="LeaderLockName"/>; only the instance that wins the lock runs the work, the
    /// rest skip the tick. This coordinates jobs that mutate shared state (the database or the
    /// blob store) across replicas so a multi-replica (HA) deployment does not run them N times.
    /// In standalone mode the in-process lock always grants on first acquire, so the single
    /// instance runs everything exactly as before. Default is false — keep per-node work
    /// (local staging-file sweeps, disk pollers) ungated so every replica maintains its own state.
    /// </summary>
    protected virtual bool RequiresLeaderLock => false;

    /// <summary>
    /// Name of the distributed lock acquired per tick when <see cref="RequiresLeaderLock"/> is
    /// true. Defaults to a per-job name derived from the concrete type so each coordinated job
    /// contends independently (rather than one global scheduler lock serialising unrelated jobs).
    /// </summary>
    protected virtual string LeaderLockName => $"job:{GetType().Name}";

    /// <summary>
    /// TTL held on the leader lock for the duration of a tick, and the window a
    /// <see cref="LeaderLease"/> renewal extends it by. A running tick heartbeats the lock well
    /// inside this window, so the TTL bounds how long the lock survives a crashed or wedged
    /// holder rather than how long a pass may run. It is released as soon as the tick completes.
    /// Default 5 min.
    /// </summary>
    protected virtual TimeSpan LeaderLockTtl => TimeSpan.FromMinutes(5);

    private readonly IConfiguration _config;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly IDistributedLock _locks;

    /// <summary>
    /// Constructs the base with the DI services it needs directly.
    /// Subclasses pass these through their own constructors.
    /// </summary>
    protected ScheduledBackgroundService(
        IConfiguration config,
        ILogger logger,
        TimeProvider time,
        IDistributedLock locks)
    {
        _config = config;
        _logger = logger;
        _time = time;
        _locks = locks;
    }

    /// <summary>
    /// Runs the work for one scheduled tick. Called by the base class at each cron
    /// occurrence (and at startup when <see cref="RunOnStartup"/> is true).
    /// </summary>
    protected abstract Task RunTickAsync(CancellationToken ct);

    /// <summary>
    /// Delays execution until the next scheduled occurrence. Runs on the injected
    /// <see cref="TimeProvider"/>, so advancing a <c>FakeTimeProvider</c> releases the wait;
    /// still virtual for subclasses that need a different waiting strategy entirely.
    /// </summary>
    protected virtual Task DelayAsync(TimeSpan delay, CancellationToken ct) =>
        Task.Delay(delay, _time, ct);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        CronExpression schedule;
        string scheduleText = _config[CronEnvKey] ?? DefaultCron;
        try
        {
            schedule = CronExpression.Parse(scheduleText, CronFormat.Standard);
        }
        catch (CronFormatException)
        {
            if (DisableOnInvalidCron)
            {
                _logger.LogInformation(
                    "{ServiceType} disabled ({EnvKey}='{Schedule}' not parseable as cron).",
                    GetType().Name, CronEnvKey, scheduleText);
                return;
            }
            throw;
        }

        if (RunOnStartup)
        {
            await RunTickGuardedAsync(stoppingToken);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var next = schedule.GetNextOccurrence(_time.GetUtcNow(), TimeZoneInfo.Utc);
            if (next is null)
            {
                break;
            }

            var delay = next.Value - _time.GetUtcNow() + ComputeJitter();

            if (delay > TimeSpan.Zero)
            {
                bool cancelled = await DelayUntilAsync(delay, stoppingToken);
                if (cancelled)
                {
                    break;
                }
            }

            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            await RunTickGuardedAsync(stoppingToken);
        }
    }

    // Returns a random jitter delay when JitterEnvKey is configured, otherwise zero.
    private TimeSpan ComputeJitter()
    {
        if (JitterEnvKey is not { } jitterKey)
        {
            return TimeSpan.Zero;
        }

        int jitterMaxSeconds = int.TryParse(_config[jitterKey], out int j) && j >= 0
            ? j
            : DefaultJitterMaxSeconds;
        if (jitterMaxSeconds <= 0)
        {
            return TimeSpan.Zero;
        }

        // SCS0005: load-spreading jitter, not a security boundary — weak RNG is intentional.
#pragma warning disable SCS0005
        return TimeSpan.FromSeconds(Random.Shared.Next(0, jitterMaxSeconds + 1));
#pragma warning restore SCS0005
    }

    // Waits for the specified delay; returns true when the wait was cancelled.
    private async Task<bool> DelayUntilAsync(TimeSpan delay, CancellationToken ct)
    {
        try
        {
            await DelayAsync(delay, ct);
            return false;
        }
        catch (OperationCanceledException)
        {
            return true;
        }
    }

    private async Task RunTickGuardedAsync(CancellationToken ct)
    {
        if (RequiresLeaderLock)
        {
            ILockHandle? leaderLock;
            try
            {
                leaderLock = await _locks.TryAcquireAsync(LeaderLockName, LeaderLockTtl, ct);
            }
            catch (Exception ex)
            {
                // A distributed-lock backend failure (e.g. a Redis connection blip/failover) is an
                // infrastructure-layer failure orthogonal to ContinueOnTickError, which governs the
                // job body's own failures. Left uncaught, this escapes ExecuteAsync and — under
                // BackgroundService's default StopHost behavior — takes the whole replica down on
                // a routine Redis hiccup. Treat it exactly like "another instance holds the lock":
                // skip this tick and let the next scheduled occurrence retry.
                _logger.LogError(ex,
                    "{ServiceType} tick skipped — leader lock acquire for {LockName} failed.",
                    GetType().Name, LeaderLockName);
                return;
            }

            if (leaderLock is null)
            {
                _logger.LogDebug(
                    "{ServiceType} tick skipped — another instance holds the {LockName} leader lock.",
                    GetType().Name, LeaderLockName);
                return;
            }

            // Hold the lock for the whole tick with a renewal heartbeat: a pass that outruns the
            // TTL would otherwise let the lock lapse mid-run and a second replica start a
            // concurrent pass over the same destructive work. The lease also cancels the tick if
            // renewal fails — an instance that has lost its lease is no longer the leader and
            // must stop, not finish unleased.
            var lease = LeaderLease.Start(leaderLock, LeaderLockTtl, _time, _logger, ct);
            try
            {
                await RunTickCoreAsync(lease.Token, lease);
            }
            catch (OperationCanceledException) when (lease.LeaseLost)
            {
                // Backstop for the no-scope, ContinueOnTickError = false shape, where
                // RunTickCoreAsync deliberately lets everything through: swallow the abort so a
                // lost lease cannot fault ExecuteAsync and take the replica down under
                // BackgroundService's default StopHost behavior.
            }
            finally
            {
                await lease.DisposeAsync();
            }

            if (lease.LeaseLost)
            {
                _logger.LogWarning(
                    "{ServiceType} tick aborted — the {LockName} leader lease was lost mid-run.",
                    GetType().Name, LeaderLockName);
            }
            return;
        }

        await RunTickCoreAsync(ct);
    }

    // A tick cancelled because its leader lease was lost is a coordinated stop, not a job failure.
    // It has to be recognised here rather than only around the call: with ContinueOnTickError true
    // — the default, and what the destructive jobs use — the catch-all below would otherwise
    // swallow the abort first and record it as a failed pass with a "tick failed" error.
    private static bool IsLeaseAbort(LeaderLease? lease) => lease is { LeaseLost: true };

    private async Task RunTickCoreAsync(CancellationToken ct, LeaderLease? lease = null)
    {
        if (ScopeJobName is { } jobName && ScopeMetricName is { } metricName)
        {
            await RunScopedTickAsync(jobName, metricName, lease, ct);
        }
        else if (ContinueOnTickError)
        {
            await RunContinuingTickAsync(lease, ct);
        }
        else
        {
            await RunTickAsync(ct);
        }
    }

    // The scoped shape (job-run row + span via BackgroundJobScope): runs the tick, records the
    // outcome, and — for a genuine failure rather than a lease abort — either logs it (when the
    // job continues on error) or lets it propagate.
    private async Task RunScopedTickAsync(string jobName, string metricName, LeaderLease? lease, CancellationToken ct)
    {
        using var scope = BackgroundJobScope.Begin(jobName, metricName, _time);
        try
        {
            await RunTickAsync(ct);
            scope.Complete();
        }
        catch (OperationCanceledException) when (IsLeaseAbort(lease))
        {
            // Neither Complete nor Fail: the scope's default outcome is "cancelled", which is
            // what a leadership handover is. Recording Fail here would put a server_error
            // job-run row and an error-status span on every handover. RunTickGuardedAsync
            // logs the abort once, with the lock name.
        }
        catch (Exception ex)
        {
            scope.Fail(ex);
            if (ContinueOnTickError)
            {
                _logger.LogError(ex, "{ServiceType} tick failed.", GetType().Name);
            }
            else
            {
                throw;
            }
        }
    }

    // The unscoped, continue-on-error shape: runs the tick and logs a genuine failure rather than
    // letting it fault ExecuteAsync; a lease abort is a coordinated stop, not a tick failure.
    private async Task RunContinuingTickAsync(LeaderLease? lease, CancellationToken ct)
    {
        try
        {
            await RunTickAsync(ct);
        }
        catch (OperationCanceledException) when (IsLeaseAbort(lease))
        {
            // Coordinated stop; RunTickGuardedAsync logs it as an abort, not a tick failure.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "{ServiceType} tick failed.", GetType().Name);
        }
    }
}
