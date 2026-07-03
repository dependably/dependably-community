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
    /// TTL held on the leader lock for the duration of a tick. Sized well above a normal pass so
    /// the lock is not lost mid-run; it is released as soon as the tick completes. Default 5 min.
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
    /// Delays execution until the next scheduled occurrence. Override in tests to
    /// advance a <c>FakeTimeProvider</c> instead of waiting on real wall-clock time.
    /// </summary>
    protected virtual Task DelayAsync(TimeSpan delay, CancellationToken ct) =>
        Task.Delay(delay, ct);

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

            try
            {
                await RunTickCoreAsync(ct);
            }
            finally
            {
                await leaderLock.DisposeAsync();
            }
            return;
        }

        await RunTickCoreAsync(ct);
    }

    private async Task RunTickCoreAsync(CancellationToken ct)
    {
        if (ScopeJobName is { } jobName && ScopeMetricName is { } metricName)
        {
            using var scope = BackgroundJobScope.Begin(jobName, metricName, _time);
            try
            {
                await RunTickAsync(ct);
                scope.Complete();
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
        else if (ContinueOnTickError)
        {
            try
            {
                await RunTickAsync(ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "{ServiceType} tick failed.", GetType().Name);
            }
        }
        else
        {
            await RunTickAsync(ct);
        }
    }
}
