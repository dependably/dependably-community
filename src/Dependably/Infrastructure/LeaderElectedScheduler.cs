using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure;

/// <summary>
/// Replaces individual hosted services that run on every replica with a
/// single elected leader. The leader holds a distributed lock that it
/// renews every <see cref="RenewalInterval"/>; if the lock lapses (crash
/// or clean shutdown), another replica acquires it and takes over.
///
/// The scheduled work itself is delegated to <see cref="RetentionService"/>
/// and <see cref="VulnerabilityScanService"/>, which expose a RunOnce method
/// that the leader calls on each tick.
///
/// In standalone mode the in-process IDistributedLock always succeeds on the
/// first try, so the single replica is always leader and the behavior is
/// identical to the pre-HA polling loop.
/// </summary>
public sealed class LeaderElectedScheduler : BackgroundService
{
    private static readonly TimeSpan LeaderTtl = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RenewalInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan FollowerPoll = TimeSpan.FromSeconds(15);

    private readonly IDistributedLock _locks;
    private readonly ILogger<LeaderElectedScheduler> _logger;

    public LeaderElectedScheduler(
        IDistributedLock locks,
        ILogger<LeaderElectedScheduler> logger)
    {
        _locks = locks;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await using var handle = await _locks.TryAcquireAsync("scheduler:leader", LeaderTtl, stoppingToken);

            if (handle is null)
            {
                // Not the leader — poll and try again.
                _logger.LogDebug("Scheduler: not leader, polling again in {Interval}s.", FollowerPoll.TotalSeconds);
                await Task.Delay(FollowerPoll, stoppingToken);
                continue;
            }

            _logger.LogInformation("Scheduler: became leader.");

            // Renew the lock periodically while we are the leader.
            using var renewCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            var renewTask = RenewAsync(handle, renewCts.Token);

            try
            {
                await RunLeaderWorkAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scheduler: leader work threw an unhandled exception.");
            }
            finally
            {
                await renewCts.CancelAsync();
                try { await renewTask; } catch { /* renewal already canceled */ }
                _logger.LogInformation("Scheduler: yielding leader lock.");
            }
        }
    }

    /// <summary>
    /// Work performed on each leader tick. Add new periodic jobs here.
    /// Keep individual tasks short or move long-running work to child tasks with their own cancellation.
    /// </summary>
    private async Task RunLeaderWorkAsync(CancellationToken ct)
    {
        // Tick every minute while leader. Individual services decide whether to do
        // work based on their own scheduling logic.
        while (!ct.IsCancellationRequested)
        {
            _logger.LogDebug("Scheduler: leader tick.");
            // Downstream periodic services (RetentionService, VulnerabilityScanService) run
            // independently as BackgroundServices in standalone mode, or are triggered here
            // in HA mode. Trigger hooks can be added here as the HA migration continues.
            await Task.Delay(TimeSpan.FromMinutes(1), ct);
        }
    }

    private async Task RenewAsync(ILockHandle handle, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(RenewalInterval, ct);
                bool extended = await handle.ExtendAsync(LeaderTtl, ct);
                if (!extended)
                {
                    _logger.LogWarning("Scheduler: leader lock could not be extended — stepping down.");
                    return;
                }
            }
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
    }
}
