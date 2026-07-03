namespace Dependably.Infrastructure;

/// <summary>
/// Keeps the shared-SQLite instance lock alive while this node runs and releases it on graceful
/// shutdown. Refreshes <see cref="InstanceLock.RefreshAsync"/> every <see cref="InstanceLock.RefreshInterval"/>
/// (a third of the staleness window) so a peer only treats this node as crashed after several
/// missed beats. On <see cref="StopAsync"/> the lock row is deleted so an immediate restart claims
/// it without waiting out the staleness window.
///
/// <para>The initial acquisition happens in <see cref="StartupService"/> (before the server accepts
/// requests, so a fail-fast surfaces before any traffic). This service owns only the ongoing
/// refresh and the release. It is a no-op for stores the guard does not apply to (Postgres,
/// in-memory SQLite), because every <see cref="InstanceLock"/> method self-skips those.</para>
///
/// <para>Timer cadence is driven by the injected <see cref="TimeProvider"/> so tests can advance a
/// <c>FakeTimeProvider</c> and assert the heartbeat advances without real waits.</para>
/// </summary>
public sealed class InstanceLockHeartbeatService : BackgroundService
{
    private readonly InstanceLock _lock;
    private readonly TimeProvider _time;
    private readonly ILogger<InstanceLockHeartbeatService> _logger;

    public InstanceLockHeartbeatService(
        InstanceLock instanceLock,
        TimeProvider time,
        ILogger<InstanceLockHeartbeatService> logger)
    {
        _lock = instanceLock;
        _time = time;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_lock.RefreshInterval, _time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await RefreshOnceAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown requested — the release runs in StopAsync below.
        }
    }

    internal async Task RefreshOnceAsync(CancellationToken ct)
    {
        try
        {
            await _lock.RefreshAsync(ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // A transient failure to refresh (e.g. brief disk contention) must not crash the node;
            // the next tick retries. Only a sustained failure lets the lock go stale.
            _logger.LogWarning(ex, "Instance-lock heartbeat refresh failed; will retry on next tick.");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _lock.ReleaseAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // A failed release is not fatal — the lock simply falls back to the staleness-window
            // takeover path. Log so an operator can see why an immediate restart waited.
            _logger.LogWarning(ex, "Failed to release instance lock on shutdown; it will expire after the staleness window.");
        }

        await base.StopAsync(cancellationToken);
    }
}
