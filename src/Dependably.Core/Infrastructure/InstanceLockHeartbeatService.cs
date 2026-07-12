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
    // Budget for the release DELETE on shutdown, independent of the host's shutdown timeout.
    private static readonly TimeSpan ReleaseTimeout = TimeSpan.FromSeconds(5);

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
            // Stop the refresh loop before the row is deleted: a tick landing after the release finds
            // no row of its own and logs a spurious "the lock was taken over" warning.
            await base.StopAsync(cancellationToken);
        }
        finally
        {
            try
            {
                // Deliberately not the host's shutdown token — which is why the release sits in a
                // finally. That token is already cancelled once the shutdown timeout expires, and the
                // host still calls the remaining StopAsync methods with it, so the release (a single
                // DELETE, and the one thing that spares the replacement node a wait-out of the
                // staleness window) would be skipped exactly when a slow drain has made it most
                // valuable. Bound it on its own short timeout instead.
                using var cts = new CancellationTokenSource(ReleaseTimeout, _time);
                await _lock.ReleaseAsync(cts.Token);
            }
            catch (Exception ex)
            {
                // A failed release is not fatal — the lock falls back to the staleness-window takeover
                // path. Log so an operator can see why a restart waited.
                _logger.LogWarning(ex, "Failed to release instance lock on shutdown; it will expire after the staleness window.");
            }
        }
    }
}
