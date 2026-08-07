using System.Diagnostics;
using System.Text.Json;
using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure;

/// <summary>
/// Background service that pre-computes the dashboard aggregates for every active org and
/// stores them in <c>org_stats_snapshot</c>. The /api/v1/stats endpoint reads that snapshot
/// instead of running <see cref="PackageAnalyticsRepository.GetOrgStatsAsync"/>'s eight live
/// aggregate queries on every page load (which took seconds on large instances).
///
/// Runs one pass on startup so snapshots populate shortly after boot, then refreshes on a
/// fixed interval (STATS_REFRESH_INTERVAL_SECONDS env var, default 60s). Large multi-tenant
/// instances where the aggregate pass is expensive can raise the interval to trade dashboard
/// freshness for less background query load.
/// </summary>
public sealed class StatsRefreshService : BackgroundService
{
    // In a multi-replica (HA) deployment every replica runs this timer; the snapshot recompute is
    // the same fleet-wide work, so only the instance that wins the sweep lock does it per pass.
    // The pass holds the lock through a LeaderLease that heartbeats the TTL, so the TTL bounds
    // how long the lock survives a crashed leader, not how long a pass may take.
    private static readonly TimeSpan RefreshLockTtl = TimeSpan.FromMinutes(5);
    private const string RefreshLockName = "stats-refresh:sweep";

    private readonly StatsSnapshotRepository _snapshots;
    private readonly PackageAnalyticsRepository _analytics;
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly IDistributedLock _locks;
    private readonly ILogger<StatsRefreshService> _logger;
    private readonly TimeProvider _time;

    public StatsRefreshService(
        StatsSnapshotRepository snapshots,
        PackageAnalyticsRepository analytics,
        IConfiguration config,
        IAirGapMode airGap,
        IDistributedLock locks,
        ILogger<StatsRefreshService> logger,
        TimeProvider time)
    {
        _snapshots = snapshots;
        _analytics = analytics;
        _config = config;
        _airGap = airGap;
        _locks = locks;
        _logger = logger;
        _time = time;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        int intervalSeconds = int.TryParse(_config["STATS_REFRESH_INTERVAL_SECONDS"], out int s) && s > 0
            ? s
            : 60;

        // Initial pass on startup so the dashboard hits a warm snapshot soon after boot.
        await RunRefreshPassAsync(stoppingToken);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(intervalSeconds), _time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await RunRefreshPassAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
    }

    // The pass entry point ExecuteAsync calls at startup and on every tick. It mirrors
    // ScheduledBackgroundService.ContinueOnTickError: a transient failure in one pass — an
    // unguarded query like ListActiveOrgIdsAsync throwing SQLITE_BUSY while a large import holds
    // the single writer — is logged and swallowed so the loop continues to the next tick, rather
    // than escaping ExecuteAsync and, under BackgroundService's default StopHost behavior, taking
    // the whole replica down. Genuine shutdown cancellation still propagates for a clean stop.
    internal async Task RunRefreshPassAsync(CancellationToken ct)
    {
        try
        {
            await RunRefreshPassScopedAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (LeaseAbortedException)
        {
            // The sweep lease was lost mid-pass, not a host shutdown. RunRefreshPassInnerAsync has
            // already logged the abort; the pass is over and the next tick re-contends for the lock.
        }
        catch (OperationCanceledException ex)
        {
            // Neither host shutdown nor a recorded lease loss: an unrecognized cancellation source.
            // Logged rather than swallowed so an unexpected cancellation cannot vanish unnoticed,
            // and still treated as a skipped pass rather than a fatal one.
            _logger.LogWarning(ex, "Stats refresh pass cancelled for an unrecognized reason; skipping this pass.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Stats refresh pass failed; skipping this pass.");
        }
    }

    private async Task RunRefreshPassScopedAsync(CancellationToken ct)
    {
        using var scope = Observability.BackgroundJobScope.Begin("stats-refresh", "stats.refresh", _time);
        try
        {
            await RunRefreshPassInnerAsync(ct);
            scope.Complete();
        }
        catch (OperationCanceledException)
        {
            // A stopped pass — host shutdown or a lost sweep lease — is not a job failure. Calling
            // Fail here would record outcome=server_error and persist a failed job-run row on every
            // graceful shutdown; leaving the scope untouched keeps its default "cancelled" outcome.
            throw;
        }
        catch (Exception ex)
        {
            scope.Fail(ex);
            throw;
        }
    }

    private async Task RunRefreshPassInnerAsync(CancellationToken ct)
    {
        if (_airGap.IsJobDisabled("stats-refresh"))
        {
            _logger.LogInformation("Stats refresh pass skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return;
        }

        // Coordinate across replicas: only the lock winner recomputes the shared snapshots this
        // pass. In standalone mode the in-process lock always grants, so the single node refreshes.
        ILockHandle? sweepLock;
        try
        {
            sweepLock = await _locks.TryAcquireAsync(RefreshLockName, RefreshLockTtl, ct);
        }
        catch (Exception ex)
        {
            // RunRefreshPassAsync rethrows on failure and ExecuteAsync's loop has no catch around
            // it, so an uncaught exception here escapes and — under BackgroundService's default
            // StopHost behavior — takes the whole replica down on a routine distributed-lock
            // backend blip (e.g. Redis failover). Treat it exactly like "another instance holds
            // the lock": skip this pass.
            _logger.LogError(ex, "Stats refresh pass skipped — sweep lock acquire failed.");
            return;
        }

        if (sweepLock is null)
        {
            _logger.LogDebug("Stats refresh pass skipped — another instance holds the sweep lock.");
            return;
        }

        // A pass over a large instance can outrun the lock TTL, at which point a second replica
        // would acquire the same lock and recompute the same snapshots concurrently. Renew the
        // lease for as long as the pass runs, and abort the pass if renewal fails.
        var lease = LeaderLease.Start(sweepLock, RefreshLockTtl, _time, _logger, ct);
        var leaseCt = lease.Token;
        try
        {
            // now-ok: measures real elapsed time for a duration log/metric only — no control
            // flow branches on the value, so a substitutable clock would change the reported
            // number without changing what the code does.
            var sw = Stopwatch.StartNew();
            var orgIds = await _snapshots.ListActiveOrgIdsAsync(leaseCt);
            int refreshed = 0;

            foreach (string orgId in orgIds)
            {
                // The per-org guard below swallows failures, so this is the point at which a lost
                // lease (or a host shutdown) actually stops the pass.
                if (leaseCt.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    // now-ok: measures real elapsed time for a duration log/metric only — no control
                    // flow branches on the value, so a substitutable clock would change the reported
                    // number without changing what the code does.
                    var orgSw = Stopwatch.StartNew();
                    var stats = await _analytics.GetOrgStatsAsync(orgId, leaseCt);
                    orgSw.Stop();

                    string json = JsonSerializer.Serialize(stats, JsonContracts.Web);
                    string computedAt = _time.GetUtcNow().ToUtcIso();
                    await _snapshots.UpsertSnapshotAsync(orgId, json, computedAt, orgSw.ElapsedMilliseconds, leaseCt);
                    refreshed++;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to refresh stats snapshot for org {OrgId}.", orgId);
                }
            }

            sw.Stop();
            _logger.LogDebug(
                "Stats refresh pass complete. Refreshed {Refreshed}/{Total} org(s) in {ElapsedMs}ms.",
                refreshed, orgIds.Count, sw.ElapsedMilliseconds);
        }
        catch (OperationCanceledException) when (lease.LeaseLost)
        {
            // Log the abort with the lock name here, where the lease is in scope, then throw the
            // dedicated exception type so RunRefreshPassAsync can recognize a lease abort apart
            // from host shutdown (LeaderLease.LeaseLost) without a field shared across the call
            // chain — the exception type is the signal, and the scope wrapper still records the
            // pass as cancelled rather than completed since LeaseAbortedException derives from
            // OperationCanceledException.
            _logger.LogWarning(
                "Stats refresh pass aborted — the {LockName} sweep lease was lost mid-pass.",
                RefreshLockName);
            throw new LeaseAbortedException();
        }
        finally
        {
            // The lease owns the handle: stopping the heartbeat and releasing the lock are one step.
            await lease.DisposeAsync();
        }
    }

    // Signals "the sweep lease was lost mid-pass" from RunRefreshPassInnerAsync up to
    // RunRefreshPassAsync's catch, replacing a field that would otherwise have to be shared
    // mutable state across that call chain. Private and file-scoped: never crosses this type's
    // boundary, so callers have no need to catch it by type.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Critical Code Smell", "S3871:Exception types should be \"public\"",
        Justification = "Private, file-scoped control-flow signal used only within RunRefreshPassAsync's " +
            "own catch of RunRefreshPassInnerAsync; it never crosses this type's boundary, so callers have " +
            "no need to catch it by type.")]
    private sealed class LeaseAbortedException() : OperationCanceledException("Sweep lease lost mid-pass.");
}
