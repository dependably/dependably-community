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

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(intervalSeconds));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await RunRefreshPassAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
    }

    internal async Task RunRefreshPassAsync(CancellationToken ct)
    {
        using var scope = Observability.BackgroundJobScope.Begin("stats-refresh", "stats.refresh", _time);
        try
        {
            await RunRefreshPassInnerAsync(ct);
            scope.Complete();
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

        try
        {
            var sw = Stopwatch.StartNew();
            var orgIds = await _snapshots.ListActiveOrgIdsAsync(ct);
            int refreshed = 0;

            foreach (string orgId in orgIds)
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    var orgSw = Stopwatch.StartNew();
                    var stats = await _analytics.GetOrgStatsAsync(orgId, ct);
                    orgSw.Stop();

                    string json = JsonSerializer.Serialize(stats, JsonContracts.Web);
                    string computedAt = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
                    await _snapshots.UpsertSnapshotAsync(orgId, json, computedAt, orgSw.ElapsedMilliseconds, ct);
                    refreshed++;
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
        finally
        {
            await sweepLock.DisposeAsync();
        }
    }
}
