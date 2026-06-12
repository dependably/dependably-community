using System.Diagnostics;
using System.Text.Json;

namespace Dependably.Infrastructure;

/// <summary>
/// Background service that pre-computes the dashboard aggregates for every active org and
/// stores them in <c>org_stats_snapshot</c>. The /api/v1/stats endpoint reads that snapshot
/// instead of running <see cref="PackageAnalyticsRepository.GetOrgStatsAsync"/>'s eight live
/// aggregate queries on every page load (which took seconds on large instances).
///
/// Runs one pass on startup so snapshots populate shortly after boot, then refreshes on a
/// fixed interval (STATS_REFRESH_INTERVAL_SECONDS env var, default 300s).
/// </summary>
public sealed class StatsRefreshService : BackgroundService
{
    // Match the MVC pipeline's camelCase output so the cached JSON returned verbatim by
    // GetStats is byte-compatible with the live Ok(stats) path the frontend already consumes.
    private static readonly JsonSerializerOptions SnapshotJson = new(JsonSerializerDefaults.Web);

    private readonly StatsSnapshotRepository _snapshots;
    private readonly PackageAnalyticsRepository _analytics;
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<StatsRefreshService> _logger;

    public StatsRefreshService(
        StatsSnapshotRepository snapshots,
        PackageAnalyticsRepository analytics,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<StatsRefreshService> logger)
    {
        _snapshots = snapshots;
        _analytics = analytics;
        _config = config;
        _airGap = airGap;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        int intervalSeconds = int.TryParse(_config["STATS_REFRESH_INTERVAL_SECONDS"], out int s) && s > 0
            ? s
            : 300;

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
        using var scope = Observability.BackgroundJobScope.Begin("stats-refresh", "stats.refresh");
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

                string json = JsonSerializer.Serialize(stats, SnapshotJson);
                string computedAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                await _snapshots.UpsertSnapshotAsync(orgId, json, computedAt, orgSw.ElapsedMilliseconds, ct);
                refreshed++;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to refresh stats snapshot for org {OrgId}.", orgId);
            }
        }

        sw.Stop();
        _logger.LogInformation(
            "Stats refresh pass complete. Refreshed {Refreshed}/{Total} org(s) in {ElapsedMs}ms.",
            refreshed, orgIds.Count, sw.ElapsedMilliseconds);
    }
}
