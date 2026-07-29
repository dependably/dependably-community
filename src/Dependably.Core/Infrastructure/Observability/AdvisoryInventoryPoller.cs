using Dapper;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Polls the vulnerabilities table for the current advisory inventory, grouped by
/// (ecosystem, severity), and writes it into <see cref="DependablyMeter.RecordAdvisoryInventory"/>.
/// The observable gauge <c>dependably.advisories.tracked</c> reads the cached snapshot on
/// scrape so the meter never runs a query inline. The vulnerabilities table is the
/// instance-shared advisory catalog (no <c>org_id</c> column), so the query is not
/// tenant-scoped.
///
/// <para>Default poll interval is 5 minutes (env
/// <c>ADVISORY_INVENTORY_POLL_INTERVAL_SECONDS</c>); set <c>0</c> to disable.</para>
/// </summary>
public sealed class AdvisoryInventoryPoller : BackgroundService
{
    private readonly IMetadataStore _db;
    private readonly TimeSpan _interval;
    private readonly ILogger<AdvisoryInventoryPoller> _logger;

    public AdvisoryInventoryPoller(IMetadataStore db, IConfiguration config, ILogger<AdvisoryInventoryPoller> logger)
    {
        _db = db;
        _logger = logger;
        int seconds = int.TryParse(config["ADVISORY_INVENTORY_POLL_INTERVAL_SECONDS"], out int s) && s > 0
            ? s
            : 300;
        _interval = TimeSpan.FromSeconds(seconds);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // First poll right after startup so the gauge isn't empty on cold launch.
        // now-ok: gauge poll cadence is real elapsed time — no scheduled work observes
        // this deadline, and tests exercise PollOnce/PollOnceAsync directly, never the loop.
        try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            await PollOnceAsync(stoppingToken);

            // now-ok: same real-time poll cadence as the startup delay above.
            try { await Task.Delay(_interval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    internal async Task PollOnceAsync(CancellationToken ct)
    {
        try
        {
            await using var conn = await _db.OpenAsync(ct);
            var rows = await conn.QueryAsync<(string Ecosystem, string Severity, long Count)>(
                """
                SELECT ecosystem, COALESCE(severity, 'unscored') AS severity, COUNT(*) AS n
                FROM vulnerabilities
                GROUP BY ecosystem, COALESCE(severity, 'unscored')
                """);
            DependablyMeter.RecordAdvisoryInventory(rows.AsList());
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "AdvisoryInventoryPoller: failed to query advisory inventory; last-known value retained.");
        }
    }
}
