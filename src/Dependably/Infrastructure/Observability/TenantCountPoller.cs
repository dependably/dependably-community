using Dapper;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Polls the orgs table for the count of active (non-soft-deleted) tenants
/// and writes it into <see cref="DependablyMeter.RecordTenantCount"/>. The
/// observable gauge <c>dependably.tenants.count</c> reads the cached value
/// on scrape so the meter never runs a query inline.
///
/// <para>Default poll interval is 60 seconds (env
/// <c>TENANT_COUNT_POLL_INTERVAL_SECONDS</c>); set <c>0</c> to disable.</para>
/// </summary>
public sealed class TenantCountPoller : BackgroundService
{
    private readonly IMetadataStore _db;
    private readonly IAirGapMode _airGap;
    private readonly TimeSpan _interval;
    private readonly ILogger<TenantCountPoller> _logger;

    public TenantCountPoller(IMetadataStore db, IConfiguration config, IAirGapMode airGap, ILogger<TenantCountPoller> logger)
    {
        _db = db;
        _airGap = airGap;
        _logger = logger;
        int seconds = int.TryParse(config["TENANT_COUNT_POLL_INTERVAL_SECONDS"], out int s) && s > 0
            ? s
            : 60;
        _interval = TimeSpan.FromSeconds(seconds);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // First poll right after startup so the gauge isn't empty on cold launch.
        try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            await PollOnceAsync(stoppingToken);

            try { await Task.Delay(_interval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    internal async Task PollOnceAsync(CancellationToken ct)
    {
        // A headless edge node has one implicit org and no tenant lifecycle, so this gauge is
        // inert there — edge mode force-disables tenant-count-poller (not in the allowlist).
        if (_airGap.IsJobDisabled("tenant-count-poller"))
        {
            return;
        }

        try
        {
            await using var conn = await _db.OpenAsync(ct);
            long count = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM orgs WHERE deleted_at IS NULL");
            DependablyMeter.RecordTenantCount(count);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TenantCountPoller: failed to query tenant count; last-known value retained.");
        }
    }
}
