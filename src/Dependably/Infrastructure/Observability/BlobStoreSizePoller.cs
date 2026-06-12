using Dependably.Storage;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Polls <see cref="IBlobStore.GetTotalSizeAsync"/> for each tier and writes
/// the result into <see cref="DependablyMeter.RecordBlobStoreSize"/>. The
/// observable gauge <c>dependably.blob_store.size_bytes</c> reads from that
/// cache on scrape, so the meter never invokes a slow size-walk inline.
///
/// <para>Default poll interval is 5 minutes (env
/// <c>BLOB_STORE_SIZE_POLL_INTERVAL_SECONDS</c>); set <c>0</c> to disable
/// the poller while keeping the gauge present (it will read zero until
/// something else writes).</para>
///
/// <para><see cref="IBlobStore.GetTotalSizeAsync"/> is O(objects) for S3
/// and Azure backends, so the poll interval should comfortably exceed how
/// long a single sweep takes. The first poll happens shortly after startup
/// so dashboards aren't empty on cold-launch.</para>
/// </summary>
public sealed class BlobStoreSizePoller : BackgroundService
{
    private readonly TieredBlobStorage _tiers;
    private readonly TimeSpan _interval;
    private readonly ILogger<BlobStoreSizePoller> _logger;

    public BlobStoreSizePoller(
        TieredBlobStorage tiers,
        IConfiguration config,
        ILogger<BlobStoreSizePoller> logger)
    {
        _tiers = tiers;
        _logger = logger;
        int seconds = int.TryParse(config["BLOB_STORE_SIZE_POLL_INTERVAL_SECONDS"], out int s) && s > 0
            ? s
            : 300;
        _interval = TimeSpan.FromSeconds(seconds);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // First poll happens 30s after startup so the gauge isn't empty for
        // the first poll interval.
        try { await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); }
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
        await PollTierAsync("registry", _tiers.Registry, ct);

        // Skip the second walk when both tiers share a backing store —
        // otherwise we'd double-count and emit two identical gauge values
        // under different labels.
        if (_tiers.IsSplit)
        {
            await PollTierAsync("cache", _tiers.Cache, ct);
        }
    }

    private async Task PollTierAsync(string tier, IBlobStore store, CancellationToken ct)
    {
        try
        {
            long size = await store.GetTotalSizeAsync(ct);
            DependablyMeter.RecordBlobStoreSize(tier, size);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "BlobStoreSizePoller: failed to poll {Tier} tier; last-known value retained.", tier);
        }
    }
}
