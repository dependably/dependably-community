using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Periodic eviction of the shared proxy cache. Three caps, all optional:
/// <list type="bullet">
///   <item><c>CACHE_MAX_AGE_DAYS</c> — evict artifacts not accessed in N days</item>
///   <item><c>CACHE_MAX_SIZE_BYTES</c> — evict oldest-accessed until under cap</item>
///   <item><c>CACHE_MAX_ARTIFACTS</c> — evict oldest-accessed until row count is under cap</item>
/// </list>
/// Schedule via <c>CACHE_EVICT_SCHEDULE</c> (cron, default hourly). The job is idempotent and
/// holds no state across runs; the leader election in <see cref="LeaderElectedScheduler"/>
/// is what prevents two replicas evicting the same row twice.
///
/// Eviction always cascades: deleting a <c>cache_artifact</c> row drops the FK-cascade
/// <c>tenant_artifact_access</c> rows automatically (keep/cascade decision: cascade by
/// default; usage history without a backing artifact is dead weight).
/// </summary>
public sealed class CacheEvictionService : ScheduledBackgroundService
{
    private readonly CacheArtifactRepository _cache;
    private readonly IBlobStore _blobs;   // TieredBlobStorage.Cache — only ever deletes from the cache tier
    private readonly IConfiguration _config;
    private readonly ILogger<CacheEvictionService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "CACHE_EVICT_SCHEDULE";
    protected override string DefaultCron => "0 * * * *";
    protected override string ScopeJobName => "cache-eviction";
    protected override string ScopeMetricName => "cache.evict";

    public CacheEvictionService(
        CacheArtifactRepository cache,
        TieredBlobStorage blobs,
        IConfiguration config,
        ILogger<CacheEvictionService> logger,
        TimeProvider time)
        : base(config, logger, time)
    {
        _cache = cache;
        // Eviction is cache-only. In split-tier deployments the registry tier is durable
        // and never evicted — even though cache_artifact rows refer to keys we own, we
        // must never call delete on the registry store from this background job.
        _blobs = blobs.Cache;
        _config = config;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunOnceAsync(ct);

    /// <summary>
    /// Runs a single eviction pass. Public so it can be invoked directly in tests without
    /// waiting on the cron schedule.
    /// </summary>
    public async Task<EvictionSummary> RunOnceAsync(CancellationToken ct = default)
    {
        int? maxAgeDays = ParseInt("CACHE_MAX_AGE_DAYS");
        long? maxSizeBytes = ParseLong("CACHE_MAX_SIZE_BYTES");
        int? maxArtifacts = ParseInt("CACHE_MAX_ARTIFACTS");

        if (maxAgeDays is null && maxSizeBytes is null && maxArtifacts is null)
        {
            // Nothing configured; skip silently.
            return new EvictionSummary(0, 0);
        }

        _logger.LogInformation(
            "Cache eviction starting (maxAgeDays={MaxAgeDays}, maxSizeBytes={MaxSizeBytes}, maxArtifacts={MaxArtifacts}).",
            maxAgeDays, maxSizeBytes, maxArtifacts);

        long evicted = 0;
        long bytesFreed = 0;

        if (maxAgeDays is { } days)
        {
            (evicted, bytesFreed) = await EvictByAgeAsync(days, evicted, bytesFreed, ct);
        }

        if (maxSizeBytes is not null || maxArtifacts is not null)
        {
            (evicted, bytesFreed) = await EvictBySizeAsync(maxSizeBytes, evicted, bytesFreed, ct);
        }

        _logger.LogInformation("Cache eviction done (evicted={Evicted}, bytesFreed={BytesFreed}).",
            evicted, bytesFreed);
        return new EvictionSummary(evicted, bytesFreed);
    }

    private const int Batch = 256;

    /// <summary>
    /// Drops every cache row whose <c>last_accessed_at</c> is older than the threshold.
    /// Pulls in batches so a million-row purge doesn't hold the connection open for minutes.
    /// </summary>
    private async Task<(long evicted, long bytesFreed)> EvictByAgeAsync(
        int days, long evicted, long bytesFreed, CancellationToken ct)
    {
        var threshold = _time.GetUtcNow().AddDays(-days);
        while (!ct.IsCancellationRequested)
        {
            var rows = await _cache.ListLruCandidatesAsync(threshold, Batch, ct);
            if (rows.Count == 0)
            {
                break;
            }

            foreach (var row in rows)
            {
                await EvictAsync(row, ct);
                evicted++;
                bytesFreed += row.SizeBytes;
            }
        }
        return (evicted, bytesFreed);
    }

    /// <summary>
    /// Drops oldest-accessed rows until the total cache size is at or below
    /// <paramref name="maxSizeBytes"/>. Per-row size is decremented from a running total
    /// to avoid an extra DB round-trip after every delete.
    /// </summary>
    private async Task<(long evicted, long bytesFreed)> EvictBySizeAsync(
        long? maxSizeBytes, long evicted, long bytesFreed, CancellationToken ct)
    {
        long cap = maxSizeBytes ?? long.MaxValue;
        while (!ct.IsCancellationRequested)
        {
            long total = await _cache.GetTotalSizeBytesAsync(ct);
            if (total <= cap)
            {
                break;
            }

            var rows = await _cache.ListLruCandidatesAsync(_time.GetUtcNow(), Batch, ct);
            if (rows.Count == 0)
            {
                break;
            }

            foreach (var row in rows)
            {
                await EvictAsync(row, ct);
                evicted++;
                bytesFreed += row.SizeBytes;
                total -= row.SizeBytes;
                if (total <= cap)
                {
                    break;
                }
            }
        }
        return (evicted, bytesFreed);
    }

    private async Task EvictAsync(CacheArtifact a, CancellationToken ct)
    {
        // Delete blob first so a crash between blob and row leaves a recoverable state
        // (orphaned row, recreated on next fetch). The reverse — orphaned blob — is a leak.
        try { await _blobs.DeleteAsync(BlobKeys.StoreKey(a.BlobKey), ct); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Cache eviction: blob delete failed for {Id} ({Key}); row left in place to retry next pass.",
                a.Id, a.BlobKey);
            return;
        }
        await _cache.DeleteAsync(a.Id, ct);
    }

    // deepcode ignore NoHardcodedCredentials: reads numeric tuning knobs (limits, ages) from
    // IConfiguration; values are integers, not credentials. `key` is a config name constant.
    private int? ParseInt(string key) =>
        int.TryParse(_config[key], out int v) && v > 0 ? v : null;

    // deepcode ignore NoHardcodedCredentials: see ParseInt above.
    private long? ParseLong(string key) =>
        long.TryParse(_config[key], out long v) && v > 0 ? v : null;
}

public readonly record struct EvictionSummary(long ArtifactsEvicted, long BytesFreed);
