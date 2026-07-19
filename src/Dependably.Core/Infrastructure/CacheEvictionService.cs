using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Periodic eviction of the shared proxy cache. Three caps, all optional:
/// <list type="bullet">
///   <item><c>CACHE_MAX_AGE_DAYS</c> — evict artifacts not accessed in N days</item>
///   <item><c>CACHE_MAX_SIZE_BYTES</c> — evict oldest-accessed until under cap</item>
///   <c>CACHE_MAX_ARTIFACTS</c> — evict oldest-accessed until row count is under cap</item>
/// </list>
/// When none of the three caps are configured, a default age cap of 30 days applies so the
/// proxy cache does not grow unbounded. Set any cap explicitly to take full control; setting
/// any one cap suppresses the default.
///
/// Schedule via <c>CACHE_EVICT_SCHEDULE</c> (cron, default hourly). The job is idempotent and
/// holds no state across runs; in a multi-replica (HA) deployment the per-tick leader lock (see
/// <see cref="RequiresLeaderLock"/>) ensures only one replica evicts each row per pass.
///
/// Eviction always cascades: deleting a <c>cache_artifact</c> row drops the FK-cascade
/// <c>tenant_artifact_access</c> rows automatically (keep/cascade decision: cascade by
/// default; usage history without a backing artifact is dead weight).
/// </summary>
public sealed class CacheEvictionService : ScheduledBackgroundService
{
    private readonly CacheArtifactRepository _cache;
    private readonly IBlobStore _blobs;   // TieredBlobStorage.Cache — only ever deletes from the cache tier
    private readonly CacheOrphanBlobDeleter _orphanBlobs;
    private readonly IConfiguration _config;
    private readonly ILogger<CacheEvictionService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "CACHE_EVICT_SCHEDULE";
    protected override string DefaultCron => "0 * * * *";
    protected override string ScopeJobName => "cache-eviction";
    protected override string ScopeMetricName => "cache.evict";

    // Deletes shared cache_artifact rows and cache-tier blobs — one replica per tick in HA mode.
    protected override bool RequiresLeaderLock => true;

    public CacheEvictionService(
        CacheArtifactRepository cache,
        TieredBlobStorage blobs,
        CacheOrphanBlobDeleter orphanBlobs,
        IConfiguration config,
        ILogger<CacheEvictionService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _cache = cache;
        // Eviction is cache-only. In split-tier deployments the registry tier is durable
        // and never evicted — even though cache_artifact rows refer to keys we own, we
        // must never call delete on the registry store from this background job.
        _blobs = blobs.Cache;
        _orphanBlobs = orphanBlobs;
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

        bool usingDefault = maxAgeDays is null && maxSizeBytes is null && maxArtifacts is null;
        if (usingDefault)
        {
            maxAgeDays = DefaultMaxAgeDays;
            _logger.LogInformation(
                "No cache caps configured; applying default CACHE_MAX_AGE_DAYS={Default}. " +
                "Proxy-cache artefacts not accessed within {Default} days are evicted. Set " +
                "CACHE_MAX_SIZE_BYTES or CACHE_MAX_ARTIFACTS to bound the cache by disk size or count.",
                DefaultMaxAgeDays, DefaultMaxAgeDays);
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
            (evicted, bytesFreed) = await EvictBySizeAsync(maxSizeBytes, maxArtifacts, evicted, bytesFreed, ct);
        }

        _logger.LogInformation("Cache eviction done (evicted={Evicted}, bytesFreed={BytesFreed}).",
            evicted, bytesFreed);

        if (evicted > 0)
        {
            DependablyMeter.CacheEvictions.Add(evicted);
            DependablyMeter.CacheEvictedBytes.Add(bytesFreed);
        }

        return new EvictionSummary(evicted, bytesFreed);
    }

    private const int DefaultMaxAgeDays = 30;
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

            bool progress = false;
            foreach (var row in rows)
            {
                if (ct.IsCancellationRequested) { break; }
                if (await EvictAsync(row, ct))
                {
                    evicted++;
                    bytesFreed += row.SizeBytes;
                    progress = true;
                }
            }

            // A row whose blob delete fails is left in place, and the next LRU query (ORDER BY
            // last_accessed_at, no offset) re-lists it at the same position. If a whole batch
            // fails — e.g. the cache blob backend is unreachable — re-listing would spin on the
            // same rows forever, so stop the pass once a batch makes no forward progress.
            if (!progress)
            {
                break;
            }
        }
        return (evicted, bytesFreed);
    }

    /// <summary>
    /// Drops oldest-accessed rows until the total cache size is at or below
    /// <paramref name="maxSizeBytes"/> AND the total row count is at or below
    /// <paramref name="maxArtifacts"/> — an unset cap is treated as unbounded (<see
    /// cref="long.MaxValue"/>), so a caller that passes only one of the two caps still evicts
    /// correctly against the other. Per-row size and count are decremented from running totals
    /// to avoid an extra DB round-trip after every delete.
    /// </summary>
    private async Task<(long evicted, long bytesFreed)> EvictBySizeAsync(
        long? maxSizeBytes, int? maxArtifacts, long evicted, long bytesFreed, CancellationToken ct)
    {
        long sizeCap = maxSizeBytes ?? long.MaxValue;
        long countCap = maxArtifacts ?? long.MaxValue;
        while (!ct.IsCancellationRequested)
        {
            long total = await _cache.GetTotalSizeBytesAsync(ct);
            long count = await _cache.GetTotalCountAsync(ct);
            if (total <= sizeCap && count <= countCap)
            {
                break;
            }

            var rows = await _cache.ListLruCandidatesAsync(_time.GetUtcNow(), Batch, ct);
            if (rows.Count == 0)
            {
                break;
            }

            var batch = await EvictBatchUntilCapAsync(rows, sizeCap, countCap, total, count, ct);
            evicted += batch.Evicted;
            bytesFreed += batch.BytesFreed;

            // If no row in the batch could be evicted (e.g. the cache blob backend is
            // unreachable), the running totals never drop below the caps and the next LRU query
            // re-lists the same rows — a livelock. Stop the pass once a batch makes no progress.
            if (!batch.Progress)
            {
                break;
            }
        }
        return (evicted, bytesFreed);
    }

    // Evicts rows from one LRU batch until the size/count caps are satisfied or the batch is
    // exhausted. Returns whether any row in the batch was actually evicted, so the caller can
    // detect a livelocked batch (every row's blob delete failed) and stop the outer pass.
    private async Task<(long Evicted, long BytesFreed, bool Progress)> EvictBatchUntilCapAsync(
        IReadOnlyList<CacheArtifact> rows, long sizeCap, long countCap, long total, long count, CancellationToken ct)
    {
        long evicted = 0;
        long bytesFreed = 0;
        bool progress = false;
        foreach (var row in rows)
        {
            if (ct.IsCancellationRequested) { break; }
            if (!await EvictAsync(row, ct))
            {
                continue;
            }
            evicted++;
            bytesFreed += row.SizeBytes;
            total -= row.SizeBytes;
            count--;
            progress = true;
            if (total <= sizeCap && count <= countCap)
            {
                break;
            }
        }
        return (evicted, bytesFreed, progress);
    }

    /// <summary>
    /// Evicts a single cache row: deletes its blob (unless a sibling coordinate with
    /// byte-identical content still shares the key — see <see cref="CacheOrphanBlobDeleter"/>),
    /// then its <c>cache_artifact</c> row. Returns <c>true</c> when the row was removed,
    /// <c>false</c> when the blob delete failed and the row was left in place for a later pass —
    /// callers must not count a <c>false</c> result toward evicted totals, and must treat a batch
    /// of all-<c>false</c> results as no forward progress so the re-list loop terminates instead of
    /// spinning on the same failing rows.
    /// </summary>
    private async Task<bool> EvictAsync(CacheArtifact a, CancellationToken ct)
    {
        // Delete blob first (guarded: skipped when a sibling row still shares this
        // content-addressed key) so a crash between blob and row leaves a recoverable state
        // (orphaned row, recreated on next fetch). The reverse — orphaned blob — is a leak.
        try
        {
            await _orphanBlobs.DeleteIfUnreferencedAsync(
                a.BlobKey, a.Id, BlobKeys.StoreKey(a.BlobKey), _blobs, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Cache eviction: blob delete failed for {Id} ({Key}); row left in place to retry next pass.",
                a.Id, a.BlobKey);
            return false;
        }
        await _cache.DeleteAsync(a.Id, ct);
        return true;
    }

    // reads numeric tuning knobs (limits, ages) from
    // IConfiguration; values are integers, not credentials. `key` is a config name constant.
    private int? ParseInt(string key) =>
        int.TryParse(_config[key], out int v) && v > 0 ? v : null;

    // see ParseInt above.
    private long? ParseLong(string key) =>
        long.TryParse(_config[key], out long v) && v > 0 ? v : null;
}

public readonly record struct EvictionSummary(long ArtifactsEvicted, long BytesFreed);
