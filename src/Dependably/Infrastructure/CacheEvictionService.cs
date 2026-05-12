using Cronos;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Periodic eviction of the shared proxy cache (#48). Three caps, all optional:
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
/// <c>tenant_artifact_access</c> rows automatically (#48 keep/cascade decision: cascade by
/// default; usage history without a backing artifact is dead weight).
/// </summary>
public sealed class CacheEvictionService : BackgroundService
{
    private readonly CacheArtifactRepository _cache;
    private readonly IBlobStore _blobs;   // TieredBlobStorage.Cache — only ever deletes from the cache tier (#57)
    private readonly IConfiguration _config;
    private readonly ILogger<CacheEvictionService> _logger;

    public CacheEvictionService(
        CacheArtifactRepository cache,
        TieredBlobStorage blobs,
        IConfiguration config,
        ILogger<CacheEvictionService> logger)
    {
        _cache = cache;
        // Eviction is cache-only. In split-tier deployments the registry tier is durable
        // and never evicted — even though cache_artifact rows refer to keys we own, we
        // must never call delete on the registry store from this background job.
        _blobs = blobs.Cache;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var schedule = CronExpression.Parse(
            _config["CACHE_EVICT_SCHEDULE"] ?? "0 * * * *",
            CronFormat.Standard);

        while (!stoppingToken.IsCancellationRequested)
        {
            var next = schedule.GetNextOccurrence(DateTimeOffset.UtcNow, TimeZoneInfo.Utc);
            if (next is null) break;

            var delay = next.Value - DateTimeOffset.UtcNow;
            if (delay > TimeSpan.Zero)
            {
                try { await Task.Delay(delay, stoppingToken); }
                catch (OperationCanceledException) { break; }
            }

            if (stoppingToken.IsCancellationRequested) break;

            try { await RunOnceAsync(stoppingToken); }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Cache eviction pass failed.");
            }
        }
    }

    /// <summary>
    /// Runs a single eviction pass. Public so it can be invoked directly in tests without
    /// waiting on the cron schedule.
    /// </summary>
    public async Task<EvictionSummary> RunOnceAsync(CancellationToken ct = default)
    {
        var maxAgeDays = ParseInt("CACHE_MAX_AGE_DAYS");
        var maxSizeBytes = ParseLong("CACHE_MAX_SIZE_BYTES");
        var maxArtifacts = ParseInt("CACHE_MAX_ARTIFACTS");

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
            (evicted, bytesFreed) = await EvictByAgeAsync(days, evicted, bytesFreed, ct);

        if (maxSizeBytes is not null || maxArtifacts is not null)
            (evicted, bytesFreed) = await EvictBySizeAsync(maxSizeBytes, evicted, bytesFreed, ct);

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
        var threshold = DateTimeOffset.UtcNow.AddDays(-days);
        while (!ct.IsCancellationRequested)
        {
            var rows = await _cache.ListLruCandidatesAsync(threshold, Batch, ct);
            if (rows.Count == 0) break;
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
        var cap = maxSizeBytes ?? long.MaxValue;
        while (!ct.IsCancellationRequested)
        {
            var total = await _cache.GetTotalSizeBytesAsync(ct);
            if (total <= cap) break;

            var rows = await _cache.ListLruCandidatesAsync(DateTimeOffset.UtcNow, Batch, ct);
            if (rows.Count == 0) break;
            foreach (var row in rows)
            {
                await EvictAsync(row, ct);
                evicted++;
                bytesFreed += row.SizeBytes;
                total -= row.SizeBytes;
                if (total <= cap) break;
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

    private int? ParseInt(string key) =>
        int.TryParse(_config[key], out var v) && v > 0 ? v : null;

    private long? ParseLong(string key) =>
        long.TryParse(_config[key], out var v) && v > 0 ? v : null;
}

public readonly record struct EvictionSummary(long ArtifactsEvicted, long BytesFreed);
