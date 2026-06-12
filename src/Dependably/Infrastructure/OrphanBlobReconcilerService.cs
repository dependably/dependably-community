using Cronos;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Periodic reconciliation of the registry (hosted) tier: lists every blob under the
/// <c>hosted/</c> prefix and deletes those that no <c>package_versions</c> row references.
/// This closes the SIGKILL gap in <see cref="Publish.PackagePublishService"/> — the
/// application-exception path during publish is handled by the inline compensating delete,
/// but a process killed between blob put and metadata commit leaves an orphan that only
/// this sweep can recover.
///
/// Schedule via <c>ORPHAN_RECONCILE_SCHEDULE</c> (cron, default daily 04:00 UTC). Skipped
/// silently if disabled (set the schedule to a non-parseable value to opt out). A grace
/// window (<c>ORPHAN_RECONCILE_GRACE_MINUTES</c>, default 30) keeps in-flight publishes
/// out of the deletion set — any blob whose mtime/last-modified is more recent than
/// <c>now - grace</c> is left alone even if the matching row hasn't been committed yet.
///
/// Cache-tier reconciliation is a separate concern handled by
/// <see cref="CacheEvictionService"/>; this service is registry-only and never touches
/// proxy/-prefixed blobs.
/// </summary>
public sealed class OrphanBlobReconcilerService : BackgroundService
{
    private readonly TieredBlobStorage _blobs;
    private readonly PackageRepository _packages;
    private readonly IConfiguration _config;
    private readonly ILogger<OrphanBlobReconcilerService> _logger;

    public OrphanBlobReconcilerService(
        TieredBlobStorage blobs,
        PackageRepository packages,
        IConfiguration config,
        ILogger<OrphanBlobReconcilerService> logger)
    {
        _blobs = blobs;
        _packages = packages;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string scheduleText = _config["ORPHAN_RECONCILE_SCHEDULE"] ?? "0 4 * * *";
        CronExpression schedule;
        try { schedule = CronExpression.Parse(scheduleText, CronFormat.Standard); }
        catch (CronFormatException)
        {
            _logger.LogInformation(
                "OrphanBlobReconcilerService disabled (ORPHAN_RECONCILE_SCHEDULE='{Schedule}' not parseable as cron).",
                scheduleText);
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var next = schedule.GetNextOccurrence(DateTimeOffset.UtcNow, TimeZoneInfo.Utc);
            if (next is null)
            {
                break;
            }

            var delay = next.Value - DateTimeOffset.UtcNow;
            if (delay > TimeSpan.Zero)
            {
                try { await Task.Delay(delay, stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            using var scope = Dependably.Infrastructure.Observability.BackgroundJobScope.Begin(
                "orphan-reconciler", "blob_store.reconcile");
            try
            {
                await RunOnceAsync(stoppingToken);
                scope.Complete();
            }
            catch (Exception ex)
            {
                scope.Fail(ex);
                _logger.LogError(ex, "Orphan-blob reconciliation pass failed.");
            }
        }
    }

    /// <summary>
    /// Runs one sweep. Public so tests can invoke it directly without waiting on cron.
    /// Returns a summary of what was found and deleted.
    /// </summary>
    public async Task<ReconcileSummary> RunOnceAsync(CancellationToken ct = default)
    {
        int graceMinutes = int.TryParse(_config["ORPHAN_RECONCILE_GRACE_MINUTES"], out int g) && g > 0
            ? g : 30;
        var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(graceMinutes);

        // Materialize the referenced-keys set first. For a tenant with millions of versions
        // this hits memory but is bounded by metadata size, not blob size; for community
        // scale it's fine. If this becomes a constraint the approach to swap to is
        // "stream blobs in batches of N, query EXISTS for each batch."
        var referenced = new HashSet<string>(StringComparer.Ordinal);
        await foreach (string key in _packages.StreamAllBlobKeysAsync(ct))
        {
            referenced.Add(key);
        }

        long orphansDeleted = 0;
        long bytesFreed = 0;
        long deletionFailures = 0;
        var registry = _blobs.Registry;

        await foreach (var blob in registry.ListAsync("hosted/", ct))
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            if (referenced.Contains(blob.Key))
            {
                continue;
            }

            if (blob.LastModified > cutoff)
            {
                continue;  // inside grace window
            }

            try
            {
                await registry.DeleteAsync(blob.Key, ct);
                orphansDeleted++;
                bytesFreed += blob.SizeBytes;
                _logger.LogInformation(
                    "Orphan reconciled: deleted {Key} ({Bytes} bytes, last modified {LastModified:o}).",
                    blob.Key, blob.SizeBytes, blob.LastModified);
            }
            catch (Exception ex)
            {
                deletionFailures++;
                _logger.LogWarning(ex,
                    "Orphan reconciliation: delete failed for {Key}; will retry next pass.",
                    blob.Key);
            }
        }

        if (orphansDeleted > 0 || deletionFailures > 0)
        {
            _logger.LogInformation(
                "Orphan reconciliation pass done (orphansDeleted={Deleted}, bytesFreed={Freed}, deletionFailures={Failed}, gracedMinutes={Grace}).",
                orphansDeleted, bytesFreed, deletionFailures, graceMinutes);
        }
        return new ReconcileSummary(orphansDeleted, bytesFreed, deletionFailures);
    }
}

public readonly record struct ReconcileSummary(long OrphansDeleted, long BytesFreed, long DeletionFailures);
