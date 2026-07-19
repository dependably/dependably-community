using Dependably.Infrastructure.Redis;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Periodic reconciliation of the registry (hosted) tier: lists every blob under the
/// <c>hosted/</c> prefix and deletes those no metadata row references. This closes the SIGKILL
/// gap in <see cref="Publish.PackagePublishService"/> — the application-exception path during
/// publish is handled by the inline compensating delete, but a process killed between blob put
/// and metadata commit leaves an orphan that only this sweep can recover.
///
/// The referenced set is <see cref="PackageRepository.StreamAllBlobKeysAsync"/>, the union of
/// EVERY table that can hold a hosted key — <c>package_versions</c> plus the secondary-file
/// tables (<c>package_version_files</c>, <c>maven_version_files</c>, <c>nuget_symbol_index</c>)
/// whose rows are the sole reference to a Maven <c>.pom</c>/sources jar or a PyPI sdist
/// published alongside a wheel. Anything short of that union deletes live artefacts.
///
/// Schedule via <c>ORPHAN_RECONCILE_SCHEDULE</c> (cron, default daily 04:00 UTC). Skipped
/// silently if disabled (set the schedule to a non-parseable value to opt out). A grace
/// window (<c>ORPHAN_RECONCILE_GRACE_MINUTES</c>, default 30) keeps in-flight publishes
/// out of the deletion set — any blob whose mtime/last-modified is more recent than
/// <c>now - grace</c> is left alone even if the matching row hasn't been committed yet. That
/// window, not the referenced-set read, is what makes the sweep safe against a publish
/// committing concurrently: a row committed after the set was read belongs to a blob written
/// moments earlier, so the blob is inside the grace window and is skipped regardless.
///
/// Cache-tier reconciliation is a separate concern handled by
/// <see cref="CacheEvictionService"/>; this service is registry-only and never touches
/// proxy/-prefixed blobs. The <c>oci/</c>, <c>go/</c>, <c>cargo/</c>, and <c>apk/</c> key
/// namespaces are likewise outside the <c>hosted/</c> prefix this sweep walks.
/// </summary>
public sealed class OrphanBlobReconcilerService : ScheduledBackgroundService
{
    private readonly TieredBlobStorage _blobs;
    private readonly PackageRepository _packages;
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<OrphanBlobReconcilerService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "ORPHAN_RECONCILE_SCHEDULE";
    protected override string DefaultCron => "0 4 * * *";
    protected override string ScopeJobName => "orphan-reconciler";
    protected override string ScopeMetricName => "blob_store.reconcile";
    protected override bool DisableOnInvalidCron => true;

    // Deletes shared registry-tier blobs — must run on only one replica per tick in HA mode.
    protected override bool RequiresLeaderLock => true;

    public OrphanBlobReconcilerService(
        TieredBlobStorage blobs,
        PackageRepository packages,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<OrphanBlobReconcilerService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _blobs = blobs;
        _packages = packages;
        _config = config;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunOnceAsync(ct);

    /// <summary>
    /// Runs one sweep. Public so tests can invoke it directly without waiting on cron.
    /// Returns a summary of what was found and deleted.
    /// </summary>
    public async Task<ReconcileSummary> RunOnceAsync(CancellationToken ct = default)
    {
        if (_airGap.IsJobDisabled("orphan-reconciler"))
        {
            _logger.LogInformation(
                "Orphan-blob reconcile skipped (disabled by AIR_GAPPED, DISABLE_BACKGROUND_JOBS, or edge mode).");
            return default;
        }

        int graceMinutes = int.TryParse(_config["ORPHAN_RECONCILE_GRACE_MINUTES"], out int g) && g > 0
            ? g : 30;
        var cutoff = _time.GetUtcNow() - TimeSpan.FromMinutes(graceMinutes);

        // Materialize the referenced-keys set first — the union across every table that can hold
        // a hosted key, streamed unbuffered from one statement so the DB never materializes it.
        // The set itself is bounded by metadata size, not blob size; for community scale it's
        // fine. If this becomes a constraint the approach to swap to is "stream blobs in batches
        // of N, query EXISTS for each batch."
        //
        // Reading the set BEFORE listing the blobs is the safe ordering. A publish that commits
        // its row after this read is not in the set, but its blob was put moments before the
        // commit, so the blob's LastModified lands inside the grace window below and it is
        // skipped. The inverse — listing blobs first, then reading the set — would be equally
        // safe, but this way a version DELETE racing the sweep merely defers the (already
        // deleted) blob to the next pass rather than double-deleting.
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
