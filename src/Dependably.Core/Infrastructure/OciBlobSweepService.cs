using Dapper;
using Dependably.Infrastructure.Redis;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Reclaims OCI blob rows that no image references any more — the layers and config blobs left
/// behind when an image is deleted or evicted.
///
/// Image eviction (retention, the cache LRU, a manual delete) releases the manifest and its
/// catalogue rows; it deliberately does not walk the manifest's closure, because a cascading delete
/// makes correctness depend on traversal order against concurrent pushes. This sweep closes the loop
/// afterwards, justifying each delete against the reference graph as it stands right then.
///
/// Runs per org and is gated per org on complete closure knowledge
/// (<see cref="OciBlobReclaimer.IsOrgClosureCompleteAsync"/>), so a tenant whose backfill has not
/// finished simply reclaims nothing rather than deleting on partial evidence. Leader-gated: the work
/// is shared-state only, so one replica per tick is both sufficient and cheaper.
/// </summary>
public sealed class OciBlobSweepService : ScheduledBackgroundService
{
    // Blob rows examined per org per tick. Bounds the lock hold and the physical deletes a single
    // pass issues; the sweep is convergent, so the remainder is picked up next tick.
    private const int PerOrgLimit = 500;

    private readonly IMetadataStore _db;
    private readonly OciBlobReclaimer _reclaimer;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<OciBlobSweepService> _logger;

    protected override string CronEnvKey => "OCI_BLOB_SWEEP_SCHEDULE";
    protected override string DefaultCron => "17 * * * *";
    protected override string ScopeJobName => "oci-blob-sweep";
    protected override string ScopeMetricName => "oci.blob.sweep";
    protected override bool RequiresLeaderLock => true;

    public OciBlobSweepService(
        IMetadataStore db,
        OciBlobReclaimer reclaimer,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<OciBlobSweepService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _db = db;
        _reclaimer = reclaimer;
        _airGap = airGap;
        _logger = logger;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunOnceAsync(ct);

    /// <summary>
    /// Runs one sweep across every org and returns the total rows reclaimed. Public so tests can
    /// drive it without the cron schedule.
    /// </summary>
    public async Task<int> RunOnceAsync(CancellationToken ct = default)
    {
        // This sweep is the only scheduled job in the OCI path that deletes bytes, so the operator
        // switch matters more here than anywhere else — and the edge allowlist inversion over
        // BackgroundJobs.Known must keep a cache node from reclaiming against a graph the
        // authoritative node owns.
        if (_airGap.IsJobDisabled("oci-blob-sweep"))
        {
            _logger.LogInformation(
                "OCI blob sweep skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return 0;
        }

        int total = 0;

        foreach (string orgId in await ListOrgsWithOciContentAsync(ct))
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            total += await _reclaimer.ReclaimUnreferencedAsync(orgId, PerOrgLimit, ct);
        }

        if (total > 0)
        {
            _logger.LogInformation("OCI blob sweep reclaimed {Count} unreferenced blob rows", total);
        }

        return total;
    }

    private async Task<IReadOnlyList<string>> ListOrgsWithOciContentAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: deliberately fleet-wide — the sweep visits every tenant in turn, and each org's
        // reclaim is org_id-scoped inside OciBlobReclaimer.
        var rows = await conn.QueryAsync<string>("SELECT DISTINCT org_id FROM oci_blobs ORDER BY org_id");
        return rows.AsList();
    }
}
