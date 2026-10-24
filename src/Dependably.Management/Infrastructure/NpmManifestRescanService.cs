using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure;

/// <summary>
/// Drives <see cref="NpmManifestRescan"/> on its own short schedule until the pass is complete.
/// Each tick reads a bounded number of blobs, so a large cache needs many ticks; running them on the
/// daily licence-backfill schedule would leave an already-cached ambiguous tarball serving for months.
/// The service ticks every <c>NPM_MANIFEST_RESCAN_SCHEDULE</c> (default every five minutes) from
/// startup, and ends once the completion marker is written, so a finished instance runs no timer.
///
/// The pass reads only local blobs and the database, so it has its own job name
/// (<c>npm-manifest-rescan</c>) that <c>AIR_GAPPED</c> and the whole-set <c>DISABLE_BACKGROUND_JOBS</c>
/// switch leave running; only naming it in the list (or edge mode) stops it. It mutates shared
/// rows, so the per-tick leader lock keeps one replica working at a time in HA mode.
///
/// suspension-ok: the pass reads <c>cache_artifact</c> rows and uploaded versions of every tenant
/// off shared storage, makes no outbound call, and has no per-org axis to gate on.
/// </summary>
public sealed class NpmManifestRescanService : ScheduledBackgroundService
{
    private readonly NpmManifestRescan _rescan;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<NpmManifestRescanService> _logger;

    protected override string CronEnvKey => "NPM_MANIFEST_RESCAN_SCHEDULE";
    protected override string DefaultCron => "*/5 * * * *";
    protected override bool RunOnStartup => true;
    protected override bool RequiresLeaderLock => true;

    public NpmManifestRescanService(
        NpmManifestRescan rescan,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<NpmManifestRescanService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _rescan = rescan;
        _airGap = airGap;
        _logger = logger;
    }

    protected override async Task<bool> IsCompleteAsync(CancellationToken ct)
    {
        if (_airGap.IsJobDisabled(NpmManifestRescan.JobName))
        {
            _logger.LogInformation("npm manifest rescan not running (npm-manifest-rescan is disabled).");
            return true;
        }

        return await _rescan.IsCompleteAsync(ct);
    }

    protected override async Task RunTickAsync(CancellationToken ct)
    {
        int flagged = await _rescan.RunOnceAsync(ct: ct);
        if (flagged >= 0)
        {
            _logger.LogInformation("Flagged {Flagged} stored npm tarball(s) with an ambiguous or unscannable manifest.", flagged);
        }
    }
}
