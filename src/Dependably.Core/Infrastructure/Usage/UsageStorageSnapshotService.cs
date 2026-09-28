using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Captures every org's storage into <c>storage_snapshot</c> once a day
/// (<c>USAGE_STORAGE_SNAPSHOT_SCHEDULE</c>, default 00:05 UTC). Before capturing today, checks
/// whether yesterday was ever captured at all — if the node was down at its scheduled time, this
/// catches that single missed day up using today's current composition as the best available
/// figure, rather than leaving a permanent gap in <c>storage_snapshot</c> and an un-raised
/// <c>usage_daily.storage_bytes</c> mark for that day. A day that already has a snapshot is never
/// recaptured here — see <see cref="UsageRollupHourlyService"/> and
/// <see cref="UsageRollupDailyService"/> for the events/hourly/daily catch-up story; this job's
/// own catch-up is one day deep by design, because <c>storage_snapshot</c>'s per-day composition
/// columns describe that day's actual state and re-deriving one from a much later capture would
/// misrepresent it, whereas the <c>usage_daily.storage_bytes</c> mark this raises is monotonic and
/// safe to write from any later capture.
///
/// suspension-ok: not per-tenant. The capture snapshots every org's storage in one pass with no
/// per-org selection point — a suspended org's storage still has to be captured because it still
/// occupies (and bills for) space.
/// </summary>
public sealed class UsageStorageSnapshotService : ScheduledBackgroundService
{
    internal const string JobName = "usage-storage-snapshot";

    private readonly StorageSnapshotRepository _snapshots;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<UsageStorageSnapshotService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "USAGE_STORAGE_SNAPSHOT_SCHEDULE";
    protected override string DefaultCron => "5 0 * * *";
    protected override string ScopeJobName => JobName;
    protected override string ScopeMetricName => "usage.storage.snapshot";

    // Writes shared storage_snapshot/usage_daily rows across every org — one replica per tick.
    protected override bool RequiresLeaderLock => true;

    public UsageStorageSnapshotService(
        StorageSnapshotRepository snapshots,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<UsageStorageSnapshotService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _snapshots = snapshots;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunPassAsync(ct);

    // internal (not private) so tests can drive a pass directly without the cron/leader-lock
    // scheduling machinery, mirroring RetentionService.RunGcPassAsync.
    internal async Task RunPassAsync(CancellationToken ct)
    {
        if (_airGap.IsJobDisabled(JobName))
        {
            _logger.LogInformation(
                "Usage storage snapshot skipped (disabled by AIR_GAPPED, DISABLE_BACKGROUND_JOBS, or edge mode).");
            return;
        }

        var now = _time.GetUtcNow();
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        var yesterday = today.AddDays(-1);

        if (!await _snapshots.HasAnySnapshotForDayAsync(yesterday, ct))
        {
            int caughtUp = await _snapshots.CaptureAsync(yesterday, now, ct);
            if (caughtUp > 0)
            {
                _logger.LogInformation(
                    "Usage storage snapshot: caught up {Count} org(s) for {Day} (no prior snapshot existed).",
                    caughtUp, yesterday);
            }
        }

        int captured = await _snapshots.CaptureAsync(today, now, ct);
        _logger.LogInformation(
            "Usage storage snapshot: captured {Count} org(s) for {Day}.", captured, today);
    }
}
