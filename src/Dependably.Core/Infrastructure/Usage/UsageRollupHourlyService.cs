using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Recomputes <c>usage_hourly</c> from <c>usage_events</c> on a fixed cadence
/// (<c>USAGE_ROLLUP_HOURLY_SCHEDULE</c>, default ten minutes past every hour so the hour it
/// closes has fully landed). Each tick recomputes the window from the last successful run's
/// watermark — minus a safety margin so an event that lands just after a tick is still absorbed
/// by the next one — through now, bounded to at most <see cref="MaxLookbackDays"/> days so a long
/// outage or the very first run cannot force an unbounded historical rescan. Recomputing the same
/// window twice is a no-op (see <see cref="UsageRollupRepository"/>'s own class doc), so the
/// overlapping margin never double-counts and a gap of any length is caught up safely.
///
/// The pass ends by recomputing every capped org's <c>orgs.usage_posture</c> from the buckets it
/// just wrote (<see cref="UsagePostureRepository.RecomputeAsync"/>), so an egress cap trips within
/// one pass of the usage that crossed it.
///
/// suspension-ok: not per-tenant. The rollup recomputes every org's buckets in one pass with no
/// per-org selection point, and a suspended org's already-recorded usage still has to settle into
/// its bill rather than freeze mid-period.
/// </summary>
public sealed class UsageRollupHourlyService : ScheduledBackgroundService
{
    internal const string JobName = "usage-rollup-hourly";

    // How far behind the last successful run's watermark this pass starts, so an event that was
    // still in flight (not yet committed) when the previous tick ran gets absorbed by this one
    // rather than requiring a manual backfill.
    private static readonly TimeSpan SafetyMargin = TimeSpan.FromHours(2);

    // Caps the rescanned window on a long outage or the first-ever run: RecomputeHourlyAsync's
    // cost is proportional to the window width, and usage_events itself is retained well beyond
    // this (396 days), so a catch-up run never needs to reach further back than this to produce a
    // correct current-period bill — anything older is a job for the weekly reconciliation, not
    // for this job's own catch-up window.
    private const int MaxLookbackDays = 7;

    private readonly UsageRollupRepository _rollups;
    private readonly UsagePostureRepository _postures;
    private readonly BackgroundJobRunRepository _jobRuns;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<UsageRollupHourlyService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "USAGE_ROLLUP_HOURLY_SCHEDULE";
    protected override string DefaultCron => "10 * * * *";
    protected override string ScopeJobName => JobName;
    protected override string ScopeMetricName => "usage.rollup.hourly";

    // Recomputes shared usage_hourly rows across every org — one replica per tick.
    protected override bool RequiresLeaderLock => true;

    public UsageRollupHourlyService(
        UsageRollupRepository rollups,
        UsagePostureRepository postures,
        BackgroundJobRunRepository jobRuns,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<UsageRollupHourlyService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _rollups = rollups;
        _postures = postures;
        _jobRuns = jobRuns;
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
                "Usage hourly rollup skipped (disabled by AIR_GAPPED, DISABLE_BACKGROUND_JOBS, or edge mode).");
            return;
        }

        var now = _time.GetUtcNow();
        var from = await ResolveFromAsync(now, ct);

        int written = await _rollups.RecomputeHourlyAsync(from, now, now, ct);
        _logger.LogInformation(
            "Usage hourly rollup: recomputed {Buckets} bucket(s) for window [{From}, {To}).",
            written, from, now);

        int postureChanges = await _postures.RecomputeAsync(ct);
        _logger.LogInformation(
            "Usage posture: {Changed} org(s) changed posture after the hourly rollup.",
            postureChanges);
    }

    // The lookback window's start: the last successful run's watermark minus SafetyMargin, bounded
    // to at most MaxLookbackDays back. Absent any prior success (first-ever run, or every past run
    // failed) the window opens at the full lookback floor, so a fresh deployment catches up its
    // full retained history rather than rolling up nothing.
    private async Task<DateTimeOffset> ResolveFromAsync(DateTimeOffset now, CancellationToken ct)
    {
        var floor = now.AddDays(-MaxLookbackDays);

        var (items, _) = await _jobRuns.ListAsync(
            new BackgroundJobRunQuery(
                JobName: JobName,
                Outcome: "success",
                SortBy: "startedAt",
                SortDir: "desc",
                Limit: 1,
                Offset: 0),
            ct);

        if (items.Count == 0)
        {
            return floor;
        }

        var watermark = items[0].FinishedAt - SafetyMargin;
        return watermark < floor ? floor : watermark;
    }
}
