using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Recomputes <c>usage_daily</c>'s egress meters from <c>usage_hourly</c> on a daily cadence
/// (<c>USAGE_ROLLUP_DAILY_SCHEDULE</c>, default 00:40 UTC — after the hourly job's :10 past
/// occurrences have closed the last hour of the prior UTC day). Every tick recomputes the same
/// two UTC days, yesterday and today: yesterday because a tick close to midnight can race the
/// hourly job's own catch-up, and today because the day is still accumulating and each pass
/// should reflect it in-progress.
///
/// <para>Each tick recomputes <c>usage_hourly</c> for that same two-day span before deriving
/// <c>usage_daily</c> from it, rather than trusting the hourly job's own schedule to have already
/// covered it — so a correct daily bucket does not depend on the hourly job having run at all.
/// If the hourly job is healthy this recompute is a no-op re-derivation of buckets already
/// correct; if the hourly job missed a run (or never started), this pass produces a correct
/// <c>usage_daily</c> anyway.</para>
///
/// suspension-ok: not per-tenant. The rollup recomputes every org's buckets in one pass with no
/// per-org selection point, the same posture as <see cref="UsageRollupHourlyService"/>.
/// </summary>
public sealed class UsageRollupDailyService : ScheduledBackgroundService
{
    internal const string JobName = "usage-rollup-daily";

    private readonly UsageRollupRepository _rollups;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<UsageRollupDailyService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "USAGE_ROLLUP_DAILY_SCHEDULE";
    protected override string DefaultCron => "40 0 * * *";
    protected override string ScopeJobName => JobName;
    protected override string ScopeMetricName => "usage.rollup.daily";

    // Recomputes shared usage_hourly/usage_daily rows across every org — one replica per tick.
    protected override bool RequiresLeaderLock => true;

    public UsageRollupDailyService(
        UsageRollupRepository rollups,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<UsageRollupDailyService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _rollups = rollups;
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
                "Usage daily rollup skipped (disabled by AIR_GAPPED, DISABLE_BACKGROUND_JOBS, or edge mode).");
            return;
        }

        var now = _time.GetUtcNow();
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        var yesterday = today.AddDays(-1);
        var tomorrow = today.AddDays(1);

        // Re-derive the hourly buckets for the same span first, so a correct daily result never
        // depends on the hourly job having already run — see the class doc comment.
        int hourlyWritten = await _rollups.RecomputeHourlyAsync(
            UsageRollupRepository.UtcMidnight(yesterday), now, now, ct);

        int dailyWritten = await _rollups.RecomputeDailyEgressAsync(yesterday, tomorrow, now, ct);

        _logger.LogInformation(
            "Usage daily rollup: recomputed {HourlyBuckets} hourly bucket(s) and {DailyBuckets} daily bucket(s) for [{From}, {To}).",
            hourlyWritten, dailyWritten, yesterday, tomorrow);
    }
}
