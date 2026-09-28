using System.Text;
using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Weekly integrity check (<c>USAGE_RECONCILE_SCHEDULE</c>, default Monday 02:00 UTC) over the
/// last <see cref="ReconciliationWindowDays"/> complete UTC days: for every (org, meter, day) the
/// egress quantity, redirect quantity and request count stored in <c>usage_daily</c> must match a
/// fresh recompute directly from <c>usage_events</c> (bypassing <c>usage_hourly</c> so a corruption
/// in the hourly rollup itself is caught too, not just a stale daily row) within
/// <see cref="TolerancePercent"/>. A stored row whose request count is 0 was rolled up before the
/// rollups counted requests: every row a rollup writes now holds at least one event, so 0 can only
/// mean the column's default. Its count is not compared, and its quantities still are. A missing row on either side, or a mismatch beyond tolerance,
/// fails the pass — <c>usage_daily</c> is a billing input, and a silent drift between it and the
/// raw event log is exactly the failure mode a periodic reconciliation exists to surface before an
/// operator (or a customer's invoice) does.
///
/// Only the last <see cref="ReconciliationWindowDays"/> COMPLETE days are checked — today is
/// excluded because it is still accumulating and comparing it would flag every in-progress day as
/// a false mismatch.
///
/// <para>The <c>storage_bytes</c> meter is outside this first phase: its rows come from
/// <see cref="StorageSnapshotRepository"/> snapshots, not from summing events, so they have no
/// events-derived figure to reconcile against.</para>
///
/// <para><b>Stored bytes</b> are the second phase: for each storage plane (a top-level key family
/// in <see cref="Storage.BlobKeys.PlanePrefixes"/>) the bytes the blob store holds must agree with
/// the bytes the metadata records within <see cref="TolerancePercent"/>. Attribution is per plane,
/// not per org, because blobs are content-addressed and one object can back many orgs' rows.
/// <see cref="StoredByteReconciler"/> documents both sides, what they exclude, and what the
/// metadata side holds in memory. A drift of <see cref="TolerancePercent"/> or less is logged.</para>
///
/// <para>Both phases run to completion before the pass decides, and a failure in either is thrown
/// as one exception naming everything found, so a rollup drift cannot hide a byte drift or the
/// reverse.</para>
///
/// suspension-ok: not per-tenant. The reconciliation compares every org's stored and recomputed
/// rows in one pass with no per-org selection point — a suspended org's billing period still has
/// to reconcile correctly.
/// </summary>
public sealed class UsageReconciliationService : ScheduledBackgroundService
{
    internal const string JobName = "usage-reconcile-weekly";

    internal const int ReconciliationWindowDays = 7;

    // A mismatch this small and smaller is accepted as rounding/timing noise (e.g. an event
    // committed a moment after the window's upper bound landed in the next day's bucket instead);
    // anything past this fraction of the larger of the two compared figures fails the pass.
    internal const double TolerancePercent = 0.02;

    // Caps how many individual mismatches the failure message enumerates, so a systemic corruption
    // producing thousands of violations still yields a readable (and boundedly sized) error rather
    // than a message proportional to the whole org/meter/day cross product.
    private const int MaxReportedMismatches = 20;

    private readonly UsageRollupRepository _rollups;
    private readonly StoredByteReconciler _storedBytes;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<UsageReconciliationService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "USAGE_RECONCILE_SCHEDULE";
    protected override string DefaultCron => "0 2 * * 1";
    protected override string ScopeJobName => JobName;
    protected override string ScopeMetricName => "usage.reconcile.weekly";

    // Read-only comparison over shared tables — leader-gated anyway so a multi-replica deployment
    // reports exactly one pass/fail run per week instead of N racing, duplicate-alerting copies.
    protected override bool RequiresLeaderLock => true;

    public UsageReconciliationService(
        UsageRollupRepository rollups,
        StoredByteReconciler storedBytes,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<UsageReconciliationService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _rollups = rollups;
        _storedBytes = storedBytes;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunReconciliationPassAsync(ct);

    /// <summary>
    /// Runs both comparisons and throws <see cref="InvalidOperationException"/> naming every
    /// violation when the stored <c>usage_daily</c> rows disagree with a fresh recompute from
    /// <c>usage_events</c> beyond tolerance (bounded to <see cref="MaxReportedMismatches"/>), when
    /// either side has a row the other lacks, or when any plane's stored bytes drift from its
    /// metadata beyond tolerance. A phase that cannot run at all is a failure too. Letting the
    /// exception propagate out of this method — rather than swallowing it here — is what makes
    /// <see cref="ScheduledBackgroundService"/>'s automatic <c>ScopeJobName</c> wrapper record the
    /// run as failed (<c>background_job_runs.outcome = 'server_error'</c>), which is what
    /// <c>HealthService</c> alerts an operator on.
    /// </summary>
    /// <remarks>
    /// internal (not private) so tests can drive a pass directly without the cron/leader-lock
    /// scheduling machinery, mirroring RetentionService.RunGcPassAsync.
    /// </remarks>
    internal async Task RunReconciliationPassAsync(CancellationToken ct)
    {
        if (_airGap.IsJobDisabled(JobName))
        {
            _logger.LogInformation(
                "Usage reconciliation skipped (disabled by AIR_GAPPED, DISABLE_BACKGROUND_JOBS, or edge mode).");
            return;
        }

        var failures = new List<string>();
        Exception? firstError = null;

        try
        {
            if (await ReconcileUsageRollupsAsync(ct) is { } rollupFailure)
            {
                failures.Add(rollupFailure);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            firstError = ex;
            failures.Add($"Usage rollup reconciliation could not run: {ex.Message}");
        }

        try
        {
            if (await ReconcileStoredBytesAsync(ct) is { } byteFailure)
            {
                failures.Add(byteFailure);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            firstError ??= ex;
            failures.Add($"Stored-byte reconciliation could not run: {ex.Message}");
        }

        if (failures.Count > 0)
        {
            throw new InvalidOperationException(string.Join(" | ", failures), firstError);
        }
    }

    // First phase: usage_daily against usage_events. Returns the failure message, or null when clean.
    private async Task<string?> ReconcileUsageRollupsAsync(CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        var fromDay = today.AddDays(-ReconciliationWindowDays);

        var stored = await _rollups.ListDailyEgressAsync(fromDay, today, ct);
        var recomputed = await _rollups.ComputeDailyEgressFromEventsAsync(fromDay, today, ct);

        var mismatches = FindMismatches(stored, recomputed);

        if (mismatches.Count == 0)
        {
            _logger.LogInformation(
                "Usage reconciliation: {Days} day(s) [{From}, {To}) verified clean ({Rows} row(s) compared).",
                ReconciliationWindowDays, fromDay, today, stored.Count);
            return null;
        }

        _logger.LogError(
            "Usage reconciliation FAILED: {Count} mismatch(es) in [{From}, {To}).",
            mismatches.Count, fromDay, today);
        return FormatViolations(mismatches, fromDay, today);
    }

    // Second phase: stored bytes per plane against the metadata's size sums. Returns the failure
    // message, or null when every plane is within tolerance.
    private async Task<string?> ReconcileStoredBytesAsync(CancellationToken ct)
    {
        var report = await _storedBytes.MeasureAsync(ct);

        _logger.LogInformation(
            "Stored-byte reconciliation measured {Planes} plane(s) (tiersSplit={Split}); excluded from the comparison: "
            + ".snupkg {SymbolBytes} bytes, OCI staging {StagingBytes} bytes, recordless families {RecordlessBytes} bytes.",
            report.Planes.Count, report.TiersSplit, report.ExcludedSymbolBytes,
            report.ExcludedStagingBytes, report.RecordlessBytes);

        foreach (var plane in report.Planes)
        {
            _logger.LogInformation(
                "Stored-byte reconciliation {Plane}: store={StoreBytes} bytes in {StoreObjects} object(s), "
                + "metadata={MetadataBytes} bytes over {MetadataKeys} key(s) ({NullSizeKeys} with a NULL size), drift={DriftPercent:F2}%.",
                plane.Plane, plane.StoreBytes, plane.StoreObjects, plane.MetadataBytes,
                plane.MetadataKeys, plane.NullSizeKeys, DriftFraction(plane.StoreBytes, plane.MetadataBytes) * 100);
        }

        var drifted = FindPlaneDrift(report.Planes);
        if (drifted.Count == 0)
        {
            return null;
        }

        _logger.LogError(
            "Stored-byte reconciliation FAILED: {Count} plane(s) drift beyond tolerance.", drifted.Count);
        return "Stored-byte reconciliation found " + drifted.Count
            + " plane(s) whose stored bytes drift from the metadata by more than "
            + (TolerancePercent * 100).ToString("F0", System.Globalization.CultureInfo.InvariantCulture)
            + "%: " + string.Join("; ", drifted);
    }

    // Every plane whose store and metadata figures differ beyond tolerance, one message each.
    // Both-zero (an unused plane) is never drift.
    internal static IReadOnlyList<string> FindPlaneDrift(IReadOnlyList<PlaneByteTally> planes)
        => planes
            .Where(p => ExceedsTolerance(p.StoreBytes, p.MetadataBytes))
            .Select(p => string.Create(System.Globalization.CultureInfo.InvariantCulture,
                $"{p.Plane}: store={p.StoreBytes} bytes, metadata={p.MetadataBytes} bytes ({p.NullSizeKeys} key(s) with a NULL size), drift={DriftFraction(p.StoreBytes, p.MetadataBytes) * 100:F2}%"))
            .ToList();

    private static double DriftFraction(long a, long b)
    {
        long baseline = Math.Max(Math.Abs(a), Math.Abs(b));
        return baseline == 0 ? 0 : Math.Abs(a - b) / (double)baseline;
    }

    // Compares stored usage_daily egress rows against a fresh recompute from usage_events, keyed
    // by (org, meter, day). Present-in-one-absent-in-other is always a violation, regardless of
    // tolerance — a genuinely missing row is not a rounding difference.
    internal static IReadOnlyList<string> FindMismatches(
        IReadOnlyList<UsageDailyRow> stored, IReadOnlyList<UsageDailyRow> recomputed)
    {
        var storedByKey = stored.ToDictionary(Key, r => r);
        var recomputedByKey = recomputed.ToDictionary(Key, r => r);

        var violations = new List<string>();

        foreach (string key in storedByKey.Keys.Union(recomputedByKey.Keys, StringComparer.Ordinal))
        {
            bool hasStored = storedByKey.TryGetValue(key, out var storedRow);
            bool hasRecomputed = recomputedByKey.TryGetValue(key, out var recomputedRow);

            if (!hasStored)
            {
                violations.Add($"{key}: missing from usage_daily (events recompute has quantity={recomputedRow!.Quantity})");
                continue;
            }

            if (!hasRecomputed)
            {
                violations.Add($"{key}: usage_daily has quantity={storedRow!.Quantity} but no usage_events recompute exists for it");
                continue;
            }

            if (ExceedsTolerance(storedRow!.Quantity, recomputedRow!.Quantity))
            {
                violations.Add(
                    $"{key}: quantity mismatch — usage_daily={storedRow.Quantity}, recomputed={recomputedRow.Quantity}");
            }

            if (ExceedsTolerance(storedRow.RedirectQuantity, recomputedRow.RedirectQuantity))
            {
                violations.Add(
                    $"{key}: redirect_quantity mismatch — usage_daily={storedRow.RedirectQuantity}, recomputed={recomputedRow.RedirectQuantity}");
            }

            if (storedRow.RequestCount != 0 && ExceedsTolerance(storedRow.RequestCount, recomputedRow.RequestCount))
            {
                violations.Add(
                    $"{key}: request_count mismatch — usage_daily={storedRow.RequestCount}, recomputed={recomputedRow.RequestCount}");
            }
        }

        return violations;
    }

    private static string Key(UsageDailyRow row) => $"{row.OrgId}/{row.Meter}/{row.Bucket}";

    // A mismatch of TolerancePercent or less of the larger figure is accepted; anything past it
    // fails. Both-zero is never a mismatch (handled by the a == b short-circuit).
    private static bool ExceedsTolerance(long a, long b)
    {
        if (a == b)
        {
            return false;
        }

        long baseline = Math.Max(Math.Abs(a), Math.Abs(b));
        if (baseline == 0)
        {
            return false;
        }

        double fraction = Math.Abs(a - b) / (double)baseline;
        return fraction > TolerancePercent;
    }

    private static string FormatViolations(IReadOnlyList<string> violations, DateOnly fromDay, DateOnly toDayExclusive)
    {
        var sb = new StringBuilder();
        sb.Append("Usage reconciliation found ").Append(violations.Count)
          .Append(" mismatch(es) between usage_daily and usage_events over [")
          .Append(fromDay).Append(", ").Append(toDayExclusive).Append("): ");

        var shown = violations.Take(MaxReportedMismatches).ToList();
        sb.Append(string.Join("; ", shown));

        if (violations.Count > shown.Count)
        {
            sb.Append("; ...and ").Append(violations.Count - shown.Count).Append(" more");
        }

        return sb.ToString();
    }
}
