using System.Text.Json;
using Dependably.Infrastructure.Observability;

namespace Dependably.Infrastructure.Health;

/// <summary>
/// Assembles the operator-facing health rollup for the apex system_admin surface.
/// Composes readiness checks (<see cref="ReadinessAggregator"/>), background-job
/// last-success timestamps from the <c>background_job_runs</c> DB table, and
/// staging-disk state into a single structured <see cref="HealthReport"/>.
///
/// All timestamps are read via the injected <see cref="TimeProvider"/>; no
/// <c>DateTime.UtcNow</c> or <c>DateTimeOffset.UtcNow</c> reads appear here.
/// </summary>
public sealed class HealthService
{
    // Per-job staleness thresholds sourced from the registered job intervals.
    // Conservative: drive red mostly off latest-outcome=failure; generous windows (interval×N).
    // Daily/cron jobs get 36 h so a delayed run doesn't immediately surface as stale.
    // Short-interval pollers get 10 min (10× their 60 s default interval).
    internal static readonly IReadOnlyDictionary<string, TimeSpan> JobStalenessThresholds =
        new Dictionary<string, TimeSpan>(StringComparer.OrdinalIgnoreCase)
        {
            ["vuln-scan"] = TimeSpan.FromHours(36),
            ["vuln-rescan"] = TimeSpan.FromHours(36),
            ["threat-feed"] = TimeSpan.FromHours(36),
            ["deprecation-refresh"] = TimeSpan.FromHours(36),
            ["stats-refresh"] = TimeSpan.FromMinutes(30),
            ["saml-cert-expiry"] = TimeSpan.FromHours(36),
            ["cache-eviction"] = TimeSpan.FromHours(36),
            ["retention"] = TimeSpan.FromHours(36),
            ["orphan-reconciler"] = TimeSpan.FromHours(36),
            ["blob-size-poller"] = TimeSpan.FromMinutes(10),
            ["tenant-count-poller"] = TimeSpan.FromMinutes(10),
            ["healthcheck-pinger"] = TimeSpan.FromMinutes(10),
            ["oci-staging-janitor"] = TimeSpan.FromHours(36),
        };

    // Default staleness threshold for any registry job not in JobStalenessThresholds.
    private static readonly TimeSpan DefaultStalenessThreshold = TimeSpan.FromHours(36);

    // Snapshot age threshold: warn when an org's stats snapshot is older than this.
    private static readonly TimeSpan SnapshotStaleThreshold = TimeSpan.FromHours(2);

    // Page size for the tenant-attention scan; covers the full org list in one read.
    private const int TenantScanPageSize = 200;

    // Storage fraction at which a tenant is counted as needing attention.
    private const double StorageWarnFraction = 0.90;

    // Jobs that write run rows through BackgroundJobScope and are tracked by HealthService.
    // Plain BackgroundService pollers (blob-size-poller, tenant-count-poller, healthcheck-pinger,
    // tenant-hard-delete) do not write run rows and always show ok on startup.
    internal static readonly IReadOnlySet<string> RunRowJobs =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "vuln-scan",
            "vuln-rescan",
            "threat-feed",
            "deprecation-refresh",
            "stats-refresh",
            "saml-cert-expiry",
            "cache-eviction",
            "retention",
            "orphan-reconciler",
            "oci-staging-janitor",
        };

    private readonly ReadinessAggregator _readiness;
    private readonly BackgroundJobRunRepository _jobRuns;
    private readonly MetricsSnapshotProvider _snapshots;
    private readonly IAirGapMode _airGap;
    private readonly StatsSnapshotRepository _statsSnapshots;
    private readonly OrgRepository _orgs;
    private readonly TimeProvider _time;

    public HealthService(
        ReadinessAggregator readiness,
        BackgroundJobRunRepository jobRuns,
        MetricsSnapshotProvider snapshots,
        IAirGapMode airGap,
        StatsSnapshotRepository statsSnapshots,
        OrgRepository orgs,
        TimeProvider time)
    {
        _readiness = readiness;
        _jobRuns = jobRuns;
        _snapshots = snapshots;
        _airGap = airGap;
        _statsSnapshots = statsSnapshots;
        _orgs = orgs;
        _time = time;
    }

    /// <summary>Builds a full health report, deriving job staleness from the DB run table.</summary>
    public async Task<HealthReport> GetReportAsync(CancellationToken ct)
    {
        var now = _time.GetUtcNow();

        // ── Dependency checks ────────────────────────────────────────────────
        var checks = await _readiness.CheckAsync(ct);
        var dependencies = checks.Select(kv => new DependencyStatus(
            Name: kv.Key,
            Status: kv.Value is null ? "ok" : "error",
            Error: kv.Value)).ToList();

        // ── Background jobs ─────────────────────────────────────────────────
        // Keep the in-memory snapshot available for the /observability hint only.
        var snap = _snapshots.Capture();

        // Fetch the latest run row per known job from the authoritative DB table.
        // Using DB rows makes the health status correct after a process restart (in-memory dict
        // is empty on restart but DB rows persist across restarts).
        var latestRunsByJob = await GetLatestRunsAsync(ct);

        var jobs = new List<JobStatus>();
        // Iterate explicitly-thresholded jobs plus the run-row registry, so a future job that
        // writes run rows but lacks an explicit threshold still appears with the default threshold
        // rather than being silently dropped from the report.
        foreach (string jobName in JobStalenessThresholds.Keys.Union(RunRowJobs))
        {
            jobs.Add(await EvaluateJobStatusAsync(jobName, latestRunsByJob, now, ct));
        }

        // ── Storage / staging disk ───────────────────────────────────────────
        var blobSizes = snap.BlobStoreSizesByTier;
        long stagingAvailable = DependablyMeter.ReadStagingDiskAvailable();
        long stagingUsed = DependablyMeter.ReadStagingDiskUsed();
        long stagingTotal = stagingAvailable + stagingUsed;
        bool stagingBelowThreshold = stagingTotal > 0
            && stagingAvailable < stagingTotal / 10; // < 10% free

        // ── Tenant snapshots ─────────────────────────────────────────────────
        // xtenant: system-admin cross-tenant operator view — counting stale snapshots across all tenants.
        int staleSnapshotCount = await CountStaleSnapshotsAsync(now, ct);

        // ── Overall rollup ───────────────────────────────────────────────────
        bool anyDepError = dependencies.Any(d => d.Status == "error");
        bool anyJobBad = jobs.Any(j => j.Status is "failing" or "stale");
        bool degraded = anyJobBad || stagingBelowThreshold || staleSnapshotCount > 0;

        string overall = anyDepError ? "down" : degraded ? "degraded" : "healthy";

        return new HealthReport(
            Overall: overall,
            Dependencies: dependencies,
            Jobs: jobs,
            Storage: new StorageStatus(
                BlobSizesByTier: blobSizes,
                StagingAvailableBytes: stagingAvailable,
                StagingUsedBytes: stagingUsed,
                StagingBelowThreshold: stagingBelowThreshold),
            Tenants: new TenantsSummary(
                NeedAttention: await CountTenantsNeedingAttentionAsync(ct)),
            StaleSnapshotCount: staleSnapshotCount,
            CapturedAt: now);
    }

    // Derives a single job's health status from its latest run row, falling back to the most
    // recent success when the latest run was cancelled mid-tick by graceful shutdown.
    private async Task<JobStatus> EvaluateJobStatusAsync(
        string jobName,
        IReadOnlyDictionary<string, BackgroundJobRunSummary> latestRunsByJob,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var threshold = JobStalenessThresholds.GetValueOrDefault(jobName, DefaultStalenessThreshold);
        if (_airGap.IsJobDisabled(jobName))
        {
            return new JobStatus(Name: jobName, Status: "disabled", AgeSeconds: null,
                LastRunAt: null, LastOutcome: null);
        }

        if (!latestRunsByJob.TryGetValue(jobName, out var latestRun))
        {
            // No run row at all — startup grace; treat as ok.
            return new JobStatus(Name: jobName, Status: "ok", AgeSeconds: null,
                LastRunAt: null, LastOutcome: null);
        }

        // latest outcome == server_error → failing immediately.
        if (string.Equals(latestRun.Outcome, "server_error", StringComparison.OrdinalIgnoreCase))
        {
            long? ageSeconds = ComputeAgeSeconds(latestRun.FinishedAt, now);
            return new JobStatus(Name: jobName, Status: "failing", AgeSeconds: ageSeconds,
                LastRunAt: latestRun.FinishedAt.ToString("O"),
                LastOutcome: latestRun.Outcome);
        }

        // latest outcome == cancelled → skip it (graceful-shutdown disposal mid-tick).
        // Fall back to the most recent success row to evaluate staleness.
        BackgroundJobRunSummary? refRun;
        if (string.Equals(latestRun.Outcome, "cancelled", StringComparison.OrdinalIgnoreCase))
        {
            var (successItems, _) = await _jobRuns.ListAsync(
                new BackgroundJobRunQuery(
                    JobName: jobName,
                    Outcome: "success",
                    SortBy: "startedAt",
                    SortDir: "desc",
                    Limit: 1,
                    Offset: 0),
                ct);
            refRun = successItems.Count > 0
                ? new BackgroundJobRunSummary(successItems[0].Outcome, successItems[0].FinishedAt)
                : null;
        }
        else
        {
            refRun = latestRun;
        }

        if (refRun is null || !string.Equals(refRun.Outcome, "success", StringComparison.OrdinalIgnoreCase))
        {
            // No usable success run found (only cancelled or nothing) — startup grace.
            return new JobStatus(Name: jobName, Status: "ok", AgeSeconds: null,
                LastRunAt: latestRun.FinishedAt.ToString("O"),
                LastOutcome: latestRun.Outcome);
        }

        long age = (long)(now - refRun.FinishedAt).TotalSeconds;
        string status = age > (long)threshold.TotalSeconds ? "stale" : "ok";
        return new JobStatus(
            Name: jobName,
            Status: status,
            AgeSeconds: age,
            LastRunAt: refRun.FinishedAt.ToString("O"),
            LastOutcome: refRun.Outcome);
    }

    // Queries the latest run row per known job and returns a map of job_name → summary.
    // Only fetches jobs that write run rows (pollers and tenant-hard-delete are excluded).
    private async Task<IReadOnlyDictionary<string, BackgroundJobRunSummary>> GetLatestRunsAsync(
        CancellationToken ct)
    {
        var result = new Dictionary<string, BackgroundJobRunSummary>(StringComparer.OrdinalIgnoreCase);
        foreach (string jobName in RunRowJobs)
        {
            var (items, _) = await _jobRuns.ListAsync(
                new BackgroundJobRunQuery(
                    JobName: jobName,
                    SortBy: "startedAt",
                    SortDir: "desc",
                    Limit: 1,
                    Offset: 0),
                ct);
            if (items.Count > 0)
            {
                result[jobName] = new BackgroundJobRunSummary(items[0].Outcome, items[0].FinishedAt);
            }
        }
        return result;
    }

    private static long? ComputeAgeSeconds(DateTimeOffset finishedAt, DateTimeOffset now)
    {
        long age = (long)(now - finishedAt).TotalSeconds;
        return age >= 0 ? age : null;
    }

    private async Task<int> CountStaleSnapshotsAsync(DateTimeOffset now, CancellationToken ct)
    {
        // xtenant: system-admin cross-tenant operator view — scanning all org snapshot rows.
        var orgIds = await _statsSnapshots.ListActiveOrgIdsAsync(ct);
        int stale = 0;
        foreach (string orgId in orgIds)
        {
            var snapshot = await _statsSnapshots.GetSnapshotAsync(orgId, ct);
            if (snapshot is null)
            {
                stale++;
                continue;
            }
            if (DateTimeOffset.TryParse(snapshot.ComputedAt, out var computedAt)
                && now - computedAt > SnapshotStaleThreshold)
            {
                stale++;
            }
        }
        return stale;
    }

    private async Task<int> CountTenantsNeedingAttentionAsync(CancellationToken ct)
    {
        var (items, _) = await _orgs.ListOrgsAsync(TenantScanPageSize, 0, includeDeleted: false, ct: ct);
        int count = 0;
        foreach (var item in items)
        {
            if (item.Status == "suspended") { count++; continue; }
            if (item.StorageQuotaBytes.HasValue
                && item.StorageBytes >= (long)(item.StorageQuotaBytes.Value * StorageWarnFraction)) { count++; }
        }
        return count;
    }
}

// Minimal projection for health staleness computation — avoids pulling all run fields.
internal sealed record BackgroundJobRunSummary(string Outcome, DateTimeOffset FinishedAt);

/// <summary>Full health report returned by <see cref="HealthService.GetReportAsync"/>.</summary>
public sealed record HealthReport(
    string Overall,
    IReadOnlyList<DependencyStatus> Dependencies,
    IReadOnlyList<JobStatus> Jobs,
    StorageStatus Storage,
    TenantsSummary Tenants,
    int StaleSnapshotCount,
    DateTimeOffset CapturedAt);

public sealed record DependencyStatus(string Name, string Status, string? Error);

/// <summary>Per-job health status in the <see cref="HealthReport"/>.</summary>
/// <param name="Name">Registered job name (e.g. "vuln-scan").</param>
/// <param name="Status">"ok", "stale", "failing", or "disabled".</param>
/// <param name="AgeSeconds">Seconds since the last successful run. Null when no success run exists or the job is disabled.</param>
/// <param name="LastRunAt">ISO 8601 UTC timestamp of the last run's finished_at. Null when no run exists or the job is disabled.</param>
/// <param name="LastOutcome">Outcome string from the last run row ("success", "server_error", "cancelled"). Null when no run exists.</param>
public sealed record JobStatus(
    string Name,
    string Status,
    long? AgeSeconds,
    string? LastRunAt,
    string? LastOutcome);

public sealed record StorageStatus(
    IReadOnlyDictionary<string, long> BlobSizesByTier,
    long StagingAvailableBytes,
    long StagingUsedBytes,
    bool StagingBelowThreshold);
public sealed record TenantsSummary(int NeedAttention);
