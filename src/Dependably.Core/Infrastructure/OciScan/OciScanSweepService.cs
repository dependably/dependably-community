using System.Globalization;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.RowLevelSecurity;

namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// Queues every catalogued OCI image that has no scan job yet, for each active org with a
/// scanner (<c>OCI_SCAN_SWEEP_SCHEDULE</c>, default hourly). Push and pull enqueue as they
/// happen; this pass catches what they could not: images catalogued before scanning was enabled,
/// before the org ran a scanner, or whose enqueue failed.
///
/// <para>For an org whose scanner claims rematch jobs, it also keeps findings current as OSV
/// moves: each scanned image the org still holds whose last match is older than
/// <c>OCI_SCAN_RESCAN_AGE_HOURS</c> gets a <c>rematch</c> job, or a <c>scan</c> (re-extraction)
/// when its stored result predates content-gap classification and so cannot be re-matched
/// without losing a gap. An org whose scanner never opted in gets neither, so an older scanner's
/// legacy results are not re-extracted every age window. Two kinds of image are queued again for
/// every org, opted in or not, once per age window: one whose scan job was parked as failed (a
/// parked job is never claimed again, and under <c>oci_scan_enforcement=block</c> the image would
/// otherwise stay unpullable), and one whose result holds advisories the advisory source has not
/// yet verified, as a <c>scan</c> when the org's scanner does not claim rematch jobs.</para>
///
/// <para>A replica that stops leading the sweep clears the gauges it last reported, at the next
/// wait after a tick it did not lead: another replica owns those readings now.</para>
///
/// <para>It reads and writes the database only, so it runs under <c>AIR_GAPPED</c>
/// (<see cref="BackgroundJobs.AirGapExempt"/>): an air-gapped scanner matches against sideloaded
/// OSV dumps, and only a rematch carries a newer dump to an image already scanned.</para>
///
/// <para>Per tenant: the org list comes from active orgs only (<c>o.status = 'active'</c>), so a
/// suspended or deleted tenant's images are never queued, and each org's work runs under its own
/// database scope.</para>
/// </summary>
public sealed class OciScanSweepService : ScheduledBackgroundService
{
    internal const string JobName = "oci-scan-sweep";

    /// <summary>Images queued per org per pass; the next pass continues where this one stopped.</summary>
    internal const int PerOrgLimit = 5_000;

    /// <summary>Rematch and re-extraction requeues per org per pass, oldest match first.</summary>
    internal const int RematchPerOrgLimit = 5_000;

    private readonly OciScanOptions _options;
    private readonly OciScanRepository _repo;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<OciScanSweepService> _logger;
    private readonly TimeProvider _time;
    private readonly OciPlatformManifestReader? _platforms;

    protected override string CronEnvKey => "OCI_SCAN_SWEEP_SCHEDULE";
    protected override string DefaultCron => "17 * * * *";
    protected override string ScopeJobName => JobName;
    protected override string ScopeMetricName => "oci.scan.sweep";

    // Enqueues across every org; one replica per tick keeps two passes from racing the same rows.
    protected override bool RequiresLeaderLock => true;

    public OciScanSweepService(
        OciScanOptions options,
        OciScanRepository repo,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<OciScanSweepService> logger,
        TimeProvider time,
        IDistributedLock locks,
        // Fills manifest_digest on coverage rows that predate it; absent skips that backfill.
        OciPlatformManifestReader? platforms = null)
        : base(config, logger, time, locks)
    {
        _platforms = platforms;
        _options = options;
        _repo = repo;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    /// <summary>
    /// What the last pass reported to the <c>dependably.oci.scan.oldest_match_age</c> gauge: the
    /// age of the oldest match among opted-in orgs' images, or null when there is none.
    /// </summary>
    internal double? LastOldestMatchAgeSeconds { get; private set; }

    /// <summary>
    /// What the last pass reported to the <c>dependably.oci.tag_pending_hold_age</c> gauge: how
    /// long the oldest still-pending moving-tag hold has lasted, or null when no tag is holding.
    /// </summary>
    internal double? LastOldestPendingHoldAgeSeconds { get; private set; }

    // Images whose coverage rows predate manifest_digest, handled per pass and per org.
    private const int CoverageBackfillPerOrg = 50;

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _backfillCursor = new();

    /// <summary>
    /// Fills <c>oci_scan_coverage.manifest_digest</c> on rows written before the column existed,
    /// from each image's stored manifest. A row with a digest, or one marked as listed by no
    /// platform, stops matching. A row marked non-covering because its image's bytes could not be
    /// read (<c>unknown</c>) matches again and is retried each time the per-org cursor reaches it, until the manifest is
    /// readable.
    /// </summary>
    private async Task BackfillCoverageManifestDigestsAsync(string orgId, CancellationToken ct)
    {
        if (_platforms is null)
        {
            return;
        }

        int filled = 0;
        _backfillCursor.TryGetValue(orgId, out string? after);
        var page = await _repo.ListCoverageMissingManifestDigestAsync(orgId, CoverageBackfillPerOrg, after, ct);
        // The cursor advances past every image of the page whether or not it filled, and wraps to
        // the start once a pass finds nothing further, so an image that cannot be filled (its
        // bytes are gone) never starves the ones behind it.
        if (page.Count == 0)
        {
            _backfillCursor.TryRemove(orgId, out _);
        }
        else
        {
            _backfillCursor[orgId] = page[^1].Owner.Id;
        }

        foreach (var (owner, digest) in page)
        {
            if (await _platforms.ReadAsync(orgId, digest, ct) is { } map)
            {
                filled += await _repo.FillCoverageManifestDigestsAsync(orgId, owner, map, ct);
            }
            else
            {
                // Unreadable bytes: stop the legacy rows claiming coverage of every platform.
                await _repo.MarkCoverageManifestUnreadableAsync(orgId, owner, ct);
            }
        }

        if (filled > 0)
        {
            _logger.LogInformation(
                "OCI scan sweep for org {OrgId}: recorded the manifest of {Filled} scanned platform(s).", orgId, filled);
        }
    }

    private static DateTimeOffset? ParseInstant(string? value) =>
        value is not null
        && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;

    protected override Task RunTickAsync(CancellationToken ct)
    {
        _ledSinceLastWait = true;
        return RunPassAsync(ct);
    }

    // Set when this replica runs a tick, cleared at each wait for the next one. A wait that finds
    // it unset follows a tick this replica did not lead (another replica held the leader lock),
    // so the gauges it reported on an earlier pass are no longer its to report.
    private bool _ledSinceLastWait;

    protected override Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        if (!_ledSinceLastWait)
        {
            ClearGauges();
        }

        _ledSinceLastWait = false;
        return base.DelayAsync(delay, ct);
    }

    private void ClearGauges()
    {
        if (LastOldestMatchAgeSeconds is null && LastOldestPendingHoldAgeSeconds is null)
        {
            return;
        }

        LastOldestMatchAgeSeconds = null;
        LastOldestPendingHoldAgeSeconds = null;
        Observability.DependablyMeter.RecordOciScanOldestMatchAge(null);
        Observability.DependablyMeter.RecordOciTagPendingHoldAge(null);
    }

    /// <summary>Runs one pass and returns how many jobs were queued, of every kind.</summary>
    internal async Task<int> RunPassAsync(CancellationToken ct)
    {
        if (!_options.Enabled)
        {
            return 0;
        }

        if (_airGap.IsJobDisabled(JobName))
        {
            _logger.LogInformation(
                "OCI scan sweep skipped (disabled by DISABLE_BACKGROUND_JOBS or edge mode).");
            return 0;
        }

        IReadOnlyList<string> orgs;
        // xtenant: lists the active orgs that run a scanner; each is then swept under its own scope.
        using (DbScope.CrossTenant("oci scan sweep org enumeration"))
        {
            orgs = await _repo.ListScanningOrgsAsync(ct);
        }

        var now = _time.GetUtcNow();
        int queued = 0;
        DateTimeOffset? oldest = null;
        DateTimeOffset? oldestHold = null;
        foreach (string orgId in orgs)
        {
            using (DbScope.ForOrg(orgId))
            {
                queued += await _repo.EnqueueMissingAsync(orgId, now.ToUtcIsoMillis(), PerOrgLimit, ct);
                queued += await RequeueParkedAsync(orgId, now, ct);
                var (requeued, orgOldest) = await RequeueDueAsync(orgId, now, ct);
                queued += requeued;
                if (orgOldest is { } o && (oldest is null || o < oldest))
                {
                    oldest = o;
                }

                await BackfillCoverageManifestDigestsAsync(orgId, ct);

                if (ParseInstant(await _repo.GetOldestPendingHoldAsync(orgId, ct)) is { } hold
                    && (oldestHold is null || hold < oldestHold))
                {
                    oldestHold = hold;
                }
            }
        }

        LastOldestMatchAgeSeconds = oldest is { } instant ? Math.Max(0, (now - instant).TotalSeconds) : null;
        Observability.DependablyMeter.RecordOciScanOldestMatchAge(LastOldestMatchAgeSeconds);
        LastOldestPendingHoldAgeSeconds = oldestHold is { } h ? Math.Max(0, (now - h).TotalSeconds) : null;
        Observability.DependablyMeter.RecordOciTagPendingHoldAge(LastOldestPendingHoldAgeSeconds);
        _logger.LogInformation("OCI scan sweep queued {Queued} job(s) across {Orgs} org(s).", queued, orgs.Count);
        return queued;
    }

    // Replaces each scan job parked as failed a rescan age ago with a fresh one, for any org.
    private async Task<int> RequeueParkedAsync(string orgId, DateTimeOffset now, CancellationToken ct)
    {
        string threshold = (now - _options.RescanAge).ToUtcIsoMillis();
        string stamp = now.ToUtcIsoMillis();
        int requeued = 0;
        foreach (var (owner, repository, digest) in await _repo.ListParkedScansDueAsync(orgId, threshold, PerOrgLimit, ct))
        {
            if (await _repo.RequeueAsync(orgId, owner, repository, digest, OciScanKinds.Scan, stamp, ct))
            {
                requeued++;
            }
        }

        if (requeued > 0)
        {
            _logger.LogInformation(
                "OCI scan sweep for org {OrgId}: queued {Requeued} parked image(s) for another scan.", orgId, requeued);
        }

        return requeued;
    }

    // An org whose scanner does not claim rematch jobs still gets its unverified advisories asked
    // about again: each result holding one is queued for a scan, once per age window.
    private async Task<int> RequeueUnverifiedAsync(string orgId, DateTimeOffset now, CancellationToken ct)
    {
        string threshold = (now - _options.RescanAge).ToUtcIsoMillis();
        string stamp = now.ToUtcIsoMillis();
        int requeued = 0;
        foreach (var due in await _repo.ListRematchDueAsync(orgId, threshold, RematchPerOrgLimit, unverifiedOnly: true, ct))
        {
            if (await _repo.RequeueAsync(orgId, due.Owner, due.Repository, due.Digest, OciScanKinds.Scan, stamp, ct))
            {
                requeued++;
            }
        }

        if (requeued > 0)
        {
            _logger.LogInformation(
                "OCI scan sweep for org {OrgId}: queued {Requeued} image(s) with unverified advisories for another scan.",
                orgId, requeued);
        }

        return requeued;
    }

    // The rematch half of the pass, for one org: for an org whose scanner has not opted in, only
    // the results holding unverified advisories. Returns the jobs queued and, for an opted-in org,
    // its oldest last match, which feeds the staleness gauge.
    private async Task<(int Queued, DateTimeOffset? Oldest)> RequeueDueAsync(
        string orgId, DateTimeOffset now, CancellationToken ct)
    {
        if (!await _repo.AcceptsRematchAsync(orgId, ct))
        {
            return (await RequeueUnverifiedAsync(orgId, now, ct), null);
        }

        string threshold = (now - _options.RescanAge).ToUtcIsoMillis();
        string stamp = now.ToUtcIsoMillis();
        int rematches = 0;
        int reextractions = 0;
        foreach (var due in await _repo.ListRematchDueAsync(orgId, threshold, RematchPerOrgLimit, ct: ct))
        {
            string kind = due.Legacy ? OciScanKinds.Scan : OciScanKinds.Rematch;
            if (!await _repo.RequeueAsync(orgId, due.Owner, due.Repository, due.Digest, kind, stamp, ct))
            {
                continue;
            }

            if (due.Legacy)
            {
                reextractions++;
            }
            else
            {
                rematches++;
            }
        }

        string? oldestMatch = await _repo.GetOldestMatchAsync(orgId, ct);
        DateTimeOffset? oldest = oldestMatch is not null
            && DateTimeOffset.TryParse(oldestMatch, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;
        _logger.LogInformation(
            "OCI scan sweep for org {OrgId}: queued {Rematches} rematch(es) and {Reextractions} re-extraction(s); "
            + "oldest match {OldestMatch}.",
            orgId, rematches, reextractions, oldestMatch ?? "none");
        return (rematches + reextractions, oldest);
    }
}
