using Dependably.Infrastructure.Redis;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Background service that enriches the shared <c>vulnerabilities</c> table with two public
/// exploitation signals, joined through each advisory's CVE aliases: CISA KEV catalog
/// membership (<c>is_kev</c>, recomputed every pass so catalog removals clear the flag) and
/// the maximum FIRST.org EPSS exploitation probability (<c>epss_score</c>). The block gate
/// reads both via <see cref="VulnerabilityRepository.GetGateSignalsForVersionAsync"/>.
/// Runs on a cron schedule (<c>THREAT_FEED_SCHEDULE</c>, default daily at 5am UTC, offset an
/// hour from the OSV scan so the freshly scanned advisories get enriched the same morning),
/// with the same thundering-herd jitter shape as <see cref="VulnerabilityScanService"/>.
///
/// suspension-ok: not per-tenant. This pass enriches the shared, instance-wide
/// <c>vulnerabilities</c> table (one row per advisory, not per org) from two public feeds
/// (KEV, EPSS) and enumerates no org — there is no per-tenant selection point a suspension
/// check could apply to, and no tenant's own egress or third-party delivery is at stake.
/// </summary>
public sealed class ThreatFeedRefreshService : ScheduledBackgroundService
{
    private readonly VulnerabilityRepository _vulns;
    private readonly IThreatFeedSource _source;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<ThreatFeedRefreshService> _logger;
    private readonly TimeProvider _time;

    // A fetched catalogue smaller than 1/ShrinkGuardDenominator of the stored copy (under half) is
    // rejected as a broken feed. The real catalogue only grows; removals are rare and small.
    private const int ShrinkGuardDenominator = 2;

    protected override string CronEnvKey => "THREAT_FEED_SCHEDULE";
    protected override string DefaultCron => "0 5 * * *";
    protected override string? JitterEnvKey => "THREAT_FEED_JITTER_SECONDS";
    protected override bool RunOnStartup => true;

    // Enriches shared vulnerabilities rows and fetches external KEV/EPSS feeds — RunOnStartup=true
    // means a rolling deploy would otherwise fire N simultaneous feed pulls and racing writers.
    protected override bool RequiresLeaderLock => true;

    public ThreatFeedRefreshService(
        VulnerabilityRepository vulns,
        IThreatFeedSource source,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<ThreatFeedRefreshService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
    {
        _vulns = vulns;
        _source = source;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunRefreshPassAsync(ct);

    internal async Task RunRefreshPassAsync(CancellationToken ct)
    {
        using var scope = Observability.BackgroundJobScope.Begin("threat-feed", "threatfeed.refresh", _time);
        try
        {
            var rejections = await RunRefreshPassInnerAsync(ct);
            if (rejections.Count > 0)
            {
                // The pass ran and kept the previous copy of every rejected feed, which is not a
                // success: an operator pointing a feed at a bad mirror otherwise sees a green job
                // beside data that never updates.
                scope.Degrade(string.Join("; ", rejections));
            }
            else
            {
                scope.Complete();
            }
        }
        catch (Exception ex)
        {
            scope.Fail(ex);
            throw;
        }
    }

    private async Task<List<string>> RunRefreshPassInnerAsync(CancellationToken ct)
    {
        var rejections = new List<string>();
        // Instance-level gate only: the feeds are instance-shared data and no tenant artefact
        // metadata leaves the box, so per-tenant air_gapped doesn't apply — air-gapped tenants
        // still benefit from the gate evaluating locally held flags.
        if (_airGap.IsJobDisabled("threat-feed"))
        {
            _logger.LogInformation("Threat-feed refresh pass skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return rejections;
        }

        _logger.LogInformation("Threat-feed refresh pass starting.");
        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
        var sw = System.Diagnostics.Stopwatch.StartNew();

        // The previous release writes advisories without maintaining the alias index the package
        // lookup resolves through; converging it here keeps a long-running instance current
        // between boots. Runs before the feeds so a failed fetch never skips it, and a failure here
        // (a database deadlock against a concurrent upsert, say) never skips them either: the
        // feeds read the alias JSON column, not the index, so they can still run, and the sweep
        // retries on the next pass.
        try
        {
            await _vulns.ReconcileAliasIndexAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Alias-index reconcile failed; continuing with the threat feeds.");
            Reject(rejections, "alias_reconcile_failed");
        }

        var rows = await _vulns.ListAliasRowsAsync(ct);
        var cvesByVuln = rows
            .Select(r => (r.Id, Cves: ExtractCves(r.Aliases, r.OsvId)))
            .ToList();

        int kevFlagged = await RunKevPassAsync(cvesByVuln, rejections, ct);
        var (epssScored, epssStamped) = await RunEpssPassAsync(cvesByVuln, ct);
        int epssStored = await RunEpssBulkPassAsync(rejections, ct);

        sw.Stop();
        _logger.LogInformation(
            "Threat-feed refresh pass complete. {Rows} advisories: {Kev} KEV-flagged, {EpssScored} EPSS-scored ({EpssStamped} stamped), {EpssStored} EPSS scores stored, took {ElapsedMs}ms.",
            rows.Count, kevFlagged, epssScored, epssStamped, epssStored, sw.ElapsedMilliseconds);
        return rejections;
    }

    // Records a step that was attempted but not applied: a metric a dashboard can alert on, and
    // the reason string the job run row carries. reason is one of a closed set:
    // (kev|epss)_(fetch_failed|empty|shrunk), epss_replace_failed, epss_fill_failed, or alias_reconcile_failed.
    private static void Reject(List<string> rejections, string reason)
    {
        Observability.DependablyMeter.ThreatFeedRejections.Add(
            1, new KeyValuePair<string, object?>("reason", reason));
        rejections.Add(reason);
    }

    private async Task<int> RunKevPassAsync(
        List<(string Id, List<string> Cves)> cvesByVuln, List<string> rejections, CancellationToken ct)
    {
        IReadOnlyDictionary<string, Dependably.Protocol.KevEntry> kev;
        try
        {
            kev = await _source.GetKevCatalogAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Fail-soft: a broken feed skips the pass (flags keep their last-known values)
            // rather than clearing every is_kev to 0 against an empty set.
            _logger.LogWarning(ex, "KEV feed fetch failed; skipping KEV pass this run.");
            Reject(rejections, "kev_fetch_failed");
            return 0;
        }

        // A 200 that parses to nothing (renamed key, empty array, every entry unparseable) or to a
        // fraction of the stored catalogue is a broken feed, not a catalogue that emptied: acting
        // on it would clear every is_kev flag and the stored catalogue, switching the KEV gate off
        // on missing input. It is treated as a failed fetch and nothing is written.
        // An upgraded install starts with an empty catalogue table but may already carry is_kev
        // flags from earlier passes. With nothing stored to compare against, the CVEs behind the
        // flagged rows are the baseline: a first fetch far smaller than what the flags already assert is the same
        // broken feed, and applying it would clear them.
        int storedCount = await _vulns.CountKevCatalogAsync(ct);
        int baseline = storedCount > 0 ? storedCount : await _vulns.CountKevFlaggedCvesAsync(ct);
        if (kev.Count == 0 || kev.Count * ShrinkGuardDenominator < baseline)
        {
            _logger.LogWarning(
                "KEV feed returned {Fetched} entries against {Baseline} {BaselineSource}; treating it as a failed fetch and keeping the previous catalogue and flags.",
                kev.Count, baseline, storedCount > 0 ? "stored" : "already flagged (distinct CVEs)");
            Reject(rejections, kev.Count == 0 ? "kev_empty" : "kev_shrunk");
            return 0;
        }

        await _vulns.ReplaceKevCatalogAsync(kev, ct);

        int flagged = 0;
        foreach (var (id, cves) in cvesByVuln)
        {
            ct.ThrowIfCancellationRequested();

            var entry = PickKevEntry(cves, kev);
            bool isKev = entry is not null;
            await _vulns.SetKevAsync(id, isKev, entry, ct);
            if (isKev)
            {
                flagged++;
            }
        }
        return flagged;
    }

    // One advisory can alias several CVEs, so pick the entry deliberately rather than taking
    // whichever matched first: prefer one CISA marks as known ransomware use, then any entry
    // carrying an assertion either way, then the first match. Without that, an advisory aliasing
    // two KEV entries would report a ransomware verdict that depends on dictionary ordering.
    private static Dependably.Protocol.KevEntry? PickKevEntry(
        List<string> cves, IReadOnlyDictionary<string, Dependably.Protocol.KevEntry> kev)
    {
        Dependably.Protocol.KevEntry? entry = null;
        foreach (string cve in cves)
        {
            if (!kev.TryGetValue(cve, out var candidate))
            {
                continue;
            }

            if (candidate.KnownRansomwareCampaignUse == true)
            {
                return candidate;
            }

            if (entry is null || (entry.KnownRansomwareCampaignUse is null
                && candidate.KnownRansomwareCampaignUse is not null))
            {
                entry = candidate;
            }
        }

        return entry;
    }

    private async Task<(int Scored, int Stamped)> RunEpssPassAsync(
        List<(string Id, List<string> Cves)> cvesByVuln, CancellationToken ct)
    {
        var allCves = cvesByVuln.SelectMany(v => v.Cves)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (allCves.Count == 0)
        {
            return (0, 0);
        }

        var result = await _source.GetEpssScoresAsync(allCves, ct);

        int scored = 0, stamped = 0;
        foreach (var (id, cves) in cvesByVuln)
        {
            ct.ThrowIfCancellationRequested();

            // Rows whose CVEs all sat in failed batches stay unstamped so the next pass
            // retries them; a successfully queried CVE that EPSS doesn't know yields a
            // stamped NULL (a real "no score" answer, not a retryable failure).
            if (!cves.Any(result.Queried.Contains))
            {
                continue;
            }

            // The percentile travels with the probability it belongs to rather than being
            // maximised separately: the pair describes one CVE, and pairing one CVE's probability
            // with another's rank would describe nothing real.
            double? maxEpss = null;
            double? percentile = null;
            foreach (string cve in cves)
            {
                if (result.Scores.TryGetValue(cve, out var s) && (maxEpss is null || s.Probability > maxEpss))
                {
                    maxEpss = s.Probability;
                    percentile = s.Percentile;
                }
            }

            await _vulns.SetEpssAsync(id, maxEpss, percentile, ct);
            stamped++;
            if (maxEpss is not null)
            {
                scored++;
            }
        }
        return (scored, stamped);
    }

    /// <summary>
    /// Keeps a local copy of FIRST.org's full EPSS file, so the package lookup can score a CVE this
    /// instance has never stored an advisory for without a network call of its own. The fetched
    /// file replaces the stored one only when it is plausible: an empty file, or one under half the
    /// stored size, is a broken feed and not a model that stopped scoring, and acting on it would
    /// make every CVE read as unscored — which the EPSS verdict arms treat as no signal.
    /// </summary>
    /// <returns>The number of scores stored this pass; 0 when the fetch failed or was rejected.</returns>
    private async Task<int> RunEpssBulkPassAsync(List<string> rejections, CancellationToken ct)
    {
        EpssBulkFile file;
        try
        {
            file = await _source.GetEpssBulkAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "EPSS bulk file fetch failed; keeping the stored EPSS scores.");
            Reject(rejections, "epss_fetch_failed");
            return 0;
        }

        int storedCount = await _vulns.CountEpssScoresAsync(ct);
        if (file.Scores.Count == 0 || file.Scores.Count * ShrinkGuardDenominator < storedCount)
        {
            _logger.LogWarning(
                "EPSS bulk file held {Fetched} scores against {Stored} stored; treating it as a failed fetch and keeping the stored scores.",
                file.Scores.Count, storedCount);
            Reject(rejections, file.Scores.Count == 0 ? "epss_empty" : "epss_shrunk");
            return 0;
        }

        try
        {
            await _vulns.ReplaceEpssScoresAsync(file.Scores, file.ScoreDate, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The apply step upserts whole rows in committed batches and removes dropped CVEs last,
            // so a failure here (an incomplete staging copy, a database error) leaves every CVE
            // with a complete score from the previous or the new file. KEV has already been
            // applied, so the run reports the lost step as a degraded run rather than a crash.
            _logger.LogWarning(ex, "EPSS bulk file could not be stored; keeping the stored EPSS scores.");
            Reject(rejections, "epss_replace_failed");
            return 0;
        }

        try
        {
            int filled = await _vulns.FillMissingEpssFromStoredScoresAsync(ct);
            _logger.LogInformation("EPSS fill after the bulk pass scored {Filled} previously unscored advisories.", filled);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The file replace is committed and each fill batch is its own transaction, so a
            // failure leaves the new scores in place and the batches already applied; the rest
            // are retried by the next pass.
            _logger.LogWarning(ex, "EPSS fill from the stored scores failed; the new scores are kept.");
            Reject(rejections, "epss_fill_failed");
        }

        return file.Scores.Count;
    }

    /// <summary>
    /// CVE ids relevant to an advisory: its alias list (JSON array column, parsed fail-soft)
    /// plus the OSV id itself when the advisory IS a CVE record.
    /// </summary>
    internal static List<string> ExtractCves(string? aliasesJson, string osvId)
    {
        var cves = new List<string>();
        if (osvId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
        {
            cves.Add(osvId);
        }

        if (!string.IsNullOrWhiteSpace(aliasesJson))
        {
            try
            {
                var aliases = System.Text.Json.JsonSerializer.Deserialize<List<string>>(aliasesJson);
                if (aliases is not null)
                {
                    cves.AddRange(aliases.Where(a =>
                        !string.IsNullOrWhiteSpace(a)
                        && a.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)));
                }
            }
            catch (System.Text.Json.JsonException)
            {
                // Malformed alias JSON on a legacy row — treat as no aliases rather than
                // failing the whole pass.
            }
        }

        return cves;
    }
}
