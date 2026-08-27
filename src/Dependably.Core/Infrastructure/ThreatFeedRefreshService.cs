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

    protected override string CronEnvKey => "THREAT_FEED_SCHEDULE";
    protected override string DefaultCron => "0 5 * * *";
    protected override string? JitterEnvKey => "THREAT_FEED_JITTER_SECONDS";
    protected override bool RunOnStartup => true;
    protected override bool ContinueOnTickError => false;

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
            await RunRefreshPassInnerAsync(ct);
            scope.Complete();
        }
        catch (Exception ex)
        {
            scope.Fail(ex);
            throw;
        }
    }

    private async Task RunRefreshPassInnerAsync(CancellationToken ct)
    {
        // Instance-level gate only: the feeds are instance-shared data and no tenant artefact
        // metadata leaves the box, so per-tenant air_gapped doesn't apply — air-gapped tenants
        // still benefit from the gate evaluating locally held flags.
        if (_airGap.IsJobDisabled("threat-feed"))
        {
            _logger.LogInformation("Threat-feed refresh pass skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return;
        }

        _logger.LogInformation("Threat-feed refresh pass starting.");
        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
        var sw = System.Diagnostics.Stopwatch.StartNew();

        var rows = await _vulns.ListAliasRowsAsync(ct);
        var cvesByVuln = rows
            .Select(r => (r.Id, Cves: ExtractCves(r.Aliases, r.OsvId)))
            .ToList();

        int kevFlagged = await RunKevPassAsync(cvesByVuln, ct);
        var (epssScored, epssStamped) = await RunEpssPassAsync(cvesByVuln, ct);

        sw.Stop();
        _logger.LogInformation(
            "Threat-feed refresh pass complete. {Rows} advisories: {Kev} KEV-flagged, {EpssScored} EPSS-scored ({EpssStamped} stamped), took {ElapsedMs}ms.",
            rows.Count, kevFlagged, epssScored, epssStamped, sw.ElapsedMilliseconds);
    }

    private async Task<int> RunKevPassAsync(
        List<(string Id, List<string> Cves)> cvesByVuln, CancellationToken ct)
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
            return 0;
        }

        int flagged = 0;
        foreach (var (id, cves) in cvesByVuln)
        {
            ct.ThrowIfCancellationRequested();

            // One advisory can alias several CVEs, so pick the entry deliberately rather than
            // taking whichever matched first: prefer one CISA marks as known ransomware use, then
            // any entry carrying an assertion either way, then the first match. Without that, an
            // advisory aliasing two KEV entries would report a ransomware verdict that depends on
            // dictionary ordering.
            Dependably.Protocol.KevEntry? entry = null;
            foreach (string cve in cves)
            {
                if (!kev.TryGetValue(cve, out var candidate))
                {
                    continue;
                }

                if (candidate.KnownRansomwareCampaignUse == true)
                {
                    entry = candidate;
                    break;
                }

                if (entry is null || (entry.KnownRansomwareCampaignUse is null
                    && candidate.KnownRansomwareCampaignUse is not null))
                {
                    entry = candidate;
                }
            }

            bool isKev = entry is not null;
            await _vulns.SetKevAsync(id, isKev, entry, ct);
            if (isKev)
            {
                flagged++;
            }
        }
        return flagged;
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
