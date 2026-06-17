using Cronos;
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
/// </summary>
public sealed class ThreatFeedRefreshService : BackgroundService
{
    private readonly VulnerabilityRepository _vulns;
    private readonly IThreatFeedSource _source;
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<ThreatFeedRefreshService> _logger;
    private readonly TimeProvider _time;

    public ThreatFeedRefreshService(
        VulnerabilityRepository vulns,
        IThreatFeedSource source,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<ThreatFeedRefreshService> logger,
        TimeProvider time)
    {
        _vulns = vulns;
        _source = source;
        _config = config;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial pass on startup so advisories that accumulated before the service existed
        // (or while the instance was down) get enriched without waiting for the schedule.
        await RunRefreshPassAsync(stoppingToken);

        var schedule = CronExpression.Parse(
            _config["THREAT_FEED_SCHEDULE"] ?? "0 5 * * *",
            CronFormat.Standard);

        while (!stoppingToken.IsCancellationRequested)
        {
            var next = schedule.GetNextOccurrence(_time.GetUtcNow(), TimeZoneInfo.Utc);
            if (next is null)
            {
                break;
            }

            int jitterMaxSeconds = int.TryParse(_config["THREAT_FEED_JITTER_SECONDS"], out int j) && j >= 0 ? j : 3600;
            // SCS0005: load-spreading jitter, not a security boundary — weak RNG is intentional.
#pragma warning disable SCS0005
            var jitter = jitterMaxSeconds > 0
                ? TimeSpan.FromSeconds(Random.Shared.Next(0, jitterMaxSeconds + 1))
                : TimeSpan.Zero;
#pragma warning restore SCS0005
            var delay = (next.Value - _time.GetUtcNow()) + jitter;
            if (delay > TimeSpan.Zero)
            {
                try { await Task.Delay(delay, stoppingToken); }
                catch (OperationCanceledException) { break; }
            }

            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            await RunRefreshPassAsync(stoppingToken);
        }
    }

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
        IReadOnlySet<string> kev;
        try
        {
            kev = await _source.GetKevCveIdsAsync(ct);
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
            bool isKev = cves.Any(kev.Contains);
            await _vulns.SetKevAsync(id, isKev, ct);
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

            double? maxEpss = null;
            foreach (string cve in cves)
            {
                if (result.Scores.TryGetValue(cve, out double s) && (maxEpss is null || s > maxEpss))
                {
                    maxEpss = s;
                }
            }

            await _vulns.SetEpssAsync(id, maxEpss, ct);
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
