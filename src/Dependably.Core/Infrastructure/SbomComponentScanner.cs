using Dependably.Infrastructure.Observability;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Shared OSV batch-scan-and-persist primitive for one batch of SBOM components (the caller
/// enforces the &lt;=100-purl OSV batch ceiling). Reused by the upload-triggered
/// <c>SbomScanWorker</c> (Management) and the nightly restart/missed-upload safety net in
/// <see cref="VulnerabilityScanService"/> (Core), so both surfaces defer on an unreached source
/// the same way.
///
/// An unreached source answers with a full-length list of empty advisory lists that is
/// byte-identical to a genuinely clean batch. Persisting it would stamp <c>vuln_checked_at</c>
/// and hand the SBOM policy evaluator a record claiming "screened, nothing found" for a
/// component that was never screened. This scanner defers the whole batch instead: every row
/// keeps <c>vuln_checked_at</c> NULL and is re-selected by the very next pass or the next
/// upload's rescan. Callers must use <see cref="IOsvSource.TryQueryBatchAsync"/> — never the
/// fail-open <c>QueryBatchAsync</c> form, which cannot report an unreached source at all.
///
/// A reached source that answers with fewer result slots than purls queried gets the same
/// treatment for the part it did not answer: the answered prefix is persisted and the unanswered
/// tail is left unstamped, rather than read as a clean result the response never contained.
/// </summary>
public sealed class SbomComponentScanner
{
    private readonly IOsvSource _osv;
    private readonly VulnerabilityRepository _vulns;
    private readonly SbomComponentVulnRepository _sbomVulns;
    private readonly ILogger<SbomComponentScanner> _logger;

    public SbomComponentScanner(
        IOsvSource osv,
        VulnerabilityRepository vulns,
        SbomComponentVulnRepository sbomVulns,
        ILogger<SbomComponentScanner> logger)
    {
        _osv = osv;
        _vulns = vulns;
        _sbomVulns = sbomVulns;
        _logger = logger;
    }

    /// <summary>
    /// Scans one batch and persists every hydrated advisory hit. Non-hydrated advisories are
    /// skipped (same precondition as <see cref="VulnerabilityRepository.UpsertVulnerabilityAsync"/>
    /// — <c>/querybatch</c> returns id+modified only, and persisting a partial record would
    /// clobber existing severity/cvss data via the upsert).
    /// </summary>
    public async Task<SbomScanBatchResult> ScanBatchAsync(
        IReadOnlyList<ScannableSbomComponent> batch, CancellationToken ct)
    {
        if (batch.Count == 0)
        {
            return new SbomScanBatchResult(
                new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<string, int>(StringComparer.Ordinal),
                Deferred: false);
        }

        var purls = batch.Select(c => c.Purl).ToList();
        OsvBatchQueryResult batchResult;
        try
        {
            batchResult = await _osv.TryQueryBatchAsync(purls, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OSV batch query failed for {Count} SBOM component(s).", batch.Count);
            RecordOutcome(scanned: 0, deferred: batch.Count);
            return Deferred();
        }

        if (!batchResult.Reached)
        {
            _logger.LogWarning(
                "OSV source unreachable while scanning {Count} SBOM component(s); deferring — none marked as scanned.",
                batch.Count);
            RecordOutcome(scanned: 0, deferred: batch.Count);
            return Deferred();
        }

        var results = batchResult.Results;
        var scanned = new HashSet<string>(StringComparer.Ordinal);
        var advisoryCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        if (results.Count < batch.Count)
        {
            // A reached source that answers with fewer result slots than purls queried has not
            // answered for the tail. Stamping those rows would record a screening that never
            // happened — the same fail-open shape as trusting an unreachable source — so the
            // unanswered tail is left unstamped and stays in the scan work queue.
            _logger.LogWarning(
                "OSV answered {Answered} result slot(s) for {Queried} SBOM component purl(s); the unanswered tail is left unscanned.",
                results.Count, batch.Count);
        }

        for (int i = 0; i < batch.Count && i < results.Count; i++)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            var component = batch[i];
            var (outcome, linked) = await PersistComponentAsync(component, results[i], ct);
            if (outcome == ComponentScanOutcome.Cancelled)
            {
                break;
            }

            if (outcome == ComponentScanOutcome.Persisted)
            {
                scanned.Add(component.Id);
                advisoryCounts[component.Id] = linked;
            }
        }

        // Every component in the batch is accounted for exactly once: persisted-and-stamped
        // counts as scanned, everything else (the unanswered tail, a per-component persist
        // failure) counts as deferred — coverage that did not land this pass and stays in the
        // scan work queue for the next one.
        RecordOutcome(scanned: scanned.Count, deferred: batch.Count - scanned.Count);
        return new SbomScanBatchResult(scanned, advisoryCounts, Deferred: false);
    }

    private enum ComponentScanOutcome { Persisted, Failed, Cancelled }

    /// <summary>
    /// Persists one component's advisories and stamps it checked. A per-component failure is
    /// logged and reported as <see cref="ComponentScanOutcome.Failed"/> so the batch continues and
    /// the component stays unstamped — it is counted as deferred and returns on the next pass.
    /// Cancellation stops the batch instead.
    /// </summary>
    private async Task<(ComponentScanOutcome Outcome, int Linked)> PersistComponentAsync(
        ScannableSbomComponent component, List<OsvAdvisory> advisories, CancellationToken ct)
    {
        try
        {
            int linked = await LinkHydratedAdvisoriesAsync(component, advisories, ct);
            await _sbomVulns.MarkComponentCheckedAsync(component.Id, ct);
            return (ComponentScanOutcome.Persisted, linked);
        }
        catch (OperationCanceledException)
        {
            // Cancelled mid-component: stop the batch rather than attempting the rest.
            return (ComponentScanOutcome.Cancelled, 0);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to persist SBOM component scan result for {Id} ({Purl}).",
                component.Id, component.Purl);
            return (ComponentScanOutcome.Failed, 0);
        }
    }

    /// <summary>Links every hydrated advisory to the component and answers how many landed.</summary>
    private async Task<int> LinkHydratedAdvisoriesAsync(
        ScannableSbomComponent component, List<OsvAdvisory> advisories, CancellationToken ct)
    {
        int linked = 0;
        foreach (var advisory in advisories)
        {
            if (!advisory.IsHydrated)
            {
                continue;
            }

            string vulnId = await _vulns.UpsertVulnerabilityAsync(
                advisory, component.Ecosystem, component.PurlName ?? "", ct);
            await _sbomVulns.LinkComponentVulnAsync(component.Id, vulnId, ct);
            linked++;
        }

        return linked;
    }

    private static SbomScanBatchResult Deferred() => new(
        new HashSet<string>(StringComparer.Ordinal),
        new Dictionary<string, int>(StringComparer.Ordinal),
        Deferred: true);

    /// <summary>
    /// Makes the fail-closed deferral branch visible as a metric rather than only a log line: an
    /// OSV outage degrading SBOM coverage previously surfaced only as a wall of warn versions or
    /// the health page's 36-hour staleness signal.
    /// </summary>
    private static void RecordOutcome(int scanned, int deferred)
    {
        if (scanned > 0)
        {
            DependablyMeter.ScanComponents.Add(scanned, new KeyValuePair<string, object?>("outcome", "scanned"));
        }

        if (deferred > 0)
        {
            DependablyMeter.ScanComponents.Add(deferred, new KeyValuePair<string, object?>("outcome", "deferred"));
        }
    }
}

/// <summary>
/// Result of one <see cref="SbomComponentScanner.ScanBatchAsync"/> call.
/// <see cref="Deferred"/> true means the source was not reached: <see cref="ScannedComponentIds"/>
/// and <see cref="AdvisoryCountByComponentId"/> are both empty and no row in the batch was
/// stamped. Otherwise <see cref="ScannedComponentIds"/> is every component that was successfully
/// persisted (a per-component exception can leave one out even on a reached batch) and
/// <see cref="AdvisoryCountByComponentId"/> carries the hydrated-advisory link count written for
/// each.
/// </summary>
public sealed record SbomScanBatchResult(
    IReadOnlySet<string> ScannedComponentIds,
    IReadOnlyDictionary<string, int> AdvisoryCountByComponentId,
    bool Deferred);
