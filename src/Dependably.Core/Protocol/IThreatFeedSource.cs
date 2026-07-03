namespace Dependably.Protocol;

/// <summary>
/// Source of the two public exploitation-signal feeds consumed by
/// <see cref="Infrastructure.ThreatFeedRefreshService"/>: the CISA Known Exploited
/// Vulnerabilities catalog (a set of CVE ids) and FIRST.org EPSS exploitation-probability
/// scores. Abstracted so tests inject canned feeds, mirroring <see cref="IOsvSource"/>.
/// </summary>
public interface IThreatFeedSource
{
    /// <summary>
    /// The full KEV catalog as a CVE-id set (case-insensitive). Throws on fetch/parse failure —
    /// the refresh pass treats that as "skip the KEV pass this run" rather than clearing flags.
    /// </summary>
    Task<IReadOnlySet<string>> GetKevCveIdsAsync(CancellationToken ct = default);

    /// <summary>
    /// EPSS scores for the given CVE ids. Partial results are the normal case twice over:
    /// CVEs unknown to EPSS are absent from <see cref="EpssQueryResult.Scores"/> but present in
    /// <see cref="EpssQueryResult.Queried"/>; CVEs whose batch failed outright are absent from
    /// both, so the caller can leave their rows unstamped and retry next pass.
    /// </summary>
    Task<EpssQueryResult> GetEpssScoresAsync(IReadOnlyCollection<string> cveIds, CancellationToken ct = default);
}

/// <summary>Outcome of <see cref="IThreatFeedSource.GetEpssScoresAsync"/>.</summary>
public sealed record EpssQueryResult(
    IReadOnlyDictionary<string, double> Scores,
    IReadOnlySet<string> Queried);
