namespace Dependably.Protocol;

/// <summary>
/// Source of the two public exploitation-signal feeds consumed by
/// <see cref="Infrastructure.ThreatFeedRefreshService"/>: the CISA Known Exploited
/// Vulnerabilities catalog and FIRST.org EPSS exploitation-probability scores. Abstracted so
/// tests inject canned feeds, mirroring <see cref="IOsvSource"/>.
///
/// <para>
/// Both feeds carry materially more than membership and a probability, and both are fetched by
/// the deployment itself with no external service involved — so everything here is available on
/// every deployment, including one that configures no vulnerability tracker.
/// </para>
/// </summary>
public interface IThreatFeedSource
{
    /// <summary>
    /// The full KEV catalog, keyed by CVE id (case-insensitive). Membership is
    /// <c>ContainsKey</c>; the value carries the entry's context. Throws on fetch/parse failure —
    /// the refresh pass treats that as "skip the KEV pass this run" rather than clearing flags.
    /// </summary>
    Task<IReadOnlyDictionary<string, KevEntry>> GetKevCatalogAsync(CancellationToken ct = default);

    /// <summary>
    /// EPSS scores for the given CVE ids. Partial results are the normal case twice over:
    /// CVEs unknown to EPSS are absent from <see cref="EpssQueryResult.Scores"/> but present in
    /// <see cref="EpssQueryResult.Queried"/>; CVEs whose batch failed outright are absent from
    /// both, so the caller can leave their rows unstamped and retry next pass.
    /// </summary>
    Task<EpssQueryResult> GetEpssScoresAsync(IReadOnlyCollection<string> cveIds, CancellationToken ct = default);
}

/// <summary>
/// One KEV catalog entry's context, beyond the fact of membership.
/// </summary>
/// <param name="KnownRansomwareCampaignUse">
/// <b>Tri-state, and the distinction is the point.</b> <c>true</c> = CISA marks the entry
/// <c>Known</c>. <c>false</c> = CISA marks it <c>Unknown</c>, which is an assertion that no
/// ransomware use is known — a real answer from the source. <c>null</c> = the entry carried no
/// such field at all, so there is no assertion either way. A gate arm must not collapse the last
/// two: "the source says no" and "the source did not say" are different, and only one of them is
/// safe to treat as a pass.
/// </param>
/// <param name="DateAdded">The calendar date CISA added the entry (<c>YYYY-MM-DD</c>), or null.</param>
/// <param name="DueDate">The federal remediation due date (<c>YYYY-MM-DD</c>), or null.</param>
/// <param name="RequiredAction">
/// CISA's prescribed remediation step, in prose. Null when the entry carries no such field —
/// never coerced to empty string.
/// </param>
/// <param name="Cwes">
/// The entry's CWE classification ids, in catalogue order. Null when the entry has no
/// <c>cwes</c> field at all; an empty (non-null) list when the entry has the field but recorded
/// zero classifications — the two are different facts and must stay distinguishable all the way
/// to storage.
/// </param>
/// <param name="Notes">Vendor advisory/patch links, free text. Null when absent.</param>
public sealed record KevEntry(
    bool? KnownRansomwareCampaignUse,
    string? DateAdded,
    string? DueDate,
    string? RequiredAction = null,
    IReadOnlyList<string>? Cwes = null,
    string? Notes = null);

/// <summary>
/// One CVE's EPSS result: the exploitation probability and, where FIRST published it, the
/// percentile rank.
/// </summary>
/// <param name="Probability">Exploitation probability in 0..1.</param>
/// <param name="Percentile">
/// Rank within the corpus, 0..1, or null when the feed omitted it. Kept beside the probability
/// rather than derived, because it is what stays comparable across model retrains: the
/// probability attached to a given rank moves when FIRST retrains, the rank does not.
/// </param>
public sealed record EpssScore(double Probability, double? Percentile);

/// <summary>Outcome of <see cref="IThreatFeedSource.GetEpssScoresAsync"/>.</summary>
public sealed record EpssQueryResult(
    IReadOnlyDictionary<string, EpssScore> Scores,
    IReadOnlySet<string> Queried);
