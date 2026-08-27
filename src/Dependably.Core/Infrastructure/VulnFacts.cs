namespace Dependably.Infrastructure;

/// <summary>
/// Everything Dependably knows about one vulnerability's exploitation/decision-support signals —
/// the single vocabulary shared by the block gate (<see cref="Protocol.VersionFacts"/>), the SBOM
/// component inventory (<c>SbomComponentVulnFact</c>), and the projects-plane priority derivation
/// (<c>PriorityFacts</c>), so a signal added once (an EPSS refresh, a new SSVC assessment) is a
/// change to one record rather than three independently-drifting shapes.
///
/// <para>
/// Deliberately does <b>not</b> carry VEX state, reachability, or dependency-graph facts. Those
/// describe the <em>link</em> between a component and a vulnerability (VEX), or the <em>component</em>
/// itself (reachability, dependency kind/scope) — not the vulnerability, which is what this type
/// models. A caller that needs those pairs a <see cref="VulnFacts"/> with them alongside it, as
/// <c>SbomComponentVulnFact</c> and <c>PriorityFacts</c> both do.
/// </para>
/// </summary>
/// <param name="Cvss">
/// CVSS base score from the advisory's own source (e.g. OSV), or null when unscored. Not
/// NVD-fallback-adjusted — see <see cref="EffectiveCvss"/> for that.
/// </param>
/// <param name="NvdScore">
/// CVSS score from the optional NVD enrichment overlay, or null when the overlay is unconfigured,
/// unreachable, or has not scored this advisory.
/// </param>
/// <param name="IsMalicious">
/// True when the advisory is an OSV <c>MAL-</c> malicious-package report (the OpenSSF
/// malicious-packages feed), scored or not.
/// </param>
/// <param name="IsKev">True when the advisory aliases a CISA-KEV-listed CVE.</param>
/// <param name="IsKevRansomware">
/// Tri-state: <see langword="true"/> when CISA explicitly marks the KEV entry as used in
/// ransomware campaigns, <see langword="false"/> when CISA explicitly asserts no known ransomware
/// use, and <see langword="null"/> when no assertion was made at all (including "not a KEV entry").
/// The false/null distinction is load-bearing for a ranking formula built over this value and must
/// never be collapsed to a plain bool by a producer that cannot tell them apart.
/// </param>
/// <param name="KevDueDate">
/// CISA KEV federal remediation due date (<c>YYYY-MM-DD</c>, matching how it is fetched and
/// stored), or null when not KEV-listed or unknown.
/// </param>
/// <param name="Epss">Highest EPSS exploitation probability (0.0–1.0), or null when unscored by EPSS.</param>
/// <param name="EpssPercentile">EPSS percentile rank (0.0–1.0), the rank sibling of <see cref="Epss"/>.</param>
/// <param name="SsvcExploitation">
/// CISA Vulnrichment SSVC exploitation state — <c>"none"</c>, <c>"poc"</c>, or <c>"active"</c> — or
/// null when the overlay is unconfigured, unreachable, or has not assessed this advisory.
/// </param>
/// <param name="SsvcAutomatable">SSVC automatable assessment — <c>"yes"</c>/<c>"no"</c> — or null.</param>
/// <param name="SsvcTechnicalImpact">SSVC technical-impact assessment — <c>"partial"</c>/<c>"total"</c> — or null.</param>
/// <param name="HasStaleEnrichment">
/// True when tracker enrichment was recorded before the operator's staleness horizon — distinct
/// from "never enriched": one is a signal that can no longer be vouched for, the other is a signal
/// never had at all.
/// </param>
public readonly record struct VulnFacts(
    double? Cvss,
    double? NvdScore,
    bool IsMalicious,
    bool IsKev,
    bool? IsKevRansomware,
    string? KevDueDate,
    double? Epss,
    double? EpssPercentile,
    string? SsvcExploitation,
    string? SsvcAutomatable,
    string? SsvcTechnicalImpact,
    bool HasStaleEnrichment)
{
    /// <summary>
    /// The score a ceiling arm should compare against: the advisory's own CVSS when it has one,
    /// otherwise the NVD overlay's. OSV wins when both exist — it is the source of record, and
    /// preferring the optional overlay would let it quietly override the primary feed.
    /// </summary>
    public double? EffectiveCvss => Cvss ?? NvdScore;

    /// <summary>No signal at all — every field at its unknown/absent default.</summary>
    public static readonly VulnFacts None = default;
}
