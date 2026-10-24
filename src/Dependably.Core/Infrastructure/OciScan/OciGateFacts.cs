namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// One org's block-gate facts for one OCI image, read from that org's own scan tables and never
/// from the shared cache-plane rows. <see cref="HasResult"/> is false when the org's scanner has
/// posted nothing for the image; <see cref="GapCount"/> counts the coverage gaps across its
/// platforms; <see cref="Signals"/> aggregates every advisory the result did match, with the same
/// projection and freshness rules the other ecosystems' gate signals use.
///
/// <para>A result with gaps is positive-only evidence: every advisory it found still feeds the
/// arms, but it is never a complete answer, so the image reads as unscanned when nothing it found
/// refuses it. <see cref="ScannerLive"/> only separates "nobody is scanning for this org" from
/// "the scan has not landed yet" in the refusal's recorded sub-reason.</para>
/// </summary>
public sealed record OciGateFacts(bool HasResult, int GapCount, VulnGateSignals Signals, bool ScannerLive = true)
{
    /// <summary>No stored result for the image.</summary>
    public static OciGateFacts Absent(bool scannerLive) =>
        new(false, 0, new VulnGateSignals(VulnFacts.None), scannerLive);

    /// <summary>The OSV ids of the <c>MAL-</c> advisories the result matched, for a refusal's detail.</summary>
    public IReadOnlyList<string> MaliciousOsvIds { get; init; } = [];

    /// <summary>The OSV ids of the CISA-KEV-listed advisories the result matched, for a refusal's detail.</summary>
    public IReadOnlyList<string> KevOsvIds { get; init; } = [];

    /// <summary>A stored result with no coverage gaps: the only complete answer.</summary>
    public bool IsComplete => HasResult && GapCount == 0;

    /// <summary>
    /// True when there is any scan evidence to feed the advisory arms: a stored result, or (for
    /// facts merged across owners) a finding from an owner that has one. The advisory arms read
    /// this as "scanned", so a finding is enforced even when the overall answer is incomplete.
    /// </summary>
    public bool HasEvidence => HasResult || Signals.Facts != VulnFacts.None;

    /// <summary>
    /// Why the image has no complete answer, as recorded on an <c>unscanned</c> refusal:
    /// <c>no_scanner</c> (no result and no live scanner for the org), <c>absent</c> (no result
    /// yet), or <c>partial</c> (a result with gaps). Null for a complete result.
    /// </summary>
    public string? UnscannedSubReason =>
        IsComplete ? null
        : !HasResult ? (ScannerLive ? "absent" : "no_scanner")
        : "partial";

    /// <summary>
    /// The facts for an image reached through several owners (a platform manifest referenced by
    /// more than one index the org holds): the strictest combination. Any owner without a complete
    /// result makes the whole answer incomplete, and every signal takes its most severe value, so
    /// no arm can pass on the merged facts that would refuse on one owner's.
    ///
    /// <para>The CVSS ceiling folds each owner's effective score (its own CVSS, else NVD's) before
    /// taking the maximum: taking the two sources' maxima separately would let one owner's low OSV
    /// score mask another owner's NVD-only high score.</para>
    /// </summary>
    public static OciGateFacts Strictest(IReadOnlyList<OciGateFacts> owners)
    {
        if (owners.Count == 0)
        {
            throw new ArgumentException("At least one owner's facts are required.", nameof(owners));
        }

        if (owners.Count == 1)
        {
            return owners[0];
        }

        var facts = owners.Select(o => o.Signals.Facts).ToList();
        var merged = new VulnFacts(
            Cvss: Max(facts.Select(f => f.EffectiveCvss)),
            NvdScore: Max(facts.Select(f => f.NvdScore)),
            IsMalicious: facts.Any(f => f.IsMalicious),
            IsKev: facts.Any(f => f.IsKev),
            IsKevRansomware: facts.Any(f => f.IsKevRansomware == true) ? true : null,
            KevDueDate: null,
            Epss: Max(facts.Select(f => f.Epss)),
            EpssPercentile: Max(facts.Select(f => f.EpssPercentile)),
            SsvcExploitation: facts.Any(f => f.SsvcExploitation == "active") ? "active" : null,
            SsvcAutomatable: null,
            SsvcTechnicalImpact: null,
            HasStaleEnrichment: facts.Any(f => f.HasStaleEnrichment),
            MalStillLive: facts.Any(f => f.MalStillLive));

        bool allHaveResults = owners.All(o => o.HasResult);
        return new OciGateFacts(
            // Any owner lacking a result leaves the merged answer without one, so the sub-reason
            // names the weakest owner rather than the best-covered one.
            HasResult: allHaveResults,
            GapCount: allHaveResults ? owners.Sum(o => o.GapCount) : 0,
            Signals: new VulnGateSignals(merged),
            ScannerLive: owners.All(o => o.ScannerLive))
        {
            MaliciousOsvIds = owners.SelectMany(o => o.MaliciousOsvIds).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList(),
            KevOsvIds = owners.SelectMany(o => o.KevOsvIds).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList(),
        };
    }

    private static double? Max(IEnumerable<double?> values)
    {
        double? max = null;
        foreach (double? v in values)
        {
            if (v is { } d && (max is null || d > max))
            {
                max = d;
            }
        }

        return max;
    }
}
