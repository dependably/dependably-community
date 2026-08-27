namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The single comparison rule for the <c>(purl_key, vuln_key)</c> pair every <c>vuln_key</c> match
/// compares on: the analysis projection's advisory lookup, the policy evaluator's VEX resolution,
/// and the CycloneDX VDR export's analysis-block binding.
///
/// <para><c>purl_key</c> is compared ordinally — it is already canonicalized to one spelling by
/// <see cref="SbomPurlKey"/> at write time. <c>vuln_key</c> is matched case-insensitively rather
/// than canonicalized to one case, because advisory ids do not share one casing convention: a CVE
/// id is conventionally all-uppercase, but a GHSA id's alphanumeric suffix is conventionally
/// lowercase (<c>GHSA-xxxx-xxxx-xxxx</c>). Folding every id to one case at write time would
/// silently corrupt whichever convention disagreed with the chosen case, in storage and in every
/// surface that renders <c>vuln_key</c> back to an operator — the analysis view, and the exported
/// VEX document, both of which display the stored spelling verbatim. Comparing case-insensitively
/// instead, without ever rewriting the stored value, is what lets a VEX citing a lowercase
/// <c>cve-2023-1234</c> suppress the same finding a scanner recorded as <c>CVE-2023-1234</c> —
/// identically in the analysis view, the policy evaluator, and the export — while every surface
/// keeps rendering whichever spelling its own row actually holds.</para>
///
/// <para>The three writers of <c>project_vuln_analysis</c> — the VEX arm, the reachability arm
/// and the manual triage — apply the same rule to their <c>ON CONFLICT</c> target, which is a
/// plain byte-for-byte UNIQUE and would otherwise miss a conflict every reader here considers a
/// match. Each resolves the spelling the tenant's own row already holds
/// (<c>UPPER(stored.vuln_key) = UPPER(@vulnKey)</c>, lowest by ordinal sort when more than one
/// exists) and writes that, inside the INSERT rather than in a preceding round trip, so the
/// stored id stays verbatim and the conflict fires. Missing it does not merely duplicate a row:
/// the VEX arm's <c>vex_source &lt;&gt; 'manual'</c> refusal is expressed as the conflict
/// update's WHERE clause, so a statement that never conflicts is never refused, and an uploaded
/// document silently overrides the operator decision that guard exists to protect.</para>
///
/// <para>The retraction sweeps match their asserted key set through this comparer for the same
/// reason: with the writers resolving onto the stored spelling, an ordinal keep-set would fail to
/// recognise the row the same request had just written and retract it immediately. A database
/// already holding case-variant rows keeps both under that broader match, which errs toward
/// keeping a fact rather than deleting one.</para>
///
/// <para>Resolving inside the INSERT closes the race under SQLite, which evaluates the statement
/// under its single writer. Under Postgres read-committed two genuinely simultaneous writes of
/// one advisory in different case, with no row yet, can still each insert — neither snapshot sees
/// the other's uncommitted row — and the case-insensitive matching here is what keeps that pair
/// reading as one advisory until the next write collapses them.</para>
/// </summary>
public sealed class SbomVulnKeyComparer : IEqualityComparer<(string PurlKey, string VulnKey)>
{
    public static readonly SbomVulnKeyComparer Instance = new();

    public bool Equals((string PurlKey, string VulnKey) x, (string PurlKey, string VulnKey) y) =>
        string.Equals(x.PurlKey, y.PurlKey, StringComparison.Ordinal)
        && string.Equals(x.VulnKey, y.VulnKey, StringComparison.OrdinalIgnoreCase);

    public int GetHashCode((string PurlKey, string VulnKey) obj) =>
        HashCode.Combine(obj.PurlKey, obj.VulnKey.ToUpperInvariant());
}
