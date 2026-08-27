using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;

namespace Dependably.Protocol;

/// <summary>
/// One linked advisory on an SBOM component, already carrying its VEX disposition (if any) so
/// <see cref="SbomPolicyEvaluator.Evaluate"/> can pre-filter suppressed signals before any arm
/// runs. <see cref="VexState"/> is the CycloneDX analysis-state vocabulary
/// (<c>project_vuln_analysis.vex_state</c>); null means no VEX statement covers this
/// (component, advisory) pair. <see cref="Vuln"/> carries every exploitation/decision-support
/// signal in the vocabulary shared with the block gate and the projects-plane priority
/// derivation — this is the plane where <see cref="VulnFacts.IsKevRansomware"/>'s true tri-state
/// is preserved untouched, unlike the gate-arm level's collapse to a plain bool.
/// </summary>
public readonly record struct SbomComponentVulnFact(
    string VulnKey,
    VulnFacts Vuln,
    string? VexState);

/// <summary>
/// Everything <see cref="SbomPolicyEvaluator.Evaluate"/> needs to decide one SBOM component's
/// vulnerability-arm findings. <see cref="VulnCheckedAt"/> null means the component was never
/// successfully scanned — the caller must not read an empty finding set for such a component as
/// "clean" (see the evaluator's own doc comment). <see cref="DependencyScope"/> and
/// <see cref="DependencyKind"/> are populated from the component row but not yet consulted by any
/// arm here — they are component-level facts (not part of <see cref="VulnFacts"/>) ready for a
/// future evaluator to read.
/// </summary>
public readonly record struct SbomComponentFacts(
    string ComponentId,
    string? Ecosystem,
    string? SbomScope,
    DateTimeOffset? VulnCheckedAt,
    IReadOnlyList<SbomComponentVulnFact> Vulns,
    string? DependencyScope = null,
    string? DependencyKind = null);

/// <summary>
/// One materialized policy violation, shaped to write directly onto a <c>sbom_policy_findings</c>
/// row. <see cref="Arm"/> is one of the five values the schema's CHECK constraint allows.
/// </summary>
public sealed record SbomPolicyFindingResult(
    string Arm,
    string? VulnKey,
    string? LicenseSpdx,
    string Detail);

/// <summary>
/// Pure policy core for SBOM component inventories. A sibling of
/// <see cref="BlockGateService.Evaluate"/>, not a reuse of it: every one of that method's pure
/// arms reads a serve-path fact (manual block state, deprecation, revocation, release age,
/// provenance, install scripts) that does not exist for an SBOM component, it returns the first
/// arm that fires rather than every arm that does, and it has no notion of pre-filtering a vuln
/// aggregate by VEX disposition before scoring it. None of that fits an inventory of components
/// describing an already-built application, where the point is to surface every violation for
/// review, not to decide serve/deny.
///
/// Arms: malicious, KEV, EPSS ceiling, CVSS ceiling — each evaluated per linked advisory on a
/// component the SBOM does not declare out of scope (see <see cref="ExcludedSbomScope"/>), after
/// excluding advisories whose <see cref="SbomComponentVulnFact.VexState"/> is
/// <c>not_affected</c>, <c>false_positive</c>, or <c>resolved</c> (the VEX-suppression
/// pre-filter). All four arms can fire independently for the same advisory (a KEV-listed
/// advisory that also exceeds the CVSS ceiling produces two findings, not one), and every
/// advisory on the component is scored, not just the first one that violates something — the
/// caller needs the full violation set, not a verdict.
///
/// A component whose <see cref="SbomComponentFacts.VulnCheckedAt"/> is null was never
/// successfully scanned. This method returns no findings for such a component (there is nothing
/// scored), but that empty result is not "clean" — it is "unknown" — and callers computing a
/// per-version rollup must fold "component never scanned" into a distinct state (e.g. <c>warn</c>)
/// rather than letting an absence of findings read as <c>pass</c>. See
/// <c>CLAUDE.md</c>'s "a security gate never degrades to allow because its input signal is
/// missing". That applies to a component a scan could still answer for: a row failing
/// <see cref="SbomScannableComponents.IsScannable"/> is unscannable rather than unscanned, and
/// the caller counts it separately instead of leaving the version at <c>warn</c> forever.
///
/// The licence arm is deliberately not here: it needs <c>LicenseRepository.CheckPolicyAsync</c>
/// (a database read), so it is evaluated by the orchestrating service alongside this method's
/// output rather than folded into it — mirroring how
/// <see cref="BlockGateService.EvaluateLicenseArmAsync"/> sits beside <c>Evaluate</c> rather than
/// inside it.
/// </summary>
public static class SbomPolicyEvaluator
{
    /// <summary>
    /// CycloneDX/OpenVEX-normalized analysis states under which an advisory is a resolved,
    /// non-issue for this component and must not reach the malicious/KEV/EPSS/CVSS arms.
    /// <c>resolved_with_pedigree</c> is deliberately excluded: it asserts a fix exists somewhere
    /// in the component's pedigree, not that this exact linked advisory no longer applies, so
    /// treating it as suppressed would be the "missing signal reads as allow" failure this
    /// evaluator exists to avoid. <c>exploitable</c> and <c>in_triage</c> are not suppressing —
    /// an open or unreviewed VEX statement is not a reason to hide a finding.
    /// </summary>
    private static readonly HashSet<string> VexSuppressedStates =
        new(StringComparer.Ordinal) { "not_affected", "false_positive", "resolved" };

    /// <summary>
    /// The CycloneDX <c>components[].scope</c> value that puts a component outside the assembled
    /// deliverable. The producer is stating that these bytes do not ship, which is a statement
    /// about the artefact rather than about the advisory, so the four vulnerability arms have
    /// nothing to score.
    /// </summary>
    public const string ExcludedSbomScope = "excluded";

    public static IReadOnlyList<SbomPolicyFindingResult> Evaluate(SbomComponentFacts facts, BlockPolicy policy)
    {
        // Never scanned: nothing here is scoreable. Returning no findings is correct (there is no
        // violation to report), but the caller must not treat this as equivalent to a scanned,
        // clean component — see the class doc comment.
        if (facts.VulnCheckedAt is null)
        {
            return [];
        }

        // A component the SBOM's own producer marks 'excluded' is not part of the assembled
        // deliverable, so an advisory against it describes code that does not ship. Scoring it
        // sets the version to 'violation' and, through the folder rollup's Worst fold, reds
        // every ancestor — permanently, because no re-upload can retire a finding the inventory
        // is correct to keep declaring.
        //
        // Only these four arms are exempted. The licence arm still evaluates an excluded
        // component, because a licence obligation attaches to distribution of the source and not
        // to whether the bytes ship. dependency_scope = 'dev' is likewise still evaluated, and
        // deliberately: that column defaults to 'unknown' and is the reachability scanner's to
        // fill, so skipping on it would let every component nothing has classified escape policy.
        // sbom_scope carries no such default — it is present only when a producer asserted it.
        if (string.Equals(facts.SbomScope, ExcludedSbomScope, StringComparison.Ordinal))
        {
            return [];
        }

        List<SbomPolicyFindingResult>? findings = null;

        foreach (var vuln in facts.Vulns)
        {
            if (vuln.VexState is not null && VexSuppressedStates.Contains(vuln.VexState))
            {
                continue;
            }

            foreach (var finding in ScoreVulnerability(vuln, policy))
            {
                findings ??= [];
                findings.Add(finding);
            }
        }

        return findings ?? (IReadOnlyList<SbomPolicyFindingResult>)[];
    }

    /// <summary>
    /// The four advisory arms, scored against one vulnerability. Each is independent — a malicious
    /// package over the EPSS tolerance raises both — and the caller's list stays unallocated until
    /// one of them fires, which is the common case.
    /// </summary>
    private static IEnumerable<SbomPolicyFindingResult> ScoreVulnerability(
        SbomComponentVulnFact vuln, BlockPolicy policy)
    {
        // Only malicious/KEV/EPSS/CVSS are consulted here — vuln.Vuln carries the full unified
        // vocabulary (NVD, SSVC, ransomware, percentile), but wiring those into this evaluator is
        // deferred to a later change.
        if (vuln.Vuln.IsMalicious && policy.BlockMaliciousMode == "block")
        {
            yield return MaliciousFinding(vuln.VulnKey);
        }

        if (vuln.Vuln.IsKev && policy.BlockKevMode == "block")
        {
            yield return KevFinding(vuln.VulnKey);
        }

        if (policy.MaxEpssTolerance is { } epssTolerance && vuln.Vuln.Epss is { } epss && epss > epssTolerance)
        {
            yield return EpssFinding(vuln.VulnKey, epss, epssTolerance);
        }

        if (vuln.Vuln.Cvss is { } cvss && cvss > policy.MaxOsvScoreTolerance)
        {
            yield return CvssFinding(vuln.VulnKey, cvss, policy.MaxOsvScoreTolerance);
        }
    }

    private static SbomPolicyFindingResult MaliciousFinding(string vulnKey) =>
        new("malicious", vulnKey, null,
            JsonSerializer.Serialize(new { osv_id = vulnKey }, EventJsonOptions.Detail));

    private static SbomPolicyFindingResult KevFinding(string vulnKey) =>
        new("kev", vulnKey, null,
            JsonSerializer.Serialize(new { osv_id = vulnKey }, EventJsonOptions.Detail));

    private static SbomPolicyFindingResult EpssFinding(string vulnKey, double epss, double tolerance) =>
        new("epss", vulnKey, null,
            JsonSerializer.Serialize(
                new { osv_id = vulnKey, max_epss = epss, tolerance }, EventJsonOptions.Detail));

    private static SbomPolicyFindingResult CvssFinding(string vulnKey, double cvss, double tolerance) =>
        new("cvss", vulnKey, null,
            JsonSerializer.Serialize(
                new { osv_id = vulnKey, max_score = cvss, tolerance }, EventJsonOptions.Detail));
}
