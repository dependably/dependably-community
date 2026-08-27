using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Pure, no-I/O coverage of <see cref="SbomPolicyEvaluator.Evaluate"/>: each vulnerability arm in
/// isolation, VEX-suppression pre-filtering, the never-scanned posture, and "all violations, not
/// first-arm-wins" — the exact properties that make this evaluator a sibling of
/// <see cref="BlockGateService.Evaluate"/> rather than a reuse of it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomPolicyEvaluatorTests
{
    private static readonly DateTimeOffset Scanned = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static BlockPolicy Policy(
        string blockMalicious = "off", string blockKev = "off",
        double? maxEpss = null, double maxCvss = 10.0) =>
        new(
            MinReleaseAgeHours: null,
            BlockDeprecatedMode: null,
            BlockMaliciousMode: blockMalicious,
            BlockKevMode: blockKev,
            MaxEpssTolerance: maxEpss,
            MaxOsvScoreTolerance: maxCvss);

    private static SbomComponentFacts Facts(
        DateTimeOffset? vulnCheckedAt, params SbomComponentVulnFact[] vulns) =>
        new("component-1", "npm", null, vulnCheckedAt, vulns);

    private static SbomComponentFacts ScopedFacts(
        string? sbomScope, DateTimeOffset? vulnCheckedAt, params SbomComponentVulnFact[] vulns) =>
        new("component-1", "npm", sbomScope, vulnCheckedAt, vulns);

    // ── unscanned posture ────────────────────────────────────────────────────

    [Fact]
    public void NeverScanned_ProducesNoFindings_RegardlessOfPolicy()
    {
        var facts = Facts(vulnCheckedAt: null,
            new SbomComponentVulnFact("MAL-2024-1", new VulnFacts(Cvss: 9.9, NvdScore: null, IsMalicious: true, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: 0.9, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));
        var policy = Policy(blockMalicious: "block", blockKev: "block", maxEpss: 0.1, maxCvss: 1.0);

        var findings = SbomPolicyEvaluator.Evaluate(facts, policy);

        Assert.Empty(findings);
    }

    // ── sbom scope ───────────────────────────────────────────────────────────

    [Fact]
    public void AnExcludedComponentIsNotScored_EvenForAKevAdvisory()
    {
        var facts = ScopedFacts("excluded", Scanned,
            new SbomComponentVulnFact("CVE-2100-1", new VulnFacts(Cvss: 9.9, NvdScore: null, IsMalicious: true, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: 0.9, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));
        var policy = Policy(blockMalicious: "block", blockKev: "block", maxEpss: 0.1, maxCvss: 1.0);

        Assert.Empty(SbomPolicyEvaluator.Evaluate(facts, policy));
    }

    [Theory]
    [InlineData("required")]
    [InlineData("optional")]
    [InlineData(null)]
    public void EveryOtherScopeIsStillScored(string? sbomScope)
    {
        var facts = ScopedFacts(sbomScope, Scanned,
            new SbomComponentVulnFact("CVE-2100-2", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));
        var policy = Policy(blockKev: "block");

        Assert.Single(SbomPolicyEvaluator.Evaluate(facts, policy));
    }

    // ── malicious arm ────────────────────────────────────────────────────────

    [Fact]
    public void Malicious_Blocked_And_ModeBlock_ProducesFinding()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("MAL-2024-1", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: true, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(blockMalicious: "block"));

        var finding = Assert.Single(findings);
        Assert.Equal("malicious", finding.Arm);
        Assert.Equal("MAL-2024-1", finding.VulnKey);
    }

    [Fact]
    public void Malicious_ModeWarn_ProducesNoFinding()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("MAL-2024-1", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: true, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(blockMalicious: "warn"));

        Assert.Empty(findings);
    }

    // ── KEV arm ──────────────────────────────────────────────────────────────

    [Fact]
    public void Kev_ModeBlock_ProducesFinding()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-1", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(blockKev: "block"));

        var finding = Assert.Single(findings);
        Assert.Equal("kev", finding.Arm);
        Assert.Equal("CVE-2024-1", finding.VulnKey);
    }

    [Fact]
    public void Kev_ModeOff_ProducesNoFinding()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-1", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(blockKev: "off"));

        Assert.Empty(findings);
    }

    // ── EPSS arm ─────────────────────────────────────────────────────────────

    [Fact]
    public void Epss_ExceedsTolerance_ProducesFinding()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-2", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: 0.5, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(maxEpss: 0.1));

        var finding = Assert.Single(findings);
        Assert.Equal("epss", finding.Arm);
    }

    [Fact]
    public void Epss_AtTolerance_PassesOnEqual()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-2", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: 0.1, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(maxEpss: 0.1));

        Assert.Empty(findings);
    }

    [Fact]
    public void Epss_ToleranceOff_NeverFires()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-2", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: 0.99, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(maxEpss: null));

        Assert.Empty(findings);
    }

    // ── CVSS arm ─────────────────────────────────────────────────────────────

    [Fact]
    public void Cvss_ExceedsCeiling_ProducesFinding()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-3", new VulnFacts(Cvss: 9.0, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(maxCvss: 7.0));

        var finding = Assert.Single(findings);
        Assert.Equal("cvss", finding.Arm);
    }

    [Fact]
    public void Cvss_AtCeiling_PassesOnEqual()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-3", new VulnFacts(Cvss: 7.0, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(maxCvss: 7.0));

        Assert.Empty(findings);
    }

    // ── VEX suppression pre-filter ───────────────────────────────────────────

    [Theory]
    [InlineData("not_affected")]
    [InlineData("false_positive")]
    [InlineData("resolved")]
    public void VexSuppressedState_SuppressesEveryArm(string vexState)
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-4", new VulnFacts(Cvss: 9.9, NvdScore: null, IsMalicious: true, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: 0.99, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: vexState));
        var policy = Policy(blockMalicious: "block", blockKev: "block", maxEpss: 0.01, maxCvss: 1.0);

        var findings = SbomPolicyEvaluator.Evaluate(facts, policy);

        Assert.Empty(findings);
    }

    /// <summary>
    /// <c>resolved_with_pedigree</c> asserts a fix exists somewhere in the pedigree, not that
    /// this exact advisory no longer applies to this exact component — it must not suppress.
    /// </summary>
    [Fact]
    public void ResolvedWithPedigree_DoesNotSuppress()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-5", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: "resolved_with_pedigree"));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(blockKev: "block"));

        var finding = Assert.Single(findings);
        Assert.Equal("kev", finding.Arm);
    }

    [Theory]
    [InlineData("exploitable")]
    [InlineData("in_triage")]
    public void OpenOrUnreviewedVexState_DoesNotSuppress(string vexState)
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-6", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: vexState));

        var findings = SbomPolicyEvaluator.Evaluate(facts, Policy(blockKev: "block"));

        Assert.Single(findings);
    }

    // ── all violations, not first-arm-wins ───────────────────────────────────

    [Fact]
    public void SingleAdvisory_ViolatingMultipleArms_ProducesOneFindingPerArm()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-2024-7", new VulnFacts(Cvss: 9.5, NvdScore: null, IsMalicious: false, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: 0.9, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));
        var policy = Policy(blockKev: "block", maxEpss: 0.1, maxCvss: 7.0);

        var findings = SbomPolicyEvaluator.Evaluate(facts, policy);

        Assert.Equal(3, findings.Count);
        Assert.Contains(findings, f => f.Arm == "kev");
        Assert.Contains(findings, f => f.Arm == "epss");
        Assert.Contains(findings, f => f.Arm == "cvss");
    }

    [Fact]
    public void MixedComponent_PassingAndViolatingAdvisories_ReturnsOnlyViolations()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("CVE-clean", new VulnFacts(Cvss: 2.0, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: 0.01, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null),
            new SbomComponentVulnFact("CVE-bad", new VulnFacts(Cvss: 9.9, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null),
            new SbomComponentVulnFact("CVE-suppressed", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: "not_affected"));
        var policy = Policy(blockKev: "block", maxCvss: 7.0);

        var findings = SbomPolicyEvaluator.Evaluate(facts, policy);

        var finding = Assert.Single(findings);
        Assert.Equal("cvss", finding.Arm);
        Assert.Equal("CVE-bad", finding.VulnKey);
    }

    [Fact]
    public void MultipleAdvisories_EachViolatingADifferentArm_ReturnsAllOfThem()
    {
        var facts = Facts(Scanned,
            new SbomComponentVulnFact("MAL-1", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: true, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null),
            new SbomComponentVulnFact("CVE-kev", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: true, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null),
            new SbomComponentVulnFact("CVE-epss", new VulnFacts(Cvss: null, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: 0.9, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null),
            new SbomComponentVulnFact("CVE-cvss", new VulnFacts(Cvss: 9.9, NvdScore: null, IsMalicious: false, IsKev: false, IsKevRansomware: null, KevDueDate: null, Epss: null, EpssPercentile: null, SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null, HasStaleEnrichment: false), VexState: null));
        var policy = Policy(blockMalicious: "block", blockKev: "block", maxEpss: 0.1, maxCvss: 7.0);

        var findings = SbomPolicyEvaluator.Evaluate(facts, policy);

        Assert.Equal(4, findings.Count);
        Assert.Contains(findings, f => f.Arm == "malicious" && f.VulnKey == "MAL-1");
        Assert.Contains(findings, f => f.Arm == "kev" && f.VulnKey == "CVE-kev");
        Assert.Contains(findings, f => f.Arm == "epss" && f.VulnKey == "CVE-epss");
        Assert.Contains(findings, f => f.Arm == "cvss" && f.VulnKey == "CVE-cvss");
    }
}
