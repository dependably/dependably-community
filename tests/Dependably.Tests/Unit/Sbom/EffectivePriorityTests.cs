using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Exhaustive proof of the epic's security-judgement core. Every rule gets its own fact, and the
/// rules are then swept across the whole input cross-product against an independently written
/// oracle, so a reordering that happens to satisfy the hand-picked cases still fails here.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EffectivePriorityTests
{
    // Thin shim over the real 1-arg Derive(PriorityFacts). Every new field defaults to its
    // absent/neutral value so the pre-#612 hand-picked facts and the sweep below stay expressed as
    // the original five raw inputs, and any test that cares about a new signal supplies it
    // explicitly.
    private static PriorityVerdict Derive(
        double? cvss, bool isKev, double? epss, string? vexState, string? reachability,
        double? nvdScore = null, bool? isKevRansomware = null, double? epssPercentile = null,
        string? ssvcExploitation = null, string? dependencyKind = null, string? dependencyScope = null,
        bool hasInstallScript = false, bool isMalicious = false) =>
        EffectivePriority.Derive(PriorityFacts.ForProjectsPlane(
            VulnFacts.None with
            {
                Cvss = cvss,
                NvdScore = nvdScore,
                IsKev = isKev,
                IsKevRansomware = isKevRansomware,
                Epss = epss,
                EpssPercentile = epssPercentile,
                SsvcExploitation = ssvcExploitation,
                IsMalicious = isMalicious,
            },
            vexState, reachability, dependencyKind, dependencyScope, hasInstallScript));

    // ── Rule 1: a suppressing VEX state is final ─────────────────────────────

    [Theory]
    [InlineData("not_affected")]
    [InlineData("false_positive")]
    [InlineData("resolved")]
    public void SuppressingVexState_WinsOverEveryOtherSignal(string state)
    {
        // KEV, a 10.0 score, a 0.9 EPSS and reachable code — nothing outranks the statement that
        // the advisory does not apply to this product.
        var verdict = Derive(10.0, isKev: true, epss: 0.9, state, "reachable");
        Assert.Equal(EffectivePriority.Suppressed, verdict.Bucket);
    }

    [Fact]
    public void ResolvedWithPedigree_IsNotSuppressing()
    {
        // The state asserts a fix carried with provenance the platform does not verify, so the
        // advisory keeps its derived bucket and stays on screen.
        var verdict = Derive(9.0, isKev: false, epss: null, "resolved_with_pedigree", null);
        Assert.Equal(EffectivePriority.Attend, verdict.Bucket);
    }

    [Fact]
    public void InTriage_IsNotSuppressing()
    {
        var verdict = Derive(9.0, isKev: false, epss: null, "in_triage", null);
        Assert.Equal(EffectivePriority.Attend, verdict.Bucket);
    }

    // ── Rule 2: top-tier exploitation evidence is Act, whatever the score ────

    [Theory]
    [InlineData(null)]
    [InlineData(0.1)]
    [InlineData(3.9)]
    [InlineData(10.0)]
    public void Kev_IsAlwaysAct(double? cvss)
    {
        var verdict = Derive(cvss, isKev: true, epss: null, null, null);
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    [Fact]
    public void Kev_IsActEvenWhenNotObserved()
    {
        // Rule 2 is final: the reachability adjustment never runs, so a KEV advisory the analyzer
        // did not see called is still Act.
        var verdict = Derive(2.0, isKev: true, epss: null, null, "not-observed");
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    [Fact]
    public void Malicious_IsAlwaysAct()
    {
        // A MAL- advisory names a package that is itself the attack, so even a low score is Act.
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, isMalicious: true);
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    [Fact]
    public void Malicious_IsActEvenWhenNotObserved()
    {
        // Rule 2 is final: the reachability adjustment never runs, so a malicious advisory the
        // analyzer did not see called is still Act.
        var verdict = Derive(2.0, isKev: false, epss: null, null, "not-observed", isMalicious: true);
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    [Fact]
    public void KevRansomware_IsActIndependentlyOfTheKevFlag()
    {
        // In real data kev_known_ransomware is only ever true alongside is_kev, but the rule is
        // evaluated as its own condition — this fixture deliberately sets a combination that
        // "shouldn't" occur in stored data, specifically to prove this arm fires on its own rather
        // than piggy-backing on the IsKev check.
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, isKevRansomware: true);
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    [Fact]
    public void KevRansomwareFalse_IsNotTopTierEvidenceOnItsOwn()
    {
        // False is a real CISA assertion ("no known ransomware use"), not a promotion signal.
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, isKevRansomware: false);
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
    }

    [Fact]
    public void KevRansomwareNull_IsNotTopTierEvidence()
    {
        // Absent is unknown, never a positive signal.
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, isKevRansomware: null);
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
    }

    [Fact]
    public void SsvcActive_IsAct()
    {
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, ssvcExploitation: "active");
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("poc")]
    [InlineData(null)]
    public void SsvcNonActive_IsNotTopTierEvidence(string? exploitation)
    {
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, ssvcExploitation: exploitation);
        Assert.NotEqual(EffectivePriority.Act, verdict.Bucket);
    }

    [Theory]
    [InlineData(0.90, "act")]
    [InlineData(0.95, "act")]
    [InlineData(0.89, "track")]  // just below the top-decile threshold
    public void EpssPercentile_PromotesAtTheTopDecileThreshold(double percentile, string expected)
    {
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, epssPercentile: percentile);
        Assert.Equal(expected, verdict.Bucket);
    }

    [Fact]
    public void EpssPercentile_NullIsNotTopTierEvidence()
    {
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, epssPercentile: null);
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
    }

    // ── Rule 2 (existing arm): high EPSS on a high effective score is Act ────

    [Theory]
    [InlineData(0.10, 7.0, "act")]
    [InlineData(0.50, 9.8, "act")]
    [InlineData(0.09, 9.8, "attend")]   // EPSS below the threshold — falls through to the base rule
    [InlineData(0.90, 6.9, "track")]    // score below the threshold — both halves are required
    public void EpssAndCvss_BothMustCrossTheThreshold(double epss, double cvss, string expected)
    {
        var verdict = Derive(cvss, isKev: false, epss, null, null);
        Assert.Equal(expected, verdict.Bucket);
    }

    [Fact]
    public void HighEpss_WithNoScore_DoesNotReachAct()
    {
        // An unscored advisory cannot satisfy the CVSS half, so a high EPSS alone leaves it in
        // Track — flagged unscored so the reader knows the score is missing, not low.
        var verdict = Derive(null, isKev: false, epss: 0.99, null, null);
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
        Assert.True(verdict.Unscored);
    }

    // ── Rule 3: the base bucket, now NVD-fallback-aware ──────────────────────

    [Theory]
    [InlineData(10.0, "attend")]
    [InlineData(7.0, "attend")]
    [InlineData(6.9, "track")]
    [InlineData(4.0, "track")]
    [InlineData(3.9, "track")]
    [InlineData(0.0, "track")]
    public void BaseBucket_FollowsTheCvssBands(double cvss, string expected)
    {
        var verdict = Derive(cvss, isKev: false, epss: null, null, null);
        Assert.Equal(expected, verdict.Bucket);
        Assert.False(verdict.Unscored);
    }

    [Fact]
    public void NoScore_IsTrackAndFlaggedUnscored()
    {
        var verdict = Derive(null, isKev: false, epss: null, null, null);
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
        Assert.True(verdict.Unscored);
    }

    [Fact]
    public void Unscored_IsReportedEvenWhenAnotherRuleDecidedTheBucket()
    {
        // The flag reports "no CVSS exists", not "low severity". A KEV advisory nobody scored is
        // both Act and unscored, and the panel renders both.
        var verdict = Derive(null, isKev: true, epss: null, null, null);
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
        Assert.True(verdict.Unscored);
    }

    [Fact]
    public void Unscored_IsReportedOnASuppressedAdvisoryToo()
    {
        var verdict = Derive(null, isKev: false, epss: null, "not_affected", null);
        Assert.Equal(EffectivePriority.Suppressed, verdict.Bucket);
        Assert.True(verdict.Unscored);
    }

    [Fact]
    public void NvdScore_FillsInWhenOsvCarriesNoScore()
    {
        // OSV unscored, NVD scored high: the base bucket reads the NVD fallback and the advisory
        // is no longer reported as unscored.
        var verdict = Derive(null, isKev: false, epss: null, null, null, nvdScore: 9.1);
        Assert.Equal(EffectivePriority.Attend, verdict.Bucket);
        Assert.False(verdict.Unscored);
    }

    [Fact]
    public void OwnCvss_WinsOverNvdWhenBothExist()
    {
        // OSV is the source of record: a low OSV score is not silently overridden by a high NVD one.
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, nvdScore: 9.8);
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
    }

    [Fact]
    public void NvdScore_NullAndOwnCvssNull_StaysUnscored()
    {
        var verdict = Derive(null, isKev: false, epss: null, null, null, nvdScore: null);
        Assert.True(verdict.Unscored);
    }

    // ── Rule 3: dependency-kind adjustment ────────────────────────────────────

    [Theory]
    [InlineData("transitive", "track")]     // Attend base, demoted to Track
    [InlineData("direct", "attend")]
    [InlineData("root", "attend")]
    [InlineData("graph-unknown", "attend")] // explicit "don't know" must never demote
    [InlineData(null, "attend")]
    public void DependencyKind_OnlyTransitiveDemotes(string? kind, string expected)
    {
        var verdict = Derive(9.0, isKev: false, epss: null, null, null, dependencyKind: kind);
        Assert.Equal(expected, verdict.Bucket);
    }

    // ── Rule 3: dependency-scope adjustment ───────────────────────────────────

    [Theory]
    [InlineData("dev", "track")]        // Attend base, demoted to Track
    [InlineData("runtime", "attend")]
    [InlineData("unknown", "attend")]
    [InlineData(null, "attend")]
    public void DependencyScope_OnlyDevDemotes(string? scope, string expected)
    {
        var verdict = Derive(9.0, isKev: false, epss: null, null, null, dependencyScope: scope);
        Assert.Equal(expected, verdict.Bucket);
    }

    [Fact]
    public void DependencyKindAndScope_BothDemoteAndAccumulate()
    {
        // Attend base (9.0), transitive (-1) and dev (-1) accumulate to -2 before the single clamp,
        // landing at Track rather than the ladder floor stopping the second demotion short.
        var verdict = Derive(9.0, isKev: false, epss: null, null, null,
            dependencyKind: "transitive", dependencyScope: "dev");
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
    }

    // ── Rule 3: the reachability adjustment ───────────────────────────────────

    [Theory]
    [InlineData(9.0, "reachable", "act")]        // Attend promoted
    [InlineData(5.0, "reachable", "attend")]     // Track promoted
    [InlineData(9.0, "not-observed", "track")]   // Attend demoted
    [InlineData(5.0, "not-observed", "track")]   // already at the floor
    [InlineData(9.0, "unknown", "attend")]
    [InlineData(9.0, "imported-not-called", "attend")]
    [InlineData(9.0, null, "attend")]
    [InlineData(9.0, "", "attend")]
    [InlineData(9.0, "something-else", "attend")]
    public void Reachability_MovesTheBucketOneStep(double cvss, string? reachability, string expected)
    {
        var verdict = Derive(cvss, isKev: false, epss: null, null, reachability);
        Assert.Equal(expected, verdict.Bucket);
    }

    [Theory]
    [InlineData("not_observed")]
    [InlineData("NOT-OBSERVED")]
    [InlineData("  not observed  ")]
    public void Reachability_SpellingIsFolded(string spelling)
    {
        // A producer that wrote the value with an underscore, in caps, or padded still lands on the
        // demote arm rather than silently taking the no-change branch.
        var verdict = Derive(9.0, isKev: false, epss: null, null, spelling);
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
    }

    [Fact]
    public void Reachable_CannotPromoteAboveAct()
    {
        // Rule 2 already produced Act, so rule 3 never runs; but the ladder itself is also capped,
        // which this pins from the base-rule side.
        var verdict = Derive(7.0, isKev: false, epss: 0.05, null, "reachable");
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    // ── Rule 3: install-script promotion, and the discriminating suppression ─

    [Fact]
    public void HasInstallScript_PromotesInIsolation()
    {
        // Track base (5.0), install-script alone promotes to Attend.
        var verdict = Derive(5.0, isKev: false, epss: null, null, null, hasInstallScript: true);
        Assert.Equal(EffectivePriority.Attend, verdict.Bucket);
    }

    /// <summary>
    /// The discriminating case the issue requires: naive independent arithmetic (install-script's
    /// +1 and not-observed's -1 treated as two ordinary deltas that cancel to 0) would leave this at
    /// Track. The correct rule — not-observed contributes exactly 0, not -1, when an install script
    /// is present — instead nets a +1 promotion to Attend. A regression that reintroduces plain
    /// additive cancellation fails this test while a correct implementation passes it.
    /// </summary>
    [Fact]
    public void HasInstallScript_SuppressesTheNotObservedDemotion_RatherThanCancellingIt()
    {
        var verdict = Derive(5.0, isKev: false, epss: null, null, "not-observed", hasInstallScript: true);
        Assert.Equal(EffectivePriority.Attend, verdict.Bucket);
    }

    [Fact]
    public void HasInstallScript_DoesNotSuppressAReachableDemotion_BecauseThereIsNoDemotionToSuppress()
    {
        // Reachable already promotes; install-script promotes again, independently and additively.
        var verdict = Derive(5.0, isKev: false, epss: null, null, "reachable", hasInstallScript: true);
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    [Fact]
    public void NotObserved_WithoutInstallScript_StillDemotes()
    {
        var verdict = Derive(9.0, isKev: false, epss: null, null, "not-observed", hasInstallScript: false);
        Assert.Equal(EffectivePriority.Track, verdict.Bucket);
    }

    // ── Rule 4: exploitable floors at Attend ─────────────────────────────────

    [Theory]
    [InlineData(1.0, null, "attend")]
    [InlineData(null, null, "attend")]
    [InlineData(1.0, "not-observed", "attend")]
    [InlineData(5.0, "reachable", "attend")]
    [InlineData(9.0, "reachable", "act")]
    public void Exploitable_FloorsAtAttend(double? cvss, string? reachability, string expected)
    {
        var verdict = Derive(cvss, isKev: false, epss: null, "exploitable", reachability);
        Assert.Equal(expected, verdict.Bucket);
    }

    [Fact]
    public void Exploitable_NeverDemotesAnAlreadyHigherBucket()
    {
        var verdict = Derive(9.0, isKev: true, epss: null, "exploitable", null);
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    // ── Rule 4: SSVC poc floors at Attend ─────────────────────────────────────

    [Fact]
    public void SsvcPoc_FloorsAtAttend()
    {
        // Track base (2.0, dev-scope demoted further), poc still floors it back up to Attend.
        var verdict = Derive(2.0, isKev: false, epss: null, null, null, ssvcExploitation: "poc",
            dependencyScope: "dev");
        Assert.Equal(EffectivePriority.Attend, verdict.Bucket);
    }

    [Fact]
    public void SsvcPoc_NeverDemotesAnAlreadyHigherBucket()
    {
        var verdict = Derive(9.0, isKev: false, epss: null, null, "reachable", ssvcExploitation: "poc");
        Assert.Equal(EffectivePriority.Act, verdict.Bucket);
    }

    [Fact]
    public void SsvcPocAndExploitable_BothFloorToTheSameAttend()
    {
        var verdict = Derive(1.0, isKev: false, epss: null, "exploitable", null, ssvcExploitation: "poc");
        Assert.Equal(EffectivePriority.Attend, verdict.Bucket);
    }

    // ── Ranking ──────────────────────────────────────────────────────────────

    [Fact]
    public void RankOf_OrdersActAboveAttendAboveTrackAboveSuppressed()
    {
        Assert.True(EffectivePriority.RankOf(EffectivePriority.Act) > EffectivePriority.RankOf(EffectivePriority.Attend));
        Assert.True(EffectivePriority.RankOf(EffectivePriority.Attend) > EffectivePriority.RankOf(EffectivePriority.Track));
        Assert.True(EffectivePriority.RankOf(EffectivePriority.Track) > EffectivePriority.RankOf(EffectivePriority.Suppressed));
        Assert.Equal(0, EffectivePriority.RankOf("not-a-bucket"));
        Assert.Equal(0, EffectivePriority.RankOf(null));
    }

    // ── Upgrade safety: every new field absent reproduces the pre-#612 verdict ─

    /// <summary>
    /// The acceptance-criteria property this issue names explicitly: an operator with no
    /// VulnerabilityTracker connection configured (every enrichment field permanently null) and no
    /// dependency-graph/install-script data wired in sees byte-identical rankings after upgrading —
    /// not just "similar", but the exact verdict the pre-#612 five-argument <c>Derive</c> produced
    /// for the same five original inputs. Swept across the same cross-product the pre-existing
    /// sweep test below covers, so this is not just a handful of hand-picked points.
    /// </summary>
    [Fact]
    public void AbsentNewSignals_ReproduceThePre612Verdict_AcrossTheOriginalInputSweep()
    {
        double?[] scores = [null, 0.0, 3.9, 4.0, 6.9, 7.0, 9.8];
        double?[] epssValues = [null, 0.0, 0.09, 0.10, 0.99];
        string?[] states = [null, "in_triage", "exploitable", "resolved", "resolved_with_pedigree", "false_positive", "not_affected"];
        string?[] reachValues = [null, "reachable", "not-observed", "unknown", "imported-not-called"];

        int checkedCount = 0;
        foreach (double? cvss in scores)
        {
            foreach (bool isKev in new[] { false, true })
            {
                foreach (double? epss in epssValues)
                {
                    foreach (string? state in states)
                    {
                        foreach (string? reach in reachValues)
                        {
                            var verdict = Derive(cvss, isKev, epss, state, reach);
                            Assert.Equal(Oracle(cvss, isKev, epss, state, reach), verdict.Bucket);
                            Assert.Equal(cvss is null, verdict.Unscored);
                            checkedCount++;
                        }
                    }
                }
            }
        }

        Assert.Equal(scores.Length * 2 * epssValues.Length * states.Length * reachValues.Length, checkedCount);
    }

    // ── Sweep ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Every combination of the interesting inputs, checked against an oracle written from the rule
    /// text rather than from the implementation. This is what catches a reordering: the hand-picked
    /// facts above each exercise one rule, while the oracle re-states the composition order. With
    /// every new field left at its absent default here, this is exactly the pre-#612 oracle — the
    /// new-signal rules each get their own targeted tests above instead of being folded into this
    /// cross-product, which would otherwise grow combinatorially with every new dimension.
    /// </summary>
    [Fact]
    public void EveryCombination_MatchesTheRuleText()
    {
        double?[] scores = [null, 0.0, 3.9, 4.0, 6.9, 7.0, 9.8];
        double?[] epssValues = [null, 0.0, 0.09, 0.10, 0.99];
        string?[] states = [null, "in_triage", "exploitable", "resolved", "resolved_with_pedigree", "false_positive", "not_affected"];
        string?[] reachValues = [null, "reachable", "not-observed", "unknown", "imported-not-called"];

        int checkedCount = 0;
        foreach (double? cvss in scores)
        {
            foreach (bool isKev in new[] { false, true })
            {
                foreach (double? epss in epssValues)
                {
                    foreach (string? state in states)
                    {
                        foreach (string? reach in reachValues)
                        {
                            var verdict = Derive(cvss, isKev, epss, state, reach);
                            Assert.Equal(Oracle(cvss, isKev, epss, state, reach), verdict.Bucket);
                            Assert.Equal(cvss is null, verdict.Unscored);
                            checkedCount++;
                        }
                    }
                }
            }
        }

        // A loop that silently degenerated to zero iterations would assert nothing.
        Assert.Equal(scores.Length * 2 * epssValues.Length * states.Length * reachValues.Length, checkedCount);
    }

    /// <summary>
    /// Independent restatement of the rules, deliberately written as a plain sequence rather than
    /// by calling into the implementation. Every new field is at its absent default across this
    /// entire sweep, so this oracle is unchanged from before #612 — it exercises only rules 1, 2's
    /// KEV/EPSS-CVSS arms, 3's base bucket and reachability term, and 4's exploitable floor.
    /// </summary>
    private static string Oracle(double? cvss, bool isKev, double? epss, string? state, string? reach)
    {
        if (state is "not_affected" or "false_positive" or "resolved")
        {
            return "suppressed";
        }

        if (isKev)
        {
            return "act";
        }

        if (epss is >= 0.10 && cvss is >= 7.0)
        {
            return "act";
        }

        string bucket = cvss is >= 7.0 ? "attend" : "track";

        if (reach == "reachable")
        {
            bucket = bucket == "attend" ? "act" : "attend";
        }
        else if (reach == "not-observed")
        {
            bucket = bucket == "act" ? "attend" : bucket == "attend" ? "track" : "track";
        }

        if (state == "exploitable" && bucket == "track")
        {
            bucket = "attend";
        }

        return bucket;
    }
}
