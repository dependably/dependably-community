using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The two arms added for the sharper exploitation signals dependably already downloads:
/// <c>block_kev_ransomware</c> (CISA's known-ransomware-campaign-use verdict) and
/// <c>max_epss_percentile_tolerance</c> (the EPSS rank ceiling).
///
/// <para>
/// Both are deliberately <b>independent settings</b> rather than modes on their broader siblings,
/// and the tests below are mostly about that independence: the useful policies are combinations
/// (<c>block_kev='warn'</c> with ransomware at <c>'block'</c>; a probability ceiling and a
/// percentile ceiling set together), and a mode enum could express neither.
/// </para>
///
/// <para>
/// The ransomware arm also carries the one deliberate departure from fail-closed-on-unknown in
/// the gate, so its unknown-handling is pinned in both directions here.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class RansomwareAndPercentileArmTests
{
    private static readonly DateTimeOffset Now = TestTime.KnownNow;

    private static VersionFacts Facts(
        bool hasKev = false,
        bool hasKevRansomware = false,
        double? maxEpss = null,
        double? maxEpssPercentile = null)
        => new(
            ManualState: null,
            Deprecated: null,
            PublishedAt: Now.AddYears(-1),
            Scanned: true,
            Vulnerability: VulnFacts.None with
            {
                IsKev = hasKev,
                IsKevRansomware = hasKevRansomware ? true : null,
                Epss = maxEpss,
                EpssPercentile = maxEpssPercentile,
            });

    private static BlockPolicy Policy(
        string? kev = "off",
        string? kevRansomware = "off",
        double? epss = null,
        double? epssPercentile = null)
        => new(
            MinReleaseAgeHours: null,
            BlockDeprecatedMode: "off",
            BlockMaliciousMode: "off",
            BlockKevMode: kev,
            MaxEpssTolerance: epss,
            MaxOsvScoreTolerance: 10.0,
            BlockKevRansomwareMode: kevRansomware,
            MaxEpssPercentileTolerance: epssPercentile);

    // ── The ransomware arm ────────────────────────────────────────────────────

    [Fact]
    public void RansomwareVerdict_Blocks_WhenTheNarrowArmIsOn()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(hasKev: true, hasKevRansomware: true), Policy(kevRansomware: "block"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.KevRansomware, verdict.Arm);
    }

    [Fact]
    public void KevWithoutARansomwareVerdict_DoesNotTripTheNarrowArm()
    {
        // The adversarial twin, and the whole reason the arm exists: it must be narrower than
        // block_kev, not a second spelling of it.
        var verdict = BlockGateService.Evaluate(
            Facts(hasKev: true, hasKevRansomware: false), Policy(kevRansomware: "block"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.Arm);
    }

    [Fact]
    public void WarnOnAllKev_BlockOnRansomware_IsExpressible()
    {
        // The policy a mode enum on block_kev could not express, and the reason these are two
        // independent settings. Both facts are present; the ransomware arm must win the verdict.
        var policy = Policy(kev: "warn", kevRansomware: "block");

        var ransomware = BlockGateService.Evaluate(
            Facts(hasKev: true, hasKevRansomware: true), policy, Now);
        Assert.False(ransomware.Servable);
        Assert.Equal(BlockArm.KevRansomware, ransomware.Arm);

        // ...while a plain KEV advisory still serves, because the broad arm is only warning.
        var plain = BlockGateService.Evaluate(Facts(hasKev: true), policy, Now);
        Assert.True(plain.Servable);
    }

    [Fact]
    public void BroadArmBlocking_StillBlocks_WhenTheNarrowArmIsOff()
    {
        // Independence in the other direction: adding the narrow arm must not have weakened the
        // broad one.
        var verdict = BlockGateService.Evaluate(
            Facts(hasKev: true), Policy(kev: "block", kevRansomware: "off"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Kev, verdict.Arm);
    }

    [Fact]
    public void RansomwareArmOff_NeverBlocks_EvenOnAKnownVerdict()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(hasKev: true, hasKevRansomware: true), Policy(kevRansomware: "off"), Now);

        Assert.True(verdict.Servable);
    }

    [Fact]
    public void RansomwareArmWarn_DoesNotBlock()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(hasKev: true, hasKevRansomware: true), Policy(kevRansomware: "warn"), Now);

        Assert.True(verdict.Servable);
    }

    // ── The percentile arm ────────────────────────────────────────────────────

    [Fact]
    public void PercentileAboveTheCeiling_Blocks()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(maxEpssPercentile: 0.98), Policy(epssPercentile: 0.95), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.EpssPercentile, verdict.Arm);
    }

    [Fact]
    public void PercentileEqualToTheCeiling_Passes()
    {
        // Pass-on-equal, matching every other ceiling arm in the gate.
        var verdict = BlockGateService.Evaluate(
            Facts(maxEpssPercentile: 0.95), Policy(epssPercentile: 0.95), Now);

        Assert.True(verdict.Servable);
    }

    [Fact]
    public void TheTwoEpssCeilings_AreIndependent_EitherTripping_IsEnough()
    {
        // A version well under the probability ceiling but high in rank must still block, and
        // vice versa. If one were a reinterpretation of the other, one of these would pass.
        var highRankLowProbability = BlockGateService.Evaluate(
            Facts(maxEpss: 0.01, maxEpssPercentile: 0.99),
            Policy(epss: 0.5, epssPercentile: 0.95),
            Now);
        Assert.False(highRankLowProbability.Servable);
        Assert.Equal(BlockArm.EpssPercentile, highRankLowProbability.Arm);

        var highProbabilityLowRank = BlockGateService.Evaluate(
            Facts(maxEpss: 0.9, maxEpssPercentile: 0.10),
            Policy(epss: 0.5, epssPercentile: 0.95),
            Now);
        Assert.False(highProbabilityLowRank.Servable);
        Assert.Equal(BlockArm.Epss, highProbabilityLowRank.Arm);
    }

    [Fact]
    public void PercentileCeilingUnset_NeverBlocks()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(maxEpssPercentile: 0.999), Policy(epssPercentile: null), Now);

        Assert.True(verdict.Servable);
    }

    [Fact]
    public void PercentileAbsentFromTheAdvisories_NeverBlocks()
    {
        // A feed row that carried no percentile leaves the fact null. The arm has nothing to
        // compare, so it passes rather than treating "no rank" as the worst rank.
        var verdict = BlockGateService.Evaluate(
            Facts(maxEpss: 0.99, maxEpssPercentile: null), Policy(epssPercentile: 0.5), Now);

        Assert.True(verdict.Servable);
    }

    // ── The early-exit guard ──────────────────────────────────────────────────

    [Fact]
    public void ARansomwareOnlySignal_IsNotSwallowedByTheNoSignalShortCircuit()
    {
        // The gate short-circuits when no exploitation or score signal is present. Every fact the
        // arms read has to appear in that guard, or the arm is unreachable rather than merely
        // unused — and it still reads correctly at its own call site, so nothing else catches it.
        var verdict = BlockGateService.Evaluate(
            Facts(hasKev: false, hasKevRansomware: true), Policy(kevRansomware: "block"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.KevRansomware, verdict.Arm);
    }

    [Fact]
    public void APercentileOnlySignal_IsNotSwallowedByTheNoSignalShortCircuit()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(maxEpss: null, maxEpssPercentile: 0.99), Policy(epssPercentile: 0.5), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.EpssPercentile, verdict.Arm);
    }

    [Fact]
    public void NoSignalsAtAll_StillShortCircuitsToServable()
    {
        // The twin for the two above: the guard must still do its job for a version with nothing
        // recorded, or the additions would have turned it into dead code.
        var verdict = BlockGateService.Evaluate(
            Facts(), Policy(kev: "block", kevRansomware: "block", epss: 0.0, epssPercentile: 0.0), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.Arm);
    }
}
