using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Arm 4a: the still-live-malicious gate (<c>block_malicious_live</c>) — a narrower,
/// higher-confidence sub-arm of the broad malicious arm (<c>block_malicious</c>), evaluated
/// immediately before it. Mirrors <see cref="RansomwareAndPercentileArmTests"/>'s KEV/ransomware
/// coverage: the tests are mostly about the two settings being genuinely independent, since the
/// useful policy is a combination (<c>block_malicious='warn'</c> with this at <c>'block'</c>) a
/// single mode enum could not express.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MaliciousLiveArmTests
{
    private static readonly DateTimeOffset Now = TestTime.KnownNow;

    private static VersionFacts Facts(bool isMalicious = false, bool malStillLive = false)
        => new(
            ManualState: null,
            Deprecated: null,
            PublishedAt: Now.AddYears(-1),
            Scanned: true,
            Vulnerability: VulnFacts.None with
            {
                IsMalicious = isMalicious,
                MalStillLive = malStillLive,
            });

    private static BlockPolicy Policy(string? malicious = "off", string? maliciousLive = "off")
        => new(
            MinReleaseAgeHours: null,
            BlockDeprecatedMode: "off",
            BlockMaliciousMode: malicious,
            BlockKevMode: "off",
            MaxEpssTolerance: null,
            MaxOsvScoreTolerance: 10.0,
            BlockMaliciousLiveMode: maliciousLive);

    // ── Fires independently of BlockMaliciousMode ────────────────────────────

    [Fact]
    public void StillLiveVerdict_Blocks_WhenTheNarrowArmIsOn()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(isMalicious: true, malStillLive: true), Policy(maliciousLive: "block"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.MaliciousLive, verdict.Arm);
    }

    [Fact]
    public void MaliciousWithoutAStillLiveVerdict_DoesNotTripTheNarrowArm()
    {
        // The adversarial twin: the narrow arm must be narrower than block_malicious, not a
        // second spelling of it.
        var verdict = BlockGateService.Evaluate(
            Facts(isMalicious: true, malStillLive: false), Policy(maliciousLive: "block"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.Arm);
    }

    [Fact]
    public void BroadArmWarn_NarrowArmBlock_IsExpressible()
    {
        // The policy a single mode enum on block_malicious could not express. Both facts are
        // present; the narrow arm must win the verdict.
        var policy = Policy(malicious: "warn", maliciousLive: "block");

        var stillLive = BlockGateService.Evaluate(
            Facts(isMalicious: true, malStillLive: true), policy, Now);
        Assert.False(stillLive.Servable);
        Assert.Equal(BlockArm.MaliciousLive, stillLive.Arm);

        // ...while a plain malicious advisory (not still-live) still serves, because the broad
        // arm is only warning.
        var plain = BlockGateService.Evaluate(Facts(isMalicious: true), policy, Now);
        Assert.True(plain.Servable);
    }

    [Fact]
    public void BroadArmOff_NarrowArmBlock_StillBlocksOnStillLive()
    {
        // The other combination: a tenant could have the broad arm off and the narrow one on.
        var verdict = BlockGateService.Evaluate(
            Facts(isMalicious: true, malStillLive: true),
            Policy(malicious: "off", maliciousLive: "block"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.MaliciousLive, verdict.Arm);
    }

    [Fact]
    public void BroadArmBlocking_StillBlocks_WhenTheNarrowArmIsOff()
    {
        // Independence in the other direction: adding the narrow arm must not have weakened the
        // broad one.
        var verdict = BlockGateService.Evaluate(
            Facts(isMalicious: true), Policy(malicious: "block", maliciousLive: "off"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Malicious, verdict.Arm);
    }

    [Fact]
    public void NarrowArmOff_NeverBlocks_EvenWhenStillLive()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(isMalicious: true, malStillLive: true), Policy(maliciousLive: "off"), Now);

        Assert.True(verdict.Servable);
    }

    [Fact]
    public void NarrowArmWarn_DoesNotBlock_ButRecordsTheWarnArm()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(isMalicious: true, malStillLive: true), Policy(maliciousLive: "warn"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.MaliciousLive, verdict.WarnArm);
    }

    [Fact]
    public void UnscannedVersion_NeverTripsTheNarrowArm()
    {
        // Fail-open: an unscanned version has made no judgement, so it must not warn either.
        var facts = Facts(isMalicious: true, malStillLive: true) with { Scanned = false };
        var verdict = BlockGateService.Evaluate(facts, Policy(maliciousLive: "block"), Now);

        Assert.True(verdict.Servable);
    }

    // ── The early-exit guard ──────────────────────────────────────────────────

    [Fact]
    public void AStillLiveOnlySignal_IsNotSwallowedByTheNoSignalShortCircuit()
    {
        // Defensive coverage for the shared early-return guard in EvaluateVulnArms: even though
        // arm 4a's own check runs before that guard (same as the broad malicious arm), the guard
        // still names MalStillLive so a future reordering cannot silently reintroduce the
        // unreachable-arm hazard the guard's own comment warns about.
        var verdict = BlockGateService.Evaluate(
            Facts(isMalicious: false, malStillLive: true), Policy(maliciousLive: "block"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.MaliciousLive, verdict.Arm);
    }

    [Fact]
    public void NoSignalsAtAll_StillShortCircuitsToServable()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(), Policy(malicious: "block", maliciousLive: "block"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.Arm);
    }
}
