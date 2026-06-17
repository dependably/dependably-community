using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Verifies that the pure policy core (<see cref="BlockGateService.Evaluate"/>) and the
/// stored-state predicate (<see cref="BlockGateService.IsHardBlockedByStoredState"/>) agree
/// on every arm, so the two entry points can never silently diverge again.
///
/// All tests are pure (no DB, no I/O). <see cref="BlockGateService.Evaluate"/> is exercised
/// directly; <see cref="BlockGateService.IsHardBlockedByStoredState"/> is exercised by
/// projecting the same scenario into a <see cref="PackageVersion"/> + <see cref="OrgSettings"/>
/// pair and asserting the outcomes match.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlockGatePolicyParityTests
{
    private readonly DateTimeOffset _now = TestTime.KnownNow;

    // ── blocking arms — Evaluate returns Blocked + expected arm ──────────────

    [Fact]
    public void ManualBlock_Returns_BlockedManual()
    {
        var facts = BaseFacts() with { ManualState = "blocked" };
        var verdict = BlockGateService.Evaluate(facts, BasePolicy(), _now);
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Manual, verdict.Arm);
        Assert.True(IsHardBlocked(facts, BasePolicy()));
    }

    [Fact]
    public void DeprecatedBlockAll_Returns_BlockedDeprecated()
    {
        var facts = BaseFacts() with { Deprecated = "use something newer" };
        var policy = BasePolicy() with { BlockDeprecatedMode = "block_all" };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Deprecated, verdict.Arm);
        Assert.True(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void DeprecatedLegacyBlock_MapsToBlockAll()
    {
        // Legacy 'block' value is treated identically to 'block_all' on the serve path.
        var facts = BaseFacts() with { Deprecated = "old and deprecated" };
        var policy = BasePolicy() with { BlockDeprecatedMode = "block" };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Deprecated, verdict.Arm);
        Assert.True(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void ReleaseAge_TooYoung_Returns_BlockedReleaseAge()
    {
        // Published 6 hours ago against a 24-hour hold — too young.
        var facts = BaseFacts() with { PublishedAt = _now.AddHours(-6) };
        var policy = BasePolicy() with { MinReleaseAgeHours = 24 };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.ReleaseAge, verdict.Arm);
        Assert.True(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void Malicious_BlockMode_Returns_BlockedMalicious()
    {
        var facts = BaseFacts() with { Scanned = true, HasMalicious = true };
        var policy = BasePolicy() with { BlockMaliciousMode = "block" };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Malicious, verdict.Arm);
        Assert.True(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void Kev_BlockMode_Returns_BlockedKev()
    {
        var facts = BaseFacts() with { Scanned = true, HasKev = true };
        var policy = BasePolicy() with { BlockKevMode = "block" };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Kev, verdict.Arm);
        Assert.True(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void Epss_OverTolerance_Returns_BlockedEpss()
    {
        var facts = BaseFacts() with { Scanned = true, MaxEpss = 0.92 };
        var policy = BasePolicy() with { MaxEpssTolerance = 0.5 };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Epss, verdict.Arm);
        Assert.True(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void Cvss_OverTolerance_Returns_BlockedVulnScore()
    {
        var facts = BaseFacts() with { Scanned = true, MaxCvss = 9.8 };
        var policy = BasePolicy() with { MaxOsvScoreTolerance = 5.0 };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.VulnScore, verdict.Arm);
        Assert.True(IsHardBlocked(facts, policy));
    }

    // ── negative / parity cases — Evaluate returns Servable ──────────────────

    [Fact]
    public void ManualAllow_Overrides_Everything_IsServable()
    {
        // Even with deprecated + malicious + KEV + high CVSS, manual allow wins.
        var facts = new VersionFacts(
            ManualState: "allowed",
            Deprecated: "deprecated",
            PublishedAt: _now.AddHours(-1),
            Scanned: true,
            HasMalicious: true,
            HasKev: true,
            MaxEpss: 0.99,
            MaxCvss: 10.0);
        var policy = new BlockPolicy(
            MinReleaseAgeHours: 720,
            BlockDeprecatedMode: "block_all",
            BlockMaliciousMode: "block",
            BlockKevMode: "block",
            MaxEpssTolerance: 0.1,
            MaxOsvScoreTolerance: 0.0);
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.Arm);
        Assert.False(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void DeprecatedBlockNew_IsNotAServePathBlock()
    {
        // block_new only fires on the first-fetch path; cached versions keep serving.
        var facts = BaseFacts() with { Deprecated = "old" };
        var policy = BasePolicy() with { BlockDeprecatedMode = "block_new" };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.Arm);
        Assert.False(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void DeprecatedWarn_IsNotAServePathBlock()
    {
        var facts = BaseFacts() with { Deprecated = "old" };
        var policy = BasePolicy() with { BlockDeprecatedMode = "warn" };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.True(verdict.Servable);
        Assert.False(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void Unscanned_WithMaliciousSignals_IsServable()
    {
        // VulnCheckedAt null → fail-open; signals present but Scanned=false.
        var facts = BaseFacts() with { Scanned = false, HasMalicious = true, HasKev = true, MaxEpss = 0.99, MaxCvss = 10.0 };
        var policy = BasePolicy() with
        {
            BlockMaliciousMode = "block",
            BlockKevMode = "block",
            MaxEpssTolerance = 0.1,
            MaxOsvScoreTolerance = 0.0,
        };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.Arm);
        Assert.False(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void ReleaseAge_NullPublishedAt_FailsOpen()
    {
        // Upstream metadata didn't carry a timestamp — fail-open, not fail-closed.
        var facts = BaseFacts() with { PublishedAt = null };
        var policy = BasePolicy() with { MinReleaseAgeHours = 720 };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.True(verdict.Servable);
        Assert.False(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void ReleaseAge_ExactlyAtHold_IsServable()
    {
        // ageHours >= minHours means pass (boundary inclusive on allowed side).
        var facts = BaseFacts() with { PublishedAt = _now.AddHours(-24) };
        var policy = BasePolicy() with { MinReleaseAgeHours = 24 };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.True(verdict.Servable);
        Assert.False(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void Cvss_ExactlyAtTolerance_IsServable()
    {
        // Pass-on-equal convention: maxCvss == tolerance is allowed.
        var facts = BaseFacts() with { Scanned = true, MaxCvss = 5.0 };
        var policy = BasePolicy() with { MaxOsvScoreTolerance = 5.0 };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.True(verdict.Servable);
        Assert.False(IsHardBlocked(facts, policy));
    }

    [Fact]
    public void Epss_ExactlyAtTolerance_IsServable()
    {
        // Pass-on-equal for EPSS matches the CVSS convention.
        var facts = BaseFacts() with { Scanned = true, MaxEpss = 0.5 };
        var policy = BasePolicy() with { MaxEpssTolerance = 0.5 };
        var verdict = BlockGateService.Evaluate(facts, policy, _now);
        Assert.True(verdict.Servable);
        Assert.False(IsHardBlocked(facts, policy));
    }

    // ── cross-check matrix: Evaluate and IsHardBlockedByStoredState agree ────

    [Theory]
    [InlineData("blocked", null, null, false, false, false, null, null, "block_all", "block", "block", 0.5, 5.0)]
    [InlineData("allowed", "dep", null, true, true, true, 0.9, 9.0, "block_all", "block", "block", 0.5, 5.0)]
    [InlineData(null, "dep", null, false, false, false, null, null, "block_all", "off", "off", null, 10.0)]
    [InlineData(null, null, null, false, false, false, null, null, null, null, null, null, 10.0)]
    [InlineData(null, null, null, true, true, false, null, null, null, "block", null, null, 10.0)]
    [InlineData(null, null, null, true, false, true, null, null, null, null, "block", null, 10.0)]
    [InlineData(null, null, null, true, false, false, 0.9, null, null, null, null, 0.5, 10.0)]
    [InlineData(null, null, null, true, false, false, null, 9.0, null, null, null, null, 5.0)]
    public void CrossCheck_EvaluateAndIsHardBlocked_AlwaysAgree(
        string? manualState, string? deprecated, double? publishedOffsetHours,
        bool scanned, bool hasMalicious, bool hasKev,
        double? maxEpss, double? maxCvss,
        string? blockDeprecatedMode, string? blockMaliciousMode, string? blockKevMode,
        double? maxEpssTolerance, double maxOsvScoreTolerance)
    {
        DateTimeOffset? publishedAt = publishedOffsetHours.HasValue
            ? _now.AddHours(-publishedOffsetHours.Value)
            : null;

        var facts = new VersionFacts(
            ManualState: manualState,
            Deprecated: deprecated,
            PublishedAt: publishedAt,
            Scanned: scanned,
            HasMalicious: hasMalicious,
            HasKev: hasKev,
            MaxEpss: maxEpss,
            MaxCvss: maxCvss);

        var policy = new BlockPolicy(
            MinReleaseAgeHours: 24,
            BlockDeprecatedMode: blockDeprecatedMode,
            BlockMaliciousMode: blockMaliciousMode,
            BlockKevMode: blockKevMode,
            MaxEpssTolerance: maxEpssTolerance,
            MaxOsvScoreTolerance: maxOsvScoreTolerance);

        bool evaluateBlocks = !BlockGateService.Evaluate(facts, policy, _now).Servable;
        bool hardBlocks = IsHardBlocked(facts, policy);

        Assert.Equal(evaluateBlocks, hardBlocks);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    // Baseline facts: unscanned, no deprecation, no signals — servable by default.
    private static VersionFacts BaseFacts() => new(
        ManualState: null,
        Deprecated: null,
        PublishedAt: null,
        Scanned: false,
        HasMalicious: false,
        HasKev: false,
        MaxEpss: null,
        MaxCvss: null);

    // Baseline policy: all gates off / tolerant.
    private static BlockPolicy BasePolicy() => new(
        MinReleaseAgeHours: null,
        BlockDeprecatedMode: null,
        BlockMaliciousMode: null,
        BlockKevMode: null,
        MaxEpssTolerance: null,
        MaxOsvScoreTolerance: 10.0);

    // Project VersionFacts + BlockPolicy back into the IsHardBlockedByStoredState shape
    // (PackageVersion + OrgSettings + VulnGateSignals) and call the predicate directly
    // so the cross-check actually exercises the projection layer in IsHardBlockedByStoredState.
    private bool IsHardBlocked(VersionFacts facts, BlockPolicy policy)
    {
        var version = new PackageVersion
        {
            Id = "test-version-id",
            ManualBlockState = facts.ManualState,
            Deprecated = facts.Deprecated,
            PublishedAt = facts.PublishedAt,
            // VulnCheckedAt non-null iff Scanned; value is arbitrary.
            VulnCheckedAt = facts.Scanned ? _now : null,
            // Index path uses IsMalicious row flag.
            IsMalicious = facts.HasMalicious,
        };

        var settings = new OrgSettings
        {
            MinReleaseAgeHours = policy.MinReleaseAgeHours,
            BlockDeprecated = policy.BlockDeprecatedMode ?? "off",
            BlockMalicious = policy.BlockMaliciousMode ?? "off",
            BlockKev = policy.BlockKevMode ?? "off",
            MaxEpssTolerance = policy.MaxEpssTolerance,
            MaxOsvScoreTolerance = policy.MaxOsvScoreTolerance,
        };

        // When no signals (no KEV, no EPSS, no CVSS), pass null to match current callers.
        var signals = (facts.HasKev || facts.MaxEpss.HasValue || facts.MaxCvss.HasValue)
            ? new VulnGateSignals(facts.MaxCvss, HasMalicious: false, facts.HasKev, facts.MaxEpss)
            : null;

        return BlockGateService.IsHardBlockedByStoredState(version, settings, signals, _now);
    }
}
