using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// <c>warn</c> used to be a stored, validated, UI-selectable mode that no enforcement path read:
/// selecting it was byte-for-byte identical to <c>off</c>. These tests pin the behaviour that
/// makes it real — the artefact still serves, and the verdict now carries the arm that
/// <em>would</em> have refused it.
///
/// <para>
/// The property that matters most is the last one: warn and block must trigger on <b>exactly the
/// same facts</b> and differ only in what the mode says to do. A warn pass with its own copy of
/// each condition is a second copy of the policy, and it drifts silently — an arm gains a
/// condition on the blocking side, the warning side keeps the old one, and the preview an
/// operator relies on stops predicting the refusal they will get.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class WarnModeRecordsWouldHaveBlockedTests
{
    private static readonly DateTimeOffset Now = TestTime.KnownNow;

    private static VersionFacts Facts(
        string? manualState = null,
        string? deprecated = null,
        DateTimeOffset? revokedAt = null,
        bool hasMalicious = false,
        bool hasKev = false,
        bool hasKevRansomware = false,
        string? provenanceStatus = null,
        bool hasInstallScript = false,
        bool installScriptAllowlisted = false,
        bool scanned = true)
        => new(
            ManualState: manualState,
            Deprecated: deprecated,
            PublishedAt: Now.AddYears(-1),
            Scanned: scanned,
            Vulnerability: VulnFacts.None with
            {
                IsMalicious = hasMalicious,
                IsKev = hasKev,
                IsKevRansomware = hasKevRansomware ? true : null,
            },
            HasInstallScript: hasInstallScript,
            ProvenanceStatus: provenanceStatus,
            InstallScriptAllowlisted: installScriptAllowlisted,
            RevokedAt: revokedAt);

    private static BlockPolicy Policy(
        string? deprecated = "off",
        string? revoked = "off",
        string? malicious = "off",
        string? kev = "off",
        string? kevRansomware = "off",
        string? provenance = "off",
        string? installScripts = "off")
        => new(
            MinReleaseAgeHours: null,
            BlockDeprecatedMode: deprecated,
            BlockMaliciousMode: malicious,
            BlockKevMode: kev,
            MaxEpssTolerance: null,
            MaxOsvScoreTolerance: 10.0,
            BlockInstallScriptsMode: installScripts,
            VerifyProvenanceMode: provenance,
            BlockRevokedMode: revoked,
            BlockKevRansomwareMode: kevRansomware,
            MaxEpssPercentileTolerance: null);

    /// <summary>Every arm that offers the mode, with the fact that triggers it.</summary>
    public static TheoryData<string, BlockArm> WarnCapableArms() => new()
    {
        { "deprecated", BlockArm.Deprecated },
        { "revoked", BlockArm.Revoked },
        { "malicious", BlockArm.Malicious },
        { "kevRansomware", BlockArm.KevRansomware },
        { "kev", BlockArm.Kev },
        { "provenance", BlockArm.Provenance },
        { "installScripts", BlockArm.InstallScript },
    };

    private static VersionFacts FactsTriggering(string arm) => arm switch
    {
        "deprecated" => Facts(deprecated: "old"),
        "revoked" => Facts(revokedAt: Now.AddDays(-1)),
        "malicious" => Facts(hasMalicious: true),
        "kevRansomware" => Facts(hasKev: true, hasKevRansomware: true),
        "kev" => Facts(hasKev: true),
        "provenance" => Facts(provenanceStatus: ProvenanceStatuses.Unsigned),
        _ => Facts(hasInstallScript: true),
    };

    private static BlockPolicy PolicyWith(string arm, string mode) => arm switch
    {
        "deprecated" => Policy(deprecated: mode == "block" ? "block_all" : mode),
        "revoked" => Policy(revoked: mode),
        "malicious" => Policy(malicious: mode),
        "kevRansomware" => Policy(kevRansomware: mode),
        "kev" => Policy(kev: mode),
        "provenance" => Policy(provenance: mode),
        _ => Policy(installScripts: mode),
    };

    // ── warn serves, and says what would have refused ────────────────────────

    [Theory]
    [MemberData(nameof(WarnCapableArms))]
    public void Warn_Serves_AndNamesTheArmThatWouldHaveBlocked(string arm, BlockArm expected)
    {
        var verdict = BlockGateService.Evaluate(FactsTriggering(arm), PolicyWith(arm, "warn"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.Arm);
        Assert.Equal(expected, verdict.WarnArm);
    }

    [Theory]
    [MemberData(nameof(WarnCapableArms))]
    public void Off_Serves_AndWarnsAboutNothing(string arm, BlockArm expected)
    {
        // The adversarial twin: warn must differ from off. Before this change these two tests
        // were indistinguishable, which is exactly what the bug was.
        _ = expected;
        var verdict = BlockGateService.Evaluate(FactsTriggering(arm), PolicyWith(arm, "off"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.WarnArm);
    }

    [Theory]
    [MemberData(nameof(WarnCapableArms))]
    public void Block_Refuses_AndCarriesNoWarn(string arm, BlockArm expected)
    {
        // A refusal subsumes the warning: the artefact was not served, so there is nothing left
        // to preview. This also keeps `Arm != None` meaning exactly "blocked" for every consumer.
        var verdict = BlockGateService.Evaluate(FactsTriggering(arm), PolicyWith(arm, "block"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(expected, verdict.Arm);
        Assert.Equal(BlockArm.None, verdict.WarnArm);
    }

    // ── the shape of the warning ─────────────────────────────────────────────

    [Fact]
    public void ManualAllow_SilencesWarningsToo()
    {
        // The override means an operator has already judged this version acceptable. Continuing
        // to report what would have refused it would produce a permanent stream of records for a
        // decision that has been made.
        var verdict = BlockGateService.Evaluate(
            Facts(manualState: "allowed", hasKev: true), Policy(kev: "warn"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.WarnArm);
    }

    [Fact]
    public void AnUnscannedVersion_DoesNotWarnOnTheVulnArms()
    {
        // Unscanned is fail-open for the blocking pass, so it must be fail-quiet for the warning
        // pass: a warning implies a judgement, and none was made.
        var verdict = BlockGateService.Evaluate(
            Facts(hasKev: true, hasMalicious: true, scanned: false),
            Policy(kev: "warn", malicious: "warn"),
            Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.WarnArm);
    }

    [Fact]
    public void AnAllowlistedInstallScript_DoesNotWarn()
    {
        // The allowlist exempts a package from the arm entirely, so it must not warn either —
        // otherwise an operator who explicitly permitted a package gets told about it forever.
        var verdict = BlockGateService.Evaluate(
            Facts(hasInstallScript: true, installScriptAllowlisted: true),
            Policy(installScripts: "warn"),
            Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.WarnArm);
    }

    [Fact]
    public void TheHighestPriorityWarningWins_MatchingTheBlockingOrder()
    {
        // Two arms warning at once reports the one that would have refused first, so the preview
        // predicts the actual refusal rather than an arbitrary one of several.
        var verdict = BlockGateService.Evaluate(
            Facts(deprecated: "old", hasKev: true),
            Policy(deprecated: "warn", kev: "warn"),
            Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.Deprecated, verdict.WarnArm);
    }

    [Fact]
    public void AStrongerBlockBeatsAWeakerWarn()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(deprecated: "old", hasKev: true),
            Policy(deprecated: "warn", kev: "block"),
            Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Kev, verdict.Arm);
        Assert.Equal(BlockArm.None, verdict.WarnArm);
    }

    // ── the anti-drift property ──────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(WarnCapableArms))]
    public void WarnAndBlockTriggerOnExactlyTheSameFacts(string arm, BlockArm expected)
    {
        // The one that guards against warn becoming a second copy of the policy. For each arm:
        // the SAME facts must block under 'block' and warn under 'warn', and the SAME
        // non-triggering facts must do neither. If a condition is ever added to one side only,
        // one half of this fails.
        var triggering = FactsTriggering(arm);
        var inert = Facts();

        var blocked = BlockGateService.Evaluate(triggering, PolicyWith(arm, "block"), Now);
        var warned = BlockGateService.Evaluate(triggering, PolicyWith(arm, "warn"), Now);
        Assert.Equal(expected, blocked.Arm);
        Assert.Equal(expected, warned.WarnArm);

        var inertBlock = BlockGateService.Evaluate(inert, PolicyWith(arm, "block"), Now);
        var inertWarn = BlockGateService.Evaluate(inert, PolicyWith(arm, "warn"), Now);
        Assert.True(inertBlock.Servable);
        Assert.Equal(BlockArm.None, inertWarn.WarnArm);
    }
}
