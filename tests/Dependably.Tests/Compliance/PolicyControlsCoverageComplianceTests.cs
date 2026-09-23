using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Xunit;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every <see cref="BlockArm"/> that can produce a reason token a caller sees on the 403
/// <c>X-Dependably-Block-Reason</c> header must also appear as a key in
/// <c>GET /api/v1/policies</c>'s <c>controls</c> object — otherwise a member (or an MCP client
/// reading the policy summary) can be refused by a gate the policy page never mentions.
/// <see cref="BlockArm.Manual"/> is the one exemption from the controls-key check: it is an
/// ad-hoc per-version override, not a tenant-configurable gate, so it has no policy row to
/// summarize.
///
/// Mirrors <see cref="BlockArmSideEffectComplianceTests"/>'s shape (enumerate
/// <see cref="BlockArm"/>, assert an exemption list plus everything else covered) but checks
/// runtime output — <see cref="PolicySummaryBuilder.Build"/>'s actual <c>Controls</c> keys —
/// rather than scanning source, since <c>controls</c> is a dictionary built at request time, not
/// a switch a text scan could enumerate.
///
/// This runs as two separate assertions rather than one filtered pass so each failure mode is
/// diagnosable on its own: the first proves <see cref="BlockOutcome.ReasonToken"/> itself has no
/// silent hole (an arm added to <see cref="BlockArm"/> without a case in that switch reads as
/// <c>null</c> and would have been quietly filtered out of the second check, passing green while
/// covering nothing); the second is the actual controls-key coverage the class doc comment
/// describes.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class PolicyControlsCoverageComplianceTests
{
    // BlockArm.None is not a refusal — it is the "nothing fired" sentinel — so it is the only arm
    // ReasonToken is allowed to answer null for.
    private static readonly HashSet<BlockArm> NoReasonTokenExpected = new() { BlockArm.None };

    private static readonly HashSet<BlockArm> ExemptFromControlsKey = new() { BlockArm.Manual };

    [Fact]
    public void EveryArmExceptNone_HasANonNullReasonToken()
    {
        var arms = Enum.GetValues<BlockArm>();
        // A reflection/enum regression that emptied this list would make the gate green-but-blind.
        Assert.True(arms.Length >= 10, $"only {arms.Length} BlockArm members found");

        var missingToken = arms
            .Where(arm => !NoReasonTokenExpected.Contains(arm))
            .Where(arm => new BlockOutcome(BlockDecision.Blocked, arm).ReasonToken is null)
            .ToList();

        Assert.True(
            missingToken.Count == 0,
            "These BlockArm members produce no ReasonToken at all, so BlockOutcome silently drops "
            + "them from the 403 header AND from the controls-key check below: "
            + string.Join(", ", missingToken));
    }

    [Fact]
    public void EveryReasonTokenExceptManual_AppearsAsAControlsKey()
    {
        var anchors = new ProvenanceAnchorStatus(
            Npm: true, NuGet: true, PyPi: true, Rpm: true, Maven: true, Terraform: true);
        var summary = PolicySummaryBuilder.Build(
            settings: null, vulnTrackerActive: true, threatFeedActive: true, anchors);

        var expectedTokens = Enum.GetValues<BlockArm>()
            .Where(arm => arm != BlockArm.None && !ExemptFromControlsKey.Contains(arm))
            .Select(arm => new BlockOutcome(BlockDecision.Blocked, arm).ReasonToken)
            .Where(token => token is not null)
            .Cast<string>()
            .ToList();

        // A reflection or enum regression that emptied this list would make the gate
        // green-but-blind. Pin a floor well below the real arm count.
        Assert.True(expectedTokens.Count >= 10, $"only {expectedTokens.Count} reason tokens found");

        var missing = expectedTokens.Where(token => !summary.Controls.ContainsKey(token)).ToList();

        Assert.True(
            missing.Count == 0,
            "These block-gate reason tokens have no corresponding key in PolicySummaryBuilder's "
            + "controls output, so a member reading GET /api/v1/policies has no way to see the "
            + "gate that refused them: " + string.Join(", ", missing));
    }

    [Fact]
    public void Manual_IsExemptedButStillAWireReasonToken()
    {
        // Proves the exemption is deliberate rather than a token that simply doesn't exist:
        // BlockArm.Manual still produces a "manual" ReasonToken (BlockGateService writes
        // "blocked_manual" on the per-version override path), it just has no tenant policy row.
        Assert.Equal(
            "manual", new BlockOutcome(BlockDecision.Blocked, BlockArm.Manual).ReasonToken);
    }
}
