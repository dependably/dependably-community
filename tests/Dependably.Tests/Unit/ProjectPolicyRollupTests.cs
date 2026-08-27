using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The worst-wins fold a collection's verdict is derived by. Pure, so it is pinned here rather
/// than through a repository fixture — and it is worth pinning precisely because its one
/// asymmetry (a NULL descendant blocks <c>pass</c> but does not mask a violation) is the kind of
/// rule a later reader "simplifies" into a plain max.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProjectPolicyRollupTests
{
    [Fact]
    public void Empty_IsUnevaluated()
        => Assert.Null(ProjectPolicyRollup.Worst([]));

    [Fact]
    public void AllPass_IsPass()
        => Assert.Equal("pass", ProjectPolicyRollup.Worst(["pass", "pass"]));

    [Fact]
    public void AnyViolation_WinsOutright()
        => Assert.Equal("violation", ProjectPolicyRollup.Worst(["pass", "warn", "violation", null]));

    [Fact]
    public void AnyWarn_BeatsPass()
        => Assert.Equal("warn", ProjectPolicyRollup.Worst(["pass", "warn"]));

    [Fact]
    public void UnevaluatedDescendant_BlocksPass()
    {
        // The whole point: a folder must not report a clean bill of health for a subtree holding
        // a project nobody has scanned. "Not scanned" is an open question, not a pass.
        Assert.Null(ProjectPolicyRollup.Worst(["pass", null]));
        Assert.Null(ProjectPolicyRollup.Worst([null]));
    }

    [Fact]
    public void UnevaluatedDescendant_DoesNotMaskAWorseVerdict()
    {
        // The other half of the asymmetry. Downgrading a real violation to "unknown" because a
        // sibling is unscanned would hide the finding the rollup exists to surface.
        Assert.Equal("violation", ProjectPolicyRollup.Worst([null, "violation"]));
        Assert.Equal("warn", ProjectPolicyRollup.Worst([null, "warn"]));
    }

    [Fact]
    public void UnrecognisedStatus_IsTreatedAsUnevaluated()
    {
        // Fail-closed on a value the column's vocabulary does not carry: it is not evidence of a
        // pass, so it must not license one.
        Assert.Null(ProjectPolicyRollup.Worst(["pass", "something-new"]));
    }
}
