using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class ClaimStateMachineTests
{
    [Theory]
    [InlineData("local_only", true)]
    [InlineData("mixed", false)]
    public void ValidateCreate_ValidStates_AllowsAndReportsPurge(string state, bool expectPurge)
    {
        var r = ClaimStateMachine.ValidateCreate(state);
        Assert.True(r.Allowed);
        Assert.Equal(expectPurge, r.PurgesProxy);
    }

    [Theory]
    [InlineData("unclaimed")]
    [InlineData("garbage")]
    public void ValidateCreate_InvalidStates_Rejects(string state)
    {
        var r = ClaimStateMachine.ValidateCreate(state);
        Assert.False(r.Allowed);
        Assert.NotNull(r.RejectionReason);
    }

    [Fact]
    public void ValidateChange_LocalOnlyToMixed_AllowsNoPurge()
    {
        var r = ClaimStateMachine.ValidateChange(ClaimStateMachine.LocalOnly, ClaimStateMachine.Mixed);
        Assert.True(r.Allowed);
        Assert.False(r.PurgesProxy);
    }

    [Fact]
    public void ValidateChange_MixedToLocalOnly_PurgesProxy()
    {
        var r = ClaimStateMachine.ValidateChange(ClaimStateMachine.Mixed, ClaimStateMachine.LocalOnly);
        Assert.True(r.Allowed);
        Assert.True(r.PurgesProxy);
    }

    [Fact]
    public void ValidateChange_SameState_Rejects()
    {
        var r = ClaimStateMachine.ValidateChange(ClaimStateMachine.LocalOnly, ClaimStateMachine.LocalOnly);
        Assert.False(r.Allowed);
    }

    [Fact]
    public void ValidateChange_UnclaimedToMixed_Rejects_UseCreateInstead()
    {
        // Going from unclaimed is creation, not a state change — caller should call ValidateCreate.
        var r = ClaimStateMachine.ValidateChange(ClaimStateMachine.Unclaimed, ClaimStateMachine.Mixed);
        Assert.False(r.Allowed);
    }

    [Fact]
    public void ValidateRelease_ZeroLocalVersions_Allows()
    {
        var r = ClaimStateMachine.ValidateRelease(ClaimStateMachine.LocalOnly, localVersionCount: 0);
        Assert.True(r.Allowed);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(42)]
    public void ValidateRelease_WithLocalVersions_Rejects(int n)
    {
        var r = ClaimStateMachine.ValidateRelease(ClaimStateMachine.Mixed, localVersionCount: n);
        Assert.False(r.Allowed);
        Assert.Contains(n.ToString(), r.RejectionReason);
    }
}
