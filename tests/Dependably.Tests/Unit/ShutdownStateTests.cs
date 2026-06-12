using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class ShutdownStateTests
{
    [Fact]
    [Trait("Category", "Unit")]
    public void InitialState_IsNotShuttingDown()
    {
        var state = new ShutdownState();
        Assert.False(state.IsShuttingDown);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void MarkShuttingDown_SetsIsShuttingDownToTrue()
    {
        var state = new ShutdownState();
        state.MarkShuttingDown();
        Assert.True(state.IsShuttingDown);
    }
}
