using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers the two bounds <see cref="ClockPump"/> keeps separate: the virtual-time envelope
/// (<c>maxAdvances</c>) and the real-time deadline. Conflating them is what makes a pump flaky —
/// the advance budget burns in under a second of wall time whether or not the background consumer
/// was ever scheduled, so a loaded runner fails a test whose subject is perfectly healthy.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ClockPumpTests
{
    /// <summary>
    /// The regression case. A consumer that needs far more polls than the advance budget allows
    /// still settles, because exhausting the virtual-time envelope stops the clock advancing —
    /// it does not end the wait. An iteration-bounded pump throws here instead.
    /// </summary>
    [Fact]
    public async Task UntilAsync_ConsumerSettlesAfterAdvanceBudgetExhausted_StillSucceeds()
    {
        var clock = TestTime.Frozen();
        int polls = 0;

        await ClockPump.UntilAsync(
            clock, () => ++polls >= 50, TimeSpan.FromSeconds(1),
            maxAdvances: 2, timeout: TimeSpan.FromSeconds(10));

        Assert.True(polls >= 50);
    }

    /// <summary>
    /// The virtual-time envelope is a real bound, not advisory: once <c>maxAdvances</c> steps have
    /// been applied the clock stops moving, so a runaway retry chain cannot spin fake time forever
    /// while the pump waits out its real-time deadline.
    /// </summary>
    [Fact]
    public async Task UntilAsync_StopsAdvancingTheClockOnceTheBudgetIsSpent()
    {
        var clock = TestTime.Frozen();
        int polls = 0;

        await ClockPump.UntilAsync(
            clock, () => ++polls >= 40, TimeSpan.FromSeconds(1),
            maxAdvances: 3, timeout: TimeSpan.FromSeconds(10));

        Assert.Equal(TestTime.KnownNow.AddSeconds(3), clock.GetUtcNow());
    }

    /// <summary>A condition that never holds still fails, bounded by the real-time deadline.</summary>
    [Fact]
    public async Task UntilAsync_ConditionNeverHolds_ThrowsWithinTheTimeout()
    {
        var clock = TestTime.Frozen();

        await Assert.ThrowsAsync<TimeoutException>(() => ClockPump.UntilAsync(
            clock, () => false, TimeSpan.FromSeconds(1),
            maxAdvances: 5, timeout: TimeSpan.FromMilliseconds(250)));
    }

    /// <summary>An already-satisfied condition neither advances the clock nor yields.</summary>
    [Fact]
    public async Task UntilAsync_ConditionAlreadyTrue_LeavesTheClockUntouched()
    {
        var clock = TestTime.Frozen();

        await ClockPump.UntilAsync(clock, () => true, TimeSpan.FromSeconds(1));

        Assert.Equal(TestTime.KnownNow, clock.GetUtcNow());
    }
}
