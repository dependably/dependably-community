using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Semantics of the passive edge master-reachability tracker: the coarse state transitions
/// (unknown → ok/degraded and back, driven by the MOST RECENT outcome), the FakeTimeProvider
/// timestamps recorded on each outcome, and that concurrent updates never corrupt state.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EdgeStatusTrackerTests
{
    [Fact]
    public void FreshTracker_IsUnknown_WithNoTimestamps()
    {
        var tracker = new EdgeStatusTracker(TestTime.Frozen());

        Assert.Equal(EdgeReachabilityState.Unknown, tracker.State);
        Assert.Equal(0, tracker.LastSuccessAtTicks);
        Assert.Equal(0, tracker.LastFailureAtTicks);
    }

    [Fact]
    public void RecordSuccess_SetsOk_AndStampsSuccessTimestamp()
    {
        var clock = TestTime.Frozen();
        var tracker = new EdgeStatusTracker(clock);

        tracker.RecordSuccess();

        Assert.Equal(EdgeReachabilityState.Ok, tracker.State);
        Assert.Equal(clock.GetUtcNow().UtcTicks, tracker.LastSuccessAtTicks);
        Assert.Equal(0, tracker.LastFailureAtTicks);
    }

    [Fact]
    public void RecordFailure_SetsDegraded_AndStampsFailureTimestamp()
    {
        var clock = TestTime.Frozen();
        var tracker = new EdgeStatusTracker(clock);

        tracker.RecordFailure();

        Assert.Equal(EdgeReachabilityState.Degraded, tracker.State);
        Assert.Equal(clock.GetUtcNow().UtcTicks, tracker.LastFailureAtTicks);
        Assert.Equal(0, tracker.LastSuccessAtTicks);
    }

    [Fact]
    public void MostRecentOutcomeWins_SuccessThenFailure_IsDegraded()
    {
        var clock = TestTime.Frozen();
        var tracker = new EdgeStatusTracker(clock);

        tracker.RecordSuccess();
        long successTicks = clock.GetUtcNow().UtcTicks;

        clock.Advance(TimeSpan.FromMinutes(5));
        tracker.RecordFailure();
        long failureTicks = clock.GetUtcNow().UtcTicks;

        // The most recent outcome (the failure) drives state, but the success timestamp is retained.
        Assert.Equal(EdgeReachabilityState.Degraded, tracker.State);
        Assert.Equal(successTicks, tracker.LastSuccessAtTicks);
        Assert.Equal(failureTicks, tracker.LastFailureAtTicks);
    }

    [Fact]
    public void MostRecentOutcomeWins_FailureThenSuccess_IsOk()
    {
        var clock = TestTime.Frozen();
        var tracker = new EdgeStatusTracker(clock);

        tracker.RecordFailure();
        clock.Advance(TimeSpan.FromMinutes(1));
        tracker.RecordSuccess();

        // Recovery: a fresh success after a failure returns the node to ok, and both
        // timestamps remain visible so an operator can see the last time each happened.
        Assert.Equal(EdgeReachabilityState.Ok, tracker.State);
        Assert.NotEqual(0, tracker.LastSuccessAtTicks);
        Assert.NotEqual(0, tracker.LastFailureAtTicks);
    }

    [Fact]
    public void RepeatedOutcomes_AdvanceTimestamp_ToLatest()
    {
        var clock = TestTime.Frozen();
        var tracker = new EdgeStatusTracker(clock);

        tracker.RecordSuccess();
        clock.Advance(TimeSpan.FromSeconds(30));
        tracker.RecordSuccess();

        Assert.Equal(clock.GetUtcNow().UtcTicks, tracker.LastSuccessAtTicks);
        Assert.Equal(EdgeReachabilityState.Ok, tracker.State);
    }

    [Fact]
    public async Task ConcurrentUpdates_DoNotCorruptState_AndYieldAConsistentTerminalState()
    {
        // A real (non-frozen) provider so the interleaved successes/failures get monotonic
        // timestamps; the assertion is about corruption-freedom and a coherent terminal state,
        // not an exact instant.
        var tracker = new EdgeStatusTracker(TimeProvider.System);
        const int iterations = 5_000;

        var successes = Task.Run(() =>
        {
            for (int i = 0; i < iterations; i++)
            {
                tracker.RecordSuccess();
            }
        });
        var failures = Task.Run(() =>
        {
            for (int i = 0; i < iterations; i++)
            {
                tracker.RecordFailure();
            }
        });

        await Task.WhenAll(successes, failures);

        // Both outcome timestamps must be set (both paths ran), and the derived state must be a
        // valid, non-corrupt value — never Unknown, since thousands of outcomes were recorded.
        Assert.NotEqual(0, tracker.LastSuccessAtTicks);
        Assert.NotEqual(0, tracker.LastFailureAtTicks);
        Assert.Contains(tracker.State, new[] { EdgeReachabilityState.Ok, EdgeReachabilityState.Degraded });

        // One more deterministic outcome pins the terminal state — proving the tracker is still
        // live and coherent after the concurrent storm.
        tracker.RecordSuccess();
        Assert.Equal(EdgeReachabilityState.Ok, tracker.State);
    }
}
