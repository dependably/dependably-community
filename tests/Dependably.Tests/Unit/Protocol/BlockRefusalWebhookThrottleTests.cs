using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Direct coverage of <see cref="BlockRefusalWebhookThrottle"/>, mirroring
/// <c>AuthDenialAuditCoalescerTests</c>'s shape for the same coalescing-map pattern: the
/// throttle's whole job is to say "no" to a burst, so the suppression itself is what these pin,
/// not just the first-call pass.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlockRefusalWebhookThrottleTests
{
    [Fact]
    public void FirstRefusal_Dispatches_AndTheBurstBehindItDoesNot()
    {
        var throttle = new BlockRefusalWebhookThrottle(TestTime.Frozen(), TimeSpan.FromMinutes(15));

        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));

        for (int i = 0; i < 50; i++)
        {
            Assert.False(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));
        }
    }

    [Fact]
    public void DistinctOrgPurlOrArm_EachDispatchesOnce()
    {
        var throttle = new BlockRefusalWebhookThrottle(TestTime.Frozen(), TimeSpan.FromMinutes(15));

        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));
        Assert.True(throttle.ShouldDispatch("org-2", "pkg:npm/acme@1.0.0", "manual"));
        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/other@1.0.0", "manual"));
        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "release_age"));

        Assert.False(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));
    }

    [Fact]
    public void AfterTheWindowElapses_TheRefusalDispatchesAgain()
    {
        var clock = TestTime.Frozen();
        var throttle = new BlockRefusalWebhookThrottle(clock, TimeSpan.FromMinutes(15));

        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));

        clock.Advance(TimeSpan.FromMinutes(14));
        Assert.False(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));

        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));
    }

    [Fact]
    public void TrackedCoordinatesAreBounded_SoAKeySprayCannotGrowTheMapWithoutLimit()
    {
        var throttle = new BlockRefusalWebhookThrottle(TestTime.Frozen(), TimeSpan.FromMinutes(15));

        // Push the tracked-coordinate count past KeyCap with distinct purls — the release-age
        // arm's real-world shape, where every newly published upstream version mints a fresh
        // coordinate that never repeats.
        for (int i = 0; i < 5000; i++)
        {
            Assert.True(throttle.ShouldDispatch("org-1", $"pkg:npm/acme@1.0.{i}", "release_age"));
            // The count is what this test is actually named for — ShouldDispatch's return value
            // alone cannot distinguish a bounded map from an unbounded one, since a fresh key
            // always dispatches either way. Asserted every iteration (not just at the end) so a
            // regression that removed the cap check entirely still fails on the very first
            // iteration that would have crossed it, rather than only on the last.
            Assert.True(throttle.TrackedCoordinateCount <= BlockRefusalWebhookThrottle.KeyCap);
        }

        // Eviction is whole-map, so a coordinate seen before the flush may dispatch a second
        // time — that is the accepted trade documented on the class, not a bug. What must hold
        // is that suppression still works for a coordinate seen after the cap was crossed.
        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/final@9.9.9", "release_age"));
        Assert.False(throttle.ShouldDispatch("org-1", "pkg:npm/final@9.9.9", "release_age"));
        Assert.True(throttle.TrackedCoordinateCount <= BlockRefusalWebhookThrottle.KeyCap);
    }

    [Fact]
    public void CoordinateClearedByEviction_ReDispatchesOnItsNextRefusal()
    {
        // Pins the specific re-dispatch-after-clear behaviour the doc comment calls out:
        // once a coordinate is evicted by the whole-map clear, it dispatches again on its very
        // next refusal exactly as if it were being seen for the first time — acceptable by
        // design, since the map exists to suppress a burst, not to remember history forever.
        var throttle = new BlockRefusalWebhookThrottle(TestTime.Frozen(), TimeSpan.FromMinutes(15));

        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));
        Assert.False(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));

        for (int i = 0; i < BlockRefusalWebhookThrottle.KeyCap; i++)
        {
            throttle.ShouldDispatch("org-1", $"pkg:npm/filler@1.0.{i}", "manual");
        }

        // The original coordinate's tracked entry is gone; it reads as brand-new.
        Assert.True(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));
        Assert.False(throttle.ShouldDispatch("org-1", "pkg:npm/acme@1.0.0", "manual"));
    }

    [Fact]
    public async Task ConcurrentRefusalsOnAFreshCoordinate_ExactlyOneDispatches()
    {
        // Two callers refusing the same (org, purl, arm) coordinate at once — parallel `npm ci`
        // or `docker pull` retries hitting the same blocked artefact from different connections.
        // A Barrier(2), mirroring PackageRepositoryDeleteVersionRaceTests' technique, releases
        // both tasks together right before they call ShouldDispatch so real concurrent execution
        // is exercised rather than a sequential simulation of it.
        //
        // The assertion this pins does not depend on whether the two calls actually overlapped
        // at the instruction level (which no test can force deterministically): given a fresh
        // key, ConcurrentDictionary.TryAdd guarantees at most one of any number of concurrent
        // callers ever succeeds, and ShouldDispatch's retry loop guarantees the other(s) always
        // observe the winner's entry and return false — never zero, never two. That guarantee
        // holds by construction under the CAS implementation, so this test is exactly-one on
        // every run, not merely likely-one; a regression to a bare check-then-write would make
        // it flake toward occasionally observing two, which is the failure mode this exists to
        // catch (see BlockRefusalWebhookThrottleTests, project memory on unsequenced-concurrency
        // tests that pin nothing — this one pins an invariant true regardless of interleaving,
        // not an outcome that merely happens not to have been observed failing yet).
        var throttle = new BlockRefusalWebhookThrottle(TestTime.Frozen(), TimeSpan.FromMinutes(15));
        using var barrier = new Barrier(2);
        const string purl = "pkg:npm/race@1.0.0";

        bool Race()
        {
            barrier.SignalAndWait();
            return throttle.ShouldDispatch("org-1", purl, "manual");
        }

        var task1 = Task.Run(Race);
        var task2 = Task.Run(Race);

        bool[] results = await Task.WhenAll(task1, task2);

        Assert.Equal(1, results.Count(r => r));
    }
}
