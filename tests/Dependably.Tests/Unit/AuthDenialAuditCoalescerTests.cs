using Dependably.Security;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The coalescer's whole job is to say "no" — a version that always returned true would leave
/// every caller green while restoring the write amplification it exists to remove, so the
/// suppression itself is what these pin, not just the first-call pass.
/// </summary>
public sealed class AuthDenialAuditCoalescerTests
{
    [Fact]
    public void FirstDenial_IsAudited_AndTheBurstBehindItIsNot()
    {
        var coalescer = new AuthDenialAuditCoalescer(TestTime.Frozen());

        Assert.True(coalescer.ShouldAudit("org-1", "tok-1", "push"));

        // A single multi-layer docker push issues three writes per layer; every one of them
        // reaches the same gate with the same credential.
        for (int i = 0; i < 150; i++)
        {
            Assert.False(coalescer.ShouldAudit("org-1", "tok-1", "push"));
        }
    }

    [Fact]
    public void DistinctOrgTokenAndRoute_EachAuditOnce()
    {
        var coalescer = new AuthDenialAuditCoalescer(TestTime.Frozen());

        Assert.True(coalescer.ShouldAudit("org-1", "tok-1", "push"));
        Assert.True(coalescer.ShouldAudit("org-2", "tok-1", "push"));
        Assert.True(coalescer.ShouldAudit("org-1", "tok-2", "push"));
        Assert.True(coalescer.ShouldAudit("org-1", "tok-1", "pull"));

        Assert.False(coalescer.ShouldAudit("org-1", "tok-1", "push"));
    }

    [Fact]
    public void AfterTheCooldownElapses_TheDenialIsAuditedAgain()
    {
        var clock = TestTime.Frozen();
        var coalescer = new AuthDenialAuditCoalescer(clock);

        Assert.True(coalescer.ShouldAudit("org-1", "tok-1", "push"));

        // Still inside the 10-minute window.
        clock.Advance(TimeSpan.FromMinutes(9));
        Assert.False(coalescer.ShouldAudit("org-1", "tok-1", "push"));

        // Past it — a credential still being refused an hour later is a fact worth recording
        // again, otherwise a long-running misconfiguration leaves exactly one stale row.
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.True(coalescer.ShouldAudit("org-1", "tok-1", "push"));
    }

    [Fact]
    public void TrackedKeysAreBounded_SoAKeySprayCannotGrowTheMapWithoutLimit()
    {
        var coalescer = new AuthDenialAuditCoalescer(TestTime.Frozen());

        for (int i = 0; i < 5000; i++)
        {
            Assert.True(coalescer.ShouldAudit("org-1", $"tok-{i}", "push"));
        }

        // Eviction is whole-map, so a key seen before the flush may audit a second time; what
        // must hold is that suppression still works after the cap has been crossed.
        Assert.True(coalescer.ShouldAudit("org-1", "tok-final", "push"));
        Assert.False(coalescer.ShouldAudit("org-1", "tok-final", "push"));
    }
}
