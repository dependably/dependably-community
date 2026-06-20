using System.Net;
using Dependably.Security;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Covers the fixed-size ring buffer in <see cref="ScrapeDiagnostics"/>,
/// its lifetime totals, audit-coalescing gate (<see cref="ScrapeDiagnostics.ShouldAudit"/>),
/// and the <see cref="ScrapeDiagnostics.RecentDeniedIps"/> accessor.
/// The buffer wraps at capacity (500); reads return newest-first; lifetime counters never wrap.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ScrapeDiagnosticsTests
{
    [Fact]
    public void Recent_ReturnsNewestFirst()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        d.Record(IPAddress.Parse("10.0.0.1"), ScrapeDiagnostics.Outcome.Allowed);
        d.Record(IPAddress.Parse("10.0.0.2"), ScrapeDiagnostics.Outcome.DeniedIp);
        d.Record(IPAddress.Parse("10.0.0.3"), ScrapeDiagnostics.Outcome.Allowed);

        var recent = d.Recent();
        Assert.Equal(3, recent.Count);
        Assert.Equal("10.0.0.3", recent[0].RemoteIp);
        Assert.Equal("10.0.0.2", recent[1].RemoteIp);
        Assert.Equal("10.0.0.1", recent[2].RemoteIp);
    }

    [Fact]
    public void Recent_Empty_WhenNothingRecorded()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        Assert.Empty(d.Recent());
    }

    [Fact]
    public void Recent_RespectsN()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        for (int i = 0; i < 10; i++)
        {
            d.Record(IPAddress.Parse($"10.0.0.{i}"), ScrapeDiagnostics.Outcome.Allowed);
        }

        Assert.Equal(3, d.Recent(3).Count);
        Assert.Equal(10, d.Recent(50).Count);
    }

    [Fact]
    public void Buffer_WrapsAtCapacity()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        int total = ScrapeDiagnostics.Capacity + 50;
        for (int i = 0; i < total; i++)
        {
            d.Record(IPAddress.Parse($"10.0.{i / 256}.{i % 256}"), ScrapeDiagnostics.Outcome.Allowed);
        }

        // Even though we recorded 550 entries, only the last 500 are retained.
        var recent = d.Recent(ScrapeDiagnostics.Capacity);
        Assert.Equal(ScrapeDiagnostics.Capacity, recent.Count);

        // Lifetime counter does not wrap.
        var (allowed, _, _) = d.LifetimeCounts();
        Assert.Equal(total, allowed);
    }

    [Fact]
    public void LifetimeCounts_TrackOutcomeSeparately()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        for (int i = 0; i < 5; i++)
        {
            d.Record(IPAddress.Loopback, ScrapeDiagnostics.Outcome.Allowed);
        }

        for (int i = 0; i < 3; i++)
        {
            d.Record(IPAddress.Loopback, ScrapeDiagnostics.Outcome.DeniedIp);
        }

        for (int i = 0; i < 2; i++)
        {
            d.Record(IPAddress.Loopback, ScrapeDiagnostics.Outcome.DeniedDisabled);
        }

        var (allowed, deniedIp, deniedDisabled) = d.LifetimeCounts();
        Assert.Equal(5, allowed);
        Assert.Equal(3, deniedIp);
        Assert.Equal(2, deniedDisabled);
    }

    [Fact]
    public void Record_TolerablesNullIp()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        d.Record(null, ScrapeDiagnostics.Outcome.DeniedIp);

        var recent = d.Recent();
        Assert.Single(recent);
        Assert.Null(recent[0].RemoteIp);
    }

    // ── ShouldAudit cooldown gate ──────────────────────────────────────────────

    [Fact]
    public void ShouldAudit_TrueOnFirstCall()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        Assert.True(d.ShouldAudit("system", null, "10.0.0.5", "/metrics"));
    }

    [Fact]
    public void ShouldAudit_FalseWithinCooldownWindow()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        // First call → true
        Assert.True(d.ShouldAudit("system", null, "10.0.0.6", "/metrics"));

        // Advance by 5 minutes (within the 10-minute window)
        clock.Advance(TimeSpan.FromMinutes(5));

        // Same key within window → false
        Assert.False(d.ShouldAudit("system", null, "10.0.0.6", "/metrics"));
    }

    [Fact]
    public void ShouldAudit_TrueAfterCooldownExpiry()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        Assert.True(d.ShouldAudit("system", null, "10.0.0.7", "/metrics"));

        // Advance past the 10-minute window
        clock.Advance(TimeSpan.FromMinutes(11));

        // Window expired → should audit again
        Assert.True(d.ShouldAudit("system", null, "10.0.0.7", "/metrics"));
    }

    [Fact]
    public void ShouldAudit_DifferentKeysAreIndependent()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        // Two different IPs each get their own cooldown
        Assert.True(d.ShouldAudit("system", null, "10.0.0.10", "/metrics"));
        Assert.True(d.ShouldAudit("system", null, "10.0.0.11", "/metrics"));

        // Same scope+orgId+endpoint, different endpoint
        Assert.True(d.ShouldAudit("system", null, "10.0.0.10", "/version"));
    }

    [Fact]
    public void ShouldAudit_ScopeAndOrgIdArePartOfKey()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        // system scope first call
        Assert.True(d.ShouldAudit("system", null, "10.0.0.20", "/metrics"));

        // tenant scope with different orgId — independent key
        Assert.True(d.ShouldAudit("tenant", "org-abc", "10.0.0.20", "/metrics"));

        // system scope within window → false
        Assert.False(d.ShouldAudit("system", null, "10.0.0.20", "/metrics"));

        // tenant scope within window → false
        Assert.False(d.ShouldAudit("tenant", "org-abc", "10.0.0.20", "/metrics"));
    }

    [Fact]
    public void ShouldAudit_MapEviction_ReturnsTrue()
    {
        // When the map exceeds the cap (1024), it is cleared and the next call returns true.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        // Fill map to cap with distinct IPs
        for (int i = 0; i < 1024; i++)
        {
            int a = i / 256;
            int b = i % 256;
            d.ShouldAudit("system", null, $"10.{a}.0.{b}", "/metrics");
        }

        // Adding the 1025th distinct key triggers eviction; result must be true
        bool result = d.ShouldAudit("system", null, "172.16.0.1", "/metrics");
        Assert.True(result);
    }

    // ── RecentDeniedIps accessor ───────────────────────────────────────────────

    [Fact]
    public void RecentDeniedIps_Empty_WhenNoDenials()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        d.Record(IPAddress.Parse("10.0.0.1"), ScrapeDiagnostics.Outcome.Allowed);
        Assert.Empty(d.RecentDeniedIps());
    }

    [Fact]
    public void RecentDeniedIps_ReturnsDeduped_NewestFirst()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        d.Record(IPAddress.Parse("10.0.0.1"), ScrapeDiagnostics.Outcome.DeniedIp);
        clock.Advance(TimeSpan.FromSeconds(10));
        d.Record(IPAddress.Parse("10.0.0.2"), ScrapeDiagnostics.Outcome.DeniedIp);
        clock.Advance(TimeSpan.FromSeconds(10));
        // Same IP again — dedup should show the latest timestamp only
        d.Record(IPAddress.Parse("10.0.0.1"), ScrapeDiagnostics.Outcome.DeniedIp);

        var denied = d.RecentDeniedIps(10);
        // Expect 2 distinct IPs
        Assert.Equal(2, denied.Count);
        // Newest first: 10.0.0.1 was last seen most recently (second occurrence)
        Assert.Equal("10.0.0.1", denied[0].Ip);
        Assert.Equal("10.0.0.2", denied[1].Ip);
    }

    [Fact]
    public void RecentDeniedIps_RespectsMaxCap()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        for (int i = 0; i < 20; i++)
        {
            d.Record(IPAddress.Parse($"10.0.0.{i + 1}"), ScrapeDiagnostics.Outcome.DeniedIp);
        }

        var denied = d.RecentDeniedIps(5);
        Assert.Equal(5, denied.Count);
    }

    [Fact]
    public void RecentDeniedIps_ExcludesAllowedAndDisabled()
    {
        var d = new ScrapeDiagnostics(TimeProvider.System);
        d.Record(IPAddress.Parse("10.0.0.1"), ScrapeDiagnostics.Outcome.Allowed);
        d.Record(IPAddress.Parse("10.0.0.2"), ScrapeDiagnostics.Outcome.DeniedDisabled);
        d.Record(IPAddress.Parse("10.0.0.3"), ScrapeDiagnostics.Outcome.DeniedIp);

        var denied = d.RecentDeniedIps();
        Assert.Single(denied);
        Assert.Equal("10.0.0.3", denied[0].Ip);
    }

    [Fact]
    public void Record_NormalizesIpv4MappedIpv6_InRecentDeniedIps()
    {
        // Dual-stack sockets report IPv4 connections as ::ffff:<v4>. Storing the
        // raw form breaks the allowlist matcher, which always compares dotted-quad.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 17, 10, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        d.Record(IPAddress.Parse("::ffff:172.17.0.1"), ScrapeDiagnostics.Outcome.DeniedIp);

        var denied = d.RecentDeniedIps();
        Assert.Single(denied);
        Assert.Equal("172.17.0.1", denied[0].Ip);
    }

    [Fact]
    public void Record_NormalizesIpv4MappedIpv6_InRecent()
    {
        // Canonical form is stored at record time so the panel and add-button both
        // see the dotted-quad string, not the ::ffff: prefix.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 17, 10, 0, 0, TimeSpan.Zero));
        var d = new ScrapeDiagnostics(clock);

        d.Record(IPAddress.Parse("::ffff:172.17.0.1"), ScrapeDiagnostics.Outcome.Allowed);

        var recent = d.Recent();
        Assert.Single(recent);
        Assert.Equal("172.17.0.1", recent[0].RemoteIp);
    }
}
