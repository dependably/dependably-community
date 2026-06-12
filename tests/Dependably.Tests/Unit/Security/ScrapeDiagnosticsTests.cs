using System.Net;
using Dependably.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Covers the fixed-size ring buffer in <see cref="ScrapeDiagnostics"/>
/// and its lifetime totals. The buffer wraps at capacity (500); reads
/// return newest-first; lifetime counters never wrap.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ScrapeDiagnosticsTests
{
    [Fact]
    public void Recent_ReturnsNewestFirst()
    {
        var d = new ScrapeDiagnostics();
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
        var d = new ScrapeDiagnostics();
        Assert.Empty(d.Recent());
    }

    [Fact]
    public void Recent_RespectsN()
    {
        var d = new ScrapeDiagnostics();
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
        var d = new ScrapeDiagnostics();
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
        var d = new ScrapeDiagnostics();
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
        var d = new ScrapeDiagnostics();
        d.Record(null, ScrapeDiagnostics.Outcome.DeniedIp);

        var recent = d.Recent();
        Assert.Single(recent);
        Assert.Null(recent[0].RemoteIp);
    }
}
