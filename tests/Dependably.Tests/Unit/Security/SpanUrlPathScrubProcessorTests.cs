using System.Diagnostics;
using Dependably.Infrastructure.Observability;
using Dependably.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// The span estate exports off-box via OTLP; an email in <c>url.path</c> would leave the DB's
/// retention controls just like the log leak. The processor masks the local part on span end,
/// and leaves non-PII path tags untouched. Masked-form assertions run with a generous match
/// timeout (see <see cref="TestScrubbers"/>); the fail-closed timeout path is pinned on its own.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SpanUrlPathScrubProcessorTests
{
    [Theory]
    [InlineData("url.path")]
    [InlineData("http.target")]
    [InlineData("url.full")]
    [InlineData("http.url")]
    public void OnEnd_MasksEmailInUrlTag(string tag)
    {
        using var activity = new Activity("test").Start();
        activity.SetTag(tag, "/api/v1/system/users/alice@customer.example/account-status");

        new SpanUrlPathScrubProcessor(TestScrubbers.Generous).OnEnd(activity);

        string? value = activity.GetTagItem(tag) as string;
        Assert.Equal("/api/v1/system/users/***@customer.example/account-status", value);
        Assert.DoesNotContain("alice", value);
    }

    [Theory]
    [InlineData("url.path")]
    [InlineData("http.target")]
    [InlineData("url.full")]
    [InlineData("http.url")]
    public void OnEnd_MatcherTimesOut_RedactsTagWhole(string tag)
    {
        using var activity = new Activity("test").Start();
        activity.SetTag(tag, TestScrubbers.SlowToScan);

        new SpanUrlPathScrubProcessor(TestScrubbers.Instant).OnEnd(activity);

        string? value = activity.GetTagItem(tag) as string;
        Assert.Equal(LogPathScrubber.RedactedValue, value);
        Assert.DoesNotContain("alice", value);
    }

    [Fact]
    public void OnEnd_ProductionScrubber_NeverEmitsTheEmail()
    {
        // The parameterless constructor is the production wiring. Whether its matcher finishes
        // inside the default deadline depends on scheduling, so this asserts the property that
        // holds either way: the tag is masked or redacted whole, and the local part never survives.
        using var activity = new Activity("test").Start();
        activity.SetTag("url.path", "/api/v1/system/users/alice@customer.example/account-status");

        new SpanUrlPathScrubProcessor().OnEnd(activity);

        string? value = activity.GetTagItem("url.path") as string;
        Assert.Contains(value, new[]
        {
            "/api/v1/system/users/***@customer.example/account-status",
            LogPathScrubber.RedactedValue,
        });
        Assert.DoesNotContain("alice", value);
    }

    [Fact]
    public void OnEnd_LeavesNonEmailPathUntouched()
    {
        using var activity = new Activity("test").Start();
        activity.SetTag("url.path", "/api/v1/system/users/account-status");

        new SpanUrlPathScrubProcessor(TestScrubbers.Generous).OnEnd(activity);

        Assert.Equal("/api/v1/system/users/account-status", activity.GetTagItem("url.path"));
    }

    [Fact]
    public void OnEnd_NoUrlTags_NoOp()
    {
        using var activity = new Activity("test").Start();
        activity.SetTag("dependably.operation", "system.account_status");

        new SpanUrlPathScrubProcessor(TestScrubbers.Generous).OnEnd(activity);

        Assert.Equal("system.account_status", activity.GetTagItem("dependably.operation"));
        Assert.Null(activity.GetTagItem("url.path"));
    }
}
