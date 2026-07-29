using System.Diagnostics;
using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// The span estate exports off-box via OTLP; an email in <c>url.path</c> would leave the DB's
/// retention controls just like the log leak. The processor masks the local part on span end,
/// and leaves non-PII path tags untouched.
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

        new SpanUrlPathScrubProcessor().OnEnd(activity);

        string? value = activity.GetTagItem(tag) as string;
        Assert.Equal("/api/v1/system/users/***@customer.example/account-status", value);
        Assert.DoesNotContain("alice", value);
    }

    [Fact]
    public void OnEnd_LeavesNonEmailPathUntouched()
    {
        using var activity = new Activity("test").Start();
        activity.SetTag("url.path", "/api/v1/system/users/account-status");

        new SpanUrlPathScrubProcessor().OnEnd(activity);

        Assert.Equal("/api/v1/system/users/account-status", activity.GetTagItem("url.path"));
    }

    [Fact]
    public void OnEnd_NoUrlTags_NoOp()
    {
        using var activity = new Activity("test").Start();
        activity.SetTag("dependably.operation", "system.account_status");

        new SpanUrlPathScrubProcessor().OnEnd(activity);

        Assert.Equal("system.account_status", activity.GetTagItem("dependably.operation"));
        Assert.Null(activity.GetTagItem("url.path"));
    }
}
