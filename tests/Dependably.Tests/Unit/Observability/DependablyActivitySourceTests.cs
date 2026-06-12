using System.Diagnostics;
using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Sanity checks on the shared <see cref="DependablyActivitySource"/>:
/// the source name matches what <c>ConfigureOpenTelemetry</c> subscribes
/// to, and spans started from it carry the expected tags.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DependablyActivitySourceTests
{
    [Fact]
    public void SourceNameMatchesSubscriptionConstant()
    {
        Assert.Equal("dependably", DependablyActivitySource.SourceName);
        Assert.Equal(DependablyActivitySource.SourceName, DependablyActivitySource.Source.Name);
    }

    [Fact]
    public void StartActivity_WithListener_CreatesActivityAndAcceptsTags()
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == DependablyActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);

        using var activity = DependablyActivitySource.Source.StartActivity(
            "proxy.fetch", ActivityKind.Client);
        Assert.NotNull(activity);
        activity!.SetTag("dependably.ecosystem", "npm");
        activity.SetTag("dependably.outcome", "success");

        Assert.Equal("proxy.fetch", activity.OperationName);
        Assert.Equal(ActivityKind.Client, activity.Kind);
        Assert.Equal("npm", activity.GetTagItem("dependably.ecosystem"));
        Assert.Equal("success", activity.GetTagItem("dependably.outcome"));
    }
}
