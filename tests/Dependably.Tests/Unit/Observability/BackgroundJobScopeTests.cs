using System.Collections.Concurrent;
using System.Diagnostics;
using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Coverage for <see cref="BackgroundJobScope"/>. Activity outcomes are observed
/// via an in-test <see cref="ActivityListener"/>; the duration histogram and
/// last-success gauge are read via <see cref="DependablyMeter"/> accessors. Each
/// test uses a unique job-name suffix so the global meter state stays clean across
/// parallel test runs.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BackgroundJobScopeTests : IDisposable
{
    private readonly ActivityListener _listener;
    private readonly ConcurrentBag<Activity> _stoppedActivities = new();

    public BackgroundJobScopeTests()
    {
        _listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == DependablyActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a => _stoppedActivities.Add(a),
        };
        ActivitySource.AddActivityListener(_listener);
    }

    public void Dispose() => _listener.Dispose();

    [Fact]
    public void Complete_Success_RecordsLastSuccessGauge()
    {
        string jobName = $"unit-success-{Guid.NewGuid():N}";

        using (var scope = BackgroundJobScope.Begin(jobName, "test_op"))
        {
            scope.Complete();
        }

        Assert.True(DependablyMeter.ReadBackgroundJobLastSuccess().ContainsKey(jobName));

        var activity = Assert.Single(_stoppedActivities, a => (string?)a.GetTagItem("dependably.job_name") == jobName);
        Assert.Equal("success", activity.GetTagItem("dependably.outcome"));
        Assert.Equal(ActivityStatusCode.Ok, activity.Status);
    }

    [Fact]
    public void Complete_NonSuccessOutcome_DoesNotRecordLastSuccess()
    {
        // The Complete path only writes the last-success gauge when outcome == "success".
        // A non-default outcome (e.g. "skipped") sets the activity tag but leaves the gauge alone.
        string jobName = $"unit-skipped-{Guid.NewGuid():N}";

        using (var scope = BackgroundJobScope.Begin(jobName, "test_op"))
        {
            scope.Complete("skipped");
        }

        Assert.False(DependablyMeter.ReadBackgroundJobLastSuccess().ContainsKey(jobName));
        var activity = Assert.Single(_stoppedActivities, a => (string?)a.GetTagItem("dependably.job_name") == jobName);
        Assert.Equal("skipped", activity.GetTagItem("dependably.outcome"));
    }

    [Fact]
    public void Fail_WithException_AttachesAndMarksError()
    {
        string jobName = $"unit-fail-{Guid.NewGuid():N}";
        var ex = new InvalidOperationException("boom");

        using (var scope = BackgroundJobScope.Begin(jobName, "test_op"))
        {
            scope.Fail(ex);
        }

        var activity = Assert.Single(_stoppedActivities, a => (string?)a.GetTagItem("dependably.job_name") == jobName);
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
        Assert.Equal("server_error", activity.GetTagItem("dependably.outcome"));
        // The exception is attached as an event on the activity (Activity.AddException).
        Assert.Contains(activity.Events, e => e.Name == "exception");
    }

    [Fact]
    public void Fail_WithoutException_MarksErrorWithoutAttachment()
    {
        // The exception?.Message null-coalesce + the `if (exception is not null)` guard:
        // both branches must fire — this test hits the null-exception branch of both.
        string jobName = $"unit-fail-nullex-{Guid.NewGuid():N}";

        using (var scope = BackgroundJobScope.Begin(jobName, "test_op"))
        {
            scope.Fail();
        }

        var activity = Assert.Single(_stoppedActivities, a => (string?)a.GetTagItem("dependably.job_name") == jobName);
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
        Assert.DoesNotContain(activity.Events, e => e.Name == "exception");
    }

    [Fact]
    public void Fail_CustomOutcome_TagsActivity()
    {
        // Verifies a non-default outcome flows to the activity tag (and, via Dispose, the
        // duration histogram). Cardinality-budget enforcement lives elsewhere; here we only
        // assert the value propagates.
        string jobName = $"unit-fail-custom-{Guid.NewGuid():N}";

        using (var scope = BackgroundJobScope.Begin(jobName, "test_op"))
        {
            scope.Fail(outcome: "throttled");
        }

        var activity = Assert.Single(_stoppedActivities, a => (string?)a.GetTagItem("dependably.job_name") == jobName);
        Assert.Equal("throttled", activity.GetTagItem("dependably.outcome"));
    }

    [Fact]
    public void Dispose_WithoutCompleteOrFail_DefaultsToCancelled()
    {
        // When neither Complete nor Fail is called, _outcome stays "cancelled" — Dispose
        // still records the duration histogram with that label and the activity carries
        // no explicit outcome tag (since it's set inside Complete/Fail).
        string jobName = $"unit-cancelled-{Guid.NewGuid():N}";

        using (BackgroundJobScope.Begin(jobName, "test_op")) { }

        // Activity is recorded but never received the outcome tag.
        var activity = Assert.Single(_stoppedActivities, a => (string?)a.GetTagItem("dependably.job_name") == jobName);
        Assert.Null(activity.GetTagItem("dependably.outcome"));
        // The last-success gauge stayed empty for this job.
        Assert.False(DependablyMeter.ReadBackgroundJobLastSuccess().ContainsKey(jobName));
    }
}
