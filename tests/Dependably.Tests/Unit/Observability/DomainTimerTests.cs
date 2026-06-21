using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Coverage for <see cref="DomainTimer"/>. Histogram recordings are observed via an
/// in-test <see cref="MeterListener"/>; activity outcomes via an
/// <see cref="ActivityListener"/>. Each test uses a fresh <see cref="Meter"/> so
/// recorded measurements are isolated across parallel runs.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DomainTimerTests : IDisposable
{
    private readonly ActivityListener _activityListener;
    private readonly ConcurrentBag<Activity> _stoppedActivities = new();

    public DomainTimerTests()
    {
        _activityListener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == DependablyActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a => _stoppedActivities.Add(a),
        };
        ActivitySource.AddActivityListener(_activityListener);
    }

    public void Dispose() => _activityListener.Dispose();

    // ── Histogram recording ───────────────────────────────────────────────────

    [Fact]
    public void Dispose_RecordsHistogramExactlyOnce()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        int recordCount = 0;
        using var listener = HistogramListener(histogram.Name, meter.Name, (_, _) => recordCount++);

        using (DomainTimer.Start(histogram, activityName: null)) { }

        Assert.Equal(1, recordCount);
    }

    [Fact]
    public void Dispose_DefaultOutcome_IsSuccess()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        string? capturedOutcome = null;
        using var listener = HistogramListener(
            histogram.Name, meter.Name,
            (_, tags) => capturedOutcome = FindTag(tags, "outcome"));

        using (DomainTimer.Start(histogram, activityName: null)) { }

        Assert.Equal("success", capturedOutcome);
    }

    [Fact]
    public void Fail_SetsOutcomeServerError()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        string? capturedOutcome = null;
        using var listener = HistogramListener(
            histogram.Name, meter.Name,
            (_, tags) => capturedOutcome = FindTag(tags, "outcome"));

        using (var timer = DomainTimer.Start(histogram, activityName: null))
        {
            timer.Fail();
        }

        Assert.Equal("server_error", capturedOutcome);
    }

    [Fact]
    public void Cancelled_SetsOutcomeCancelled()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        string? capturedOutcome = null;
        using var listener = HistogramListener(
            histogram.Name, meter.Name,
            (_, tags) => capturedOutcome = FindTag(tags, "outcome"));

        using (var timer = DomainTimer.Start(histogram, activityName: null))
        {
            timer.Cancelled();
        }

        Assert.Equal("cancelled", capturedOutcome);
    }

    [Fact]
    public void Start_Labels_AppearOnRecordedMeasurement()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        KeyValuePair<string, object?>[]? capturedTags = null;
        using var listener = HistogramListener(
            histogram.Name, meter.Name,
            (_, tags) => capturedTags = tags);

        using (DomainTimer.Start(
            histogram,
            activityName: null,
            new KeyValuePair<string, object?>("ecosystem", "npm"),
            new KeyValuePair<string, object?>("operation", "search")))
        { }

        Assert.NotNull(capturedTags);
        Assert.Equal("npm", FindTag(capturedTags, "ecosystem"));
        Assert.Equal("search", FindTag(capturedTags, "operation"));
        Assert.Equal("success", FindTag(capturedTags, "outcome"));
    }

    // ── Activity lifecycle ────────────────────────────────────────────────────

    [Fact]
    public void Start_WithActivityName_CreatesAndStopsActivity()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        string activityName = $"test.op.{Guid.NewGuid():N}";

        using (var timer = DomainTimer.Start(histogram, activityName: activityName))
        {
            Assert.NotNull(timer.Activity);
        }

        Assert.Single(_stoppedActivities, a => a.OperationName == activityName);
    }

    [Fact]
    public void Start_WithNullActivityName_CreatesNoActivity()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        int countBefore = _stoppedActivities.Count;

        using (var timer = DomainTimer.Start(histogram, activityName: null))
        {
            Assert.Null(timer.Activity);
        }

        Assert.Equal(countBefore, _stoppedActivities.Count);
    }

    [Fact]
    public void Dispose_SetsActivityOutcomeTag_Success()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        string activityName = $"test.op.{Guid.NewGuid():N}";

        using (DomainTimer.Start(histogram, activityName: activityName)) { }

        var stopped = Assert.Single(_stoppedActivities, a => a.OperationName == activityName);
        Assert.Equal("success", stopped.GetTagItem("dependably.outcome"));
        Assert.Equal(ActivityStatusCode.Ok, stopped.Status);
    }

    [Fact]
    public void Fail_SetsActivityStatusError()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        string activityName = $"test.op.{Guid.NewGuid():N}";

        using (var timer = DomainTimer.Start(histogram, activityName: activityName))
        {
            timer.Fail();
        }

        var stopped = Assert.Single(_stoppedActivities, a => a.OperationName == activityName);
        Assert.Equal("server_error", stopped.GetTagItem("dependably.outcome"));
        Assert.Equal(ActivityStatusCode.Error, stopped.Status);
    }

    // ── SetTag passthrough ────────────────────────────────────────────────────

    [Fact]
    public void SetTag_AppearsOnActivity()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        string activityName = $"test.op.{Guid.NewGuid():N}";

        using (var timer = DomainTimer.Start(histogram, activityName: activityName))
        {
            timer.SetTag("dependably.result_count", 42);
        }

        var stopped = Assert.Single(_stoppedActivities, a => a.OperationName == activityName);
        Assert.Equal(42, stopped.GetTagItem("dependably.result_count"));
    }

    [Fact]
    public void SetTag_WithNullActivity_DoesNotThrow()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        using var timer = DomainTimer.Start(histogram, activityName: null);
        var ex = Record.Exception(() => timer.SetTag("dependably.result_count", 42));
        Assert.Null(ex);
    }

    // ── Mixed partial-failure scenario (house rule) ───────────────────────────
    // When multiple timers run concurrently, each records independently: the successful
    // ones record "success" and the failed ones record "server_error". Neither interferes
    // with the other's histogram recording or outcome tag.

    [Fact]
    public void MixedOutcomes_EachTimerRecordsItsOwnOutcomeIndependently()
    {
        using var meter = new Meter($"test-{Guid.NewGuid():N}");
        var histogram = meter.CreateHistogram<double>("test.duration", unit: "s");

        var outcomes = new ConcurrentBag<string>();
        using var listener = HistogramListener(
            histogram.Name, meter.Name,
            (_, tags) =>
            {
                string? outcome = FindTag(tags, "outcome");
                if (outcome is not null)
                {
                    outcomes.Add(outcome);
                }
            });

        // Three succeed, two fail — interleaved creation and disposal.
        var timers = new[]
        {
            DomainTimer.Start(histogram, activityName: null, new KeyValuePair<string, object?>("index", "0")),
            DomainTimer.Start(histogram, activityName: null, new KeyValuePair<string, object?>("index", "1")),
            DomainTimer.Start(histogram, activityName: null, new KeyValuePair<string, object?>("index", "2")),
            DomainTimer.Start(histogram, activityName: null, new KeyValuePair<string, object?>("index", "3")),
            DomainTimer.Start(histogram, activityName: null, new KeyValuePair<string, object?>("index", "4")),
        };

        timers[1].Fail();
        timers[3].Fail();

        foreach (var timer in timers)
        {
            timer.Dispose();
        }

        Assert.Equal(5, outcomes.Count);
        Assert.Equal(3, outcomes.Count(o => o == "success"));
        Assert.Equal(2, outcomes.Count(o => o == "server_error"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a <see cref="MeterListener"/> that fires <paramref name="onRecord"/>
    /// for every double-valued measurement on the named histogram in the named meter.
    /// Tags are materialized from the span into an array inside the callback so they
    /// can be captured across the async boundary. Caller must dispose the returned listener.
    /// </summary>
    private static MeterListener HistogramListener(
        string instrumentName,
        string meterName,
        Action<double, KeyValuePair<string, object?>[]> onRecord)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == meterName &&
                    instrument.Name == instrumentName)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<double>(
            (_, measurement, tags, _) => onRecord(measurement, tags.ToArray()));
        listener.Start();
        return listener;
    }

    private static string? FindTag(IEnumerable<KeyValuePair<string, object?>> tags, string tagName)
    {
        foreach (var tag in tags)
        {
            if (tag.Key == tagName)
            {
                return tag.Value?.ToString();
            }
        }
        return null;
    }
}
