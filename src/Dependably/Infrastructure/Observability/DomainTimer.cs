using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Lightweight timing helper for low-QPS single-lexical-scope operations such as
/// search and metadata builds. Captures labels at <see cref="Start"/>, records the
/// histogram once on <see cref="Dispose"/>, and optionally opens an
/// <see cref="Activity"/> so the operation appears in distributed traces.
///
/// Use <see cref="Fail"/> or <see cref="Cancelled"/> to set a non-success outcome
/// before disposal; the default outcome is <c>success</c>.
///
/// Must be used as a class (not a ref struct) so instances survive <c>await</c>
/// boundaries inside async search and metadata methods.
/// </summary>
public sealed class DomainTimer : IDisposable
{
    private readonly Histogram<double> _histogram;
    private readonly KeyValuePair<string, object?>[] _labels;
    private readonly Stopwatch _stopwatch;
    private string _outcome = "success";

    private DomainTimer(
        Histogram<double> histogram,
        KeyValuePair<string, object?>[] labels,
        Activity? activity)
    {
        _histogram = histogram;
        _labels = labels;
        Activity = activity;
        _stopwatch = Stopwatch.StartNew();
    }

    /// <summary>
    /// Starts a timing scope for <paramref name="histogram"/>. Captures
    /// <paramref name="labels"/> (appended with the final <c>outcome</c> tag on
    /// disposal) and, when <paramref name="activityName"/> is non-null, opens an
    /// <see cref="Activity"/> of kind <see cref="ActivityKind.Internal"/> from
    /// <see cref="DependablyActivitySource.Source"/>.
    /// </summary>
    public static DomainTimer Start(
        Histogram<double> histogram,
        string? activityName,
        params KeyValuePair<string, object?>[] labels)
    {
        var activity = activityName is not null
            ? DependablyActivitySource.Source.StartActivity(activityName, ActivityKind.Internal)
            : null;

        return new DomainTimer(histogram, labels, activity);
    }

    /// <summary>The underlying activity, or <c>null</c> when no activity name was supplied.</summary>
    public Activity? Activity { get; }

    /// <summary>Sets an extra tag on the current activity (no-op when no activity is open).</summary>
    public void SetTag(string key, object? value) => Activity?.SetTag(key, value);

    /// <summary>
    /// Records outcome <c>server_error</c> and marks the activity status Error.
    /// Call before <see cref="Dispose"/> when the operation fails due to a server fault.
    /// </summary>
    public void Fail()
    {
        _outcome = "server_error";
        Activity?.SetStatus(ActivityStatusCode.Error);
    }

    /// <summary>
    /// Records outcome <c>cancelled</c>. Call before <see cref="Dispose"/> when the
    /// operation is aborted (e.g. request cancellation).
    /// </summary>
    public void Cancelled()
    {
        _outcome = "cancelled";
    }

    /// <summary>
    /// Stops the stopwatch, records the histogram with elapsed seconds and the captured
    /// labels plus the resolved <c>outcome</c> tag, finalises the activity, and disposes it.
    /// </summary>
    public void Dispose()
    {
        _stopwatch.Stop();

        var allLabels = new KeyValuePair<string, object?>[_labels.Length + 1];
        _labels.CopyTo(allLabels, 0);
        allLabels[_labels.Length] = new KeyValuePair<string, object?>("outcome", _outcome);

        _histogram.Record(_stopwatch.Elapsed.TotalSeconds, allLabels);

        Activity?.SetTag("dependably.outcome", _outcome);

        if (_outcome == "server_error")
        {
            Activity?.SetStatus(ActivityStatusCode.Error);
        }
        else if (_outcome == "success")
        {
            Activity?.SetStatus(ActivityStatusCode.Ok);
        }

        Activity?.Dispose();
    }
}
