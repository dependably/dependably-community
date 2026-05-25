using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Context;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Per-tick scope for an <c>IHostedService</c> background job. Opens:
/// <list type="bullet">
///   <item>A <see cref="Serilog.Context.LogContext"/> scope carrying
///         <c>JobName</c>, <c>JobRunId</c>, and <c>Operation</c> so every
///         log record emitted during the tick carries the canonical taxonomy
///         fields.</item>
///   <item>A root <see cref="Activity"/> from
///         <see cref="DependablyActivitySource"/> so spans started inside
///         the job become its children and propagate W3C trace context.</item>
/// </list>
/// On <see cref="Dispose"/>, records the
/// <c>dependably.background_job.duration</c> histogram with the recorded
/// outcome (call <see cref="Complete"/> or <see cref="Fail"/> before
/// disposal; default is <c>cancelled</c> if neither is called).
///
/// Pattern documented in
/// <c>dependably-enterprise/docs/observability/logs.md#background-jobs</c>.
/// </summary>
public sealed class BackgroundJobScope : IDisposable
{
    private readonly IDisposable _jobNameLog;
    private readonly IDisposable _jobRunIdLog;
    private readonly IDisposable _operationLog;
    private readonly Activity? _activity;
    private readonly Stopwatch _stopwatch;
    private readonly DateTimeOffset _startedAt;
    private string _outcome = "cancelled";
    private string? _errorMessage;

    /// <summary>
    /// Optional service-provider hook for persisting job-run rows. Set once at startup by
    /// <c>Program.cs</c> immediately after <c>app.Services</c> is built. Kept as a static
    /// hook (rather than threaded through every <see cref="Begin"/> call) so the existing
    /// per-service call sites need no edits. Null when running outside the host (e.g. in
    /// xUnit tests that don't boot the app) — persistence is silently skipped in that case.
    /// </summary>
    public static IServiceProvider? Services { get; set; }

    public string JobName { get; }
    public string JobRunId { get; }
    public string Operation { get; }

    private BackgroundJobScope(string jobName, string operation)
    {
        JobName = jobName;
        JobRunId = Guid.NewGuid().ToString("N");
        Operation = operation;

        _jobNameLog = LogContext.PushProperty("JobName", jobName);
        _jobRunIdLog = LogContext.PushProperty("JobRunId", JobRunId);
        _operationLog = LogContext.PushProperty("Operation", operation);

        _activity = DependablyActivitySource.Source.StartActivity(
            "background_job.run",
            ActivityKind.Internal);
        _activity?.SetTag("dependably.job_name", jobName);
        _activity?.SetTag("dependably.operation", operation);
        _activity?.SetTag("dependably.job_run_id", JobRunId);

        _startedAt = DateTimeOffset.UtcNow;
        _stopwatch = Stopwatch.StartNew();
    }

    public static BackgroundJobScope Begin(string jobName, string operation)
        => new(jobName, operation);

    public void Complete(string outcome = "success")
    {
        _outcome = outcome;
        _activity?.SetTag("dependably.outcome", outcome);
        _activity?.SetStatus(ActivityStatusCode.Ok);
        if (outcome == "success")
            DependablyMeter.RecordBackgroundJobSuccess(JobName);
    }

    public void Fail(Exception? exception = null, string outcome = "server_error")
    {
        _outcome = outcome;
        _errorMessage = exception?.Message;
        _activity?.SetTag("dependably.outcome", outcome);
        _activity?.SetStatus(ActivityStatusCode.Error, exception?.Message);
        if (exception is not null)
            _activity?.AddException(exception);
    }

    public void Dispose()
    {
        _stopwatch.Stop();
        var finishedAt = DateTimeOffset.UtcNow;
        var durationMs = _stopwatch.ElapsedMilliseconds;

        DependablyMeter.BackgroundJobDuration.Record(
            _stopwatch.Elapsed.TotalSeconds,
            new KeyValuePair<string, object?>("job_name", JobName),
            new KeyValuePair<string, object?>("outcome", _outcome));

        // Persistent run history. Fire-and-forget — an observability write must never crash a
        // job. Captured into locals first so the closure doesn't pin scope state past dispose.
        var services = Services;
        if (services is not null)
        {
            var jobName = JobName;
            var operation = Operation;
            var runId = JobRunId;
            var startedAt = _startedAt;
            var outcome = _outcome;
            var errorMessage = _errorMessage;

            _ = Task.Run(async () =>
            {
                try
                {
                    using var scope = services.CreateScope();
                    var repo = scope.ServiceProvider.GetService<BackgroundJobRunRepository>();
                    if (repo is null) return;
                    await repo.RecordAsync(new BackgroundJobRunRecord(
                        Id: Guid.NewGuid().ToString("N"),
                        JobName: jobName,
                        Operation: operation,
                        RunId: runId,
                        StartedAt: startedAt,
                        FinishedAt: finishedAt,
                        DurationMs: durationMs,
                        Outcome: outcome,
                        ErrorMessage: errorMessage));
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Failed to persist background-job run for {JobName}", jobName);
                }
            });
        }

        _activity?.Dispose();
        _operationLog.Dispose();
        _jobRunIdLog.Dispose();
        _jobNameLog.Dispose();
    }
}
