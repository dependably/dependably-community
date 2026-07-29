namespace Dependably.Infrastructure.Health;

/// <summary>
/// Maps the liveness (<c>/health</c>) and readiness (<c>/ready</c>) probe endpoints shared by
/// every composition root — the full management host and the headless edge host both expose the
/// identical probe contract, so the mapping lives here rather than being duplicated in each
/// <c>Program</c>. Both endpoints carry the per-IP <c>anon</c> rate-limit policy so an
/// unauthenticated flood cannot amplify load onto the backing stores via <c>/ready</c>'s
/// fan-out checks.
/// </summary>
public static class HealthEndpoints
{
    /// <summary>
    /// Maps <c>GET /health</c> (a fixed liveness OK) and <c>GET /ready</c> (readiness, driven by
    /// <see cref="ReadinessAggregator"/> and short-circuited to <c>draining</c> during graceful
    /// shutdown).
    ///
    /// <para><c>/ready</c> answers 503 only when a <em>required</em> dependency is down (see
    /// <see cref="ReadinessOptions"/>), which makes it safe as a load-balancer health check: a
    /// failure of a dependency shared by the whole fleet no longer deregisters every replica at
    /// once. <c>GET /ready?strict=true</c> keeps the all-dependencies view — every check must be
    /// green — for deployment gating and alerting.</para>
    ///
    /// <para>The readiness body reports per-check <c>ok</c>/<c>error</c> only; raw failure
    /// detail is logged server-side and never returned to the anonymous caller. Alongside the
    /// per-check map it names which dependencies are required and which are currently failing,
    /// so an operator can tell a load-bearing failure from a reported degradation.</para>
    /// </summary>
    public static void MapHealthAndReady(WebApplication app)
    {
        app.MapGet("/health", () => Results.Ok(new { status = "ok" })).RequireRateLimiting("anon");
        app.MapGet("/ready", BuildReadyHandler()).RequireRateLimiting("anon");
    }

    private static Func<ReadinessAggregator, ShutdownState, bool?, CancellationToken, Task<IResult>> BuildReadyHandler() =>
        async (aggregator, shutdown, strict, ct) =>
        {
            if (shutdown.IsShuttingDown)
            {
                return Results.Json(new { status = "draining" }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var report = await aggregator.CheckAsync(ct);
            var (body, statusCode) = EvaluateReadiness(report, strictView: strict == true);

            return statusCode == StatusCodes.Status200OK
                ? Results.Ok(body)
                : Results.Json(body, statusCode: statusCode);
        };

    /// <summary>
    /// Turns a <see cref="ReadinessReport"/> into the <c>/ready</c> body and HTTP status.
    /// Default view: only a failing <em>required</em> dependency answers 503, so a shared-store
    /// failure cannot deregister an entire replica fleet at once. Strict view
    /// (<c>?strict=true</c>): every dependency must be green.
    /// </summary>
    internal static (ReadyResponse Body, int StatusCode) EvaluateReadiness(
        ReadinessReport report, bool strictView)
    {
        bool pass = strictView ? report.AllOk : report.RequiredOk;

        // Per-check ok/error only. Raw failure detail (file paths, Redis endpoints,
        // driver error text) is logged server-side by ReadinessAggregator and never
        // returned to the anonymous caller.
        var body = new ReadyResponse(
            Status: report.AllOk ? "ready" : report.RequiredOk ? "degraded" : "unready",
            Strict: strictView,
            Checks: report.ToStatusMap(),
            Required: report.RequiredChecks,
            Degraded: report.FailingChecks);

        return (body, pass ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
    }
}

/// <summary>
/// The <c>GET /ready</c> response body.
/// </summary>
/// <param name="Status">
/// <c>ready</c> (every dependency green), <c>degraded</c> (a reported-only dependency is down but
/// the replica still serves), or <c>unready</c> (a required dependency is down). The graceful
/// shutdown short-circuit answers <c>draining</c> without reaching this shape.
/// </param>
/// <param name="Strict">Whether the strict all-dependencies view was requested.</param>
/// <param name="Checks">Per-dependency <c>ok</c>/<c>error</c>; never carries raw failure detail.</param>
/// <param name="Required">
/// Dependencies whose failure makes the replica unready — the load-bearing set. Intersect with
/// <paramref name="Degraded"/> to see whether a current failure is load-bearing.
/// </param>
/// <param name="Degraded">Dependencies whose probe is currently failing.</param>
public sealed record ReadyResponse(
    string Status,
    bool Strict,
    Dictionary<string, string> Checks,
    IReadOnlyList<string> Required,
    IReadOnlyList<string> Degraded);
