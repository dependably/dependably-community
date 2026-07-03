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
    /// shutdown). The readiness body reports per-check <c>ok</c>/<c>error</c> only; raw failure
    /// detail is logged server-side and never returned to the anonymous caller.
    /// </summary>
    public static void MapHealthAndReady(WebApplication app)
    {
        app.MapGet("/health", () => Results.Ok(new { status = "ok" })).RequireRateLimiting("anon");
        app.MapGet("/ready", BuildReadyHandler()).RequireRateLimiting("anon");
    }

    private static Func<ReadinessAggregator, ShutdownState, CancellationToken, Task<IResult>> BuildReadyHandler() =>
        async (aggregator, shutdown, ct) =>
        {
            if (shutdown.IsShuttingDown)
            {
                return Results.Json(new { status = "draining" }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var checks = await aggregator.CheckAsync(ct);
            bool allOk = checks.Values.All(v => v is null);

            // Per-check ok/error only. Raw failure detail (file paths, Redis endpoints,
            // driver error text) is logged server-side by ReadinessAggregator and never
            // returned to the anonymous caller.
            var body = new
            {
                status = allOk ? "ready" : "degraded",
                checks = checks.ToDictionary(kv => kv.Key, kv => kv.Value is null ? "ok" : "error"),
            };

            return allOk
                ? Results.Ok(body)
                : Results.Json(body, statusCode: StatusCodes.Status503ServiceUnavailable);
        };
}
