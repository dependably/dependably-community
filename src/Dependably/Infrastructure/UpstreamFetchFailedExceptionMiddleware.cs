using System.Text.Json;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Translates <see cref="UpstreamFetchFailedException"/> raised by <c>UpstreamClient</c>
/// into a well-formed <c>503 Service Unavailable</c> (transient upstream throttle/error)
/// or <c>502 Bad Gateway</c> (non-transient upstream failure) response. Package managers
/// treat <c>403</c> as a fatal policy block and abort the entire install; surfacing a
/// transient CDN or rate-limiting upstream response as 503 (with <c>Retry-After</c>)
/// lets clients retry rather than fail permanently. Upstream internals are not leaked in
/// the response body — only the retryability signal and the aggregate status are surfaced.
/// </summary>
public sealed class UpstreamFetchFailedExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<UpstreamFetchFailedExceptionMiddleware> _logger;

    public UpstreamFetchFailedExceptionMiddleware(
        RequestDelegate next,
        ILogger<UpstreamFetchFailedExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (UpstreamFetchFailedException ex)
        {
            if (context.Response.HasStarted)
            {
                throw;
            }

            _logger.LogWarning(
                "Upstream fetch exhausted retries: Url={Url} UpstreamStatus={UpstreamStatus} Transient={Transient}",
                ex.Url,
                ex.StatusCode,
                ex.Transient);

            context.Response.Clear();

            string title;
            string detail;

            if (ex.Transient)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                title = "Upstream temporarily unavailable";
                detail = "The upstream registry returned a transient error (throttle or temporary unavailability) " +
                         "and retries were exhausted. The client should retry the request.";

                // Propagate Retry-After when the upstream supplied a delta-seconds value; fall
                // back to a small default so clients know to back off.
                string retryAfterValue = ex.RetryAfter.HasValue
                    ? ((int)ex.RetryAfter.Value.TotalSeconds).ToString()
                    : "5";
                context.Response.Headers.RetryAfter = retryAfterValue;
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status502BadGateway;
                title = "Upstream fetch failed";
                detail = "The upstream registry returned an error that cannot be retried. " +
                         "Check the upstream registry status.";
            }

            context.Response.ContentType = "application/problem+json";

            string payload = JsonSerializer.Serialize(new
            {
                type = "about:blank",
                title,
                status = context.Response.StatusCode,
                detail,
            });
            await context.Response.WriteAsync(payload);
        }
    }
}
