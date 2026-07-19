using System.Text.Json;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Translates an escaping <see cref="SsrfBlockedException"/> into a well-formed
/// <c>502 Bad Gateway</c> problem-JSON response. <c>UpstreamClient</c> throws this exception
/// when the target of an upstream fetch (or a metadata/index lookup that feeds one) resolves
/// into a private/link-local/metadata address range — a hard policy refusal, not a transient
/// condition, so retrying against the same blocked host will never succeed (never 503).
/// Most ecosystem download paths (Apk, Go, Cargo, and <c>UpstreamClient</c>'s own connect-time
/// unwrap) already catch this exception explicitly and answer <c>502</c> themselves; this
/// middleware is the safety net for paths that do not — notably the PyPI <c>/packages/{file}</c>
/// download path, where the simple-index resolution step that precedes the cached-blob fetch
/// has no local catch and previously let the exception reach the framework as an unhandled 500.
/// Sits adjacent to <see cref="UpstreamFetchFailedExceptionMiddleware"/> so all upstream-fetch
/// exception mappings live together in the pipeline. Upstream internals (the blocked URL) are
/// not leaked in the response body.
/// </summary>
public sealed class SsrfBlockedExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SsrfBlockedExceptionMiddleware> _logger;

    public SsrfBlockedExceptionMiddleware(
        RequestDelegate next,
        ILogger<SsrfBlockedExceptionMiddleware> logger)
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
        catch (SsrfBlockedException ex)
        {
            if (context.Response.HasStarted)
            {
                throw;
            }

            _logger.LogWarning(
                "SSRF-blocked upstream fetch: ExceptionType={ExceptionType} TraceId={TraceId}",
                ex.GetType().Name,
                context.TraceIdentifier);

            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
            context.Response.ContentType = "application/problem+json";

            string payload = JsonSerializer.Serialize(new
            {
                type = "about:blank",
                title = "Upstream fetch blocked",
                status = context.Response.StatusCode,
                detail = "The upstream target resolved to an address blocked by SSRF policy " +
                         "(private, link-local, or metadata range). This is a policy refusal, " +
                         "not a transient failure — retrying will not succeed.",
            });
            await context.Response.WriteAsync(payload);
        }
    }
}
