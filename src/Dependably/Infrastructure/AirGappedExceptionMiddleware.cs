using System.Text.Json;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Translates <see cref="AirGappedException"/> raised by <c>UpstreamClient</c> into a
/// well-formed <c>503 Service Unavailable</c> response. Without this, the
/// exception would surface as a 500 and the caller would have no way to tell
/// "upstream is down" from "this deployment doesn't talk to upstream by policy".
///
/// The body is RFC 7807-style problem JSON so npm/pip/nuget clients display a
/// sensible message; <c>Retry-After: 0</c> hints "don't retry — it won't help".
/// </summary>
public sealed class AirGappedExceptionMiddleware
{
    private readonly RequestDelegate _next;

    public AirGappedExceptionMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (AirGappedException ex)
        {
            if (context.Response.HasStarted)
            {
                throw;
            }

            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.RetryAfter = "0";
            context.Response.ContentType = "application/problem+json";

            string payload = JsonSerializer.Serialize(new
            {
                type = "about:blank",
                title = "Cache disabled in air-gapped mode",
                status = 503,
                detail = "This deployment is configured AIR_GAPPED=true and cannot reach upstream registries. " +
                         "The requested artefact is not in the local cache; import it via /api/v1/admin/import.",
                resource = ex.Resource,
            });
            await context.Response.WriteAsync(payload);
        }
    }
}
