using System.Text.Json;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Translates <see cref="TenantNotReadyException"/> raised by
/// <see cref="ITenantStorageResolver.GetRegistryAsync"/> into structured HTTP responses.
/// Without this, every gated path (publish, import) returns 500 and clients can't tell
/// "tenant doesn't exist" from "your bucket is still being provisioned, retry shortly".
///
/// Mapping by <see cref="TenantNotReadyReason"/>:
///   <list type="bullet">
///     <item><c>NotFound</c> → 404</item>
///     <item><c>StatusInactive</c> → 423 Locked (suspended / archived / deleting — admin must act)</item>
///     <item><c>ProvisioningPending</c> → 503 Service Unavailable, Retry-After: 30</item>
///     <item><c>ProvisioningFailed</c> → 503 Service Unavailable, Retry-After: 60</item>
///   </list>
/// Body is RFC 7807 problem JSON; the <c>reason</c> extension carries the enum value so
/// programmatic callers can branch without parsing the title.
/// </summary>
public sealed class TenantNotReadyExceptionMiddleware
{
    private readonly RequestDelegate _next;

    public TenantNotReadyExceptionMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (TenantNotReadyException ex)
        {
            if (context.Response.HasStarted)
                throw;

            var (status, title, retryAfter) = Map(ex.Reason);

            context.Response.Clear();
            context.Response.StatusCode = status;
            if (retryAfter is not null)
                context.Response.Headers.RetryAfter = retryAfter;
            context.Response.ContentType = "application/problem+json";

            var payload = JsonSerializer.Serialize(new
            {
                type = "about:blank",
                title,
                status,
                detail = ex.Detail,
                reason = ex.Reason.ToString(),
                tenantId = ex.TenantId,
            });
            await context.Response.WriteAsync(payload);
        }
    }

    private static (int status, string title, string? retryAfter) Map(TenantNotReadyReason reason) =>
        reason switch
        {
            TenantNotReadyReason.NotFound =>
                (StatusCodes.Status404NotFound, "Tenant not found", null),
            TenantNotReadyReason.StatusInactive =>
                (StatusCodes.Status423Locked, "Tenant is not active", null),
            TenantNotReadyReason.ProvisioningPending =>
                (StatusCodes.Status503ServiceUnavailable, "Tenant registry is still being provisioned", "30"),
            TenantNotReadyReason.ProvisioningFailed =>
                (StatusCodes.Status503ServiceUnavailable, "Tenant registry provisioning failed", "60"),
            _ => (StatusCodes.Status500InternalServerError, "Tenant not ready", null),
        };
}
