using System.Text.Json;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Writes the structured HTTP response for a tenant that is not ready for a request — 404 / 423 /
/// 503 RFC 7807 problem+json, or the OCI Distribution Spec error envelope on <c>/v2/</c> routes.
///
/// <para>
/// Shared by two callers with different control-flow shapes. <see cref="TenantNotReadyExceptionMiddleware"/>
/// catches <see cref="TenantNotReadyException"/> raised deep in a controller (e.g.
/// <c>ITenantStorageResolver.GetRegistryAsync</c>) — there, throwing genuinely is the only way to
/// unwind back to the middleware. <see cref="TenantStatusEnforcementMiddleware"/> calls this
/// directly instead of throwing: it already knows the tenant is non-active before <c>_next</c>
/// would run, so raising an exception just to translate it a few frames later would unwind
/// through <c>UseSerilogRequestLogging</c> on the way — which logs an Error-level "responded 500"
/// with a full stack trace for a refusal that is steady-state behaviour, not an incident, for a
/// suspended tenant whose CI keeps polling. Writing the response directly keeps the log at the
/// single structured Warning the enforcement middleware already emits.
/// </para>
///
/// <para>
/// Reason-only: the response body never includes <c>tenantId</c> or the precise <c>orgs.status</c>
/// value (<see cref="TenantNotReadyException.Detail"/>) — this gate is reachable by an
/// unauthenticated caller on most protocol routes, which authenticate their own ecosystem token
/// inside the controller action, after this point in the pipeline. <see cref="TenantNotReadyReason"/>
/// names a class (<c>StatusInactive</c> covers suspended/archived/deleting alike), not the
/// specific value, so it does not re-open that disclosure.
/// </para>
/// </summary>
public static class TenantNotReadyResponseWriter
{
    public static async Task WriteAsync(HttpContext context, TenantNotReadyReason reason)
    {
        if (context.Response.HasStarted)
        {
            // Nothing safe to do: status/headers can no longer change. Leave the response as the
            // caller already began writing it rather than corrupt a half-written body.
            return;
        }

        if (context.Request.Path.StartsWithSegments("/v2", StringComparison.OrdinalIgnoreCase))
        {
            await WriteOciErrorAsync(context, reason);
            return;
        }

        var (status, title, retryAfter) = Map(reason);

        var headerSnapshot = ResponseHeaderPreserver.Capture(context);
        context.Response.Clear();
        context.Response.StatusCode = status;
        if (retryAfter is not null)
        {
            context.Response.Headers.RetryAfter = retryAfter;
        }

        // Response.Clear() drops the request-derived headers SecurityHeadersMiddleware set on the
        // way in — CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS, Cache-Control
        // on registry paths — restored from the snapshot taken above (see
        // ResponseHeaderPreserver's own doc comment for what it preserves and why). This refusal
        // is reachable by an anonymous caller, so the JSON body must still be sniff-proof; set
        // explicitly too, since the snapshot only captures it when SecurityHeadersMiddleware
        // actually ran ahead of this writer.
        ResponseHeaderPreserver.Restore(context, headerSnapshot);
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.ContentType = "application/problem+json";

        string payload = JsonSerializer.Serialize(new
        {
            type = "about:blank",
            title,
            status,
            reason = reason.ToString(),
        });
        await context.Response.WriteAsync(payload);
    }

    private static async Task WriteOciErrorAsync(HttpContext context, TenantNotReadyReason reason)
    {
        // Fixed, generic messages only — never the raw orgs.status value or provisioning state.
        // "not available" covers suspended/archived/deleting alike rather than naming "suspended"
        // specifically for a tenant that may be archived/deleting.
        var (status, code, message) = reason switch
        {
            TenantNotReadyReason.StatusInactive =>
                (StatusCodes.Status403Forbidden, OciErrorCode.DENIED, "Organization is not available."),
            TenantNotReadyReason.NotFound =>
                (StatusCodes.Status404NotFound, OciErrorCode.NAME_UNKNOWN, "Tenant not found."),
            TenantNotReadyReason.ProvisioningPending or TenantNotReadyReason.ProvisioningFailed =>
                (StatusCodes.Status503ServiceUnavailable, OciErrorCode.UNAVAILABLE, "Tenant registry is not ready."),
            _ => (StatusCodes.Status500InternalServerError, OciErrorCode.UNSUPPORTED, "Tenant not ready."),
        };

        var headerSnapshot = ResponseHeaderPreserver.Capture(context);
        context.Response.Clear();
        context.Response.StatusCode = status;

        // Response.Clear() drops the request-derived headers SecurityHeadersMiddleware set on the
        // way in, restored from the snapshot taken above — this OCI branch shares the same trap
        // and the same fix as the problem+json branch above.
        ResponseHeaderPreserver.Restore(context, headerSnapshot);
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.ContentType = "application/json";

        var body = new OciErrorResponse([new OciError(code, message)]);
        await context.Response.WriteAsync(JsonSerializer.Serialize(body));
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
