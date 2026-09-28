using System.Text.Json;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Writes the structured HTTP response for a tenant that is not ready for a request — 402 / 404 /
/// 423 / 503 RFC 7807 problem+json, or the OCI Distribution Spec error envelope on <c>/v2/</c> routes.
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
    /// <summary>
    /// Writes the refusal for <paramref name="reason"/>. <paramref name="usageCapInfoUrl"/> is read
    /// only for <see cref="TenantNotReadyReason.UsageCapReached"/>: when set it becomes the problem
    /// <c>type</c> and a <c>Link: &lt;…&gt;; rel="help"</c> header, and the OCI error's
    /// <c>detail</c>, so a client can follow it to where the operator explains the cap. Callers pass
    /// only an absolute http(s) URL (<see cref="ParseUsageCapInfoUrl"/>).
    /// </summary>
    public static async Task WriteAsync(
        HttpContext context, TenantNotReadyReason reason, string? usageCapInfoUrl = null)
    {
        string? infoUrl = reason == TenantNotReadyReason.UsageCapReached ? usageCapInfoUrl : null;

        if (context.Response.HasStarted)
        {
            // Nothing safe to do: status/headers can no longer change. Leave the response as the
            // caller already began writing it rather than corrupt a half-written body.
            return;
        }

        if (context.Request.Path.StartsWithSegments("/v2", StringComparison.OrdinalIgnoreCase))
        {
            await WriteOciErrorAsync(context, reason, infoUrl);
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

        if (infoUrl is not null)
        {
            context.Response.Headers.Link = $"<{infoUrl}>; rel=\"help\"";
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

        // "detail" is omitted entirely for every other reason (never emitted as a null-valued
        // key) — the reason-only discipline the class doc comment describes. ReadOnlyWrite and
        // UsageCapReached are the exceptions: each already carries no more information than "this
        // write is refused because of the org's posture", so spelling that out is not a new
        // disclosure. Neither names which meter reached its cap.
        var body = new Dictionary<string, object?>
        {
            ["type"] = infoUrl ?? "about:blank",
            ["title"] = title,
            ["status"] = status,
            ["reason"] = reason.ToString(),
        };
        if (reason == TenantNotReadyReason.ReadOnlyWrite)
        {
            body["detail"] =
                "The organization is read-only. Downloads keep working; uploads and publishes are refused.";
        }
        else if (reason == TenantNotReadyReason.UsageCapReached)
        {
            body["detail"] =
                "The organization has reached a usage cap. Downloads keep working; uploads and publishes are refused.";
        }

        string payload = JsonSerializer.Serialize(body);
        await context.Response.WriteAsync(payload);
    }

    private static async Task WriteOciErrorAsync(HttpContext context, TenantNotReadyReason reason, string? infoUrl)
    {
        // Fixed, generic messages only — never the raw orgs.status value or provisioning state.
        // "not available" covers suspended/archived/deleting alike rather than naming "suspended"
        // specifically for a tenant that may be archived/deleting.
        var (status, code, message) = reason switch
        {
            TenantNotReadyReason.StatusInactive =>
                (StatusCodes.Status403Forbidden, OciErrorCode.DENIED, "Organization is not available."),
            TenantNotReadyReason.ReadOnlyWrite =>
                (StatusCodes.Status403Forbidden, OciErrorCode.DENIED, "Organization is read-only; uploads are refused."),
            TenantNotReadyReason.UsageCapReached =>
                (StatusCodes.Status403Forbidden, OciErrorCode.DENIED, "Organization has reached a usage cap; uploads are refused."),
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

        if (infoUrl is not null)
        {
            context.Response.Headers.Link = $"<{infoUrl}>; rel=\"help\"";
        }

        var body = new OciErrorResponse([new OciError(
            code, message, infoUrl is null ? null : new Dictionary<string, string> { ["infoUrl"] = infoUrl })]);
        await context.Response.WriteAsync(JsonSerializer.Serialize(body));
    }

    /// <summary>
    /// <paramref name="configured"/> (<c>USAGE_CAP_INFO_URL</c>) as an absolute http(s) URL, or
    /// null when it is unset or anything else. A relative or non-web value is dropped rather than
    /// echoed into a response header.
    /// </summary>
    public static string? ParseUsageCapInfoUrl(string? configured) =>
        !string.IsNullOrWhiteSpace(configured)
        && Uri.TryCreate(configured.Trim(), UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            ? uri.AbsoluteUri
            : null;

    private static (int status, string title, string? retryAfter) Map(TenantNotReadyReason reason) =>
        reason switch
        {
            TenantNotReadyReason.NotFound =>
                (StatusCodes.Status404NotFound, "Tenant not found", null),
            TenantNotReadyReason.StatusInactive =>
                (StatusCodes.Status423Locked, "Tenant is not active", null),
            TenantNotReadyReason.ReadOnlyWrite =>
                (StatusCodes.Status423Locked, "Organization is read-only", null),
            TenantNotReadyReason.UsageCapReached =>
                (StatusCodes.Status402PaymentRequired, "Usage cap reached", null),
            TenantNotReadyReason.ProvisioningPending =>
                (StatusCodes.Status503ServiceUnavailable, "Tenant registry is still being provisioned", "30"),
            TenantNotReadyReason.ProvisioningFailed =>
                (StatusCodes.Status503ServiceUnavailable, "Tenant registry provisioning failed", "60"),
            _ => (StatusCodes.Status500InternalServerError, "Tenant not ready", null),
        };
}
