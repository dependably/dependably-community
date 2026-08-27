using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Logging;

namespace Dependably.Infrastructure;

/// <summary>
/// Refuses a request whose resolved <see cref="TenantContext"/> names a tenant that is not
/// <c>active</c> — the full-lockout enforcement point for a suspended/archived/deleting org.
///
/// <para>
/// Deliberately registered <em>after</em> <c>UseRateLimiter</c> rather than immediately after
/// <see cref="SubdomainTenantMiddleware"/> (which only resolves and stashes the context, never
/// refuses): throwing before the rate limiter would remove a suspended tenant's throttle at
/// exactly the moment an operator cut it off, letting it flood the registry unthrottled and
/// unrated. Placing enforcement after auth/authz/CSRF/rate-limiting instead means those stages
/// still run their normal cost and bookkeeping for a request that is refused just short of
/// actually reaching a controller — cheap relative to the resource access (egress, storage,
/// data reads) the gate exists to stop, and it keeps this a single enforcement seam rather than
/// reopening the door to the per-call-site gate this design replaces.
/// </para>
///
/// <para>
/// Writes the response directly via <see cref="TenantNotReadyResponseWriter"/> rather than
/// throwing <see cref="TenantNotReadyException"/> the way <c>ITenantStorageResolver.GetRegistryAsync</c>
/// does: this middleware is registered after <c>UseRateLimiter</c>, which puts it downstream of
/// <c>UseSerilogRequestLogging</c> as well, so a throw here would unwind through it and log an Error-level
/// "responded 500" with a full stack trace for every refused request — a suspended tenant's CI
/// polling every few seconds turns a working-as-designed 423 into a continuous 5xx alert. The
/// structured Warning below is the intended trace for this refusal; nothing about it depends on
/// an exception translator sitting elsewhere in the pipeline.
/// </para>
///
/// <para>
/// <see cref="ExemptPaths"/> is a tight, exact-match allowlist — never a prefix — for the
/// operator/observability surfaces a suspended tenant must not take down: liveness/readiness
/// probes, version/metrics scraping, and the edge status surface are not tenant-bound, and in
/// single mode (the default) <c>SingleTenantResolver</c> resolves every request, probe included,
/// to the one org, so an unexempted gate here would 423 a Kubernetes liveness probe into a crash
/// loop the moment the operator suspended the tenant they were trying to lock out.
/// </para>
/// </summary>
public sealed class TenantStatusEnforcementMiddleware
{
    // Exact paths only — a prefix match would risk silently exempting a tenant-bound route that
    // happens to share a leading segment with an operator surface.
    private static readonly string[] ExemptPaths =
        ["/health", "/ready", "/metrics", "/version", "/edge/status"];

    private readonly RequestDelegate _next;

    public TenantStatusEnforcementMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ILogger<TenantStatusEnforcementMiddleware> logger)
    {
        if (context.Items[TenantContext.HttpItemsKey] is TenantContext { IsTenant: true } ctx
            && ctx.Status != "active"
            && !IsExemptPath(context.Request.Path))
        {
            // A cut-off tenant still driving traffic at the registry is exactly the signal an
            // operator wants after suspending one. Warning, not Information: reaching here means
            // a client is still using credentials for an org that has been administratively
            // stopped. Deliberately not an audit_log write — this is reached on every request
            // from a suspended tenant, which would make audit_log a volume-driven denial of its
            // own, and by this point in the pipeline the caller may still be anonymous (no actor
            // to attribute a row to).
            logger.LogWarning(
                "Refused request for non-active tenant {TenantSlug} ({TenantId}) with status {TenantStatus}: {RequestMethod} {RequestPath} from {SourceIp}",
                ctx.TenantSlug,
                ctx.TenantId,
                ctx.Status,
                context.Request.Method,
                context.Request.Path.Value,
                context.GetNormalizedRemoteIp());

            // orgs.status is constrained to active|suspended|archived|deleting; any non-active
            // value is a full lockout — protocol, management API, and login all refuse. Reuses
            // TenantNotReadyReason.StatusInactive so the mapping is identical to
            // GlobalTenantStorageResolver's gate (423 Locked, reviewable "reason" body). See the
            // class doc comment for why this writes the response directly instead of throwing.
            await TenantNotReadyResponseWriter.WriteAsync(context, TenantNotReadyReason.StatusInactive);
            return;
        }

        await _next(context);
    }

    // ASP.NET Core routing drops a trailing empty segment, so GET /ready/ reaches the same
    // /ready endpoint as GET /ready (proven directly against a scratch host) — a k8s
    // livenessProbe.httpGet.path or a load balancer health check commonly carries that
    // trailing slash. The allowlist has to match on the same basis the router does, or it
    // exempts nothing for the exact configs it exists to protect. Still exact-match, never a
    // prefix: trim at most one trailing slash before comparing, nothing else.
    private static bool IsExemptPath(PathString path)
    {
        string? value = path.Value;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        if (value.Length > 1 && value[^1] == '/')
        {
            value = value[..^1];
        }

        return Array.Exists(ExemptPaths, p => string.Equals(p, value, StringComparison.OrdinalIgnoreCase));
    }
}
