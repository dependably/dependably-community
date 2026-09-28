using Dependably.Infrastructure.Usage;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Dependably.Infrastructure;

/// <summary>
/// Refuses a request whose resolved <see cref="TenantContext"/> names a tenant that is not
/// <c>active</c>. Two postures: <c>suspended</c>/<c>archived</c>/<c>deleting</c> are a full
/// lockout, refusing every request; <c>read_only</c> is narrower — it admits a safe method
/// (GET/HEAD/OPTIONS) on any plane and any write on the management plane (<c>/api/v1/</c> and
/// SAML's <c>/saml/*</c>, so admins can still manage tokens/members and users can still log in),
/// refusing only a state-changing request routed to a protocol controller (package publish/upload/delete/yank, OCI blob
/// upload and manifest writes, and the equivalent per-ecosystem write routes). A proxy
/// cache-fill is a GET, so it stays admitted — it is not billable hosted storage.
///
/// <para>
/// An <c>active</c> tenant is also held to its usage caps. Under an <c>orgs.usage_posture</c> of
/// <c>uploads_refused</c> or <c>downloads_throttled</c> (<see cref="TenantContext.UsagePosture"/>,
/// computed hourly from <c>org_usage_caps</c>), a protocol-plane POST/PUT/PATCH is refused with
/// <see cref="TenantNotReadyReason.UsageCapReached"/>: 402 problem+json linking to
/// <c>USAGE_CAP_INFO_URL</c> when that is set. DELETE is admitted, because it only lowers usage,
/// as is a POST that is a query rather than a write (npm's bulk advisory lookup), and reads and
/// the management plane are untouched. Throttling downloads is the rate limiter's
/// job, not this gate's. A non-active status is checked first and wins.
/// </para>
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

    // Protocol-plane POSTs that are queries, not writes: the usage-cap refusal admits them. Exact
    // paths, matched the way IsExemptPath matches. npm's bulk advisory lookup is the only one
    // routed today — npm install and npm audit send it with the caller's dependency tree, and
    // refusing it would break installs for an org that is only over a cap. A transparent-intercept
    // request reaches here already rewritten under /npm/.
    private static readonly string[] ReadOnlyProtocolPosts =
        ["/npm/-/npm/v1/security/advisories/bulk"];

    private readonly RequestDelegate _next;
    private readonly string? _usageCapInfoUrl;

    public TenantStatusEnforcementMiddleware(RequestDelegate next, IConfiguration config)
    {
        _next = next;
        _usageCapInfoUrl = TenantNotReadyResponseWriter.ParseUsageCapInfoUrl(config["USAGE_CAP_INFO_URL"]);
    }

    public async Task InvokeAsync(HttpContext context, ILogger<TenantStatusEnforcementMiddleware> logger)
    {
        if (context.Items[TenantContext.HttpItemsKey] is TenantContext { IsTenant: true } ctx
            && ctx.Status != "active"
            && !IsExemptPath(context.Request.Path))
        {
            if (ctx.Status == "read_only" && IsReadOnlyAdmittedRequest(context))
            {
                await _next(context);
                return;
            }

            // A cut-off (or read-only-but-writing) tenant still driving traffic at the registry is
            // exactly the signal an operator wants after changing its status. Warning, not
            // Information: reaching here means a client is still using credentials for an org that
            // has been administratively stopped or narrowed. Deliberately not an audit_log write —
            // this is reached on every refused request from such a tenant, which would make
            // audit_log a volume-driven denial of its own, and by this point in the pipeline the
            // caller may still be anonymous (no actor to attribute a row to).
            logger.LogWarning(
                "Refused request for non-active tenant {TenantSlug} ({TenantId}) with status {TenantStatus}: {RequestMethod} {RequestPath} from {SourceIp}",
                ctx.TenantSlug,
                ctx.TenantId,
                ctx.Status,
                context.Request.Method,
                context.Request.Path.Value,
                context.GetNormalizedRemoteIp());

            // orgs.status is constrained to active|suspended|archived|deleting|read_only.
            // 'read_only' reaching this point already failed IsReadOnlyAdmittedRequest above — a
            // state-changing protocol-plane request — and gets the narrower ReadOnlyWrite reason.
            // Every other non-active value is a full lockout — protocol, management API, and login
            // all refuse — and keeps TenantNotReadyReason.StatusInactive so the mapping is identical
            // to GlobalTenantStorageResolver's gate (423 Locked, reviewable "reason" body). See the
            // class doc comment for why this writes the response directly instead of throwing.
            var reason = ctx.Status == "read_only"
                ? TenantNotReadyReason.ReadOnlyWrite
                : TenantNotReadyReason.StatusInactive;
            await TenantNotReadyResponseWriter.WriteAsync(context, reason);
            return;
        }

        if (context.Items[TenantContext.HttpItemsKey] is TenantContext { IsTenant: true } capped
            && UsagePostures.RefusesUploads(capped.UsagePosture)
            && IsProtocolPlaneWrite(context)
            && !IsExemptPath(context.Request.Path))
        {
            // Warning for the same reason as the status refusal above: a client still pushing to an
            // org that has reached a cap is the signal the operator wants, and a per-request
            // audit_log row would let the refused client drive audit volume.
            logger.LogWarning(
                "Refused write for tenant {TenantSlug} ({TenantId}) under usage posture {UsagePosture}: {RequestMethod} {RequestPath} from {SourceIp}",
                capped.TenantSlug,
                capped.TenantId,
                capped.UsagePosture,
                context.Request.Method,
                context.Request.Path.Value,
                context.GetNormalizedRemoteIp());

            await TenantNotReadyResponseWriter.WriteAsync(
                context, TenantNotReadyReason.UsageCapReached, _usageCapInfoUrl);
            return;
        }

        await _next(context);
    }

    // The writes a usage cap refuses: a POST/PUT/PATCH routed to a protocol controller (classified
    // by endpoint, so SAML's /saml/acs sign-in POST is management plane), other than a
    // read-only query POST (ReadOnlyProtocolPosts). DELETE is not among them — removing an
    // artefact lowers usage, and refusing it would leave an org at its cap no way back under it
    // short of an operator.
    private static bool IsProtocolPlaneWrite(HttpContext context) =>
        (HttpMethods.IsPut(context.Request.Method)
         || HttpMethods.IsPatch(context.Request.Method)
         || (HttpMethods.IsPost(context.Request.Method) && !MatchesExactly(context.Request.Path, ReadOnlyProtocolPosts)))
        && RateLimitPartitions.IsProtocolControllerRequest(context);

    // A read-only org admits a request that either cannot change state (a safe HTTP method reads
    // on every plane, protocol included — a proxy cache-fill triggered by a GET is not billable
    // hosted storage) or that is not routed to a protocol controller (org settings, tokens,
    // members, and login all keep working, including SAML's /saml/acs sign-in POST, which routes
    // outside /api/v1/). The protocol plane is classified by the routed endpoint
    // (RateLimitPartitions.IsProtocolControllerRequest), not by path prefix, for exactly that
    // reason. Everything else is a state-changing protocol-plane request and is refused.
    private static bool IsReadOnlyAdmittedRequest(HttpContext context) =>
        HttpMethods.IsGet(context.Request.Method)
        || HttpMethods.IsHead(context.Request.Method)
        || HttpMethods.IsOptions(context.Request.Method)
        || !RateLimitPartitions.IsProtocolControllerRequest(context);

    // ASP.NET Core routing drops a trailing empty segment, so GET /ready/ reaches the same
    // /ready endpoint as GET /ready (proven directly against a scratch host) — a k8s
    // livenessProbe.httpGet.path or a load balancer health check commonly carries that
    // trailing slash. The allowlist has to match on the same basis the router does, or it
    // exempts nothing for the exact configs it exists to protect. Still exact-match, never a
    // prefix: trim at most one trailing slash before comparing, nothing else.
    internal static bool IsExemptPath(PathString path) => MatchesExactly(path, ExemptPaths);

    private static bool MatchesExactly(PathString path, string[] paths)
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

        return Array.Exists(paths, p => string.Equals(p, value, StringComparison.OrdinalIgnoreCase));
    }
}
