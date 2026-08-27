namespace Dependably.Infrastructure;

/// <summary>
/// Resolves the request's <see cref="TenantContext"/> via the configured
/// <see cref="ITenantResolver"/> and stashes it in <c>HttpContext.Items</c> for downstream
/// consumers (controllers, <c>RouteScopeFilter</c>, <c>UploadSizeLimitMiddleware</c>).
///
/// The resolver strategy is selected at startup by <c>DEPLOYMENT_MODE</c>:
/// <c>single</c> (default) always returns the one org; <c>multi</c> reads the Host header
/// and maps the subdomain to a tenant slug; <c>header</c> and <c>bound</c> are intercept
/// modes for enterprise edge-proxy deployments.
///
/// <para>
/// This middleware only resolves and stashes — it never refuses. The refusal for a resolved
/// tenant whose <c>orgs.status</c> is not <c>active</c> lives in
/// <see cref="TenantStatusEnforcementMiddleware"/>, registered after <c>UseRateLimiter</c> rather
/// than here: throwing this early would skip rate limiting entirely for every request from a
/// suspended tenant (removing its throttle at exactly the moment an operator cut it off) and
/// would 423 the health/ready/metrics/version probes that single mode resolves against the one
/// org regardless of Host. Splitting resolution (needed immediately, by almost everything downstream)
/// from enforcement (deferred, so the rate limiter and the exempt operator surfaces still run)
/// keeps this a single enforcement seam without paying either cost.
/// </para>
/// </summary>
public sealed class SubdomainTenantMiddleware
{
    private readonly RequestDelegate _next;

    public SubdomainTenantMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ITenantResolver resolver)
    {
        var ctx = await resolver.ResolveAsync(context, context.RequestAborted);
        context.Items[TenantContext.HttpItemsKey] = ctx;
        await _next(context);
    }
}
