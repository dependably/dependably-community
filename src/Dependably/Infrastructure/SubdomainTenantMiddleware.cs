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
