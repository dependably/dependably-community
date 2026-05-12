namespace Dependably.Infrastructure;

/// <summary>
/// Phase 1 tenant context middleware. Resolves the request's <see cref="TenantContext"/> via the
/// configured <see cref="ITenantResolver"/> and stashes it in <c>HttpContext.Items</c> for
/// downstream consumers (BootstrapController, RouteScopeFilter, future tenant-aware controllers).
///
/// Importantly this middleware is *additive* in Phase 1 — it does not reject requests or rewrite
/// paths. The legacy <c>SubdomainOrgMiddleware</c> still owns request routing for <c>/o/{slug}/...</c>.
/// In Phase 4 the legacy middleware is removed and this middleware (with the
/// <c>LegacyOrgPathAliasMiddleware</c> in front) becomes the routing source of truth.
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
