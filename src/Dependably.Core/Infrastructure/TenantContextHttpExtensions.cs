namespace Dependably.Infrastructure;

/// <summary>
/// The one read of a request's resolved tenant id for code that runs only once a tenant is known
/// to be resolved: a protocol controller (which <c>TenantStatusEnforcementMiddleware</c> never
/// lets a request without a tenant reach) or a management action after
/// <c>OrgAccessGuard.AuthorizeCapAsync</c> has returned null.
/// </summary>
public static class TenantContextHttpExtensions
{
    /// <summary>
    /// The resolved tenant id. Throws rather than returning null when no tenant is resolved
    /// (apex, uninitialized, or no context at all), so a null org id cannot travel into a query
    /// or a cache key if the ordering above is ever broken.
    /// </summary>
    public static string RequireTenantId(this HttpContext context) =>
        context.Items[TenantContext.HttpItemsKey] is TenantContext { TenantId: { Length: > 0 } tenantId }
            ? tenantId
            : throw new InvalidOperationException(
                "No tenant is resolved for this request; a tenant-bound action ran without the tenant gate.");
}
