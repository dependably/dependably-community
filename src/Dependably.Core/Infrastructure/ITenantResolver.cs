namespace Dependably.Infrastructure;

/// <summary>
/// Resolves the tenant for an incoming HTTP request. Implementations vary by deployment mode:
/// single-tenant ("appliance") deployments use <see cref="SingleTenantResolver"/>, multi-tenant
/// SaaS-style deployments use <see cref="SubdomainTenantResolver"/>.
///
/// Resolution returns a 404-ish <see cref="TenantContext.Uninitialized"/> for unknown subdomains
/// or when no tenant exists yet — <c>TenantStatusEnforcementMiddleware</c> answers a protocol
/// request under it (or under <see cref="TenantContext.Apex"/>) with a 404 response.
/// </summary>
public interface ITenantResolver
{
    Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default);
}
