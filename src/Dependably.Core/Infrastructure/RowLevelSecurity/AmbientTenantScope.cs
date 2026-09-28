namespace Dependably.Infrastructure.RowLevelSecurity;

/// <summary>What the ambient request context says a plain <c>OpenAsync</c> connection belongs to.</summary>
public enum AmbientTenantKind
{
    /// <summary>No resolved tenant: the connection carries no tenant and tenant-scoped rows raise.</summary>
    None,

    /// <summary>A resolved tenant request.</summary>
    Tenant,

    /// <summary>The apex (system-admin) surface, which is cross-tenant by design.</summary>
    Apex,
}

public readonly record struct AmbientTenant(AmbientTenantKind Kind, string? OrgId)
{
    public static AmbientTenant None { get; } = new(AmbientTenantKind.None, null);
}

/// <summary>Supplies the tenant a request-path connection is bound to.</summary>
public interface IAmbientTenantScope
{
    AmbientTenant Current { get; }
}

/// <summary>
/// Reads the host-resolved <see cref="TenantContext"/> that <c>SubdomainTenantMiddleware</c> stores
/// on the request. The value is the tenant the host (or trusted header) named, which
/// <c>RouteScopeFilter</c> already reconciles against the caller's token — never a route value.
/// Outside a request there is no context and the connection binds to no tenant, so work that
/// escapes the request (a fire-and-forget task, a channel consumer) fails loudly rather than
/// inheriting a tenant.
/// </summary>
public sealed class HttpContextAmbientTenantScope(IHttpContextAccessor accessor) : IAmbientTenantScope
{
    public AmbientTenant Current =>
        accessor.HttpContext?.Items[TenantContext.HttpItemsKey] switch
        {
            TenantContext { IsTenant: true, TenantId: { Length: > 0 } id } => new AmbientTenant(AmbientTenantKind.Tenant, id),
            TenantContext { IsApex: true } => new AmbientTenant(AmbientTenantKind.Apex, null),
            _ => AmbientTenant.None,
        };
}
