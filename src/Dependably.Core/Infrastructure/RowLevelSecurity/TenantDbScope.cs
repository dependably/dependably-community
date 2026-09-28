namespace Dependably.Infrastructure.RowLevelSecurity;

/// <summary>
/// The tenant a Postgres connection is bound to under row-level security. It is deliberately not
/// constructible from an arbitrary string on the request path: <see cref="FromTenantContext"/>
/// takes the host-resolved <see cref="TenantContext"/>, so the database tenant cannot be sourced
/// from a route parameter or a repository's <c>orgId</c> argument. <see cref="ForOrgIteration"/>
/// exists for background work that walks the <c>orgs</c> table one tenant at a time.
/// </summary>
public readonly record struct TenantDbScope
{
    private TenantDbScope(string orgId) => OrgId = orgId;

    /// <summary>The bound tenant; null only on <c>default(TenantDbScope)</c>, which stores reject.</summary>
    public string? OrgId { get; }

    /// <summary>Binds to the tenant the request resolved to. Throws for an apex or uninitialized context.</summary>
    public static TenantDbScope FromTenantContext(TenantContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context is { IsTenant: true, TenantId: { Length: > 0 } id }
            ? new TenantDbScope(id)
            : throw new InvalidOperationException("A tenant database scope needs a resolved tenant context.");
    }

    /// <summary>
    /// Binds to one org of a background loop over <c>orgs</c>. Open a new connection per org —
    /// a bound connection is never re-pointed at another tenant.
    /// </summary>
    public static TenantDbScope ForOrgIteration(string orgId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orgId);
        return new TenantDbScope(orgId);
    }
}
