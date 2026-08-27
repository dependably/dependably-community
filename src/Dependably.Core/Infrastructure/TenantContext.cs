namespace Dependably.Infrastructure;

/// <summary>
/// Per-request tenant context produced by <see cref="ITenantResolver"/> and stashed in
/// <c>HttpContext.Items["TenantContext"]</c>. Encodes which surface the request is hitting:
/// the apex (system_admin) surface, a specific tenant, or an uninitialized installation.
///
/// <para>
/// <see cref="Status"/> carries the resolved <c>orgs.status</c> value for a tenant hit
/// (<c>active</c>/<c>suspended</c>/<c>archived</c>/<c>deleting</c>) so
/// <c>TenantStatusEnforcementMiddleware</c> can refuse a non-active tenant before it reaches a
/// controller — the single seam every tenant-bound request crosses, rather than a gate each
/// bypassable call site has to remember. Null for <see cref="Apex"/> and
/// <see cref="Uninitialized"/>, which carry no tenant row.
/// </para>
/// </summary>
public sealed record TenantContext(
    bool IsApex,
    bool IsTenant,
    bool IsUninitialized,
    string? TenantId,
    string? TenantSlug,
    string? Status = null)
{
    public const string HttpItemsKey = "TenantContext";

    public static TenantContext Apex { get; } = new(true, false, false, null, null);

    public static TenantContext Uninitialized { get; } = new(false, false, true, null, null);

    public static TenantContext ForTenant(string tenantId, string tenantSlug, string status = "active") =>
        new(false, true, false, tenantId, tenantSlug, status);
}
