namespace Dependably.Infrastructure;

/// <summary>
/// Per-request tenant context produced by <see cref="ITenantResolver"/> and stashed in
/// <c>HttpContext.Items["TenantContext"]</c>. Encodes which surface the request is hitting:
/// the apex (system_admin) surface, a specific tenant, or an uninitialized installation.
/// </summary>
public sealed record TenantContext(
    bool IsApex,
    bool IsTenant,
    bool IsUninitialized,
    string? TenantId,
    string? TenantSlug)
{
    public const string HttpItemsKey = "TenantContext";

    public static TenantContext Apex { get; } = new(true, false, false, null, null);

    public static TenantContext Uninitialized { get; } = new(false, false, true, null, null);

    public static TenantContext ForTenant(string tenantId, string tenantSlug) =>
        new(false, true, false, tenantId, tenantSlug);
}
