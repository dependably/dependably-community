using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolver for <c>DEPLOYMENT_MODE=header</c> deployments. Reads the tenant slug from a configured
/// header (default <c>X-Dependably-Tenant</c>, override via <c>TENANT_HEADER_NAME</c>) injected by
/// an upstream edge proxy. Suitable for managed multi-tenant deployments under transparent
/// intercept (#43) where subdomain resolution is not viable because the host is owned by an
/// impersonated public registry.
///
/// Trust assumption: the edge proxy is the only path into the application. If the application
/// can be reached directly, the header is forgeable and this resolver is unsafe — document the
/// requirement in the deployment guide.
/// </summary>
public sealed class HeaderTenantResolver : ITenantResolver
{
    private const string DefaultHeaderName = "X-Dependably-Tenant";

    private readonly IMetadataStore _db;
    private readonly string _headerName;
    private readonly IReadOnlySet<string> _extraReserved;

    public HeaderTenantResolver(IMetadataStore db, IConfiguration config)
    {
        _db = db;
        var configured = config["TENANT_HEADER_NAME"];
        _headerName = string.IsNullOrWhiteSpace(configured) ? DefaultHeaderName : configured.Trim();
        _extraReserved = ReservedSlugs.ParseExtra(config["RESERVED_SUBDOMAINS"]);
    }

    public async Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default)
    {
        var raw = context.Request.Headers[_headerName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(raw)) return TenantContext.Uninitialized;

        var slug = ReservedSlugs.Normalize(raw, _extraReserved);
        if (slug is null) return TenantContext.Uninitialized;

        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<(string Id, string Slug)>(
            "SELECT id, slug FROM orgs WHERE slug = @slug AND deleted_at IS NULL LIMIT 1",
            new { slug });

        if (row.Id is null) return TenantContext.Uninitialized;
        return TenantContext.ForTenant(row.Id, row.Slug);
    }
}
