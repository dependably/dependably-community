using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolver for <c>DEPLOYMENT_MODE=header</c> deployments. Reads the tenant slug from a configured
/// header (default <c>X-Dependably-Tenant</c>, override via <c>TENANT_HEADER_NAME</c>) injected by
/// an upstream edge proxy. Suitable for managed multi-tenant deployments under transparent
/// intercept where subdomain resolution is not viable because the host is owned by an
/// impersonated public registry.
///
/// Trust boundary: the header names the tenant whose packages the request is served, so it is
/// honoured only on requests whose socket peer is listed in <c>TRUSTED_PROXIES</c> — the same
/// fail-closed rule <c>ForwardedHeadersMiddleware</c> applies to <c>X-Forwarded-*</c>, evaluated
/// through the same matcher. With <c>TRUSTED_PROXIES</c> unset, no peer is trusted and every
/// request resolves uninitialized, because a header taken from an arbitrary caller resolves a
/// tenant for the unauthenticated protocol surfaces (<c>/simple/</c>, <c>/npm/</c>, <c>/v2/</c>)
/// that have no JWT for <c>RouteScopeFilter</c> to cross-check: any client could then read another
/// org's artifacts wherever anonymous pull is on. <c>CoreStartupService</c> logs a startup warning
/// naming this when <c>DEPLOYMENT_MODE=header</c> is selected without <c>TRUSTED_PROXIES</c>.
///
/// The peer is read from <see cref="OriginalPeerMiddleware"/>'s recorded socket address, not from
/// <c>Connection.RemoteIpAddress</c>: forwarded-header processing runs earlier in the pipeline and
/// rewrites that property to the client address the proxy forwarded, which is never the proxy's own.
/// </summary>
public sealed class HeaderTenantResolver : ITenantResolver
{
    private const string DefaultHeaderName = "X-Dependably-Tenant";

    private readonly IMetadataStore _db;
    private readonly string _headerName;
    private readonly IReadOnlySet<string> _extraReserved;
    private readonly IReadOnlyList<System.Net.IPNetwork> _trustedNetworks;
    private readonly IReadOnlyList<System.Net.IPAddress> _trustedProxies;

    public HeaderTenantResolver(IMetadataStore db, IConfiguration config)
    {
        _db = db;
        string? configured = config["TENANT_HEADER_NAME"];
        _headerName = string.IsNullOrWhiteSpace(configured) ? DefaultHeaderName : configured.Trim();
        _extraReserved = ReservedSlugs.ParseExtra(config["RESERVED_SUBDOMAINS"]);
        var (networks, proxies) = ConfigurationExtensions.ParseTrustedProxies(config["TRUSTED_PROXIES"]);
        _trustedNetworks = networks;
        _trustedProxies = proxies;
    }

    public async Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default)
    {
        string? raw = context.Request.Headers[_headerName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return TenantContext.Uninitialized;
        }

        if (!ConfigurationExtensions.IsTrustedProxyPeer(
                OriginalPeerMiddleware.Read(context), _trustedNetworks, _trustedProxies))
        {
            return TenantContext.Uninitialized;
        }

        string? slug = ReservedSlugs.Normalize(raw, _extraReserved);
        if (slug is null)
        {
            return TenantContext.Uninitialized;
        }

        await using var conn = await _db.OpenAsync(ct);
        var (Id, Slug) = await conn.QuerySingleOrDefaultAsync<(string Id, string Slug)>(
            "SELECT id, slug FROM orgs WHERE slug = @slug AND deleted_at IS NULL LIMIT 1",
            new { slug });

        return Id is null ? TenantContext.Uninitialized : TenantContext.ForTenant(Id, Slug);
    }
}
