using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolver for <c>DEPLOYMENT_MODE=multi</c> deployments. Reads the Host header (or
/// <c>X-Forwarded-Host</c> when behind a reverse proxy), strips the apex suffix, and looks up
/// the tenant by slug.
///
/// Apex hits (host == apex) → <see cref="TenantContext.Apex"/>.
/// Subdomain hits with a known, non-reserved slug → <see cref="TenantContext.ForTenant"/>.
/// Anything else → <see cref="TenantContext.Uninitialized"/> (translated to 404 by the middleware).
/// </summary>
public sealed class SubdomainTenantResolver : ITenantResolver
{
    private readonly IMetadataStore _db;
    private readonly string _apexHost;
    private readonly IReadOnlySet<string> _extraReserved;

    public SubdomainTenantResolver(IMetadataStore db, IConfiguration config)
    {
        _db = db;

        // Prefer APEX_HOST when set (multi mode). Fall back to deriving from BASE_URL so
        // existing single-tenant installs that already configure BASE_URL continue to work
        // when promoted to multi mode without a separate config flip.
        var apex = config["APEX_HOST"];
        if (string.IsNullOrWhiteSpace(apex))
        {
            var baseUrl = config["BASE_URL"];
            if (!string.IsNullOrWhiteSpace(baseUrl) &&
                Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
            {
                apex = uri.Host;
            }
        }

        _apexHost = (apex ?? "")
            .ToLowerInvariant()
            .TrimEnd('.');

        _extraReserved = ReservedSlugs.ParseExtra(config["RESERVED_SUBDOMAINS"]);
    }

    public async Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_apexHost)) return TenantContext.Uninitialized;

        // X-Forwarded-Host wins when present (matches existing SubdomainOrgMiddleware semantics).
        var rawHost = context.Request.Headers["X-Forwarded-Host"].FirstOrDefault()
            ?? context.Request.Host.Host;
        if (string.IsNullOrEmpty(rawHost)) return TenantContext.Uninitialized;

        // Strip port and trailing dot, lowercase.
        var host = rawHost.ToLowerInvariant().TrimEnd('.');
        var colonIdx = host.IndexOf(':');
        if (colonIdx >= 0) host = host[..colonIdx];

        if (host == _apexHost) return TenantContext.Apex;

        var suffix = "." + _apexHost;
        if (!host.EndsWith(suffix, StringComparison.Ordinal)) return TenantContext.Uninitialized;

        var rawSlug = host[..^suffix.Length];

        // Reject sub-subdomains (e.g. foo.bar.apex) — only single-label slugs are tenants.
        if (rawSlug.Contains('.', StringComparison.Ordinal)) return TenantContext.Uninitialized;

        var slug = ReservedSlugs.Normalize(rawSlug, _extraReserved);
        if (slug is null) return TenantContext.Uninitialized;

        await using var conn = await _db.OpenAsync(ct);
        // Soft-deleted tenants are immediately inaccessible — the subdomain returns 404 until
        // system_admin restores within the grace window.
        var row = await conn.QuerySingleOrDefaultAsync<(string Id, string Slug)>(
            "SELECT id, slug FROM orgs WHERE slug = @slug AND deleted_at IS NULL LIMIT 1",
            new { slug });

        if (row.Id is null) return TenantContext.Uninitialized;
        return TenantContext.ForTenant(row.Id, row.Slug);
    }
}
