using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolver for <c>DEPLOYMENT_MODE=bound</c> deployments. Pinned to a single configured tenant
/// regardless of Host header or any other request context. This is the common shape for
/// transparent intercept at an enterprise customer that has exactly one tenant: the
/// instance pretends to be <c>registry.npmjs.org</c> et al. for that one organisation.
///
/// Configure via <c>BOUND_TENANT_SLUG</c>. The slug is resolved on every request (one indexed
/// lookup) so soft-deletion immediately makes the install Uninitialized without restart.
/// </summary>
public sealed class DeploymentBoundTenantResolver : ITenantResolver
{
    private readonly IMetadataStore _db;
    private readonly string _boundSlug;

    public DeploymentBoundTenantResolver(IMetadataStore db, IConfiguration config)
    {
        _db = db;
        var slug = config["BOUND_TENANT_SLUG"];
        if (string.IsNullOrWhiteSpace(slug))
            throw new InvalidOperationException(
                "DEPLOYMENT_MODE=bound requires BOUND_TENANT_SLUG to be set.");
        _boundSlug = slug.Trim().ToLowerInvariant();
    }

    public async Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<(string Id, string Slug)>(
            "SELECT id, slug FROM orgs WHERE slug = @slug AND deleted_at IS NULL LIMIT 1",
            new { slug = _boundSlug });

        if (row.Id is null) return TenantContext.Uninitialized;
        return TenantContext.ForTenant(row.Id, row.Slug);
    }
}
