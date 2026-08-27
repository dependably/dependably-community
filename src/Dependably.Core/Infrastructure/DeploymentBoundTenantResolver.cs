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
        string? slug = config["BOUND_TENANT_SLUG"];
        if (string.IsNullOrWhiteSpace(slug))
        {
            throw new InvalidOperationException(
                "DEPLOYMENT_MODE=bound requires BOUND_TENANT_SLUG to be set.");
        }

        _boundSlug = slug.Trim().ToLowerInvariant();
    }

    public async Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Status flows through to TenantContext so TenantStatusEnforcementMiddleware can refuse
        // a suspended/archived/deleting tenant the same way every other resolver strategy does.
        var (Id, Slug, Status) = await conn.QuerySingleOrDefaultAsync<(string Id, string Slug, string Status)>(
            "SELECT id, slug, status FROM orgs WHERE slug = @slug AND deleted_at IS NULL LIMIT 1",
            new { slug = _boundSlug });

        return Id is null ? TenantContext.Uninitialized : TenantContext.ForTenant(Id, Slug, Status);
    }
}
