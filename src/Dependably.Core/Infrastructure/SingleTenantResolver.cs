using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolver for <c>DEPLOYMENT_MODE=single</c> (appliance) deployments. Ignores the Host header
/// and returns the one tenant in the system. Queries the DB per request — one row, negligible
/// cost. No startup caching: avoids stale state on DB restore and avoids any startup-ordering
/// dependency between resolver registration and FirstBootService.
///
/// If no tenant exists yet (FirstBoot has not run, or the tenant was somehow purged), returns
/// <see cref="TenantContext.Uninitialized"/>. The middleware translates that into a 503.
/// </summary>
public sealed class SingleTenantResolver : ITenantResolver
{
    private readonly IMetadataStore _db;

    public SingleTenantResolver(IMetadataStore db)
    {
        _db = db;
    }

    public async Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Active tenants only — if the operator soft-deletes the single tenant, the install
        // becomes Uninitialized (503) until restore. Order is for determinism on the unlikely
        // edge of multiple rows.
        var (Id, Slug) = await conn.QuerySingleOrDefaultAsync<(string Id, string Slug)>(
            "SELECT id, slug FROM orgs WHERE deleted_at IS NULL ORDER BY created_at ASC LIMIT 1");

        return Id is null ? TenantContext.Uninitialized : TenantContext.ForTenant(Id, Slug);
    }
}
