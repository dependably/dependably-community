using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-tenant access tracking on <c>cache_artifact</c>. Upserted on every cache hit
/// and lazy-fetch population. Answers "which tenants accessed (ecosystem, name, version)"
/// for vulnerability response without breaking tenant isolation: the underlying blob is
/// shared, but visibility is tracked per tenant.
/// </summary>
public sealed class TenantArtifactAccessRepository
{
    private readonly IMetadataStore _db;

    public TenantArtifactAccessRepository(IMetadataStore db) { _db = db; }

    /// <summary>
    /// Records access for <paramref name="orgId"/> on <paramref name="cacheArtifactId"/>.
    /// Idempotent: first call inserts, subsequent calls bump <c>access_count</c> and
    /// <c>last_accessed_at</c>. Implemented with provider-agnostic upsert SQL because both
    /// SQLite and Postgres support <c>ON CONFLICT DO UPDATE</c>.
    /// </summary>
    public async Task UpsertAsync(
        string orgId, string cacheArtifactId, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO tenant_artifact_access (
                org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count)
            VALUES (@orgId, @cacheArtifactId, @at, @at, 1)
            ON CONFLICT (org_id, cache_artifact_id) DO UPDATE SET
                last_accessed_at = excluded.last_accessed_at,
                access_count = tenant_artifact_access.access_count + 1
            """, new { orgId, cacheArtifactId, at });
    }

    /// <summary>
    /// Cross-tenant query for vulnerability response. Returns the orgs that have
    /// accessed any artifact matching the coordinate. Platform-admin scope only — callers
    /// must enforce.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListAffectedTenantsAsync(
        string ecosystem, string name, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<string>("""
            SELECT DISTINCT taa.org_id
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE ca.ecosystem = @ecosystem
              AND ca.name = @name
              AND ca.version = @version
            """, new { ecosystem, name, version });
        return rows.AsList();
    }
}
