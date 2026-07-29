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
    private readonly DownloadCountWriter? _downloadCountWriter;

    public TenantArtifactAccessRepository(IMetadataStore db, DownloadCountWriter? downloadCountWriter = null)
    {
        _db = db;
        _downloadCountWriter = downloadCountWriter;
    }

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
    /// Upserts per-tenant download state for a proxy artefact: increments
    /// <c>download_count</c> and touches <c>last_used</c> on every call. Always runs
    /// immediately after <see cref="CacheAccessRecorder.RecordAccessAsync"/>, which owns
    /// <c>access_count</c> and <c>last_accessed_at</c> via <see cref="UpsertAsync"/> — so this
    /// method deliberately leaves those columns alone to avoid double-counting the same fetch.
    /// The row therefore always exists by the time this runs (the conflict branch); the insert
    /// branch is the standalone-safety path and seeds <c>access_count = 1</c> for that one case.
    /// </summary>
    public async Task UpsertStateAsync(
        string orgId, string cacheArtifactId, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO tenant_artifact_access (
                org_id, cache_artifact_id, first_accessed_at, last_accessed_at,
                last_used, download_count, access_count)
            VALUES (@orgId, @cacheArtifactId, @at, @at, @at, 1, 1)
            ON CONFLICT (org_id, cache_artifact_id) DO UPDATE SET
                last_used        = excluded.last_used,
                download_count   = tenant_artifact_access.download_count + 1
            """, new { orgId, cacheArtifactId, at });
    }

    /// <summary>
    /// Records a proxy cache-hit download tick without a synchronous write on the request
    /// path. The row is guaranteed to already exist (seeded durably by
    /// <see cref="UpsertStateAsync"/> at first-fetch), so a hit never needs the insert branch —
    /// only the conflict-branch <c>last_used</c>/<c>download_count</c> bump, which the
    /// <see cref="DownloadCountWriter"/> drainer applies in its aggregated batch.
    /// When no writer is wired (e.g. a caller running without the hosted drainer), falls back
    /// to the synchronous <see cref="UpsertStateAsync"/> so the counter is never silently lost.
    /// last_used freshness for cache eviction tolerates the drainer's flush interval (up to
    /// <see cref="DownloadCountWriterHostedService.MaxFlushInterval"/>) — eviction sweeps run
    /// on a much coarser cadence, so a delay of tens to hundreds of milliseconds never causes a
    /// recently-served artifact to be evicted as stale.
    /// </summary>
    public async Task RecordDownloadHitAsync(
        string orgId, string cacheArtifactId, DateTimeOffset at, CancellationToken ct = default)
    {
        if (_downloadCountWriter is not null)
        {
            _downloadCountWriter.TryEnqueue(
                new DownloadCountRecord(VersionId: null, Purl: null, OrgId: orgId, CacheArtifactId: cacheArtifactId));
            return;
        }

        await UpsertStateAsync(orgId, cacheArtifactId, at, ct);
    }

    /// <summary>
    /// Writes (or clears) the per-tenant manual block/allow override on an existing
    /// <c>tenant_artifact_access</c> row. This is the proxy-plane analog of
    /// <see cref="PackageRepository.SetManualBlockStateAsync"/>: the block gate's manual arm
    /// (<see cref="Protocol.BlockGateService.Evaluate"/>) reads
    /// <c>tenant_artifact_access.manual_block_state</c> for cache-hit facts built by
    /// <see cref="Protocol.BlockGateRequest.ForProxyCacheFacts"/>, so this is the only runtime
    /// writer for that column. <paramref name="state"/> is <c>"blocked"</c>, <c>"allowed"</c>,
    /// or <see langword="null"/> to clear the override and restore the automatic gates.
    /// Org-scoped by construction — callers resolve <paramref name="cacheArtifactId"/> through an
    /// org-scoped lookup (e.g. <see cref="CacheArtifactRepository.ListServeFactsForNameAsync"/>),
    /// so a cross-tenant id is never reachable here.
    /// </summary>
    public async Task SetManualBlockStateAsync(
        string orgId, string cacheArtifactId, string? state, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE tenant_artifact_access
            SET manual_block_state = @state
            WHERE org_id = @orgId AND cache_artifact_id = @cacheArtifactId
            """,
            new { orgId, cacheArtifactId, state });
    }

    /// <summary>
    /// Removes <paramref name="orgId"/>'s per-tenant access row for the proxy-cached coordinate
    /// <c>(ecosystem, name, version)</c>, without touching the shared <c>cache_artifact</c> row.
    /// Used by the OCI manifest-delete path (<c>OciController.HandleManifestDeleteAsync</c>) so a
    /// proxy-origin digest this org deleted stops appearing in its
    /// <c>ArtifactInventoryRepository.ListServeableVersionsAsync</c> / <c>artifact_inventory</c> —
    /// both read through an inner join on this table, so dropping the row alone closes the serve
    /// path for this org. The shared row (and the manifest blob it references) is left alone: OCI
    /// <c>cache_artifact</c> rows are excluded from reclamation everywhere else in the cache plane
    /// (see <see cref="CacheArtifactRepository.EvictTenantProxyVersionsForNameAsync"/>) because
    /// dropping one would strand the still-live <c>oci_blobs</c> row and layer blobs another org
    /// (or this org's own re-pull) may still depend on. A no-op when no such row exists (e.g. the
    /// digest was pushed, never proxied).
    /// </summary>
    public async Task RemoveAccessForCoordinateAsync(
        string orgId, string ecosystem, string name, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            DELETE FROM tenant_artifact_access
            WHERE org_id = @orgId
              AND cache_artifact_id IN (
                  SELECT id FROM cache_artifact
                  WHERE ecosystem = @ecosystem AND name = @name AND version = @version
              )
            """,
            new { orgId, ecosystem, name, version });
    }

    /// <summary>
    /// Deletes this org's per-tenant claim on a cache artifact. Used by the management-API
    /// version delete so a removed proxy version no longer counts toward this org's storage
    /// total or dashboard view. Does not touch the shared <c>cache_artifact</c> row or its
    /// blob — see <see cref="CountRemainingAsync"/> for the cross-org refcount gate on those.
    /// </summary>
    public async Task DeleteAsync(string orgId, string cacheArtifactId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // (org_id, cache_artifact_id) PK — org-scoped, no opt-out needed.
        await conn.ExecuteAsync(
            "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @cacheArtifactId",
            new { orgId, cacheArtifactId });
    }

    /// <summary>
    /// Cross-org refcount on a cache artifact — how many orgs still hold a
    /// <c>tenant_artifact_access</c> claim on it. <c>cache_artifact</c> is the shared global
    /// cache index (no org column), so a version delete must not remove the row, or its
    /// content-addressed blob, while any other org's claim survives.
    /// </summary>
    public async Task<int> CountRemainingAsync(string cacheArtifactId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: deliberately cross-tenant — the whole point is counting every org's claim.
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @cacheArtifactId",
            new { cacheArtifactId });
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
        // xtenant: deliberate cross-tenant fan-out — the list of affected tenants IS the answer.
        // Platform-admin scope only; callers enforce.
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
