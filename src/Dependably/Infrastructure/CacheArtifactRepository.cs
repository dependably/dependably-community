using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Persistence for the global shared proxy-cache index (#48). One row per
/// <c>(ecosystem, name, version, filename)</c>; no tenant column. Per-tenant access lives in
/// <see cref="TenantArtifactAccessRepository"/>.
/// </summary>
public sealed class CacheArtifactRepository
{
    private readonly IMetadataStore _db;

    public CacheArtifactRepository(IMetadataStore db) { _db = db; }

    public async Task<CacheArtifact?> GetByCoordinateAsync(
        string ecosystem, string name, string version, string filename, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<CacheArtifact>("""
            SELECT id AS Id, ecosystem AS Ecosystem, name AS Name, version AS Version,
                   filename AS Filename, blob_key AS BlobKey, content_hash AS ContentHash,
                   size_bytes AS SizeBytes, upstream_url AS UpstreamUrl,
                   upstream_etag AS UpstreamEtag, first_cached_at AS FirstCachedAt,
                   last_accessed_at AS LastAccessedAt
            FROM cache_artifact
            WHERE ecosystem = @ecosystem AND name = @name
              AND version = @version AND filename = @filename
            """, new { ecosystem, name, version, filename });
    }

    /// <summary>
    /// Inserts a new cache artifact row and returns the persisted record. Idempotent on the
    /// unique coordinate index — a concurrent first-fetch race resolves to a single row.
    /// </summary>
    public async Task<CacheArtifact> InsertAsync(CacheArtifact artifact, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact (
                id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                upstream_url, upstream_etag, first_cached_at, last_accessed_at)
            VALUES (
                @Id, @Ecosystem, @Name, @Version, @Filename, @BlobKey, @ContentHash, @SizeBytes,
                @UpstreamUrl, @UpstreamEtag, @FirstCachedAt, @LastAccessedAt)
            """, artifact);
        return artifact;
    }

    public async Task TouchAccessAsync(string id, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET last_accessed_at = @at WHERE id = @id",
            new { id, at });
    }

    /// <summary>
    /// Returns artifacts eligible for LRU eviction in oldest-access-first order. The caller
    /// decides how many to evict per pass based on size/count caps.
    /// </summary>
    public async Task<IReadOnlyList<CacheArtifact>> ListLruCandidatesAsync(
        DateTimeOffset olderThan, int limit, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<CacheArtifact>("""
            SELECT id AS Id, ecosystem AS Ecosystem, name AS Name, version AS Version,
                   filename AS Filename, blob_key AS BlobKey, content_hash AS ContentHash,
                   size_bytes AS SizeBytes, upstream_url AS UpstreamUrl,
                   upstream_etag AS UpstreamEtag, first_cached_at AS FirstCachedAt,
                   last_accessed_at AS LastAccessedAt
            FROM cache_artifact
            WHERE last_accessed_at < @olderThan
            ORDER BY last_accessed_at ASC
            LIMIT @limit
            """, new { olderThan, limit });
        return rows.AsList();
    }

    public async Task<long> GetTotalSizeBytesAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM cache_artifact");
    }

    public async Task DeleteAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = @id", new { id });
    }
}

public sealed class CacheArtifact
{
    public string Id { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string Name { get; init; } = "";
    public string Version { get; init; } = "";
    public string Filename { get; init; } = "";
    public string BlobKey { get; init; } = "";
    public string ContentHash { get; init; } = "";
    public long SizeBytes { get; init; }
    public string? UpstreamUrl { get; init; }
    public string? UpstreamEtag { get; init; }
    public DateTimeOffset FirstCachedAt { get; init; }
    public DateTimeOffset LastAccessedAt { get; init; }
}
