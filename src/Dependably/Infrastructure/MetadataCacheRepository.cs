using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// TTL-cached upstream metadata documents (#48). Global, no tenant column — metadata is the
/// same for all tenants reading the same upstream. Per-tenant access is not tracked
/// (low privacy value; metadata changes too often for tracking to be useful).
///
/// Default TTLs per cross-cutting-decisions.md: 60s for npm, 300s for PyPI, 600s for NuGet.
/// All configurable via <c>METADATA_TTL_{ECOSYSTEM}</c>.
/// </summary>
public sealed class MetadataCacheRepository
{
    private readonly IMetadataStore _db;

    public MetadataCacheRepository(IMetadataStore db) { _db = db; }

    public async Task<MetadataCacheEntry?> GetFreshAsync(
        string ecosystem, string name, DateTimeOffset now, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<MetadataCacheEntry>("""
            SELECT id AS Id, ecosystem AS Ecosystem, name AS Name, document AS Document,
                   content_hash AS ContentHash, upstream_etag AS UpstreamEtag,
                   fetched_at AS FetchedAt, expires_at AS ExpiresAt
            FROM metadata_cache
            WHERE ecosystem = @ecosystem AND name = @name AND expires_at > @now
            """, new { ecosystem, name, now });
    }

    public async Task UpsertAsync(MetadataCacheEntry entry, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO metadata_cache (
                id, ecosystem, name, document, content_hash, upstream_etag, fetched_at, expires_at)
            VALUES (@Id, @Ecosystem, @Name, @Document, @ContentHash, @UpstreamEtag, @FetchedAt, @ExpiresAt)
            ON CONFLICT (ecosystem, name) DO UPDATE SET
                document = excluded.document,
                content_hash = excluded.content_hash,
                upstream_etag = excluded.upstream_etag,
                fetched_at = excluded.fetched_at,
                expires_at = excluded.expires_at
            """, entry);
    }

    public async Task<int> PurgeExpiredAsync(DateTimeOffset before, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            "DELETE FROM metadata_cache WHERE expires_at < @before",
            new { before });
    }
}

public sealed class MetadataCacheEntry
{
    public string Id { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string Name { get; init; } = "";
    public string Document { get; init; } = "";
    public string ContentHash { get; init; } = "";
    public string? UpstreamEtag { get; init; }
    public DateTimeOffset FetchedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
}
