using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Persists and retrieves npm dist-tags for hosted packages. Tags are set on publish
/// (client sends dist-tags in the packument) and via the dist-tag management endpoints.
/// Each (package_id, tag) pair is unique; upsert semantics keep the version current.
/// </summary>
public sealed class NpmDistTagRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public NpmDistTagRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Returns all dist-tags for <paramref name="packageId"/> as a tag → version dictionary.
    /// </summary>
    public async Task<Dictionary<string, string>> GetTagsAsync(
        string orgId, string packageId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Tag, string Version)>(
            """
            SELECT tag AS Tag, version AS Version
            FROM npm_dist_tags
            WHERE org_id = @orgId AND package_id = @packageId
            """,
            new { orgId, packageId });
        return rows.ToDictionary(r => r.Tag, r => r.Version);
    }

    /// <summary>
    /// Sets (upserts) a single dist-tag to <paramref name="version"/> for the given package.
    /// </summary>
    public async Task SetTagAsync(
        string orgId, string packageId, string tag, string version, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO npm_dist_tags (id, org_id, package_id, tag, version, created_at, updated_at)
            VALUES (@id, @orgId, @packageId, @tag, @version, @now, @now)
            ON CONFLICT(package_id, tag) DO UPDATE
                SET version = excluded.version, updated_at = excluded.updated_at
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, packageId, tag, version, now });
    }

    /// <summary>
    /// Removes a dist-tag. Returns <see langword="true"/> when a row was deleted.
    /// </summary>
    public async Task<bool> DeleteTagAsync(
        string orgId, string packageId, string tag, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(
            """
            DELETE FROM npm_dist_tags
            WHERE org_id = @orgId AND package_id = @packageId AND tag = @tag
            """,
            new { orgId, packageId, tag });
        return affected > 0;
    }

    /// <summary>
    /// Deletes all dist-tag rows for <paramref name="packageId"/> that point at
    /// <paramref name="version"/>. Returns the set of tag names that were removed so the
    /// caller can decide whether to re-point any of them (e.g. re-anchor 'latest').
    /// </summary>
    public async Task<IReadOnlyList<string>> DeleteTagsForVersionAsync(
        string orgId, string packageId, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var removed = (await conn.QueryAsync<string>(
            """
            DELETE FROM npm_dist_tags
            WHERE org_id = @orgId AND package_id = @packageId AND version = @version
            RETURNING tag
            """,
            new { orgId, packageId, version })).AsList();
        return removed;
    }
}
