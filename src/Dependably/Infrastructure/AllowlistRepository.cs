using Dapper;

namespace Dependably.Infrastructure;

public sealed class AllowlistRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public AllowlistRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    public async Task<IReadOnlyList<AllowlistEntry>> ListAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<AllowlistEntry>(
            """
            SELECT id, org_id as OrgId, purl_pattern as PurlPattern, created_at as CreatedAt
            FROM allowlist WHERE org_id = @orgId
            ORDER BY purl_pattern
            """,
            new { orgId });
        return rows.ToList();
    }

    public async Task<AllowlistEntry> AddAsync(
        string orgId, string purlPattern, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO allowlist (id, org_id, purl_pattern)
            VALUES (@id, @orgId, @purlPattern)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, purlPattern });
        return new AllowlistEntry { Id = id, OrgId = orgId, PurlPattern = purlPattern, CreatedAt = _time.GetUtcNow() };
    }

    /// <summary>
    /// Deletes an allowlist entry, scoped to <paramref name="orgId"/>. Returns the number of rows
    /// removed (0 when the id belongs to another tenant or does not exist) so the caller can 404
    /// without revealing cross-tenant existence. The id is a global PK, so the org_id predicate is
    /// what enforces tenant isolation here.
    /// </summary>
    public async Task<int> DeleteAsync(string orgId, string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            "DELETE FROM allowlist WHERE id = @id AND org_id = @orgId", new { id = entryId, orgId });
    }
}
