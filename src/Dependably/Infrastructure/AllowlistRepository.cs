using Dapper;

namespace Dependably.Infrastructure;

public sealed class AllowlistRepository
{
    private readonly IMetadataStore _db;

    public AllowlistRepository(IMetadataStore db) => _db = db;

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
        var id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO allowlist (id, org_id, purl_pattern)
            VALUES (@id, @orgId, @purlPattern)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, purlPattern });
        return new AllowlistEntry { Id = id, OrgId = orgId, PurlPattern = purlPattern, CreatedAt = DateTimeOffset.UtcNow };
    }

    public async Task DeleteAsync(string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM allowlist WHERE id = @id", new { id = entryId });
    }
}
