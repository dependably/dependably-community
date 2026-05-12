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
            SELECT id, org_id as OrgId, ecosystem, purl_pattern as PurlPattern, created_at as CreatedAt
            FROM allowlist WHERE org_id = @orgId
            ORDER BY ecosystem, purl_pattern
            """,
            new { orgId });
        return rows.ToList();
    }

    public async Task<AllowlistEntry> AddAsync(
        string orgId, string ecosystem, string purlPattern, CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO allowlist (id, org_id, ecosystem, purl_pattern)
            VALUES (@id, @orgId, @ecosystem, @purlPattern)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, ecosystem, purlPattern });
        return new AllowlistEntry { Id = id, OrgId = orgId, Ecosystem = ecosystem, PurlPattern = purlPattern, CreatedAt = DateTimeOffset.UtcNow };
    }

    public async Task DeleteAsync(string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM allowlist WHERE id = @id", new { id = entryId });
    }
}
