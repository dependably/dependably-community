using Dapper;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Infrastructure;

public sealed class BlocklistRepository
{
    private readonly IMetadataStore _db;
    private readonly IMemoryCache _cache;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    public BlocklistRepository(IMetadataStore db, IMemoryCache cache)
    {
        _db = db;
        _cache = cache;
    }

    private static string CacheKey(string orgId) => $"blocklist:{orgId}";

    public async Task<IReadOnlyList<BlocklistEntry>> ListAsync(string orgId, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(CacheKey(orgId), out IReadOnlyList<BlocklistEntry>? cached) && cached is not null)
        {
            return cached;
        }

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<BlocklistEntry>(
            """
            SELECT id, org_id as OrgId, pattern, created_at as CreatedAt
            FROM blocklist WHERE org_id = @orgId
            ORDER BY pattern
            """,
            new { orgId });
        var list = (IReadOnlyList<BlocklistEntry>)rows.ToList();
        _cache.Set(CacheKey(orgId), list, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = CacheTtl,
            Size = 1,
        });
        return list;
    }

    public async Task<BlocklistEntry> AddAsync(
        string orgId, string pattern, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO blocklist (id, org_id, pattern)
            VALUES (@id, @orgId, @pattern)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, pattern });
        _cache.Remove(CacheKey(orgId));
        return new BlocklistEntry { Id = id, OrgId = orgId, Pattern = pattern, CreatedAt = DateTimeOffset.UtcNow };
    }

    public async Task<bool> IsBlockedAsync(string orgId, string purl, CancellationToken ct = default)
    {
        var entries = await ListAsync(orgId, ct);
        return entries.Any(e =>
        {
            try { return System.Text.RegularExpressions.Regex.IsMatch(purl, e.Pattern, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2)); }
            catch { return false; }
        });
    }

    /// <summary>
    /// Deletes a blocklist entry, scoped to <paramref name="orgId"/>. Returns the number of rows
    /// removed (0 when the id belongs to another tenant or does not exist) so the caller can 404
    /// without revealing cross-tenant existence. The id is a global PK, so the org_id predicate is
    /// what enforces tenant isolation here.
    /// </summary>
    public async Task<int> DeleteAsync(string orgId, string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            "DELETE FROM blocklist WHERE id = @id AND org_id = @orgId", new { id = entryId, orgId });
        // Only the caller's own org cache can be affected, so invalidate exactly that one.
        if (rows > 0)
        {
            _cache.Remove(CacheKey(orgId));
        }

        return rows;
    }
}
