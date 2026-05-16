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
            return cached;

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<BlocklistEntry>(
            """
            SELECT id, org_id as OrgId, pattern, created_at as CreatedAt
            FROM blocklist WHERE org_id = @orgId
            ORDER BY pattern
            """,
            new { orgId });
        var list = (IReadOnlyList<BlocklistEntry>)rows.ToList();
        _cache.Set(CacheKey(orgId), list, CacheTtl);
        return list;
    }

    public async Task<BlocklistEntry> AddAsync(
        string orgId, string pattern, CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
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

    public async Task DeleteAsync(string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Invalidate all org caches that might include this entry — fetch org_id first
        var orgId = await conn.ExecuteScalarAsync<string?>("SELECT org_id FROM blocklist WHERE id = @id", new { id = entryId });
        await conn.ExecuteAsync("DELETE FROM blocklist WHERE id = @id", new { id = entryId });
        if (orgId is not null) _cache.Remove(CacheKey(orgId));
    }
}
