using System.Collections.Concurrent;
using Dapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-org package blocklist with a short-TTL read cache over the hot <see cref="IsBlockedAsync"/>
/// proxy/publish path. A fill that reads the DB just before a concurrent <see cref="AddAsync"/>
/// commits would otherwise cache the pre-block list <em>after</em> the mutation's cache eviction
/// already ran, letting a just-blocked package be served for a full TTL. Each fill captures a
/// per-org generation token before its read and binds the cache entry to it; mutations
/// cancel-and-replace the token so a raced fill's stale write is dropped (or immediately evicted).
/// </summary>
public sealed class BlocklistRepository
{
    private readonly IMetadataStore _db;
    private readonly IMemoryCache _cache;
    private readonly TimeProvider _time;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    // Per-org generation token, bound to each cache entry as an expiration trigger so a fill
    // that raced a concurrent Add/Delete cannot persist the stale list past the mutation.
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _fillGuards =
        new(StringComparer.Ordinal);

    public BlocklistRepository(IMetadataStore db, IMemoryCache cache, TimeProvider time)
    {
        _db = db;
        _cache = cache;
        _time = time;
    }

    private static string CacheKey(string orgId) => $"blocklist:{orgId}";

    private CancellationTokenSource GuardFor(string orgId) =>
        _fillGuards.GetOrAdd(orgId, static _ => new CancellationTokenSource());

    // Test seam (InternalsVisibleTo Dependably.Tests): the live generation-guard count, asserted
    // to drain when a cached entry expires or is evicted so the map cannot grow unbounded.
    internal int FillGuardCount => _fillGuards.Count;

    // Evicts the cached list and cancels the current generation token so an in-flight fill that
    // read the pre-mutation list cannot cache it.
    private void InvalidateCache(string orgId)
    {
        _cache.Remove(CacheKey(orgId));
        if (_fillGuards.TryRemove(orgId, out var retired))
        {
            retired.Cancel();
        }
    }

    public async Task<IReadOnlyList<BlocklistEntry>> ListAsync(string orgId, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(CacheKey(orgId), out IReadOnlyList<BlocklistEntry>? cached) && cached is not null)
        {
            return cached;
        }

        // Snapshot the generation source BEFORE the read so a fill racing a concurrent mutation
        // binds an already-cancelled expiration token and never persists the stale list.
        var guardSource = GuardFor(orgId);

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<BlocklistEntry>(
            """
            SELECT id, org_id as OrgId, pattern, created_at as CreatedAt
            FROM blocklist WHERE org_id = @orgId
            ORDER BY pattern
            """,
            new { orgId });
        var list = (IReadOnlyList<BlocklistEntry>)rows.ToList();
        var options = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = CacheTtl,
            Size = 1,
        };
        options.AddExpirationToken(new CancellationChangeToken(guardSource.Token));
        // Tie the generation's lifetime to this entry so an org whose cache entry expires without
        // a mutation does not leave its guard in the map forever.
        CacheFillGuard.TieToEntryLifetime(options, _fillGuards, orgId, guardSource);
        _cache.Set(CacheKey(orgId), list, options);
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
        InvalidateCache(orgId);
        return new BlocklistEntry { Id = id, OrgId = orgId, Pattern = pattern, CreatedAt = _time.GetUtcNow() };
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
            InvalidateCache(orgId);
        }

        return rows;
    }
}
