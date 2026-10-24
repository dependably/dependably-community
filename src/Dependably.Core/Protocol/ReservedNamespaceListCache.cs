using System.Collections.Concurrent;
using Dependably.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Dependably.Protocol;

/// <summary>
/// The per-process, per-org cache of an org's reserved-namespace list, with the generation guard
/// that keeps a fill racing an invalidation from persisting the pre-change list.
///
/// <para>A singleton of its own (rather than private state inside
/// <see cref="ReservedNamespaceService"/>) because two callers clear it: the service, after its
/// own add or delete, and <see cref="Infrastructure.Caching.OrgWideCacheEviction"/>, when a peer
/// replica's org-wide invalidation arrives. Both must reach the same entry and the same guard
/// map, which is what makes a received invalidation as effective as a local one.</para>
/// </summary>
public sealed class ReservedNamespaceListCache
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IMemoryCache _cache;

    // Per-org generation token, bound to each cache entry as an expiration trigger so a fill
    // that raced a concurrent Invalidate cannot persist the stale list past the change.
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _fillGuards =
        new(StringComparer.Ordinal);

    public ReservedNamespaceListCache(IMemoryCache cache) => _cache = cache;

    internal static string CacheKey(string orgId) => $"reserved-namespace:{orgId}";

    // Test seam (InternalsVisibleTo Dependably.Tests): the live generation-guard count, asserted
    // to drain when a cached entry expires or is evicted so the map cannot grow unbounded.
    internal int FillGuardCount => _fillGuards.Count;

    private CancellationTokenSource GuardFor(string orgId) =>
        _fillGuards.GetOrAdd(orgId, static _ => new CancellationTokenSource());

    /// <summary>
    /// Returns the cached list for <paramref name="orgId"/>, or reads it through
    /// <paramref name="read"/> and caches it for the TTL. The generation is snapshotted before
    /// the read, so a read that overlaps an <see cref="Invalidate"/> stores an entry that is
    /// already expired.
    /// </summary>
    public async Task<IReadOnlyList<ReservedNamespaceEntry>> GetOrReadAsync(
        string orgId,
        Func<CancellationToken, Task<IReadOnlyList<ReservedNamespaceEntry>>> read,
        CancellationToken ct)
    {
        if (_cache.TryGetValue(CacheKey(orgId), out IReadOnlyList<ReservedNamespaceEntry>? cached) && cached is not null)
        {
            return cached;
        }

        var guardSource = GuardFor(orgId);

        // From here on guardSource MUST end up either tied to a cache entry (TieToEntryLifetime,
        // below) or explicitly retired in the finally. The map lives as long as this singleton,
        // so a read that throws before a cache entry is installed to own the guard's lifetime
        // would otherwise leak it for the rest of the process.
        bool tied = false;
        try
        {
            var list = await read(ct);
            var options = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheTtl,
                Size = 1,
            };
            options.AddExpirationToken(new CancellationChangeToken(guardSource.Token));
            // Tie the generation's lifetime to this entry so an org whose cache entry expires
            // without a change does not leave its guard in the map forever.
            CacheFillGuard.TieToEntryLifetime(options, _fillGuards, orgId, guardSource);
            _cache.Set(CacheKey(orgId), list, options);
            tied = true;
            return list;
        }
        finally
        {
            if (!tied)
            {
                CacheFillGuard.RetireUnbound(_fillGuards, orgId, guardSource);
            }
        }
    }

    /// <summary>
    /// Evicts <paramref name="orgId"/>'s cached list and cancels its current generation, so a
    /// fill already in flight from before this call cannot cache what it read.
    /// </summary>
    public void Invalidate(string orgId)
    {
        _cache.Remove(CacheKey(orgId));
        if (_fillGuards.TryRemove(orgId, out var retired))
        {
            retired.Cancel();
        }
    }
}
