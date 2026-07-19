using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Infrastructure;

/// <summary>
/// Bounds the per-key generation-token maps that the cache-aside fill guards keep. Each guarded
/// store holds a <see cref="ConcurrentDictionary{TKey,TValue}"/> of per-key
/// <see cref="CancellationTokenSource"/> generations so a mutation can cancel an in-flight fill
/// that raced it. A cache MISS mints a generation via <c>GetOrAdd</c>, but a generation is only
/// removed on an explicit invalidation (logout, tenant lifecycle, mutation). Keys that never take
/// that path — a naturally-expiring JWT, a subdomain slug that misses the cache and turns out to
/// hold no tenant — would otherwise leave their generation in the map for the whole process, one
/// <see cref="CancellationTokenSource"/> per distinct key ever seen. That map is reachable pre-auth
/// through the subdomain resolver, so unbounded growth is a memory-exhaustion amplifier.
///
/// <see cref="TieToEntryLifetime"/> ties a generation's lifetime to the cache entry it guards: when
/// the entry expires or is evicted the generation is removed from the map, so the map stays bounded
/// by the live cache rather than by the set of keys ever observed.
///
/// The source is intentionally not disposed. An in-flight fill may still hold the generation's
/// <see cref="CancellationToken"/> struct and register it as the next entry's expiration trigger;
/// that struct stays valid against cancellation and garbage collection but throws
/// <see cref="ObjectDisposedException"/> if the source is disposed underneath it — the same reason
/// the invalidation paths retire a generation without disposing it. The source carries no timer or
/// wait handle, so once no token references remain the garbage collector reclaims it; removing it
/// from the map is what bounds the memory.
/// </summary>
internal static class CacheFillGuard
{
    /// <summary>
    /// Registers a post-eviction callback on <paramref name="options"/> that retires
    /// <paramref name="source"/> from <paramref name="guards"/> under <paramref name="key"/> when
    /// the cache entry expires or is evicted. The removal is a compare-and-remove of the exact
    /// instance, so a fresh generation that a concurrent invalidation already installed under the
    /// same key is left intact.
    /// </summary>
    public static void TieToEntryLifetime(
        MemoryCacheEntryOptions options,
        ConcurrentDictionary<string, CancellationTokenSource> guards,
        string key,
        CancellationTokenSource source)
    {
        options.RegisterPostEvictionCallback(
            static (_, _, _, state) =>
            {
                var (guardMap, guardKey, guardSource) =
                    ((ConcurrentDictionary<string, CancellationTokenSource> Guards,
                      string Key,
                      CancellationTokenSource Source))state!;

                // Compare-and-remove: retire only this generation. If an invalidation already
                // replaced it with a fresh source under the same key, that fresh source survives.
                guardMap.TryRemove(new KeyValuePair<string, CancellationTokenSource>(guardKey, guardSource));
            },
            (guards, key, source));
    }

    /// <summary>
    /// Retires <paramref name="source"/> from <paramref name="guards"/> under <paramref name="key"/>
    /// on a not-cached terminal branch — a lookup that mints a generation before its read but then
    /// installs no cache entry to tie it to (a revoked jti, a deleted user, a missing admin row).
    /// Without this the generation would sit in the map for the whole process, one
    /// <see cref="CancellationTokenSource"/> per distinct key that ever hit the not-cached path — a
    /// leak that grows monotonically because those paths run on every request. The removal is a
    /// compare-and-remove of the exact instance, so a fresh generation a concurrent invalidation
    /// already installed under the same key is left intact. The source is not disposed, mirroring
    /// the invalidation path — an in-flight fill may still hold its token struct.
    /// </summary>
    public static void RetireUnbound(
        ConcurrentDictionary<string, CancellationTokenSource> guards,
        string key,
        CancellationTokenSource source)
    {
        guards.TryRemove(new KeyValuePair<string, CancellationTokenSource>(key, source));
    }
}
