using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
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
/// <para><b>The invariant.</b> A generation leaves the map only by being cancelled in the same
/// step: <c>TryRemove</c> then <c>Cancel</c>, on every path (a consumer's invalidation,
/// <see cref="RetireUnbound"/>, and the last-entry eviction below). A fill snapshots the map's
/// generation before its read and binds its entry to that token, so a fill that overlapped an
/// invalidation always holds a cancelled token and its entry is expired on insert or evicted on
/// cancel. Whatever else happens to the map, the fill guard is only as strong as this rule.</para>
///
/// <para><b>Retiring with the last entry.</b> <see cref="TieToEntryLifetime"/> counts the cache
/// entries bound to each generation, and the post-eviction callback retires the generation (removes
/// it from the map and cancels it) only when the last of them is evicted. Several entries share a
/// generation whenever fills for one key overlap: every miss in the window between the first fill's
/// mint and the next invalidation gets the same token, and each fill's <c>Set</c> replaces the
/// previous fill's entry. Retiring on <em>any</em> eviction would let the replaced entry's callback
/// cancel the generation the replacing entry is still bound to, evicting a correct entry and
/// leaving the key uncached. Under a burst of concurrent misses (a CI fan-out against one org) that
/// repeats on every fill, so the cache holds nothing and every request reads the store. A replacing
/// fill holding the same live generation read no older state than the entry it replaced (any change
/// committed since the mint would have cancelled that generation), so keeping it is correct.</para>
///
/// <para>The count covers the other replacement shapes too. A fill holding an already-cancelled
/// generation is expired on insert; the entry it displaces loses its last reference, so its
/// generation is retired (an extra miss, never stale data, and no map slot left behind). A
/// replacing fill bound to a different generation means the displaced entry's generation was
/// already retired, and retiring it again is a no-op. Post-eviction callbacks run on the thread
/// pool, so a fill can take a generation whose last entry has expired but whose callback has not yet
/// run. If the fill is bound before the callback runs, the count keeps the generation in the map
/// and a later invalidation still reaches it. If the callback runs first, it cancels the generation
/// the fill holds and the fill's entry expires: a redundant read, never a stale one.</para>
///
/// <para>The source is intentionally not disposed. An in-flight fill may still hold the
/// generation's <see cref="CancellationToken"/> struct and register it as the next entry's
/// expiration trigger; that struct stays valid against cancellation and garbage collection but
/// throws <see cref="ObjectDisposedException"/> if the source is disposed underneath it. The source
/// carries no timer or wait handle, so once no token references remain the garbage collector
/// reclaims it, along with its entry count; removing it from the map is what bounds the
/// memory.</para>
///
/// <para><see cref="RetireUnbound"/> cancels for the same reason the invariant demands. Its
/// not-cached terminal branch runs precisely when the retiring caller has learned something more
/// recent than a fill still in flight — a revoked jti, a deleted user, a missing admin row — and a
/// generation leaving the map uncancelled would let that fill install its stale (pre-invalidation)
/// answer as a normal, un-expired cache entry that a later invalidation cannot reach. On
/// <c>JwtRevocationRepository</c> specifically this is a session-invalidation correctness bound,
/// not a performance one: an uncancelled generation there means a just-revoked JWT can read as
/// not-revoked for a full negative-cache TTL.</para>
/// </summary>
internal static class CacheFillGuard
{
    // How many committed cache entries are bound to each generation. Weakly keyed, so a retired
    // generation's count is collected with the generation itself.
    private static readonly ConditionalWeakTable<CancellationTokenSource, StrongBox<int>> BoundEntries = new();

    /// <summary>
    /// Counts the entry <paramref name="options"/> is about to configure against
    /// <paramref name="source"/>, and registers a post-eviction callback that retires
    /// <paramref name="source"/> from <paramref name="guards"/> under <paramref name="key"/> — and
    /// cancels it — when the last entry bound to it is evicted. Call it immediately before the
    /// <c>Set</c> that installs the entry: the cache invokes the callback for every entry it is
    /// handed, including one it rejects as expired on insert, so each count is matched by exactly
    /// one eviction. The map removal is a compare-and-remove of the exact instance, so a fresh
    /// generation that a concurrent invalidation already installed under the same key keeps its
    /// own map slot.
    /// </summary>
    public static void TieToEntryLifetime(
        MemoryCacheEntryOptions options,
        ConcurrentDictionary<string, CancellationTokenSource> guards,
        string key,
        CancellationTokenSource source)
    {
        var bound = BoundEntries.GetValue(source, static _ => new StrongBox<int>());
        Interlocked.Increment(ref bound.Value);

        options.RegisterPostEvictionCallback(
            static (_, _, _, state) =>
            {
                var (guardMap, guardKey, guardSource, boundCount) =
                    ((ConcurrentDictionary<string, CancellationTokenSource> Guards,
                      string Key,
                      CancellationTokenSource Source,
                      StrongBox<int> Bound))state!;

                // Another entry is still bound to this generation (a replacing fill of the same
                // generation): it owns the retirement now.
                if (Interlocked.Decrement(ref boundCount.Value) > 0)
                {
                    return;
                }

                // Compare-and-remove: retire only this generation. If an invalidation already
                // replaced it with a fresh source under the same key, that fresh source survives.
                guardMap.TryRemove(new KeyValuePair<string, CancellationTokenSource>(guardKey, guardSource));

                // Cancelled unconditionally, not only when the TryRemove above found this instance:
                // a fill may hold the generation without having bound an entry yet. See the class
                // doc's paragraph on post-eviction callbacks running on the thread pool.
                guardSource.Cancel();
            },
            (guards, key, source, bound));
    }

    /// <summary>
    /// Retires <paramref name="source"/> from <paramref name="guards"/> under <paramref name="key"/>
    /// — and cancels it — on a not-cached terminal branch: a lookup that mints a generation before
    /// its read but then installs no cache entry to tie it to (a revoked jti, a deleted user, a
    /// missing admin row, a read that threw). Without the map removal the generation would sit there
    /// for the whole process, one <see cref="CancellationTokenSource"/> per distinct key that ever
    /// hit the not-cached path — a leak that grows monotonically because those paths run on every
    /// request. Without the cancellation, a concurrent fill that is still holding this exact
    /// generation could go on to install its own cache entry bound to a generation nobody will ever
    /// cancel again (the class doc's invariant). The map removal is a compare-and-remove of the
    /// exact instance, so a fresh generation a concurrent invalidation already installed under the
    /// same key is left intact. The source is not disposed, mirroring the invalidation path — an
    /// in-flight fill may still hold its token struct.
    /// </summary>
    public static void RetireUnbound(
        ConcurrentDictionary<string, CancellationTokenSource> guards,
        string key,
        CancellationTokenSource source)
    {
        guards.TryRemove(new KeyValuePair<string, CancellationTokenSource>(key, source));
        source.Cancel();
    }
}
