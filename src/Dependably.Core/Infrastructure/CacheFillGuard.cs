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
///
/// <see cref="TieToEntryLifetime"/>'s post-eviction callback also unconditionally cancels the
/// generation, not just compare-removes it from the map. <c>MemoryCache</c> dispatches post-eviction
/// callbacks on a thread-pool task, not synchronously with the eviction itself, which opens a
/// window: a concurrent fill can call <c>GuardFor</c> and receive this exact generation between the
/// owning entry logically expiring and this callback actually running, then complete its own DB read
/// and install a fresh entry bound to the very same (borrowed, about-to-retire) generation. If the
/// callback only removed the map entry, an invalidation racing that window finds an empty slot and
/// cancels nothing, and the fill's fresh entry — reading pre-invalidation state — survives for a
/// full TTL. Cancelling here closes it: whichever entry bound to this generation is swept first —
/// the original expiring entry or the racing fill's fresh one — its eviction cancels the shared
/// token, which synchronously evicts every other live entry still registered against it via the
/// ordinary <c>CancellationChangeToken</c> mechanism (the same "expired-on-insert /
/// cancel-after-insert-evicts-it" behaviour the mint-time race already relies on). The one cost:
/// a fill that reused a not-yet-swept generation purely by coincidence, with nothing actually racing
/// it, pays a redundant re-fetch on its very next request rather than serving from a self-evicted
/// entry — never stale data, only a rare extra DB round trip, which matches this codebase's
/// fail-closed bias elsewhere (never serve a state a signal loss cannot rule out). Cancelling an
/// already-cancelled source, or one that never backs any other live entry, is a harmless no-op.
///
/// <see cref="RetireUnbound"/> cancels the same way, for the identical reason. A generation
/// leaving the map without being cancelled is exactly as unsafe on that path as it is in
/// <see cref="TieToEntryLifetime"/>'s callback: the not-cached terminal branch runs precisely
/// when the retiring caller has learned something more recent than the fill still in flight —
/// a revoked jti, a deleted user, a missing admin row — and a concurrent invalidation racing the
/// same window finds an empty map slot and cancels nothing, exactly as it would for an
/// uncancelled post-eviction retire. Leaving the generation live would let the in-flight fill
/// install its stale (pre-invalidation) answer as a normal, un-expired cache entry. On
/// <c>JwtRevocationRepository</c> specifically this is a session-invalidation correctness bound,
/// not a performance one: an uncancelled generation here means a just-revoked JWT can read as
/// not-revoked for a full negative-cache TTL.
/// </summary>
internal static class CacheFillGuard
{
    /// <summary>
    /// Registers a post-eviction callback on <paramref name="options"/> that retires
    /// <paramref name="source"/> from <paramref name="guards"/> under <paramref name="key"/> — and
    /// cancels it — when the cache entry expires or is evicted. The map removal is a
    /// compare-and-remove of the exact instance, so a fresh generation that a concurrent
    /// invalidation already installed under the same key keeps its own map slot. The cancellation
    /// is unconditional: see the class doc for why a racing fill sharing this generation needs it
    /// even when the compare-and-remove above found a different instance already in the map.
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

                // Unconditional cancel — deliberately not gated on the TryRemove above having
                // found this instance. See the class doc's async-post-eviction-callback paragraph.
                guardSource.Cancel();
            },
            (guards, key, source));
    }

    /// <summary>
    /// Retires <paramref name="source"/> from <paramref name="guards"/> under <paramref name="key"/>
    /// — and cancels it — on a not-cached terminal branch: a lookup that mints a generation before
    /// its read but then installs no cache entry to tie it to (a revoked jti, a deleted user, a
    /// missing admin row). Without the map removal the generation would sit there for the whole
    /// process, one <see cref="CancellationTokenSource"/> per distinct key that ever hit the
    /// not-cached path — a leak that grows monotonically because those paths run on every request.
    /// Without the cancellation, a concurrent fill that is still holding this exact generation (it
    /// called <c>GuardFor</c> before this retire ran, and the map still held this instance at that
    /// moment) can go on to install its own cache entry bound to a generation nobody will ever
    /// cancel again — the not-cached terminal branch is reached precisely because the retiring
    /// caller learned something the in-flight fill's stale read does not yet reflect, so the fill's
    /// eventual write must not be allowed to stick. The map removal is a compare-and-remove of the
    /// exact instance, so a fresh generation a concurrent invalidation already installed under the
    /// same key is left intact; the cancellation is unconditional for the same reason
    /// <see cref="TieToEntryLifetime"/>'s callback cancels unconditionally — see the class doc. The
    /// source is not disposed, mirroring the invalidation path — an in-flight fill may still hold
    /// its token struct.
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
