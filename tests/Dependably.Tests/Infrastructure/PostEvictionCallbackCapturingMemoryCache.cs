using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test seam for the async post-eviction-callback race: wraps a real <see cref="IMemoryCache"/>
/// and captures-and-suppresses the <see cref="PostEvictionCallbackRegistration"/> list each
/// <c>Set</c> call registers, keyed by cache key, so a test can fire a PREVIOUS entry's eviction
/// callbacks at a moment it chooses. <see cref="MemoryCache"/> dispatches post-eviction callbacks
/// on a thread-pool task at a time the caller does not control — for EVERY eviction reason
/// (Removed, Replaced, TokenExpired, Expired, Capacity, Compact, and expired-on-insert), not just
/// natural TTL expiry. Capturing without suppressing would leave that real, unsequenced dispatch
/// racing the test's own manual firing: whichever wins decides whether the assertion under test
/// sees the pre- or post-cancellation state, which turns a deterministic-looking test back into an
/// unsequenced concurrency test that pins nothing (this codebase's own standing rule). Suppression
/// closes that: before the real entry commits, this seam clears its <c>PostEvictionCallbacks</c>
/// list, so <see cref="MemoryCache"/>'s own internal dispatch has nothing left to invoke — the
/// manual firing is the ONLY thing that ever runs the captured callbacks. Everything else about the
/// entry (value, expiration tokens, sliding/absolute TTL) is untouched, so normal caching behaviour
/// — including natural eviction from the cache's own dictionary — is unaffected; only the
/// callback's SIDE EFFECT is deferred to the test's explicit control. Pairs naturally with
/// <see cref="AfterDbReadHookStore"/>: fire the captured callbacks from inside
/// <c>AfterDbReadHookStore.AfterRead</c> to land the "delayed physical eviction of the previous
/// entry" exactly between a racing fill's DB read and its cache write — the precise interleaving
/// the fill-guard async-eviction race describes.
///
/// Every other <see cref="IMemoryCache"/> member passes straight through to the real cache.
/// </summary>
public sealed class PostEvictionCallbackCapturingMemoryCache(IMemoryCache inner) : IMemoryCache
{
    private readonly ConcurrentDictionary<object, List<PostEvictionCallbackRegistration>> _captured = new();

    public ICacheEntry CreateEntry(object key) => new CapturingEntry(inner.CreateEntry(key), key, this);

    public void Remove(object key) => inner.Remove(key);

    public bool TryGetValue(object key, out object? value) => inner.TryGetValue(key, out value);

    public void Dispose() => inner.Dispose();

    /// <summary>
    /// Fires the most recently captured <c>Set</c> call's post-eviction callbacks for
    /// <paramref name="key"/> — simulating the moment <see cref="MemoryCache"/> would eventually
    /// (asynchronously, on its own schedule) evict that entry — then forgets them, mirroring the
    /// real cache's own one-shot dispatch. This is the ONLY way the captured callbacks ever run:
    /// the real entry committed with an empty <c>PostEvictionCallbacks</c> list (see the class
    /// doc), so <see cref="MemoryCache"/>'s own eviction dispatch has nothing to invoke. A no-op if
    /// nothing has been captured for this key, or if it was already fired once.
    /// </summary>
    public void FireCapturedEvictionCallbacks(object key)
    {
        if (!_captured.TryRemove(key, out var callbacks))
        {
            return;
        }

        foreach (var registration in callbacks)
        {
            registration.EvictionCallback?.Invoke(key, null, EvictionReason.Replaced, registration.State);
        }
    }

    private void Capture(object key, List<PostEvictionCallbackRegistration> callbacks) => _captured[key] = callbacks;

    private sealed class CapturingEntry(ICacheEntry inner, object key, PostEvictionCallbackCapturingMemoryCache owner)
        : ICacheEntry
    {
        public object Key => inner.Key;

        public object? Value
        {
            get => inner.Value;
            set => inner.Value = value;
        }

        public DateTimeOffset? AbsoluteExpiration
        {
            get => inner.AbsoluteExpiration;
            set => inner.AbsoluteExpiration = value;
        }

        public TimeSpan? AbsoluteExpirationRelativeToNow
        {
            get => inner.AbsoluteExpirationRelativeToNow;
            set => inner.AbsoluteExpirationRelativeToNow = value;
        }

        public TimeSpan? SlidingExpiration
        {
            get => inner.SlidingExpiration;
            set => inner.SlidingExpiration = value;
        }

        public IList<IChangeToken> ExpirationTokens => inner.ExpirationTokens;

        public IList<PostEvictionCallbackRegistration> PostEvictionCallbacks => inner.PostEvictionCallbacks;

        public CacheItemPriority Priority
        {
            get => inner.Priority;
            set => inner.Priority = value;
        }

        public long? Size
        {
            get => inner.Size;
            set => inner.Size = value;
        }

        public void Dispose()
        {
            // Disposing the entry is what commits it into the real cache (MemoryCacheExtensions.Set
            // wraps CreateEntry/property-assignment/Dispose in a `using` block). Snapshot the
            // registrations this Set call made, then CLEAR the live list before handing off — the
            // real MemoryCache entry commits with zero registered callbacks, so its own internal
            // eviction dispatch (thread-pool, unsequenced) has nothing to invoke. Only
            // FireCapturedEvictionCallbacks can run them from here on; everything else about the
            // entry (value, expiration tokens, TTL) is untouched, so it still expires/evicts
            // normally from the cache's own dictionary — only the callback side effect is deferred.
            owner.Capture(key, [.. inner.PostEvictionCallbacks]);
            inner.PostEvictionCallbacks.Clear();
            inner.Dispose();
        }
    }
}
