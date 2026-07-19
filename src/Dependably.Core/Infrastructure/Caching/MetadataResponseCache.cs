using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// A typed front over the shared <see cref="IMemoryCache"/> for rendered metadata responses.
/// Every get, set, and evict routes <typeparamref name="TKey"/> through the one
/// <see cref="_keyFormatter"/> supplied at construction, so a caller cannot build an
/// inconsistent string key for the same logical entry — the structural guarantee that a
/// read path and an eviction path can never disagree on a key.
/// </summary>
/// <remarks>
/// Registered as a DI singleton (one instance per ecosystem) so it shares the single
/// global <see cref="IMemoryCache"/> and — for the single-flight subclass — holds a process-wide
/// in-flight map across the transient controller instances that resolve it.
/// </remarks>
public class MetadataResponseCache<TKey, TValue>
    where TKey : notnull
{
    private readonly IMemoryCache _cache;
    private readonly Func<TKey, string> _keyFormatter;
    private readonly OrgCacheEpochStore? _epochStore;

    // Per-key invalidation generation. Every Evict bumps the key's counter; a rebuild path that
    // captures the generation before reading state can then discard a Set whose snapshot predates
    // an intervening Evict (the lost-invalidation race). Bounded by the number of distinct keys
    // ever evicted — the same package/org coordinate cardinality that flows through the cache.
    private readonly ConcurrentDictionary<string, long> _generations = new();

    public MetadataResponseCache(IMemoryCache cache, Func<TKey, string> keyFormatter)
        : this(cache, keyFormatter, epochStore: null)
    {
    }

    /// <summary>
    /// Constructs a cache whose entries, for keys implementing <see cref="IOrgScopedCacheKey"/>,
    /// also expire the instant the owning org's <paramref name="epochStore"/> epoch is
    /// invalidated — used by the ecosystem caches whose rendered bytes reflect the org's
    /// proxy-settings gate policy, so a policy flip evicts every cached document for that org
    /// without enumerating package names. Pass <see langword="null"/> for caches that don't
    /// reflect org-level policy state (e.g. RPM repodata).
    /// </summary>
    public MetadataResponseCache(IMemoryCache cache, Func<TKey, string> keyFormatter, OrgCacheEpochStore? epochStore)
    {
        _cache = cache;
        _keyFormatter = keyFormatter;
        _epochStore = epochStore;
    }

    /// <summary>Formats <paramref name="key"/> to its canonical cache-key string.</summary>
    protected string FormatKey(TKey key) => _keyFormatter(key);

    /// <summary>True when an entry for <paramref name="key"/> is present; sets <paramref name="value"/> on hit.</summary>
    public virtual bool TryGet(TKey key, out TValue? value) =>
        _cache.TryGetValue(_keyFormatter(key), out value);

    /// <summary>
    /// The current invalidation generation for <paramref name="key"/>. Increments on every
    /// <see cref="Evict"/>. A rebuild path captures this before reading state and passes it to
    /// <see cref="SetIfGenerationUnchanged"/> so a concurrent Evict cannot be lost.
    /// </summary>
    public long GetGeneration(TKey key) =>
        _generations.TryGetValue(_keyFormatter(key), out long g) ? g : 0;

    /// <summary>
    /// Captures the org policy-epoch expiration token that a Set for <paramref name="key"/>
    /// would currently bind to (<see langword="null"/> when this cache has no
    /// <see cref="OrgCacheEpochStore"/> or <typeparamref name="TKey"/> isn't org-scoped). Capture
    /// this <em>before</em> reading any policy-dependent state — mirroring
    /// <see cref="GetGeneration"/> — and pass it to <see cref="SetIfGenerationUnchanged"/> so a
    /// concurrent <see cref="OrgCacheEpochStore.Invalidate"/> that lands mid-rebuild is not lost:
    /// the eventual write is bound to the (already-cancelled) token captured up front, so it
    /// expires immediately instead of picking up whichever fresh epoch happens to be live by the
    /// time the write actually runs.
    /// </summary>
    public IChangeToken? CaptureEpochToken(TKey key) =>
        _epochStore is not null && key is IOrgScopedCacheKey scoped ? _epochStore.GetToken(scoped.OrgId) : null;

    /// <summary>
    /// Stores <paramref name="value"/> only when the key's invalidation generation still equals
    /// <paramref name="expectedGeneration"/> — i.e. no <see cref="Evict"/> has landed since the
    /// caller captured it via <see cref="GetGeneration"/>. Returns true when the write is kept.
    /// A generation change observed after the write (an Evict racing the Set) removes the entry
    /// again so a lost invalidation can never persist to the entry's TTL.
    /// <paramref name="epochToken"/>, when supplied, is the token captured via
    /// <see cref="CaptureEpochToken"/> before the caller read any policy-dependent state; passing
    /// it here (rather than letting the entry bind to whatever epoch is live at write time) is
    /// what makes a racing <see cref="OrgCacheEpochStore.Invalidate"/> unable to be lost the same
    /// way the generation check makes a racing <see cref="Evict"/> unable to be lost.
    /// </summary>
    public bool SetIfGenerationUnchanged(
        TKey key, TValue value, TimeSpan ttl, long size, long expectedGeneration, IChangeToken? epochToken = null)
    {
        string formatted = _keyFormatter(key);
        if (CurrentGeneration(formatted) != expectedGeneration)
        {
            return false;
        }

        SetFormatted(key, formatted, value, ttl, size, epochToken);

        if (CurrentGeneration(formatted) != expectedGeneration)
        {
            _cache.Remove(formatted);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Stores <paramref name="value"/> under <paramref name="key"/> with the given TTL. The
    /// shared <see cref="IMemoryCache"/> is size-bounded, so every entry MUST declare its
    /// <paramref name="size"/> — this overload always sets it.
    /// </summary>
    public void Set(TKey key, TValue value, TimeSpan ttl, long size) =>
        SetFormatted(key, _keyFormatter(key), value, ttl, size, epochToken: null);

    // epochToken, when non-null, is used as-is (already captured by the caller before its read).
    // When null the org's *current* epoch token is fetched fresh — safe for direct Set() callers,
    // which have no read-then-write gap for a concurrent Invalidate to land inside.
    private void SetFormatted(TKey key, string formatted, TValue value, TimeSpan ttl, long size, IChangeToken? epochToken)
    {
        var options = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ttl,
            Size = size,
        };

        // Bind the entry to the owning org's policy epoch (OrgCacheEpochStore) so a
        // proxy-settings policy flip evicts every cached document for that org immediately,
        // without enumerating package names — a bulk-invalidation counterpart to the per-key
        // generation guard above, which only protects a single already-known key.
        var token = epochToken ?? CaptureEpochToken(key);
        if (token is not null)
        {
            options.AddExpirationToken(token);
        }

        _cache.Set(formatted, value, options);
    }

    private long CurrentGeneration(string formatted) =>
        _generations.TryGetValue(formatted, out long g) ? g : 0;

    /// <summary>
    /// Removes the entry for <paramref name="key"/>, if any, and bumps its invalidation
    /// generation so a rebuild whose snapshot predates this call discards its Set.
    /// </summary>
    public void Evict(TKey key)
    {
        string formatted = _keyFormatter(key);
        // Bump the generation before removing so a concurrent SetIfGenerationUnchanged observes
        // the change (its post-write re-check catches a Set that raced ahead of the removal).
        _generations.AddOrUpdate(formatted, 1, (_, v) => v + 1);
        _cache.Remove(formatted);
    }
}
