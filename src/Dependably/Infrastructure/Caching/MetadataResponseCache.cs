using Microsoft.Extensions.Caching.Memory;

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

    public MetadataResponseCache(IMemoryCache cache, Func<TKey, string> keyFormatter)
    {
        _cache = cache;
        _keyFormatter = keyFormatter;
    }

    /// <summary>Formats <paramref name="key"/> to its canonical cache-key string.</summary>
    protected string FormatKey(TKey key) => _keyFormatter(key);

    /// <summary>True when an entry for <paramref name="key"/> is present; sets <paramref name="value"/> on hit.</summary>
    public bool TryGet(TKey key, out TValue? value) =>
        _cache.TryGetValue(_keyFormatter(key), out value);

    /// <summary>
    /// Stores <paramref name="value"/> under <paramref name="key"/> with the given TTL. The
    /// shared <see cref="IMemoryCache"/> is size-bounded, so every entry MUST declare its
    /// <paramref name="size"/> — this overload always sets it.
    /// </summary>
    public void Set(TKey key, TValue value, TimeSpan ttl, long size)
    {
        _cache.Set(_keyFormatter(key), value, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ttl,
            Size = size,
        });
    }

    /// <summary>Removes the entry for <paramref name="key"/>, if any.</summary>
    public void Evict(TKey key) => _cache.Remove(_keyFormatter(key));
}
