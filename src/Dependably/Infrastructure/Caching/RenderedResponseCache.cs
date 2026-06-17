using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// A <see cref="MetadataResponseCache{TKey, TValue}"/> specialized for rendered <c>byte[]</c>
/// responses (PyPI simple indices, npm packuments, NuGet registration documents). Adds:
/// a size-inferring <see cref="Set(TKey, byte[], TimeSpan)"/> overload, and
/// <see cref="GetOrRebuildAsync"/> — single-flight orchestration that collapses concurrent
/// rebuilds for the same key onto one shared task, with an optional process-wide concurrency
/// gate that bounds the number of simultaneous buffered rebuilds.
/// </summary>
/// <remarks>
/// The in-flight map is an instance field keyed on the formatted string, so the single-flight
/// guarantee holds only while one instance is shared across requests — i.e. the helper is a
/// DI singleton and the controllers that use it are transient.
/// </remarks>
public sealed class RenderedResponseCache<TKey> : MetadataResponseCache<TKey, byte[]>
    where TKey : notnull
{
    // Single-flight map: concurrent rebuilds for the same formatted key collapse onto one
    // shared task. Removed after each rebuild completes so stale Lazy instances don't accumulate.
    private readonly ConcurrentDictionary<string, Lazy<Task<byte[]?>>> _inFlight = new();

    // Optional process-wide concurrency gate. When non-null, each cache-MISS rebuild must
    // acquire one slot before allocating the upstream response buffer, bounding peak
    // in-flight memory regardless of the number of distinct keys warming simultaneously.
    // Cache HITs bypass this gate entirely — they read already-allocated bytes.
    private readonly SemaphoreSlim? _gate;

    public RenderedResponseCache(IMemoryCache cache, Func<TKey, string> keyFormatter)
        : base(cache, keyFormatter)
    {
    }

    /// <summary>
    /// Constructs a cache with a concurrency gate applied to cache-MISS rebuilds only.
    /// <paramref name="gate"/> limits the number of rebuild lambdas executing concurrently
    /// across all cache keys on this instance.
    /// </summary>
    public RenderedResponseCache(IMemoryCache cache, Func<TKey, string> keyFormatter, SemaphoreSlim gate)
        : base(cache, keyFormatter)
    {
        _gate = gate;
    }

    /// <summary>
    /// Stores <paramref name="bytes"/> with size inferred from its length — the common case for
    /// rendered responses where the byte count is the cache weight.
    /// </summary>
    public void Set(TKey key, byte[] bytes, TimeSpan ttl) => Set(key, bytes, ttl, bytes.Length);

    /// <summary>
    /// Returns the cached bytes for <paramref name="key"/> on a hit; on a miss, runs
    /// <paramref name="rebuild"/> under single-flight (concurrent callers for the same key share
    /// one rebuild). When <paramref name="rebuild"/> yields non-null bytes they are cached with
    /// <paramref name="ttl"/> (size = length) and returned; when it yields null nothing is cached
    /// and null is returned. Each caller detaches from the shared task via <paramref name="ct"/>,
    /// so one caller's cancellation never poisons the rebuild for the others.
    ///
    /// When a process-wide concurrency gate was supplied at construction, each MISS rebuild
    /// acquires one gate slot before executing. Cache HITs return immediately without
    /// acquiring any slot.
    /// </summary>
    public async Task<byte[]?> GetOrRebuildAsync(
        TKey key,
        TimeSpan ttl,
        Func<CancellationToken, Task<byte[]?>> rebuild,
        CancellationToken ct)
    {
        // Fast path: cache hit bypasses single-flight and the concurrency gate entirely.
        if (TryGet(key, out byte[]? cached) && cached is not null)
        {
            return cached;
        }

        string formatted = FormatKey(key);
        var lazy = _inFlight.GetOrAdd(formatted,
            _ => new Lazy<Task<byte[]?>>(async () =>
            {
                // CancellationToken.None: the shared task must not be cancelled by any one
                // caller's disconnection — individual callers detach via WaitAsync(ct).
                byte[]? bytes = await RebuildWithGateAsync(rebuild, CancellationToken.None);
                if (bytes is not null)
                {
                    Set(key, bytes, ttl);
                }
                return bytes;
            }));

        try
        {
            return await lazy.Value.WaitAsync(ct);
        }
        finally
        {
            _inFlight.TryRemove(new KeyValuePair<string, Lazy<Task<byte[]?>>>(formatted, lazy));
        }
    }

    // Wraps the rebuild delegate with the optional concurrency gate. When no gate is
    // configured the delegate runs directly. The gate slot is released after the rebuild
    // completes (or throws), so a faulted rebuild does not permanently exhaust the gate.
    private async Task<byte[]?> RebuildWithGateAsync(
        Func<CancellationToken, Task<byte[]?>> rebuild,
        CancellationToken ct)
    {
        if (_gate is null)
        {
            return await rebuild(ct);
        }

        await _gate.WaitAsync(ct);
        try
        {
            return await rebuild(ct);
        }
        finally
        {
            _gate.Release();
        }
    }
}
