using System.Collections.Concurrent;

namespace Dependably.Protocol;

/// <summary>
/// Bounded in-memory TTL cache for raw OSV answers that are public data and carry no org
/// state: the per-purl query behind the advisory detail fallback and the Alpine origin probe.
/// Entries are shared across orgs, so every org-specific decision (the reserved-namespace
/// check) stays with the caller, outside the cache. Concurrent identical queries collapse into
/// one OSV round trip (striped single-flight), and only an answer the caller marks cacheable
/// is stored, so an unreached source is retried on the next call instead of being remembered as
/// an empty, clean answer. Memory is bounded by an entry cap and a byte budget (an advisory-heavy
/// coordinate holds hundreds of full OSV records): eviction drops expired entries first, then the
/// oldest, until both bounds hold, and one entry over an eighth of the budget is served but never
/// stored.
/// Singleton-scoped.
/// </summary>
public sealed class OsvQueryCache
{
    private const int MaxEntries = 4096;
    private const int StripeCount = 32;
    private const long DefaultMaxBytes = 64L * 1024 * 1024;
    private const long PerAdvisoryOverheadBytes = 512;
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim[] _stripes =
        Enumerable.Range(0, StripeCount).Select(_ => new SemaphoreSlim(1, 1)).ToArray();
    private readonly Lock _storeLock = new();
    private readonly TimeProvider _time;
    private readonly long _maxBytes;
    private long _bytes;

    public OsvQueryCache(TimeProvider time, long maxBytes = DefaultMaxBytes)
    {
        _time = time;
        _maxBytes = maxBytes;
    }

    // Test seam (InternalsVisibleTo Dependably.Tests).
    internal long TotalBytes => Volatile.Read(ref _bytes);

    internal int EntryCount => _entries.Count;

    /// <summary>Approximate heap size of a set of advisories: string payloads at two bytes per
    /// UTF-16 char plus a fixed per-advisory overhead.</summary>
    public static long EstimateBytes(IEnumerable<OsvAdvisory> advisories)
    {
        long total = 0;
        foreach (var a in advisories)
        {
            long chars = (a.RawJson?.Length ?? 0) + (a.Summary?.Length ?? 0) + a.Id.Length
                + (a.Aliases?.Sum(x => x?.Length ?? 0) ?? 0);
            foreach (var p in a.AffectedPackages ?? [])
            {
                chars += (p.Purl?.Length ?? 0) + (p.Name?.Length ?? 0) + (p.Versions?.Sum(v => v?.Length ?? 0) ?? 0);
            }

            total += (chars * 2) + PerAdvisoryOverheadBytes;
        }

        return total;
    }

    public static string PurlKey(string purl) => "purl\n" + purl;

    public static string OriginProbeKey(string osvEcosystem, string name) =>
        string.Join('\n', "origin", osvEcosystem, name);

    /// <summary>
    /// Returns the live cached value for <paramref name="key"/>, or runs <paramref name="compute"/>
    /// once per key at a time and stores its value when it reports the answer cacheable.
    /// </summary>
    public async Task<T> GetOrComputeAsync<T>(
        string key, Func<Task<(T Value, bool Cacheable, long Bytes)>> compute, CancellationToken ct) where T : class
    {
        if (TryGet(key) is T hit)
        {
            return hit;
        }

        var stripe = _stripes[(uint)key.GetHashCode() % StripeCount];
        await stripe.WaitAsync(ct);
        try
        {
            if (TryGet(key) is T again)
            {
                return again;
            }

            var (value, cacheable, bytes) = await compute();
            if (cacheable && bytes <= _maxBytes / 8)
            {
                Store(key, value, bytes);
            }

            return value;
        }
        finally
        {
            stripe.Release();
        }
    }

    private object? TryGet(string key) =>
        _entries.TryGetValue(key, out var entry) && _time.GetUtcNow() - entry.StoredAt < Ttl ? entry.Value : null;

    private void Store(string key, object value, long bytes)
    {
        lock (_storeLock)
        {
            if (_entries.TryRemove(key, out var previous))
            {
                _bytes -= previous.Bytes;
            }

            if (_entries.Count >= MaxEntries || _bytes + bytes > _maxBytes)
            {
                Prune(bytes);
            }

            _entries[key] = new Entry(value, _time.GetUtcNow(), bytes);
            _bytes += bytes;
        }
    }

    private void Prune(long incoming)
    {
        var now = _time.GetUtcNow();
        foreach (var kv in _entries)
        {
            if (now - kv.Value.StoredAt >= Ttl && _entries.TryRemove(kv.Key, out var gone))
            {
                _bytes -= gone.Bytes;
            }
        }

        foreach (var kv in _entries.OrderBy(e => e.Value.StoredAt))
        {
            if (_entries.Count < MaxEntries && _bytes + incoming <= _maxBytes)
            {
                break;
            }

            if (_entries.TryRemove(kv.Key, out var gone))
            {
                _bytes -= gone.Bytes;
            }
        }
    }

    private sealed record Entry(object Value, DateTimeOffset StoredAt, long Bytes);
}
