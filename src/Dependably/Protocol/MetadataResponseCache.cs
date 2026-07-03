using System.Diagnostics;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Protocol;

/// <summary>
/// Memory-bounded TTL cache for buffered upstream metadata responses (packuments, PyPI
/// simple-index HTML, NuGet registration JSON, maven-metadata). Layered into the metadata
/// fetch path so an edge/pull-through node absorbs metadata load and keeps resolving versions
/// while its upstream is briefly unreachable, instead of forwarding every request.
///
/// Three behaviours over one <see cref="IMemoryCache"/> (with a byte <see cref="MemoryCacheOptions.SizeLimit"/>):
///   1. Positive TTL — a 2xx response is served without an upstream call until its TTL expires.
///   2. Serve-stale-on-failure — once the TTL has expired, if the refresh fetch fails with a
///      transient upstream failure (network error, timeout, 5xx) the stale copy is served (up
///      to a bounded max-stale window) rather than propagating the failure. A 404 is NOT
///      transient — it replaces the entry per behaviour 3.
///   3. Negative TTL — a 404 is cached briefly so repeated misses for a missing package don't
///      stampede the upstream.
///
/// Cache key is the URL only. This follows <see cref="UpstreamSource"/>'s reasoning that the
/// per-upstream <c>Authorization</c> header is deliberately not part of any dedup/cache key:
/// <c>UNIQUE(org_id, ecosystem, url)</c> guarantees one auth per URL within an org, and the
/// same URL configured by two orgs names the same public content — the identical sharing
/// contract the URL-keyed single-flight dedup already applies. The entry stores the whole
/// immutable response; the header never participates.
///
/// All time reads go through the injected <see cref="TimeProvider"/>: TTL expiry and the
/// stale-window math are computed against <see cref="TimeProvider.GetUtcNow"/>, never the wall
/// clock, so tests freeze time and assert exact expiry instants.
/// </summary>
public sealed class MetadataResponseCache
{
    // Per-entry bookkeeping overhead beyond the buffered body length: the record header, the
    // URL/content-type strings, and the DateTimeOffset. A small constant keeps a flood of tiny
    // metadata documents from over-committing the byte budget purely on payload size.
    private const long EntryOverheadBytes = 512;

    private readonly MemoryCache _cache;
    private readonly TimeProvider _time;
    private readonly MetadataCacheOptions _options;

    public MetadataResponseCache(MetadataCacheOptions options, TimeProvider time)
    {
        _options = options;
        _time = time;
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = options.MaxBytes,
            // The cache's own absolute-expiration checks must read the same injected clock the
            // TTL/stale math uses, or a frozen test clock desynchronises from wall time and the
            // cache evicts entries whose AbsoluteExpiration is "past" in real time.
            Clock = new TimeProviderSystemClock(time),
        });
    }

    /// <summary>Whether the cache is doing any work at all (positive TTL configured).</summary>
    public bool Enabled => _options.Enabled;

    /// <summary>
    /// Live count of cached entries. <see cref="MemoryCache"/> compacts over-capacity entries on
    /// a background schedule; exposing the count lets a test observe eviction has settled without
    /// asserting on wall-clock timing.
    /// </summary>
    public int Count => _cache.Count;

    /// <summary>
    /// A cached entry and whether it is still fresh (within its positive/negative TTL). When
    /// <see cref="Fresh"/> is false the entry is stale-but-serveable — usable only on a
    /// transient refresh failure and only while still inside the max-stale window.
    /// </summary>
    public readonly record struct Lookup(UpstreamMetadataResponse Response, bool Fresh);

    /// <summary>
    /// Reads the cache for <paramref name="url"/>. Returns null when nothing is cached or the
    /// entry has aged past its max-stale window (fully evicted). A returned <see cref="Lookup"/>
    /// with <see cref="Lookup.Fresh"/> = true is directly serveable; a stale one is only served
    /// after a transient refresh failure via <see cref="ShouldServeStale"/>.
    /// </summary>
    public Lookup? TryGet(string url)
        => _options.Enabled && _cache.TryGetValue(url, out CacheEntry? entry) && entry is not null
            ? new Lookup(entry.Response, IsFresh(entry))
            : null;

    /// <summary>
    /// Whether a stale entry may be served after a transient refresh failure: the entry exists,
    /// is a positive (2xx) entry, and is still within <see cref="MetadataCacheOptions.MaxStale"/>
    /// beyond its positive TTL. A negative (404) entry is never served stale — a transient
    /// failure refreshing a not-found should surface, not resurrect a stale miss as an answer.
    /// </summary>
    public bool ShouldServeStale(string url, out UpstreamMetadataResponse response)
    {
        response = default!;
        if (!_options.Enabled || !_cache.TryGetValue(url, out CacheEntry? entry) || entry is null || entry.IsNegative)
        {
            return false;
        }

        var age = _time.GetUtcNow() - entry.StoredAt;
        if (age <= _options.PositiveTtl + _options.MaxStale)
        {
            response = entry.Response;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Stores a successful (2xx) response under its positive TTL. Responses whose buffered body
    /// exceeds <see cref="UpstreamClient.MaxMetadataResponseBytes"/> pass through uncached rather
    /// than risk evicting the whole cache for one oversized document.
    /// </summary>
    public void StorePositive(string url, UpstreamMetadataResponse response)
    {
        if (!_options.Enabled || response.Body.LongLength > UpstreamClient.MaxMetadataResponseBytes)
        {
            return;
        }

        // The absolute-expiration guard evicts the entry once it can no longer be served even as
        // stale, capping how long a body pins memory: positive TTL + the stale window.
        Store(url, new CacheEntry(response, _time.GetUtcNow(), IsNegative: false),
            keepFor: _options.PositiveTtl + _options.MaxStale);
    }

    /// <summary>
    /// Stores a 404 under the negative TTL so repeated misses for a missing package don't
    /// re-stampede the upstream. No-op when negative caching is disabled.
    /// </summary>
    public void StoreNegative(string url, UpstreamMetadataResponse response)
    {
        if (!_options.NegativeCachingEnabled)
        {
            return;
        }

        // Negative entries are never served stale, so they expire hard at the negative TTL.
        Store(url, new CacheEntry(response, _time.GetUtcNow(), IsNegative: true),
            keepFor: _options.NegativeTtl);
    }

    private void Store(string url, CacheEntry entry, TimeSpan keepFor)
    {
        long size = entry.Response.Body.LongLength + EntryOverheadBytes;
        var options = new MemoryCacheEntryOptions
        {
            Size = size,
            AbsoluteExpiration = _time.GetUtcNow() + keepFor,
        };
        _cache.Set(url, entry, options);
    }

    private bool IsFresh(CacheEntry entry)
    {
        var age = _time.GetUtcNow() - entry.StoredAt;
        var ttl = entry.IsNegative ? _options.NegativeTtl : _options.PositiveTtl;
        return age < ttl;
    }

    /// <summary>
    /// Emits the serve-stale Warning per the project's Serilog convention (ExceptionType first,
    /// Warning severity, explicit TraceId). Called by <see cref="UpstreamClient"/> when a
    /// transient refresh failure is absorbed by serving a stale entry.
    /// </summary>
    public static void LogServedStale(ILogger logger, string url, Exception? cause, int? upstreamStatus)
        => logger.LogWarning(
            "Served stale upstream metadata after transient refresh failure {ExceptionType} for {Url} (upstream status {UpstreamStatus}); TraceId {TraceId}",
            cause?.GetType().Name ?? "UpstreamStatus",
            url,
            upstreamStatus,
            Activity.Current?.TraceId.ToString());

    private sealed record CacheEntry(UpstreamMetadataResponse Response, DateTimeOffset StoredAt, bool IsNegative);

    // Bridges the injected TimeProvider to the clock MemoryCache reads for absolute-expiration
    // checks, so the store's own eviction and this class's TTL math share one time source.
    private sealed class TimeProviderSystemClock(TimeProvider time) : Microsoft.Extensions.Internal.ISystemClock
    {
        public DateTimeOffset UtcNow => time.GetUtcNow();
    }
}
