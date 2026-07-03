namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Process-lifetime counters maintained in parallel to the OTel
/// instruments in <see cref="DependablyMeter"/>. They exist so the
/// in-app sysadmin observability page can read counts directly from
/// memory without inventing a custom <c>MetricReader</c> or hitting
/// the OTel SDK's internal state.
///
/// <para>Each counter is incremented at the same callsite that emits
/// the corresponding OTel instrument, so the two sources stay in lock
/// step. The page labels these as "since startup" — there is no
/// windowed aggregation here. Rates and percentiles stay in Grafana.</para>
/// </summary>
public static class SnapshotCounters
{
    private static long _publishCount;
    private static long _proxyFetchCount;
    private static long _cacheHits;
    private static long _cacheMisses;

    public static long PublishCount => Interlocked.Read(ref _publishCount);
    public static long ProxyFetchCount => Interlocked.Read(ref _proxyFetchCount);
    public static long CacheHits => Interlocked.Read(ref _cacheHits);
    public static long CacheMisses => Interlocked.Read(ref _cacheMisses);

    public static void IncrementPublish() => Interlocked.Increment(ref _publishCount);
    public static void IncrementProxyFetch() => Interlocked.Increment(ref _proxyFetchCount);
    public static void IncrementCacheHit() => Interlocked.Increment(ref _cacheHits);
    public static void IncrementCacheMiss() => Interlocked.Increment(ref _cacheMisses);
}
