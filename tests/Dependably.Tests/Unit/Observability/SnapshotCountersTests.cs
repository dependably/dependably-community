using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Coverage for the four read-side properties on <see cref="SnapshotCounters"/> —
/// the increment methods are exercised across the integration suite, but the
/// getters were never directly asserted. The counters are static (process-wide),
/// so each test reads a baseline first and asserts deltas rather than absolutes
/// to stay stable when the suite runs in parallel.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SnapshotCountersTests
{
    [Fact]
    public void PublishCount_ReturnsValueAfterIncrement()
    {
        long before = SnapshotCounters.PublishCount;
        SnapshotCounters.IncrementPublish();
        Assert.True(SnapshotCounters.PublishCount >= before + 1);
    }

    [Fact]
    public void ProxyFetchCount_ReturnsValueAfterIncrement()
    {
        long before = SnapshotCounters.ProxyFetchCount;
        SnapshotCounters.IncrementProxyFetch();
        Assert.True(SnapshotCounters.ProxyFetchCount >= before + 1);
    }

    [Fact]
    public void CacheHits_ReturnsValueAfterIncrement()
    {
        long before = SnapshotCounters.CacheHits;
        SnapshotCounters.IncrementCacheHit();
        Assert.True(SnapshotCounters.CacheHits >= before + 1);
    }

    [Fact]
    public void CacheMisses_ReturnsValueAfterIncrement()
    {
        long before = SnapshotCounters.CacheMisses;
        SnapshotCounters.IncrementCacheMiss();
        Assert.True(SnapshotCounters.CacheMisses >= before + 1);
    }

    [Fact]
    public async Task IncrementPublish_IsThreadSafe()
    {
        // Interlocked.Increment guarantees atomicity — fan out 100 increments across
        // 10 threads. Use >= because xUnit runs collections in parallel and integration
        // code paths may also bump the counter; we just need to prove no increments are lost.
        long before = SnapshotCounters.PublishCount;
        var tasks = Enumerable.Range(0, 10).Select(_ => Task.Run(() =>
        {
            for (int i = 0; i < 10; i++)
            {
                SnapshotCounters.IncrementPublish();
            }
        }));
        await Task.WhenAll(tasks);
        Assert.True(SnapshotCounters.PublishCount >= before + 100);
    }
}
