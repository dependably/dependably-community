using Dependably.Infrastructure.Observability;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Coverage for <see cref="MetricsSnapshotProvider"/>. The provider has no
/// constructor dependencies — every reading comes from process-global
/// in-memory state (<see cref="DependablyMeter"/> + <see cref="SnapshotCounters"/>).
///
/// <para>Because that state is shared across the suite, the tests use
/// <i>before-and-after</i> deltas and unique job-name / tier suffixes to stay
/// stable under xUnit's parallel collection runner. Per the cardinality
/// budget, no test ever introduces a <c>tenant_id</c> attribute; the only
/// dimensions the snapshot exposes are <c>tier</c> (blob store) and
/// <c>job_name</c> (background jobs).</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetricsSnapshotProviderTests
{
    [Fact]
    public void Capture_ReturnsSnapshotWithDictionariesAndRecentTimestamp()
    {
        var provider = new MetricsSnapshotProvider();

        var before = DateTimeOffset.UtcNow;
        var snapshot = provider.Capture();
        var after = DateTimeOffset.UtcNow;

        // Shape — dictionaries are always materialized, never null. Other suites may
        // have populated them with their own keys, so we only assert the contract:
        // non-null, readable IReadOnlyDictionary instances.
        Assert.NotNull(snapshot.BlobStoreSizesByTier);
        Assert.NotNull(snapshot.BackgroundJobLastSuccessUnixSeconds);

        // CapturedAt is sampled inside Capture(); allow a tiny clock-skew window.
        Assert.InRange(snapshot.CapturedAt, before.AddSeconds(-1), after.AddSeconds(1));
    }

    [Fact]
    public void Capture_ReflectsTenantCountRecordedOnDependablyMeter()
    {
        // RecordTenantCount uses Interlocked.Exchange, so the most recent write
        // wins. Snapshotting after the write must observe the new value.
        DependablyMeter.RecordTenantCount(4242);

        var snapshot = new MetricsSnapshotProvider().Capture();

        Assert.Equal(4242L, snapshot.ActiveTenants);
    }

    [Fact]
    public void Capture_ReflectsBlobStoreSizesKeyedByTier()
    {
        // Use a uniquely-suffixed tier so the assertion survives parallel runs
        // where production code paths may also write "cache"/"registry".
        // Tier is the only label here — never tenant_id (cardinality budget).
        string tier = $"unit-tier-{Guid.NewGuid():N}";
        DependablyMeter.RecordBlobStoreSize(tier, 9_876_543L);

        var snapshot = new MetricsSnapshotProvider().Capture();

        Assert.True(snapshot.BlobStoreSizesByTier.TryGetValue(tier, out long bytes));
        Assert.Equal(9_876_543L, bytes);
    }

    [Fact]
    public void Capture_ReflectsBackgroundJobLastSuccessKeyedByJobName()
    {
        string jobName = $"unit-job-{Guid.NewGuid():N}";
        DependablyMeter.RecordBackgroundJobSuccess(jobName);

        var snapshot = new MetricsSnapshotProvider().Capture();

        Assert.True(snapshot.BackgroundJobLastSuccessUnixSeconds.TryGetValue(jobName, out long ts));
        // Recorded as DateTimeOffset.UtcNow.ToUnixTimeSeconds() — must be a sane
        // recent epoch second (sometime after 2026-01-01).
        Assert.True(ts >= 1_767_225_600L, $"Unexpected timestamp {ts}");
    }

    [Fact]
    public void Capture_ReflectsSnapshotCountersAsDeltasSinceStartup()
    {
        // SnapshotCounters are process-lifetime — assert delta, not absolute,
        // so the test doesn't race other suites incrementing the same counters.
        var baseline = new MetricsSnapshotProvider().Capture();

        SnapshotCounters.IncrementPublish();
        SnapshotCounters.IncrementProxyFetch();
        SnapshotCounters.IncrementCacheHit();
        SnapshotCounters.IncrementCacheMiss();

        var after = new MetricsSnapshotProvider().Capture();

        Assert.True(after.PublishCountSinceStartup >= baseline.PublishCountSinceStartup + 1);
        Assert.True(after.ProxyFetchCountSinceStartup >= baseline.ProxyFetchCountSinceStartup + 1);
        Assert.True(after.CacheHitsSinceStartup >= baseline.CacheHitsSinceStartup + 1);
        Assert.True(after.CacheMissesSinceStartup >= baseline.CacheMissesSinceStartup + 1);
    }

    [Fact]
    public void Capture_BlobStoreSizesAndJobMaps_AreSnapshotCopiesNotLiveViews()
    {
        // ReadBlobStoreSizes / ReadBackgroundJobLastSuccess materialize the
        // ConcurrentDictionary into a plain Dictionary — later writes must NOT
        // appear in an already-captured snapshot. This guards the page contract
        // that values are point-in-time, not live.
        string tier = $"unit-stable-tier-{Guid.NewGuid():N}";
        string jobName = $"unit-stable-job-{Guid.NewGuid():N}";

        DependablyMeter.RecordBlobStoreSize(tier, 1L);
        DependablyMeter.RecordBackgroundJobSuccess(jobName);

        var snapshot = new MetricsSnapshotProvider().Capture();

        // Mutate the underlying state after capturing.
        DependablyMeter.RecordBlobStoreSize(tier, 2L);

        Assert.Equal(1L, snapshot.BlobStoreSizesByTier[tier]);
        // Just verify the job entry was captured; its timestamp doesn't matter here.
        Assert.True(snapshot.BackgroundJobLastSuccessUnixSeconds.ContainsKey(jobName));
    }

    [Fact]
    public async Task Capture_IsSafeUnderConcurrentInvocation()
    {
        // The provider is registered as a singleton; the underlying read accessors
        // use ConcurrentDictionary / Interlocked.Read. Fan out captures across many
        // threads to prove no read throws under contention.
        var provider = new MetricsSnapshotProvider();

        var tasks = Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
        {
            for (int i = 0; i < 25; i++)
            {
                var s = provider.Capture();
                Assert.NotNull(s.BlobStoreSizesByTier);
                Assert.NotNull(s.BackgroundJobLastSuccessUnixSeconds);
            }
        }));

        await Task.WhenAll(tasks);
    }
}
