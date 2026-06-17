using Dependably.Infrastructure.Caching;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit coverage for the shared metadata-cache helper. These prove the structural guarantee
/// the helper exists for: every get/set/evict for a logical entry routes through one key
/// formatter, so a set and an equal-but-separately-built key can never disagree (the
/// cache-key-divergence class of bug). Also covers single-flight dedup and the instance-scoped
/// in-flight map that the DI singleton lifetime relies on.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetadataResponseCacheTests
{
    private static MemoryCache NewCache() =>
        new(new MemoryCacheOptions { SizeLimit = 50 * 1024 * 1024 });

    // ── Consistency guarantee ──────────────────────────────────────────────────

    [Fact]
    public void SetThenEvict_WithSeparatelyBuiltEqualKey_Misses()
    {
        var cache = new MetadataResponseCache<NuGetRegistrationKey, byte[]>(
            NewCache(), MetadataCacheKeys.NuGetRegistration);

        var setKey = new NuGetRegistrationKey("org1", "newtonsoft.json", SemVer2: true);
        cache.Set(setKey, [1, 2, 3], TimeSpan.FromMinutes(5), size: 3);
        Assert.True(cache.TryGet(setKey, out _));

        // A freshly-built key from the same components must evict the same entry.
        var evictKey = new NuGetRegistrationKey("org1", "newtonsoft.json", SemVer2: true);
        cache.Evict(evictKey);

        Assert.False(cache.TryGet(setKey, out byte[]? after));
        Assert.Null(after);
    }

    [Fact]
    public void NuGet_SemVerVariants_AreDistinctEntries()
    {
        var cache = new RenderedResponseCache<NuGetRegistrationKey>(
            NewCache(), MetadataCacheKeys.NuGetRegistration);

        cache.Set(new NuGetRegistrationKey("org1", "pkg", SemVer2: false), [1], TimeSpan.FromMinutes(5));
        cache.Set(new NuGetRegistrationKey("org1", "pkg", SemVer2: true), [2], TimeSpan.FromMinutes(5));

        // Evicting one variant must not disturb the other.
        cache.Evict(new NuGetRegistrationKey("org1", "pkg", SemVer2: false));

        Assert.False(cache.TryGet(new NuGetRegistrationKey("org1", "pkg", SemVer2: false), out _));
        Assert.True(cache.TryGet(new NuGetRegistrationKey("org1", "pkg", SemVer2: true), out _));
    }

    [Fact]
    public void PyPi_Pep503EquivalentNames_ResolveToSameEntry()
    {
        var cache = new RenderedResponseCache<PyPiSimpleIndexKey>(
            NewCache(), MetadataCacheKeys.PyPiSimpleIndex);

        // PEP 503: 'my_package' and 'My-Package' both normalize to 'my-package'. The formatter
        // owns that normalization, so a set under one spelling is found under the other and
        // evicted by a third — structurally, not by the caller remembering to normalize.
        cache.Set(new PyPiSimpleIndexKey("org1", "my_package"), [9], TimeSpan.FromMinutes(10));

        Assert.True(cache.TryGet(new PyPiSimpleIndexKey("org1", "My-Package"), out byte[]? hit));
        Assert.NotNull(hit);

        cache.Evict(new PyPiSimpleIndexKey("org1", "my.package"));
        Assert.False(cache.TryGet(new PyPiSimpleIndexKey("org1", "my_package"), out _));
    }

    [Fact]
    public void DifferentTenants_AreIsolated()
    {
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument);

        cache.Set(new NpmPackumentKey("orgA", "left-pad"), [1], TimeSpan.FromMinutes(5));
        cache.Evict(new NpmPackumentKey("orgB", "left-pad"));

        Assert.True(cache.TryGet(new NpmPackumentKey("orgA", "left-pad"), out _));
    }

    // ── Single-flight ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GetOrRebuildAsync_ConcurrentCallers_RebuildOnce()
    {
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument);
        var key = new NpmPackumentKey("org1", "concurrent-pkg");

        int rebuildCount = 0;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        async Task<byte[]?> Rebuild(CancellationToken _)
        {
            Interlocked.Increment(ref rebuildCount);
            await gate.Task;
            return [42];
        }

        var tasks = Enumerable.Range(0, 8)
            .Select(_ => Task.Run(() =>
                cache.GetOrRebuildAsync(key, TimeSpan.FromMinutes(5), Rebuild, CancellationToken.None)))
            .ToArray();

        // Let every caller reach the in-flight map before the single rebuild resolves.
        await Task.Delay(50);
        gate.SetResult();
        byte[]?[] results = await Task.WhenAll(tasks);

        Assert.Equal(1, rebuildCount);
        Assert.All(results, r => Assert.Equal([42], r));
    }

    [Fact]
    public async Task GetOrRebuildAsync_CacheHit_DoesNotRebuild()
    {
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument);
        var key = new NpmPackumentKey("org1", "warm-pkg");
        cache.Set(key, [7], TimeSpan.FromMinutes(5));

        int rebuildCount = 0;
        byte[]? result = await cache.GetOrRebuildAsync(key, TimeSpan.FromMinutes(5), _ =>
        {
            Interlocked.Increment(ref rebuildCount);
            return Task.FromResult<byte[]?>([0]);
        }, CancellationToken.None);

        Assert.Equal(0, rebuildCount);
        Assert.Equal([7], result);
    }

    [Fact]
    public async Task GetOrRebuildAsync_NullRebuild_CachesNothing()
    {
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument);
        var key = new NpmPackumentKey("org1", "missing-pkg");

        byte[]? result = await cache.GetOrRebuildAsync(
            key, TimeSpan.FromMinutes(5), _ => Task.FromResult<byte[]?>(null), CancellationToken.None);

        Assert.Null(result);
        Assert.False(cache.TryGet(key, out _));
    }

    [Fact]
    public async Task GetOrRebuildAsync_SuccessfulRebuild_PopulatesCache()
    {
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument);
        var key = new NpmPackumentKey("org1", "fresh-pkg");

        _ = await cache.GetOrRebuildAsync(
            key, TimeSpan.FromMinutes(5), _ => Task.FromResult<byte[]?>([5, 6]), CancellationToken.None);

        // A subsequent fetch is served from cache (the rebuild's Set ran) without re-running rebuild.
        int secondRebuilds = 0;
        byte[]? second = await cache.GetOrRebuildAsync(key, TimeSpan.FromMinutes(5), _ =>
        {
            Interlocked.Increment(ref secondRebuilds);
            return Task.FromResult<byte[]?>([0]);
        }, CancellationToken.None);

        Assert.Equal(0, secondRebuilds);
        Assert.Equal([5, 6], second);
    }

    // ── Singleton-lifetime contract ─────────────────────────────────────────────

    [Fact]
    public async Task InFlightMap_IsInstanceScoped_SharedAcrossCallers()
    {
        // The single-flight dedup lives on the helper instance, not on any per-request state.
        // A second "request" (modelled as a second caller against the SAME instance) joins the
        // first's in-flight rebuild rather than starting its own — proving why the helper must be
        // a DI singleton across transient controllers. A fresh instance would NOT share dedup.
        var shared = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument);
        var key = new NpmPackumentKey("org1", "shared-pkg");

        int rebuildCount = 0;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        async Task<byte[]?> Rebuild(CancellationToken _)
        {
            Interlocked.Increment(ref rebuildCount);
            await gate.Task;
            return [1];
        }

        var first = Task.Run(() => shared.GetOrRebuildAsync(key, TimeSpan.FromMinutes(5), Rebuild, CancellationToken.None));
        var second = Task.Run(() => shared.GetOrRebuildAsync(key, TimeSpan.FromMinutes(5), Rebuild, CancellationToken.None));

        await Task.Delay(50);
        gate.SetResult();
        await Task.WhenAll(first, second);

        // One shared instance ⇒ both callers collapsed onto one rebuild.
        Assert.Equal(1, rebuildCount);

        // Contrast: a separate instance has its own empty in-flight map, so it rebuilds afresh.
        var separate = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument);
        int separateRebuilds = 0;
        _ = await separate.GetOrRebuildAsync(key, TimeSpan.FromMinutes(5), _ =>
        {
            Interlocked.Increment(ref separateRebuilds);
            return Task.FromResult<byte[]?>([2]);
        }, CancellationToken.None);
        Assert.Equal(1, separateRebuilds);
    }

    // ── Size enforcement under a size-limited cache ─────────────────────────────

    [Fact]
    public void Set_ByteArrayOverload_InfersSizeFromLength()
    {
        // A size-limited MemoryCache throws if an entry omits Size. The byte[] Set overload must
        // always supply it, so this set succeeds and round-trips.
        var cache = new RenderedResponseCache<PyPiSimpleIndexKey>(
            NewCache(), MetadataCacheKeys.PyPiSimpleIndex);
        var key = new PyPiSimpleIndexKey("org1", "sized-pkg");

        cache.Set(key, [1, 2, 3, 4], TimeSpan.FromMinutes(5));

        Assert.True(cache.TryGet(key, out byte[]? bytes));
        Assert.Equal(4, bytes!.Length);
    }

    // ── MetadataConcurrencyGate integration ──────────────────────────────────────

    [Fact]
    public async Task GetOrRebuildAsync_WithGate_BoundsConcurrentRebuilds()
    {
        // Gate set to 2 slots. Fan out 6 cache-MISS rebuilds in parallel. At most 2 should
        // execute simultaneously; the rest wait for a slot. We use a manual-release gate
        // inside the rebuild to hold each rebuild in-flight long enough to observe the
        // semaphore count being depressed.
        const int gateSlots = 2;
        const int concurrentMisses = 6;
        var semaphore = new SemaphoreSlim(gateSlots, gateSlots);
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument, semaphore);

        // Each rebuild key is distinct so there is no single-flight collapsing — each
        // generates an independent rebuild task that competes for a gate slot.
        var rebuildGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int activeRebuildsPeak = 0;
        int currentActive = 0;

        async Task<byte[]?> SlowRebuild(CancellationToken ct)
        {
            // Track peak concurrency inside the rebuild (inside the gate slot).
            int active = Interlocked.Increment(ref currentActive);
            Interlocked.Exchange(ref activeRebuildsPeak,
                Math.Max(Volatile.Read(ref activeRebuildsPeak), active));
            try
            {
                // Block until all tasks have started (or the test times out), so we
                // observe actual concurrency rather than sequential scheduling.
                await rebuildGate.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
                return new byte[] { 42 };
            }
            finally
            {
                Interlocked.Decrement(ref currentActive);
            }
        }

        var tasks = Enumerable.Range(0, concurrentMisses).Select(i =>
        {
            var key = new NpmPackumentKey("org1", $"gate-pkg-{i}");
            return Task.Run(() => cache.GetOrRebuildAsync(key, TimeSpan.FromMinutes(5), SlowRebuild, CancellationToken.None));
        }).ToList();

        // Give tasks time to fill the gate slots before releasing the rebuild gate.
        // The gate is sized to 2, so at most 2 rebuilds block at SlowRebuild concurrently.
        await Task.Delay(100);
        rebuildGate.SetResult();

        byte[]?[] results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.Equal(new byte[] { 42 }, r));
        // Peak concurrency inside the gate must not exceed the slot count.
        Assert.True(activeRebuildsPeak <= gateSlots,
            $"Peak active rebuilds {activeRebuildsPeak} exceeded gate slot count {gateSlots}.");
    }

    [Fact]
    public async Task GetOrRebuildAsync_WithGate_CacheHit_BypassesGate()
    {
        // A pre-warmed cache entry must be returned without acquiring any semaphore slot.
        // We exhaust the gate (0 slots) and confirm a HIT completes immediately.
        var semaphore = new SemaphoreSlim(1, 1);
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument, semaphore);

        var key = new NpmPackumentKey("org1", "hit-pkg");
        cache.Set(key, [7], TimeSpan.FromMinutes(5));

        // Drain the semaphore so any acquisition attempt would block indefinitely.
        await semaphore.WaitAsync();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            byte[]? result = await cache
                .GetOrRebuildAsync(key, TimeSpan.FromMinutes(5),
                    _ => Task.FromResult<byte[]?>([0]), CancellationToken.None)
                .WaitAsync(cts.Token);

            // Hit must return the cached value without touching the semaphore.
            Assert.Equal(new byte[] { 7 }, result);
            Assert.Equal(0, semaphore.CurrentCount); // slot still held by us — not re-acquired
        }
        finally
        {
            semaphore.Release();
        }
    }

    [Fact]
    public async Task GetOrRebuildAsync_WithGate_Mixed_HitAndMiss_BothSucceed()
    {
        // Mixed scenario (house rule): one cache-HIT request and one cache-MISS rebuild run
        // concurrently under a gate with a single slot. The HIT must not wait for the gate;
        // both requests must succeed.
        const int gateSlots = 1;
        var semaphore = new SemaphoreSlim(gateSlots, gateSlots);
        var cache = new RenderedResponseCache<NpmPackumentKey>(
            NewCache(), MetadataCacheKeys.NpmPackument, semaphore);

        var hitKey = new NpmPackumentKey("org1", "warm");
        var missKey = new NpmPackumentKey("org1", "cold");
        cache.Set(hitKey, [1], TimeSpan.FromMinutes(5));

        // MISS rebuild is slow enough that the HIT can complete while the MISS holds the gate.
        var missGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var hitTask = cache.GetOrRebuildAsync(hitKey, TimeSpan.FromMinutes(5),
            _ => Task.FromResult<byte[]?>([0]), CancellationToken.None);
        var missTask = cache.GetOrRebuildAsync(missKey, TimeSpan.FromMinutes(5),
            async _ => { await missGate.Task; return new byte[] { 2 }; }, CancellationToken.None);

        // HIT should complete immediately (well before the MISS gate releases).
        using var hitCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        byte[]? hitResult = await hitTask.WaitAsync(hitCts.Token);
        Assert.Equal(new byte[] { 1 }, hitResult);

        // Now let the MISS rebuild finish.
        missGate.SetResult();
        byte[]? missResult = await missTask;
        Assert.Equal(new byte[] { 2 }, missResult);
    }
}
