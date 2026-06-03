using Dependably.Storage;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance tests for <see cref="LocalBlobStore.GetTotalSizeAsync"/>: it must return a
/// running counter (O(1)) instead of walking the disk on every call, while still recovering
/// from drift via a one-time walk on startup or an admin recompute.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LocalBlobStoreSizeCounterTests : IDisposable
{
    private readonly string _root;

    public LocalBlobStoreSizeCounterTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"dependably-blob-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public async Task GetTotalSizeAsync_OnEmptyRoot_ReturnsZero()
    {
        var store = new LocalBlobStore(_root);
        Assert.Equal(0L, await store.GetTotalSizeAsync());
    }

    [Fact]
    public async Task GetTotalSizeAsync_ReflectsPutIncrement()
    {
        var store = new LocalBlobStore(_root);
        await store.PutAsync("a", new MemoryStream(new byte[100]));
        await store.PutAsync("b/c", new MemoryStream(new byte[250]));
        Assert.Equal(350L, await store.GetTotalSizeAsync());
    }

    [Fact]
    public async Task GetTotalSizeAsync_ReflectsDeleteDecrement()
    {
        var store = new LocalBlobStore(_root);
        await store.PutAsync("k", new MemoryStream(new byte[1000]));
        Assert.Equal(1000L, await store.GetTotalSizeAsync());

        await store.DeleteAsync("k");
        Assert.Equal(0L, await store.GetTotalSizeAsync());
    }

    [Fact]
    public async Task Overwrite_AdjustsRunningCounterDelta()
    {
        var store = new LocalBlobStore(_root);
        await store.PutAsync("k", new MemoryStream(new byte[500]));
        await store.PutAsync("k", new MemoryStream(new byte[200])); // replace
        Assert.Equal(200L, await store.GetTotalSizeAsync());
    }

    [Fact]
    public async Task FirstAccess_WalksRoot_PicksUpPreExistingFiles()
    {
        // Drop files into the root BEFORE LocalBlobStore is constructed — simulates a fresh
        // process restart against an existing blob tree. The counter must initialize from
        // the on-disk reality on first read, not stay at zero.
        File.WriteAllBytes(Path.Combine(_root, "pre.bin"), new byte[123]);
        Directory.CreateDirectory(Path.Combine(_root, "sub"));
        File.WriteAllBytes(Path.Combine(_root, "sub", "more.bin"), new byte[456]);

        var store = new LocalBlobStore(_root);
        Assert.Equal(123L + 456L, await store.GetTotalSizeAsync());
    }

    [Fact]
    public async Task RecomputeSize_RealignsAfterExternalWrite()
    {
        var store = new LocalBlobStore(_root);
        await store.PutAsync("a", new MemoryStream(new byte[100]));
        Assert.Equal(100L, await store.GetTotalSizeAsync());

        // External write bypasses the counter — pretend something else dropped a file in
        // the root. The counter stays stale until RecomputeSize() is called.
        File.WriteAllBytes(Path.Combine(_root, "external.bin"), new byte[500]);
        Assert.Equal(100L, await store.GetTotalSizeAsync()); // still stale

        store.RecomputeSize();
        Assert.Equal(600L, await store.GetTotalSizeAsync()); // aligned
    }

    [Fact]
    public async Task GetTotalSizeAsync_IsConstantTime_NoDirectoryWalkAfterInit()
    {
        // The whole point: subsequent calls must NOT re-walk. We can't directly assert
        // "no syscalls" but we can prove the call returns instantly even with many files.
        var store = new LocalBlobStore(_root);
        for (var i = 0; i < 200; i++)
            await store.PutAsync($"f{i:000}", new MemoryStream(new byte[64]));

        // Warm up the counter.
        await store.GetTotalSizeAsync();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < 1000; i++)
            await store.GetTotalSizeAsync();
        sw.Stop();

        // 1000 calls in well under 100ms on any reasonable machine — the old walk would have
        // taken seconds at 200 files; the counter path is microseconds.
        Assert.True(sw.ElapsedMilliseconds < 500,
            $"GetTotalSizeAsync took {sw.ElapsedMilliseconds}ms for 1000 calls — looks like a walk is still happening.");
    }
}
