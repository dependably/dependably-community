using Dependably.Storage;

namespace Dependably.Tests.Storage;

/// <summary>
/// Extended tests for <see cref="LocalBlobStore"/> that exercise edge branches not
/// covered by the abstract contract suite — missing root directory on
/// <c>GetTotalSizeAsync</c>, missing prefix on <c>ListAsync</c>, deeply nested key
/// listing, large-stream copy through <c>PutAsync</c>, mid-enumeration cancellation,
/// and constructor directory-creation idempotency.
/// </summary>
public sealed class LocalBlobStoreExtendedTests : IDisposable
{
    private readonly string _root;

    public LocalBlobStoreExtendedTests()
    {
        _root = Path.Combine(
            Path.GetTempPath(),
            "dependably-test-blobs",
            "ext-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch
        {
            // best-effort cleanup
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task GetTotalSizeAsync_WhenRootDirectoryRemovedAfterConstruction_ReturnsZero()
    {
        // Constructor creates _root. We delete it to exercise the `if (!Directory.Exists(_root))` early-out branch.
        var store = new LocalBlobStore(_root);
        Directory.Delete(_root, recursive: true);

        long total = await store.GetTotalSizeAsync();

        Assert.Equal(0L, total);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task GetTotalSizeAsync_OnEmptyDirectory_ReturnsZero()
    {
        var store = new LocalBlobStore(_root);

        long total = await store.GetTotalSizeAsync();

        Assert.Equal(0L, total);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task ListAsync_WhenPrefixDirectoryMissing_YieldsNothing()
    {
        var store = new LocalBlobStore(_root);

        var results = new List<BlobInfo>();
        await foreach (var info in store.ListAsync("never-created-prefix/"))
        {
            results.Add(info);
        }

        Assert.Empty(results);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task ListAsync_WithDeeplyNestedKeys_ReturnsAllWithForwardSlashKeys()
    {
        var store = new LocalBlobStore(_root);
        string[] keys = new[]
        {
            "hosted/org-a/pypi/lib/1.0.0/a.whl",
            "hosted/org-a/pypi/lib/1.0.0/sub/b.whl",
            "hosted/org-a/pypi/other/2.0.0/c.whl",
            "hosted/org-b/pypi/lib/1.0.0/d.whl",
        };
        foreach (string? key in keys)
        {
            await store.PutAsync(key, new MemoryStream(new byte[] { 0xAB }));
        }

        var results = new List<BlobInfo>();
        await foreach (var info in store.ListAsync("hosted/org-a/"))
        {
            results.Add(info);
        }

        // Only org-a entries, with forward-slash keys regardless of OS separator
        Assert.Equal(3, results.Count);
        Assert.All(results, r => Assert.StartsWith("hosted/org-a/", r.Key));
        Assert.All(results, r => Assert.DoesNotContain('\\', r.Key));
        Assert.All(results, r => Assert.Equal(1L, r.SizeBytes));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task ListAsync_HonoursCancellationBeforeYielding()
    {
        var store = new LocalBlobStore(_root);
        for (int i = 0; i < 5; i++)
        {
            await store.PutAsync($"batch/file-{i}.bin", new MemoryStream(new byte[] { (byte)i }));
        }

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var results = new List<BlobInfo>();
        await foreach (var info in store.ListAsync("batch/", cts.Token))
        {
            results.Add(info);
        }

        // Cancellation observed inside the loop should produce zero yields.
        Assert.Empty(results);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task PutAsync_CreatesMissingParentDirectories()
    {
        var store = new LocalBlobStore(_root);
        string key = "deeply/nested/path/that/does/not/exist/blob.bin";

        await store.PutAsync(key, new MemoryStream(new byte[] { 1, 2, 3 }));

        Assert.True(await store.ExistsAsync(key));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task PutAsync_StreamsLargePayload()
    {
        var store = new LocalBlobStore(_root);
        // 1 MiB exercises the CopyToAsync streaming path beyond a single buffer.
        byte[] data = new byte[1024 * 1024];
        new Random(1234).NextBytes(data);
        string key = "large/payload.bin";

        await store.PutAsync(key, new MemoryStream(data));

        await using var stream = await store.GetAsync(key);
        Assert.NotNull(stream);
        using var ms = new MemoryStream();
        await stream!.CopyToAsync(ms);
        Assert.Equal(data.Length, ms.Length);
        Assert.Equal(data, ms.ToArray());
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void Constructor_OnExistingDirectory_DoesNotThrow()
    {
        // First construction creates the directory.
        _ = new LocalBlobStore(_root);

        // Second construction with the same root must be idempotent — Directory.CreateDirectory
        // is a no-op when the directory already exists.
        var ex = Record.Exception(() => new LocalBlobStore(_root));
        Assert.Null(ex);
    }
}
