using Dependably.Storage;

namespace Dependably.Tests.Storage;

/// <summary>
/// Abstract contract test suite for IBlobStore.
/// Every IBlobStore implementation must pass all tests in this class.
/// Concrete subclasses provide the store under test via <see cref="CreateStore"/>.
/// </summary>
public abstract class BlobStoreContractTests
{
    protected abstract IBlobStore CreateStore();

    [Fact]
    public async Task Put_ThenGet_ReturnsSameBytes()
    {
        var store = CreateStore();
        byte[] data = new byte[] { 1, 2, 3, 4, 5 };

        await store.PutAsync("test/put-get", new MemoryStream(data));

        await using var stream = await store.GetAsync("test/put-get");
        Assert.NotNull(stream);
        byte[] result = await ReadAllBytesAsync(stream!);
        Assert.Equal(data, result);
    }

    [Fact]
    public async Task Exists_BeforePut_ReturnsFalse()
    {
        var store = CreateStore();

        bool exists = await store.ExistsAsync($"test/never-written/{Guid.NewGuid():N}");

        Assert.False(exists);
    }

    [Fact]
    public async Task Exists_AfterPut_ReturnsTrue()
    {
        var store = CreateStore();
        string key = $"test/exists/{Guid.NewGuid():N}";

        await store.PutAsync(key, new MemoryStream(new byte[] { 42 }));

        Assert.True(await store.ExistsAsync(key));
    }

    [Fact]
    public async Task Get_NonExistentKey_ReturnsNull()
    {
        var store = CreateStore();

        var stream = await store.GetAsync($"test/missing/{Guid.NewGuid():N}");

        Assert.Null(stream);
    }

    [Fact]
    public async Task Delete_ThenExists_ReturnsFalse()
    {
        var store = CreateStore();
        string key = $"test/delete/{Guid.NewGuid():N}";
        await store.PutAsync(key, new MemoryStream(new byte[] { 1 }));

        await store.DeleteAsync(key);

        Assert.False(await store.ExistsAsync(key));
    }

    [Fact]
    public async Task Delete_NonExistentKey_DoesNotThrow()
    {
        var store = CreateStore();
        string key = $"test/phantom/{Guid.NewGuid():N}";

        // Deleting a key that was never written must be a no-op
        await store.DeleteAsync(key);

        Assert.False(await store.ExistsAsync(key));
    }

    [Fact]
    public async Task GetTotalSize_IncreasesByBlobSize_AfterPut()
    {
        var store = CreateStore();
        long before = await store.GetTotalSizeAsync();
        byte[] data = new byte[256];
        new Random(42).NextBytes(data);

        await store.PutAsync($"test/size/{Guid.NewGuid():N}", new MemoryStream(data));

        long after = await store.GetTotalSizeAsync();
        Assert.True(after >= before + data.Length,
            $"Expected total size to increase by at least {data.Length} bytes.");
    }

    [Fact]
    public async Task Put_OverwritesExistingKey()
    {
        var store = CreateStore();
        string key = $"test/overwrite/{Guid.NewGuid():N}";

        await store.PutAsync(key, new MemoryStream(new byte[] { 1, 2, 3 }));
        await store.PutAsync(key, new MemoryStream(new byte[] { 9, 8, 7, 6 }));

        await using var stream = await store.GetAsync(key);
        byte[] bytes = await ReadAllBytesAsync(stream!);
        Assert.Equal(new byte[] { 9, 8, 7, 6 }, bytes);
    }

    [Fact]
    public async Task HostedKeys_AreIsolatedBetweenOrgs()
    {
        var store = CreateStore();
        string key1 = BlobKeys.Hosted("org-a", "pypi", "mylib", "1.0.0", "mylib-1.0.0.whl");
        string key2 = BlobKeys.Hosted("org-b", "pypi", "mylib", "1.0.0", "mylib-1.0.0.whl");

        await store.PutAsync(key1, new MemoryStream(new byte[] { 1 }));

        // org-b must not see org-a's blob
        Assert.False(await store.ExistsAsync(key2));
    }

    [Fact]
    public async Task ProxyKeys_AreSharedAcrossOrgs()
    {
        var store = CreateStore();
        // BlobKeys.Proxy (hardened to reject non-hex input) requires 64-char lowercase hex.
        string sha256 = Convert.ToHexString(new byte[32]).ToLowerInvariant();  // all-zero hash for test
        string proxyKey = BlobKeys.Proxy(sha256);

        await store.PutAsync(proxyKey, new MemoryStream(new byte[] { 1, 2, 3 }));

        // Same proxy key is visible regardless of which org checks it
        Assert.True(await store.ExistsAsync(proxyKey));
    }

    [Fact]
    public async Task EmptyBlob_CanBeStored_AndRetrieved()
    {
        var store = CreateStore();
        string key = $"test/empty/{Guid.NewGuid():N}";

        await store.PutAsync(key, new MemoryStream(Array.Empty<byte>()));

        await using var stream = await store.GetAsync(key);
        Assert.NotNull(stream);
        byte[] bytes = await ReadAllBytesAsync(stream!);
        Assert.Empty(bytes);
    }

    private static async Task<byte[]> ReadAllBytesAsync(Stream stream)
    {
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms);
        return ms.ToArray();
    }
}
