using Azure.Storage.Blobs;

namespace Dependably.Storage;

public sealed class AzureBlobStore : IBlobStore
{
    private readonly IAzureBlobContainer _container;

    /// <summary>
    /// Test-friendly constructor: caller supplies the container adapter (typically an
    /// NSubstitute mock). Does NOT call CreateIfNotExists — tests don't need it and it
    /// would force the mock to expose every Azure SDK detail.
    /// </summary>
    public AzureBlobStore(IAzureBlobContainer container) => _container = container;

    /// <summary>
    /// Production constructor: builds the real <see cref="BlobContainerClient"/> from the
    /// connection string and wraps it. Synchronous CreateIfNotExists runs once here so
    /// the bucket exists before the first PutAsync.
    /// </summary>
    public AzureBlobStore(string connectionString, string containerName)
    {
        var client = new BlobContainerClient(connectionString, containerName);
        client.CreateIfNotExists();
        _container = new AzureBlobContainerAdapter(client);
    }

    public Task PutAsync(string key, Stream data, CancellationToken ct = default)
        => _container.UploadAsync(key, data, ct);

    public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
        => _container.DownloadOrNullAsync(key, ct);

    public async Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
    {
        var (content, totalLength) = await _container.DownloadRangeOrNullAsync(key, from, to, ct);
        if (content is null)
        {
            return null;
        }

        long effectiveTo = Math.Min(to, totalLength - 1);
        if (from > effectiveTo || totalLength == 0)
        {
            // Range starts past end of blob — return sentinel for 416 handling.
            return new RangedStream(Stream.Null, from, from - 1, totalLength);
        }

        return new RangedStream(content, from, effectiveTo, totalLength);
    }

    public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        => _container.ExistsAsync(key, ct);

    public Task DeleteAsync(string key, CancellationToken ct = default)
        => _container.DeleteIfExistsAsync(key, ct);

    public async Task<long> GetTotalSizeAsync(CancellationToken ct = default)
    {
        long total = 0;
        await foreach (long size in _container.EnumerateSizesAsync(ct))
        {
            total += size;
        }

        return total;
    }

    public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
        => _container.EnumerateBlobsAsync(prefix, ct);
}
