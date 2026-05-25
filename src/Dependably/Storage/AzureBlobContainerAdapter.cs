using System.Runtime.CompilerServices;
using Azure.Storage.Blobs;

namespace Dependably.Storage;

/// <summary>
/// Production <see cref="IAzureBlobContainer"/> adapter that wraps a real
/// <see cref="BlobContainerClient"/>. Owned by <see cref="AzureBlobStore"/>.
/// </summary>
public sealed class AzureBlobContainerAdapter : IAzureBlobContainer
{
    private readonly BlobContainerClient _container;

    public AzureBlobContainerAdapter(BlobContainerClient container) => _container = container;

    public Task CreateIfNotExistsAsync(CancellationToken ct)
    {
        // The Azure SDK's CreateIfNotExists has no native async ct overload that's stable
        // across versions — call it synchronously inside Task.Run to keep the await chain
        // cancellation-friendly. The blocking call happens once at adapter construction.
        return Task.Run(() => _container.CreateIfNotExists(cancellationToken: ct), ct);
    }

    public async Task UploadAsync(string key, Stream data, CancellationToken ct)
        => await _container.GetBlobClient(key).UploadAsync(data, overwrite: true, ct);

    public async Task<Stream?> DownloadOrNullAsync(string key, CancellationToken ct)
    {
        var blob = _container.GetBlobClient(key);
        if (!await blob.ExistsAsync(ct)) return null;
        var response = await blob.DownloadStreamingAsync(cancellationToken: ct);
        return response.Value.Content;
    }

    public async Task<bool> ExistsAsync(string key, CancellationToken ct)
        => await _container.GetBlobClient(key).ExistsAsync(ct);

    public async Task DeleteIfExistsAsync(string key, CancellationToken ct)
        => await _container.GetBlobClient(key).DeleteIfExistsAsync(cancellationToken: ct);

    public async IAsyncEnumerable<long> EnumerateSizesAsync(
        [EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var item in _container.GetBlobsAsync(cancellationToken: ct))
            yield return item.Properties.ContentLength ?? 0;
    }

    public async IAsyncEnumerable<BlobInfo> EnumerateBlobsAsync(
        string prefix, [EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var item in _container.GetBlobsAsync(
            Azure.Storage.Blobs.Models.BlobTraits.None,
            Azure.Storage.Blobs.Models.BlobStates.None,
            prefix,
            ct))
        {
            var lastModified = item.Properties.LastModified ?? DateTimeOffset.MinValue;
            yield return new BlobInfo(
                item.Name,
                item.Properties.ContentLength ?? 0,
                lastModified);
        }
    }
}
