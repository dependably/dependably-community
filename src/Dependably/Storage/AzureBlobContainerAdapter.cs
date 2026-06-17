using System.Runtime.CompilerServices;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace Dependably.Storage;

/// <summary>
/// Production <see cref="IAzureBlobContainer"/> adapter that wraps a real
/// <see cref="BlobContainerClient"/>. Owned by <see cref="AzureBlobStore"/>.
/// </summary>
public sealed class AzureBlobContainerAdapter : IAzureBlobContainer
{
    private const int HttpStatusNotFound = StatusCodes.Status404NotFound;

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
        if (!await blob.ExistsAsync(ct))
        {
            return null;
        }

        var response = await blob.DownloadStreamingAsync(cancellationToken: ct);
        return response.Value.Content;
    }

    public async Task<(Stream? Content, long TotalLength)> DownloadRangeOrNullAsync(
        string key, long from, long to, CancellationToken ct)
    {
        var blob = _container.GetBlobClient(key);

        // Fetch the blob properties first to get the total size for Content-Range.
        Response<BlobProperties> propsResponse;
        try
        {
            propsResponse = await blob.GetPropertiesAsync(cancellationToken: ct);
        }
        catch (RequestFailedException ex) when (ex.Status == HttpStatusNotFound)
        {
            return (null, 0);
        }

        long totalLength = propsResponse.Value.ContentLength;
        long effectiveTo = Math.Min(to, totalLength - 1);

        if (from > effectiveTo || totalLength == 0)
        {
            // Range starts past the end — caller will emit 416.
            return (Stream.Null, totalLength);
        }

        // Azure HttpRange uses offset + length (not inclusive end).
        long rangeLength = effectiveTo - from + 1;
        var range = new HttpRange(from, rangeLength);

        try
        {
            var response = await blob.DownloadStreamingAsync(
                new BlobDownloadOptions { Range = range },
                cancellationToken: ct);
            return (response.Value.Content, totalLength);
        }
        catch (RequestFailedException ex) when (ex.Status == HttpStatusNotFound)
        {
            return (null, 0);
        }
    }

    public async Task<bool> ExistsAsync(string key, CancellationToken ct)
        => await _container.GetBlobClient(key).ExistsAsync(ct);

    public async Task DeleteIfExistsAsync(string key, CancellationToken ct)
        => await _container.GetBlobClient(key).DeleteIfExistsAsync(cancellationToken: ct);

    public async IAsyncEnumerable<long> EnumerateSizesAsync(
        [EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var item in _container.GetBlobsAsync(cancellationToken: ct))
        {
            yield return item.Properties.ContentLength ?? 0;
        }
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
