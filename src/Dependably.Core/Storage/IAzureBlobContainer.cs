namespace Dependably.Storage;

/// <summary>
/// Thin seam over <see cref="Azure.Storage.Blobs.BlobContainerClient"/> exposing only the
/// methods <see cref="AzureBlobStore"/> uses. Exists so tests can mock the Azure SDK
/// without depending on the concrete client's connection-string-driven constructor.
/// Production code uses <see cref="AzureBlobContainerAdapter"/>; tests substitute a fake.
/// </summary>
public interface IAzureBlobContainer
{
    Task CreateIfNotExistsAsync(CancellationToken ct);
    Task UploadAsync(string key, Stream data, CancellationToken ct);
    Task<Stream?> DownloadOrNullAsync(string key, CancellationToken ct);

    /// <summary>
    /// Downloads the byte range [<paramref name="from"/>, <paramref name="to"/>] (inclusive)
    /// for the blob at <paramref name="key"/>. Returns <c>(null, 0)</c> when the blob does
    /// not exist. The <c>TotalLength</c> component carries the full unranged blob size so
    /// callers can build a correct <c>Content-Range</c> header.
    /// </summary>
    Task<(Stream? Content, long TotalLength)> DownloadRangeOrNullAsync(
        string key, long from, long to, CancellationToken ct);

    Task<bool> ExistsAsync(string key, CancellationToken ct);
    Task DeleteIfExistsAsync(string key, CancellationToken ct);

    /// <summary>
    /// Enumerates blob content lengths. Returning the raw sizes (rather than a single
    /// total) lets tests assert pagination iteration in addition to summing — see the
    /// blob-store plan's "GetTotalSizeAsync iterates pagination cursors" requirement.
    /// </summary>
    IAsyncEnumerable<long> EnumerateSizesAsync(CancellationToken ct);

    /// <summary>
    /// Enumerates (key, size, last-modified) for every blob whose name starts with
    /// <paramref name="prefix"/>. Backs <see cref="AzureBlobStore.ListAsync"/>.
    /// </summary>
    IAsyncEnumerable<BlobInfo> EnumerateBlobsAsync(string prefix, CancellationToken ct);
}
