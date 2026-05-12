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
    Task<bool> ExistsAsync(string key, CancellationToken ct);
    Task DeleteIfExistsAsync(string key, CancellationToken ct);

    /// <summary>
    /// Enumerates blob content lengths. Returning the raw sizes (rather than a single
    /// total) lets tests assert pagination iteration in addition to summing — see the
    /// blob-store plan's "GetTotalSizeAsync iterates pagination cursors" requirement.
    /// </summary>
    IAsyncEnumerable<long> EnumerateSizesAsync(CancellationToken ct);
}
