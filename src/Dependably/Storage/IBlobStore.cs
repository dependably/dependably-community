namespace Dependably.Storage;

public interface IBlobStore
{
    Task PutAsync(string key, Stream data, CancellationToken ct = default);
    Task<Stream?> GetAsync(string key, CancellationToken ct = default);
    Task<bool> ExistsAsync(string key, CancellationToken ct = default);
    Task DeleteAsync(string key, CancellationToken ct = default);
    Task<long> GetTotalSizeAsync(CancellationToken ct = default);

    /// <summary>
    /// Streams every blob under <paramref name="prefix"/> as <see cref="BlobInfo"/> records
    /// (key + size + last-modified time). Used by background reconciliation jobs that need
    /// to walk the store comparing against the metadata DB — `OrphanBlobReconcilerService`
    /// is the only caller today. Object-store implementations paginate internally; callers
    /// should iterate with <c>await foreach</c> rather than materializing the full list.
    /// </summary>
    IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default);
}

/// <summary>
/// Backend-agnostic listing entry returned by <see cref="IBlobStore.ListAsync"/>.
/// <c>LastModified</c> is sourced from the filesystem mtime (Local) or the object's
/// LastModified header (S3/Azure); used to gate orphan deletion via a grace window so
/// in-flight publishes are never reaped.
/// </summary>
public readonly record struct BlobInfo(string Key, long SizeBytes, DateTimeOffset LastModified);
