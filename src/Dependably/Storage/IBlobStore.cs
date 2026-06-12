namespace Dependably.Storage;

public interface IBlobStore
{
    Task PutAsync(string key, Stream data, CancellationToken ct = default);
    Task<Stream?> GetAsync(string key, CancellationToken ct = default);
    Task<bool> ExistsAsync(string key, CancellationToken ct = default);
    Task DeleteAsync(string key, CancellationToken ct = default);
    Task<long> GetTotalSizeAsync(CancellationToken ct = default);

    /// <summary>
    /// Returns a byte-range slice of the blob at <paramref name="key"/> for the inclusive
    /// range [<paramref name="from"/>, <paramref name="to"/>]. The implementation clamps
    /// <paramref name="to"/> to the actual blob length minus one, so the effective range
    /// in <see cref="RangedStream"/> may be narrower than requested. Returns <c>null</c>
    /// when the blob does not exist; the caller is responsible for the 404 response.
    /// Implementations that cannot serve server-side range reads must still implement this
    /// method — returning <c>null</c> signals the caller to fall back to a full read.
    /// </summary>
    Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default);

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
/// A stream slice returned by <see cref="IBlobStore.GetRangeAsync"/>. Carries the effective
/// byte range actually served (which may be narrower than the requested range when the blob
/// is shorter than <c>to</c>) alongside the total unranged blob length, so callers can
/// construct an accurate <c>Content-Range: bytes from-to/total</c> header.
/// </summary>
public sealed class RangedStream : IAsyncDisposable, IDisposable
{
    /// <summary>The byte stream for the requested range.</summary>
    public Stream Content { get; }

    /// <summary>First byte index in the response (0-based, inclusive).</summary>
    public long From { get; }

    /// <summary>Last byte index in the response (0-based, inclusive).</summary>
    public long To { get; }

    /// <summary>Total unranged size of the blob in bytes.</summary>
    public long TotalLength { get; }

    public RangedStream(Stream content, long from, long to, long totalLength)
    {
        Content = content;
        From = from;
        To = to;
        TotalLength = totalLength;
    }

    public void Dispose() => Content.Dispose();
    public ValueTask DisposeAsync() => Content.DisposeAsync();
}

/// <summary>
/// Backend-agnostic listing entry returned by <see cref="IBlobStore.ListAsync"/>.
/// <c>LastModified</c> is sourced from the filesystem mtime (Local) or the object's
/// LastModified header (S3/Azure); used to gate orphan deletion via a grace window so
/// in-flight publishes are never reaped.
/// </summary>
public readonly record struct BlobInfo(string Key, long SizeBytes, DateTimeOffset LastModified);
