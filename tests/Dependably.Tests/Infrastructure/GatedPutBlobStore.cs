using Dependably.Storage;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Blob-store decorator that parks a writer inside <see cref="PutAsync"/> on a gate the test
/// opens, so two concurrent publishes interleave at an exact point with no sleeps.
/// <c>writeBeforePark: false</c> parks BEFORE the bytes reach the inner store (the parked
/// publisher's artifact lands last); <c>true</c> parks AFTER them (the parked publisher's
/// metadata commit lands last). Everything else delegates to the inner store.
///
/// The publish paths this drives write the blob and the metadata row in separate,
/// unsynchronised steps, so these two orderings are the two ways a coordinate-addressed key
/// turns a race into permanent (blob_key, checksum_sha256) divergence.
/// </summary>
public sealed class GatedPutBlobStore : IBlobStore
{
    private readonly IBlobStore _inner;
    private readonly bool _writeBeforePark;
    private readonly TaskCompletionSource _reached =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public GatedPutBlobStore(IBlobStore inner, bool writeBeforePark)
    {
        _inner = inner;
        _writeBeforePark = writeBeforePark;
    }

    /// <summary>Completes once the gated writer has entered PutAsync.</summary>
    public Task Reached => _reached.Task;

    /// <summary>Lets the parked writer finish its put and continue to its metadata write.</summary>
    public void Release() => _release.TrySetResult();

    public async Task PutAsync(string key, Stream content, CancellationToken ct = default)
    {
        if (_writeBeforePark)
        {
            await _inner.PutAsync(key, content, ct);
        }

        _reached.TrySetResult();
        await _release.Task;

        if (!_writeBeforePark)
        {
            await _inner.PutAsync(key, content, ct);
        }
    }

    public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
    public Task<RangedStream?> GetRangeAsync(string key, long offset, long length, CancellationToken ct = default)
        => _inner.GetRangeAsync(key, offset, length, ct);
    public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
    public Task DeleteAsync(string key, CancellationToken ct = default) => _inner.DeleteAsync(key, ct);
    public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
    public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
        => _inner.ListAsync(prefix, ct);
}
