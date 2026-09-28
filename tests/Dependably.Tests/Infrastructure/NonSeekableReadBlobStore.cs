using Dependably.Storage;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// An object-store-shaped read path over an inner store: every stream <see cref="GetAsync"/>
/// hands back is forward-only and cannot report its length, as an S3 or Azure response stream
/// cannot. A serve path that measures a blob from <c>Stream.Length</c> alone reads nothing
/// through this store; one that falls back to listing the key gets the real size.
/// <paramref name="hideListing"/>, when it returns true, makes the listing come back empty.
/// </summary>
public sealed class NonSeekableReadBlobStore(IBlobStore inner, Func<bool>? hideListing = null) : IBlobStore
{
    public async Task<Stream?> GetAsync(string key, CancellationToken ct = default)
        => await inner.GetAsync(key, ct) is { } stream ? new ForwardOnlyStream(stream) : null;

    public Task PutAsync(string key, Stream data, CancellationToken ct = default) => inner.PutAsync(key, data, ct);
    public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => inner.ExistsAsync(key, ct);
    public Task DeleteAsync(string key, CancellationToken ct = default) => inner.DeleteAsync(key, ct);
    public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => inner.GetTotalSizeAsync(ct);
    public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
        => inner.GetRangeAsync(key, from, to, ct);
    public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
        => hideListing?.Invoke() == true ? AsyncEnumerable.Empty<BlobInfo>() : inner.ListAsync(prefix, ct);

    private sealed class ForwardOnlyStream(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => inner.ReadAsync(buffer, offset, count, cancellationToken);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => inner.ReadAsync(buffer, cancellationToken);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync();
            await base.DisposeAsync();
        }
    }
}
