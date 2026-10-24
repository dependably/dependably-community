using Dependably.Storage;

namespace Dependably.Tests.Infrastructure;

/// <summary>A readable stream over <c>data</c> that throws <see cref="IOException"/> once <c>throwAfter</c> bytes were served.</summary>
public sealed class ThrowingStream(byte[] data, int throwAfter) : Stream
{
    private int _position;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => _position; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_position >= throwAfter)
        {
            throw new IOException("Simulated storage read failure.");
        }

        int n = Math.Min(Math.Min(count, throwAfter - _position), data.Length - _position);
        Array.Copy(data, _position, buffer, offset, n);
        _position += n;
        return n;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// Wraps a blob store so reads of chosen keys fail part-way through the stream while the toggle is
/// on, the way a dropped storage connection does.
/// </summary>
public sealed class MidStreamFaultBlobStore(IBlobStore inner) : IBlobStore
{
    public HashSet<string> FailingKeys { get; } = [];

    /// <summary>Keys whose reads throw on open, the way an unreachable store does.</summary>
    public HashSet<string> ThrowingKeys { get; } = [];

    /// <summary>When set, every read throws on open.</summary>
    public bool ThrowOnEveryRead { get; set; }

    public Task PutAsync(string key, Stream data, CancellationToken ct = default) => inner.PutAsync(key, data, ct);

    public async Task<Stream?> GetAsync(string key, CancellationToken ct = default)
    {
        if (ThrowOnEveryRead || ThrowingKeys.Contains(key))
        {
            throw new IOException("Simulated storage outage.");
        }

        var stream = await inner.GetAsync(key, ct);
        if (stream is null || !FailingKeys.Contains(key))
        {
            return stream;
        }

        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct);
        await stream.DisposeAsync();
        return new ThrowingStream(ms.ToArray(), 20);
    }

    public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => inner.ExistsAsync(key, ct);
    public Task DeleteAsync(string key, CancellationToken ct = default) => inner.DeleteAsync(key, ct);
    public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => inner.GetTotalSizeAsync(ct);
    public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) =>
        inner.GetRangeAsync(key, from, to, ct);

    public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => inner.ListAsync(prefix, ct);
}
