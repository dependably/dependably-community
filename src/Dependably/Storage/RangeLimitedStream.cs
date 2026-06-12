namespace Dependably.Storage;

/// <summary>
/// Read-only pass-through stream that stops delivering bytes after <paramref name="maxBytes"/>
/// have been read. Used by <see cref="LocalBlobStore.GetRangeAsync"/> to serve a byte-range
/// slice from a seeked <see cref="FileStream"/> without reading past the range end.
/// </summary>
internal sealed class RangeLimitedStream : Stream
{
    private readonly Stream _inner;
    private long _remaining;

    internal RangeLimitedStream(Stream inner, long maxBytes)
    {
        _inner = inner;
        _remaining = maxBytes;
    }

    public override bool CanRead => _inner.CanRead && _remaining > 0;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_remaining <= 0)
        {
            return 0;
        }

        int toRead = (int)Math.Min(count, _remaining);
        int read = _inner.Read(buffer, offset, toRead);
        _remaining -= read;
        return read;
    }

    public override int Read(Span<byte> buffer)
    {
        if (_remaining <= 0)
        {
            return 0;
        }

        int toRead = (int)Math.Min(buffer.Length, _remaining);
        int read = _inner.Read(buffer[..toRead]);
        _remaining -= read;
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (_remaining <= 0)
        {
            return 0;
        }

        int toRead = (int)Math.Min(count, _remaining);
        int read = await _inner.ReadAsync(buffer.AsMemory(offset, toRead), cancellationToken);
        _remaining -= read;
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_remaining <= 0)
        {
            return 0;
        }

        int toRead = (int)Math.Min(buffer.Length, _remaining);
        int read = await _inner.ReadAsync(buffer[..toRead], cancellationToken);
        _remaining -= read;
        return read;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
