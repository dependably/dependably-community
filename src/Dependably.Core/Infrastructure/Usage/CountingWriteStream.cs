namespace Dependably.Infrastructure.Usage;

/// <summary>
/// A write-only pass-through over the response body stream that counts the bytes written to it.
/// Nothing is buffered, so the count is the bytes actually handed to the next layer — a range
/// counts its range, and an aborted transfer counts what was written before the abort. The pipe
/// writer and send-file paths are counted by <see cref="CountingResponseBodyFeature"/>.
/// </summary>
internal sealed class CountingWriteStream : Stream
{
    private readonly Stream _inner;
    private long _bytesWritten;

    public CountingWriteStream(Stream inner) => _inner = inner;

    public long BytesWritten => Interlocked.Read(ref _bytesWritten);

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _inner.Write(buffer, offset, count);
        Interlocked.Add(ref _bytesWritten, count);
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        _inner.Write(buffer);
        Interlocked.Add(ref _bytesWritten, buffer.Length);
    }

    public override void WriteByte(byte value)
    {
        _inner.WriteByte(value);
        Interlocked.Increment(ref _bytesWritten);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await _inner.WriteAsync(buffer.AsMemory(offset, count), cancellationToken);
        Interlocked.Add(ref _bytesWritten, count);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await _inner.WriteAsync(buffer, cancellationToken);
        Interlocked.Add(ref _bytesWritten, buffer.Length);
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
