namespace Dependably.Protocol;

/// <summary>
/// Read-only pass-through stream that fails an asynchronous read with <see cref="IOException"/>
/// when the inner stream delivers no bytes within <c>idleTimeout</c>, measured on the injected
/// <see cref="TimeProvider"/>. Wrapped around upstream response bodies: HttpClient.Timeout stops
/// applying once headers arrive, so a half-open upstream connection would otherwise hold a
/// shared single-flight fetch — and every caller joined to it — until the process restarts.
/// The window restarts on every read, so a slow but progressing transfer of any size is never
/// cut off. Synchronous reads pass through unbounded; upstream bodies are only read async.
/// </summary>
public sealed class IdleTimeoutReadStream : Stream
{
    private readonly Stream _inner;
    private readonly TimeSpan _idleTimeout;
    private readonly TimeProvider _time;
    private readonly string _description;

    public IdleTimeoutReadStream(Stream inner, TimeSpan idleTimeout, TimeProvider time, string description)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(idleTimeout, TimeSpan.Zero);
        _inner = inner;
        _idleTimeout = idleTimeout;
        _time = time;
        _description = description;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

    public override int Read(Span<byte> buffer) => _inner.Read(buffer);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        using var idle = new CancellationTokenSource(_idleTimeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, idle.Token);
        try
        {
            return await _inner.ReadAsync(buffer, linked.Token);
        }
        catch (OperationCanceledException) when (idle.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            // Reported as a broken transfer, not a cancellation: the caller's token did not fire,
            // and a truncated upstream body already surfaces as IOException on these paths.
            string message = $"{_description} received no data for {_idleTimeout.TotalSeconds:0} seconds.";
            throw new IOException(message, new TimeoutException(message));
        }
    }

    public override void Flush()
    {
        // Read-only stream: nothing to flush.
    }

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
