using System.IO.Pipelines;
using Microsoft.AspNetCore.Http.Features;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// A pass-through over the server's response body feature that counts the bytes a response
/// writes, without changing how they are written.
///
/// Every member delegates to the server's own feature. The stream and the pipe writer are thin
/// decorators over the server's stream and pipe writer — not a new pipe layered over the stream —
/// so buffering, flushing, completion, and abort behave exactly as they would unmetered: bytes a
/// handler leaves unflushed in the pipe are flushed by the server at the end of the request as
/// usual, a response starts when it would have started, and an exception after the response
/// started still resets the transfer. Send-file is delegated too, and counts the length it was
/// asked to send.
/// </summary>
internal sealed class CountingResponseBodyFeature : IHttpResponseBodyFeature
{
    private readonly IHttpResponseBodyFeature _inner;
    private readonly CountingWriteStream _stream;
    private readonly CountingPipeWriter _writer;
    private long _sendFileBytes;

    public CountingResponseBodyFeature(IHttpResponseBodyFeature inner)
    {
        _inner = inner;
        _stream = new CountingWriteStream(inner.Stream);
        _writer = new CountingPipeWriter(inner.Writer);
    }

    public long BytesWritten => _stream.BytesWritten + _writer.BytesAdvanced + Interlocked.Read(ref _sendFileBytes);

    public Stream Stream => _stream;

    public PipeWriter Writer => _writer;

    public void DisableBuffering() => _inner.DisableBuffering();

    public Task StartAsync(CancellationToken cancellationToken = default) => _inner.StartAsync(cancellationToken);

    public Task CompleteAsync() => _inner.CompleteAsync();

    public async Task SendFileAsync(string path, long offset, long? count, CancellationToken cancellationToken = default)
    {
        // Sized before the send, from the same file the server is about to read, and never allowed
        // to throw: metering must not turn a successful send into a failed one.
        long sent = count ?? RemainingLength(path, offset);
        await _inner.SendFileAsync(path, offset, count, cancellationToken);
        Interlocked.Add(ref _sendFileBytes, sent);
    }

    private static long RemainingLength(string path, long offset)
    {
        try
        {
            return Math.Max(0, new FileInfo(path).Length - offset);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    /// <summary>Counts the bytes committed with <see cref="Advance"/>; everything else delegates.</summary>
    private sealed class CountingPipeWriter : PipeWriter
    {
        private readonly PipeWriter _inner;
        private long _advanced;

        public CountingPipeWriter(PipeWriter inner) => _inner = inner;

        public long BytesAdvanced => Interlocked.Read(ref _advanced);

        public override bool CanGetUnflushedBytes => _inner.CanGetUnflushedBytes;

        public override long UnflushedBytes => _inner.UnflushedBytes;

        public override void Advance(int bytes)
        {
            _inner.Advance(bytes);
            Interlocked.Add(ref _advanced, bytes);
        }

        public override Memory<byte> GetMemory(int sizeHint = 0) => _inner.GetMemory(sizeHint);

        public override Span<byte> GetSpan(int sizeHint = 0) => _inner.GetSpan(sizeHint);

        public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default) =>
            _inner.FlushAsync(cancellationToken);

        public override void CancelPendingFlush() => _inner.CancelPendingFlush();

        public override void Complete(Exception? exception = null) => _inner.Complete(exception);

        public override ValueTask CompleteAsync(Exception? exception = null) => _inner.CompleteAsync(exception);
    }
}
