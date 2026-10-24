using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="IdleTimeoutReadStream"/> bounds how long an upstream body may stall without
/// delivering a byte, so a half-open connection fails the shared fetch instead of wedging it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class IdleTimeoutReadStreamTests
{
    private static readonly TimeSpan Idle = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task StalledRead_FailsWithIOException_AtIdleTimeout()
    {
        var time = TestTime.Frozen();
        var inner = new StallingStream();
        await using var stream = new IdleTimeoutReadStream(inner, Idle, time, "Upstream body");

        var read = stream.ReadAsync(new byte[16]).AsTask();
        await inner.ReadStarted.WaitAsync(TimeSpan.FromSeconds(10));
        time.Advance(Idle);

        var ex = await Assert.ThrowsAsync<IOException>(() => read.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.IsType<TimeoutException>(ex.InnerException);
    }

    [Fact]
    public async Task StalledRead_InsideWindow_StillPending()
    {
        var time = TestTime.Frozen();
        var inner = new StallingStream();
        await using var stream = new IdleTimeoutReadStream(inner, Idle, time, "Upstream body");

        var read = stream.ReadAsync(new byte[16]).AsTask();
        await inner.ReadStarted.WaitAsync(TimeSpan.FromSeconds(10));
        time.Advance(Idle - TimeSpan.FromSeconds(1));

        Assert.False(read.IsCompleted);
    }

    [Fact]
    public async Task CallerCancellation_SurfacesAsCancellation_NotIOException()
    {
        var time = TestTime.Frozen();
        var inner = new StallingStream();
        await using var stream = new IdleTimeoutReadStream(inner, Idle, time, "Upstream body");
        using var cts = new CancellationTokenSource();

        var read = stream.ReadAsync(new byte[16], cts.Token).AsTask();
        await inner.ReadStarted.WaitAsync(TimeSpan.FromSeconds(10));
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => read.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task ProgressingReads_EachGetAFreshWindow()
    {
        // Total elapsed time well past the window, but no single read stalls for it: a slow,
        // live transfer of a large artifact must complete.
        var time = TestTime.Frozen();
        byte[] payload = [1, 2, 3, 4];
        await using var stream = new IdleTimeoutReadStream(new MemoryStream(payload), Idle, time, "Upstream body");
        byte[] buffer = new byte[1];
        var received = new List<byte>();

        int read;
        while ((read = await stream.ReadAsync(buffer)) > 0)
        {
            received.Add(buffer[0]);
            time.Advance(Idle - TimeSpan.FromSeconds(1));
        }

        Assert.Equal(payload, received);
    }

    // Never yields a byte until its read is cancelled — a half-open upstream connection.
    private sealed class StallingStream : Stream
    {
        private readonly TaskCompletionSource _readStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task ReadStarted => _readStarted.Task;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _readStarted.TrySetResult();
            await new TaskCompletionSource().Task.WaitAsync(cancellationToken);
            return 0;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
