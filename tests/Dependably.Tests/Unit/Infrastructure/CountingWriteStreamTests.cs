using Dependably.Infrastructure.Usage;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class CountingWriteStreamTests
{
    private sealed class RecordingStream : MemoryStream
    {
        public int Flushes { get; private set; }
        public int AsyncFlushes { get; private set; }
        public bool FailWrites { get; set; }

        public override void Flush()
        {
            Flushes++;
            base.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            AsyncFlushes++;
            return Task.CompletedTask;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ThrowIfFailing();
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            ThrowIfFailing();
            base.Write(buffer);
        }

        public override void WriteByte(byte value)
        {
            ThrowIfFailing();
            base.WriteByte(value);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfFailing();
            return base.WriteAsync(buffer, cancellationToken);
        }

        private void ThrowIfFailing()
        {
            if (FailWrites)
            {
                throw new IOException("client went away");
            }
        }
    }

    [Fact]
    public void Capabilities_AreWriteOnly()
    {
        using var stream = new CountingWriteStream(new MemoryStream());

        Assert.False(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.True(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 1);
        Assert.Throws<NotSupportedException>(() => stream.Read(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(1));
    }

    [Fact]
    public async Task EveryWriteOverload_IsCountedAndForwarded()
    {
        var inner = new RecordingStream();
        await using var stream = new CountingWriteStream(inner);

        stream.Write(new byte[] { 1, 2, 3, 4, 5 }, 1, 3);
        Assert.Equal(3, stream.BytesWritten);

        stream.Write(new byte[] { 9, 9 }.AsSpan());
        Assert.Equal(5, stream.BytesWritten);

        stream.WriteByte(0x7F);
        Assert.Equal(6, stream.BytesWritten);

#pragma warning disable CA1835 // exercises the array-based override itself
        await stream.WriteAsync(new byte[] { 4, 4, 4, 4 }, 0, 4, CancellationToken.None);
#pragma warning restore CA1835
        Assert.Equal(10, stream.BytesWritten);

        await stream.WriteAsync(new ReadOnlyMemory<byte>(new byte[] { 5, 5, 5 }), CancellationToken.None);
        Assert.Equal(13, stream.BytesWritten);

        Assert.Equal(
            new byte[] { 2, 3, 4, 9, 9, 0x7F, 4, 4, 4, 4, 5, 5, 5 },
            inner.ToArray());
    }

    [Fact]
    public async Task Flush_ForwardsToTheInnerStreamWithoutCounting()
    {
        var inner = new RecordingStream();
        await using var stream = new CountingWriteStream(inner);

        stream.Flush();
        await stream.FlushAsync(CancellationToken.None);

        Assert.Equal(1, inner.Flushes);
        Assert.Equal(1, inner.AsyncFlushes);
        Assert.Equal(0, stream.BytesWritten);
    }

    [Fact]
    public async Task FailedWrites_AreNotCounted_SoAnAbortedTransferCountsWhatWasSent()
    {
        var inner = new RecordingStream();
        await using var stream = new CountingWriteStream(inner);
        stream.Write(new byte[] { 1, 2, 3 }, 0, 3);

        inner.FailWrites = true;
        Assert.Throws<IOException>(() => stream.Write(new byte[] { 1, 2 }, 0, 2));
        Assert.Throws<IOException>(() => stream.Write(new byte[] { 1, 2 }.AsSpan()));
        Assert.Throws<IOException>(() => stream.WriteByte(1));
        await Assert.ThrowsAsync<IOException>(() => stream.WriteAsync(new byte[] { 1, 2 }, 0, 2, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(
            async () => await stream.WriteAsync(new ReadOnlyMemory<byte>(new byte[] { 1 }), CancellationToken.None));

        Assert.Equal(3, stream.BytesWritten);
    }
}
