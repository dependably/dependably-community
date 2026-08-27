using System.Diagnostics.CodeAnalysis;
using Dependably.Storage;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// Pins <see cref="RangeLimitedStream"/>'s one job: a seeked inner stream is truncated at the range
/// end, so <c>LocalBlobStore.GetRangeAsync</c> serves exactly the requested slice and never the
/// bytes after it.
///
/// <para>All four read overloads are exercised separately. They carry the same logic three more
/// times over, and a caller reaches whichever one its own abstraction picks — Kestrel's response
/// writer takes the <see cref="Memory{T}"/> one, a <c>CopyTo</c> the array one — so a budget bug in
/// any single overload would leak past the range on some paths and not others.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class RangeLimitedStreamTests
{
    private static byte[] Payload(int length) =>
        Enumerable.Range(0, length).Select(i => (byte)i).ToArray();

    private static RangeLimitedStream Over(byte[] source, long maxBytes, int startAt = 0)
    {
        var inner = new MemoryStream(source);
        inner.Seek(startAt, SeekOrigin.Begin);
        return new RangeLimitedStream(inner, maxBytes);
    }

    public static TheoryData<string> ReadOverloads() => new()
    {
        "array", "span", "array-async", "memory-async",
    };

    /// <summary>Drains through one overload, in chunks, so the budget is decremented repeatedly.</summary>
    // CA1835 wants the Memory<byte> overload, but exercising the array-based one is the whole
    // point here: RangeLimitedStream implements all four reads separately, and a budget bug in
    // any single overload would leak past the range only on the paths that reach it.
    [SuppressMessage("Performance", "CA1835:Prefer the memory-based overloads of ReadAsync/WriteAsync",
        Justification = "The array overload is deliberately under test; see the class doc comment.")]
    private static async Task<byte[]> DrainAsync(RangeLimitedStream stream, string overload, int chunk)
    {
        var sink = new MemoryStream();
        byte[] buffer = new byte[chunk];
        while (true)
        {
            int read = overload switch
            {
                "array" => stream.Read(buffer, 0, buffer.Length),
                "span" => stream.Read(buffer.AsSpan()),
                "array-async" => await stream.ReadAsync(buffer, 0, buffer.Length, CancellationToken.None),
                _ => await stream.ReadAsync(buffer.AsMemory(), CancellationToken.None),
            };

            if (read == 0)
            {
                return sink.ToArray();
            }

            sink.Write(buffer, 0, read);
        }
    }

    [Theory]
    [MemberData(nameof(ReadOverloads))]
    public async Task StopsAtTheRangeEnd_EvenWhenTheInnerStreamHasMore(string overload)
    {
        byte[] source = Payload(100);

        byte[] served = await DrainAsync(Over(source, maxBytes: 10), overload, chunk: 4);

        Assert.Equal(source.Take(10), served);
    }

    [Theory]
    [MemberData(nameof(ReadOverloads))]
    public async Task ServesFromTheSeekPosition(string overload)
    {
        byte[] source = Payload(100);

        byte[] served = await DrainAsync(Over(source, maxBytes: 10, startAt: 40), overload, chunk: 3);

        Assert.Equal(source.Skip(40).Take(10), served);
    }

    [Theory]
    [MemberData(nameof(ReadOverloads))]
    public async Task ShortInnerStreamEndsTheRangeEarlyRatherThanBlocking(string overload)
    {
        // A range whose end is past EOF: the inner stream runs out first and the read must report
        // completion, not keep asking for the bytes the range promised.
        byte[] source = Payload(5);

        byte[] served = await DrainAsync(Over(source, maxBytes: 50), overload, chunk: 8);

        Assert.Equal(source, served);
    }

    [Theory]
    [MemberData(nameof(ReadOverloads))]
    public async Task ZeroLengthRangeServesNothing(string overload)
    {
        byte[] served = await DrainAsync(Over(Payload(20), maxBytes: 0), overload, chunk: 4);

        Assert.Empty(served);
    }

    [Fact]
    public async Task ABufferLargerThanTheRangeIsTruncatedToIt()
    {
        // The single-read case the chunked drain above cannot show: one oversized buffer must come
        // back with the range length, not the buffer length.
        var stream = Over(Payload(100), maxBytes: 7);
        byte[] buffer = new byte[64];

        int read = await stream.ReadAsync(buffer.AsMemory(), CancellationToken.None);

        Assert.Equal(7, read);
        Assert.Equal(0, await stream.ReadAsync(buffer.AsMemory(), CancellationToken.None));
    }

    [Fact]
    public void CanReadGoesFalseOnceTheRangeIsSpent()
    {
        var stream = Over(Payload(20), maxBytes: 4);
        Assert.True(stream.CanRead);

        Assert.Equal(4, stream.Read(new byte[8], 0, 8));

        Assert.False(stream.CanRead);
    }

    [Fact]
    public void IsReadOnlyAndNonSeekable()
    {
        // LocalBlobStore hands this to the response pipeline; anything that tried to seek or write
        // it must fail loudly rather than silently serve the wrong slice.
        var stream = Over(Payload(4), maxBytes: 4);

        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(1));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
        Assert.Null(Record.Exception(stream.Flush));
    }

    [Fact]
    public void DisposingClosesTheInnerStream()
    {
        // The inner FileStream's handle is this stream's to release — LocalBlobStore hands the
        // wrapper to the response pipeline and never sees the FileStream again.
        var inner = new MemoryStream(Payload(10));
        var stream = new RangeLimitedStream(inner, 10);

        stream.Dispose();

        Assert.Throws<ObjectDisposedException>(() => inner.ReadByte());
    }
}
