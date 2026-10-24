using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

[Trait("Category", "Unit")]
public sealed class LimitedReadStreamTests
{
    private static readonly byte[] Ten = Encoding.ASCII.GetBytes("0123456789");

    [Fact]
    public void Constructor_NullInner_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new LimitedReadStream(null!, 10, "tar entry"));
    }

    [Fact]
    public void Constructor_NegativeLimit_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new LimitedReadStream(new MemoryStream(), -1, "tar entry"));
    }

    [Fact]
    public void Capabilities_AreReadOnlyAndForwardOnly()
    {
        using var stream = new LimitedReadStream(new MemoryStream(Ten), 10, "tar entry");

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(1));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
        stream.Flush();
    }

    [Fact]
    public void Read_ArrayOverload_ReturnsBytesUpToExactlyTheLimit()
    {
        using var stream = new LimitedReadStream(new MemoryStream(Ten), 10, "tar entry");
        byte[] buffer = new byte[10];

        int read = stream.Read(buffer, 0, 10);

        Assert.Equal(10, read);
        Assert.Equal(Ten, buffer);
        Assert.Equal(0, stream.Read(buffer, 0, 10));
    }

    [Fact]
    public void Read_ArrayOverload_OneByteOverTheLimit_ThrowsInvalidDataWithDescription()
    {
        using var stream = new LimitedReadStream(new MemoryStream(Ten), 9, "package.json");
        byte[] buffer = new byte[10];

        var ex = Assert.Throws<InvalidDataException>(() => stream.Read(buffer, 0, 10));

        Assert.Equal("package.json exceeds the 9-byte decompression limit.", ex.Message);
    }

    [Fact]
    public void Read_SpanOverload_CountsAndEnforcesTheLimit()
    {
        using var stream = new LimitedReadStream(new MemoryStream(Ten), 6, "tar entry");
        byte[] first = new byte[4];

        Assert.Equal(4, stream.Read(first.AsSpan()));
        Assert.Equal("0123", Encoding.ASCII.GetString(first));
        byte[] second = new byte[4];
        Assert.Throws<InvalidDataException>(() => stream.Read(second.AsSpan()));
    }

    [Fact]
    public void ReadByte_CountsEachByte_AndEndOfStreamIsNotCharged()
    {
        using var stream = new LimitedReadStream(new MemoryStream(new byte[] { 7, 8 }), 2, "tar entry");

        Assert.Equal(7, stream.ReadByte());
        Assert.Equal(8, stream.ReadByte());
        Assert.Equal(-1, stream.ReadByte());
        Assert.Equal(-1, stream.ReadByte());
    }

    [Fact]
    public void ReadByte_PastTheLimit_Throws()
    {
        using var stream = new LimitedReadStream(new MemoryStream(Ten), 1, "tar entry");

        Assert.Equal(48, stream.ReadByte());
        Assert.Throws<InvalidDataException>(() => stream.ReadByte());
    }

    [Fact]
    public async Task ReadAsync_ArrayOverload_CountsAndEnforcesTheLimit()
    {
        await using var stream = new LimitedReadStream(new MemoryStream(Ten), 8, "tar entry");
        byte[] buffer = new byte[5];

#pragma warning disable CA1835 // exercises the array-based override itself
        Assert.Equal(5, await stream.ReadAsync(buffer, 0, 5, CancellationToken.None));
#pragma warning restore CA1835
        await Assert.ThrowsAsync<InvalidDataException>(
            () => stream.ReadAsync(buffer, 0, 5, CancellationToken.None));
    }

    [Fact]
    public async Task ReadAsync_MemoryOverload_CountsAndEnforcesTheLimit()
    {
        await using var stream = new LimitedReadStream(new MemoryStream(Ten), 8, "tar entry");
        byte[] buffer = new byte[5];

        Assert.Equal(5, await stream.ReadAsync(buffer.AsMemory(), CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(
            async () => await stream.ReadExactlyAsync(buffer.AsMemory(), CancellationToken.None));
    }

    [Fact]
    public async Task CopyToAsync_OversizedSource_StopsWithInvalidData()
    {
        await using var stream = new LimitedReadStream(new MemoryStream(new byte[100_000]), 50_000, "npm publish body");
        using var sink = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() => stream.CopyToAsync(sink));
        Assert.True(sink.Length <= 50_000, "bytes beyond the limit must not reach the sink");
    }

    [Fact]
    public void Dispose_DisposesTheInnerStream()
    {
        var inner = new MemoryStream(Ten);
        var stream = new LimitedReadStream(inner, 10, "tar entry");

        stream.Dispose();

        Assert.False(inner.CanRead);
    }
}
