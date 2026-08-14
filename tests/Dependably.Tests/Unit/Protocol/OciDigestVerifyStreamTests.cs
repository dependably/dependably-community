using System.Security.Cryptography;
using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Unit coverage for <see cref="OciDigestVerifyStream"/>.
///
/// The stream is a read-only pass-through that hashes all bytes read via SHA-256.
/// Coverage targets:
///  - ComputedDigest matches SHA-256 of a known payload after full read
///  - BytesWritten tracks cumulative bytes read
///  - Empty stream produces the SHA-256 of an empty input
///  - Multiple partial reads accumulate correctly
///  - Disposal does not throw
///  - A body exceeding the configured cap throws UpstreamResponseTooLargeException, across
///    every Read overload, whether the overflow lands within one read or across several
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciDigestVerifyStreamTests
{
    // Effectively unbounded cap for tests that exercise hashing/plumbing, not the size limit.
    private const long NoCap = long.MaxValue;

    private static string Sha256Hex(byte[] data)
        => "sha256:" + Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // ── Basic correctness ──────────────────────────────────────────────────────

    [Fact]
    public async Task ComputedDigest_AfterReadingAllBytes_MatchesSha256()
    {
        byte[] payload = "hello OCI world"u8.ToArray();
        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner, NoCap);

        await stream.CopyToAsync(Stream.Null);

        Assert.Equal(Sha256Hex(payload), stream.ComputedDigest);
    }

    [Fact]
    public async Task BytesWritten_EqualsActualBytesRead()
    {
        byte[] payload = new byte[1024];
        Random.Shared.NextBytes(payload);

        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner, NoCap);

        // Drain via CopyToAsync.
        await stream.CopyToAsync(Stream.Null);

        Assert.Equal(payload.Length, stream.BytesWritten);
    }

    [Fact]
    public async Task ComputedDigest_EmptyStream_MatchesSha256OfEmpty()
    {
        await using var inner = new MemoryStream(Array.Empty<byte>());
        await using var stream = new OciDigestVerifyStream(inner, NoCap);

        await stream.CopyToAsync(Stream.Null); // exhaust (empty) — avoids CA2022 partial-read

        Assert.Equal(Sha256Hex(Array.Empty<byte>()), stream.ComputedDigest);
        Assert.Equal(0, stream.BytesWritten);
    }

    [Fact]
    public async Task ComputedDigest_MultiplePartialReads_AccumulatesCorrectly()
    {
        byte[] part1 = "first-chunk"u8.ToArray();
        byte[] part2 = "second-chunk"u8.ToArray();
        byte[] combined = part1.Concat(part2).ToArray();

        await using var inner = new MemoryStream(combined);
        await using var stream = new OciDigestVerifyStream(inner, NoCap);

        // Read in two chunks.
        byte[] buf1 = new byte[part1.Length];
        byte[] buf2 = new byte[part2.Length];
        _ = await stream.ReadAsync(buf1);
        _ = await stream.ReadAsync(buf2);

        Assert.Equal(Sha256Hex(combined), stream.ComputedDigest);
        Assert.Equal(combined.Length, stream.BytesWritten);
    }

    // ── ValueTask<int> overload ────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_MemoryOverload_AccumulatesHash()
    {
        byte[] payload = "memory overload test"u8.ToArray();
        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner, NoCap);

        // Read all bytes through the Memory<byte> overload.
        byte[] buf = new byte[payload.Length];
        int totalRead = 0;
        while (totalRead < payload.Length)
        {
            int n = await stream.ReadAsync(buf.AsMemory(totalRead));
            if (n == 0)
            {
                break;
            }

            totalRead += n;
        }

        Assert.Equal(Sha256Hex(payload), stream.ComputedDigest);
    }

    // ── Synchronous Read overload ──────────────────────────────────────────────

    [Fact]
    public void Read_SynchronousOverload_AccumulatesHash()
    {
        byte[] payload = "sync read test"u8.ToArray();
        using var inner = new MemoryStream(payload);
        using var stream = new OciDigestVerifyStream(inner, NoCap);

        byte[] buf = new byte[payload.Length];
        _ = stream.Read(buf, 0, buf.Length);

        Assert.Equal(Sha256Hex(payload), stream.ComputedDigest);
    }

    // ── Stream contract ────────────────────────────────────────────────────────

    [Fact]
    public void StreamProperties_AreCorrect()
    {
        using var inner = new MemoryStream(Array.Empty<byte>());
        using var stream = new OciDigestVerifyStream(inner, NoCap);

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);

        Assert.Throws<NotSupportedException>(() => _ = stream.Length);
        Assert.Throws<NotSupportedException>(() => _ = stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(0));
        Assert.Throws<NotSupportedException>(() => stream.Write(Array.Empty<byte>(), 0, 0));
    }

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        var inner = new MemoryStream("dispose test"u8.ToArray());
        var stream = new OciDigestVerifyStream(inner, NoCap);
        var ex = Record.Exception(() => stream.Dispose());
        Assert.Null(ex);
    }

    // ── Size cap enforcement (DoS via unbounded upstream blob) ─────────────────────

    [Fact]
    public async Task ReadAsync_MemoryOverload_BodyExceedsCap_ThrowsUpstreamResponseTooLargeException()
    {
        byte[] payload = new byte[100];
        Random.Shared.NextBytes(payload);

        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner, maxBytes: 50);

        byte[] buf = new byte[payload.Length];
        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(async () =>
        {
            int totalRead = 0;
            while (totalRead < payload.Length)
            {
                int n = await stream.ReadAsync(buf.AsMemory(totalRead));
                if (n == 0)
                {
                    break;
                }

                totalRead += n;
            }
        });
    }

    [Fact]
    public async Task ReadAsync_ByteArrayOverload_BodyExceedsCap_ThrowsUpstreamResponseTooLargeException()
    {
        byte[] payload = new byte[100];
        Random.Shared.NextBytes(payload);

        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner, maxBytes: 50);

        byte[] buf = new byte[payload.Length];
        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(async () =>
        {
            int totalRead = 0;
            while (totalRead < payload.Length)
            {
                int n = await stream.ReadAsync(buf, totalRead, payload.Length - totalRead, CancellationToken.None);
                if (n == 0)
                {
                    break;
                }

                totalRead += n;
            }
        });
    }

    [Fact]
    public void Read_SynchronousOverload_BodyExceedsCap_ThrowsUpstreamResponseTooLargeException()
    {
        byte[] payload = new byte[100];
        Random.Shared.NextBytes(payload);

        using var inner = new MemoryStream(payload);
        using var stream = new OciDigestVerifyStream(inner, maxBytes: 50);

        byte[] buf = new byte[payload.Length];
        Assert.Throws<UpstreamResponseTooLargeException>(() =>
        {
            int totalRead = 0;
            while (totalRead < payload.Length)
            {
                int n = stream.Read(buf, totalRead, payload.Length - totalRead);
                if (n == 0)
                {
                    break;
                }

                totalRead += n;
            }
        });
    }

    [Fact]
    public async Task ReadAsync_BodyExactlyAtCap_DoesNotThrow()
    {
        byte[] payload = new byte[50];
        Random.Shared.NextBytes(payload);

        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner, maxBytes: 50);

        await stream.CopyToAsync(Stream.Null);

        Assert.Equal(Sha256Hex(payload), stream.ComputedDigest);
        Assert.Equal(50, stream.BytesWritten);
    }

    [Fact]
    public async Task ReadAsync_OverflowSpansMultipleReads_ThrowsOnceCumulativeExceedsCap()
    {
        // The malicious upstream never sends a single huge chunk; it drips bytes in small
        // pieces that individually look harmless. The cap must still trip once the RUNNING
        // total crosses the ceiling, not just when a single read is oversized.
        byte[] payload = new byte[120];
        Random.Shared.NextBytes(payload);

        await using var inner = new SmallChunkStream(payload, chunkSize: 10);
        await using var stream = new OciDigestVerifyStream(inner, maxBytes: 55);

        byte[] buf = new byte[payload.Length];
        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(async () =>
        {
            int totalRead = 0;
            while (totalRead < payload.Length)
            {
                int n = await stream.ReadAsync(buf.AsMemory(totalRead));
                if (n == 0)
                {
                    break;
                }

                totalRead += n;
            }
        });
    }

    // Forces reads through in small fixed-size chunks regardless of the caller's buffer size,
    // simulating a chunked-transfer upstream that trickles bytes rather than delivering one
    // large read.
    private sealed class SmallChunkStream : Stream
    {
        private readonly byte[] _data;
        private readonly int _chunkSize;
        private int _position;

        public SmallChunkStream(byte[] data, int chunkSize)
        {
            _data = data;
            _chunkSize = chunkSize;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int remaining = _data.Length - _position;
            if (remaining <= 0)
            {
                return 0;
            }

            int toCopy = Math.Min(Math.Min(_chunkSize, count), remaining);
            Array.Copy(_data, _position, buffer, offset, toCopy);
            _position += toCopy;
            return toCopy;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.FromResult(Read(buffer, offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            byte[] tmp = new byte[buffer.Length];
            int read = Read(tmp, 0, tmp.Length);
            tmp.AsSpan(0, read).CopyTo(buffer.Span);
            return ValueTask.FromResult(read);
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
