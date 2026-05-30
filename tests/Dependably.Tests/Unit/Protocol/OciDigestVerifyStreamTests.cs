using System.Security.Cryptography;
using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Unit coverage for <see cref="OciDigestVerifyStream"/> (#103).
///
/// The stream is a read-only pass-through that hashes all bytes read via SHA-256.
/// Coverage targets:
///  - ComputedDigest matches SHA-256 of a known payload after full read
///  - BytesWritten tracks cumulative bytes read
///  - Empty stream produces the SHA-256 of an empty input
///  - Multiple partial reads accumulate correctly
///  - Disposal does not throw
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciDigestVerifyStreamTests
{
    private static string Sha256Hex(byte[] data)
        => "sha256:" + Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // ── Basic correctness ──────────────────────────────────────────────────────

    [Fact]
    public async Task ComputedDigest_AfterReadingAllBytes_MatchesSha256()
    {
        var payload = "hello OCI world"u8.ToArray();
        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner);

        await stream.CopyToAsync(Stream.Null);

        Assert.Equal(Sha256Hex(payload), stream.ComputedDigest);
    }

    [Fact]
    public async Task BytesWritten_EqualsActualBytesRead()
    {
        var payload = new byte[1024];
        Random.Shared.NextBytes(payload);

        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner);

        // Drain via CopyToAsync.
        await stream.CopyToAsync(Stream.Null);

        Assert.Equal(payload.Length, stream.BytesWritten);
    }

    [Fact]
    public async Task ComputedDigest_EmptyStream_MatchesSha256OfEmpty()
    {
        await using var inner = new MemoryStream(Array.Empty<byte>());
        await using var stream = new OciDigestVerifyStream(inner);

        await stream.CopyToAsync(Stream.Null); // exhaust (empty) — avoids CA2022 partial-read

        Assert.Equal(Sha256Hex(Array.Empty<byte>()), stream.ComputedDigest);
        Assert.Equal(0, stream.BytesWritten);
    }

    [Fact]
    public async Task ComputedDigest_MultiplePartialReads_AccumulatesCorrectly()
    {
        var part1 = "first-chunk"u8.ToArray();
        var part2 = "second-chunk"u8.ToArray();
        var combined = part1.Concat(part2).ToArray();

        await using var inner = new MemoryStream(combined);
        await using var stream = new OciDigestVerifyStream(inner);

        // Read in two chunks.
        var buf1 = new byte[part1.Length];
        var buf2 = new byte[part2.Length];
        _ = await stream.ReadAsync(buf1);
        _ = await stream.ReadAsync(buf2);

        Assert.Equal(Sha256Hex(combined), stream.ComputedDigest);
        Assert.Equal(combined.Length, stream.BytesWritten);
    }

    // ── ValueTask<int> overload ────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_MemoryOverload_AccumulatesHash()
    {
        var payload = "memory overload test"u8.ToArray();
        await using var inner = new MemoryStream(payload);
        await using var stream = new OciDigestVerifyStream(inner);

        // Read all bytes through the Memory<byte> overload.
        var buf = new byte[payload.Length];
        var totalRead = 0;
        while (totalRead < payload.Length)
        {
            var n = await stream.ReadAsync(buf.AsMemory(totalRead));
            if (n == 0) break;
            totalRead += n;
        }

        Assert.Equal(Sha256Hex(payload), stream.ComputedDigest);
    }

    // ── Synchronous Read overload ──────────────────────────────────────────────

    [Fact]
    public void Read_SynchronousOverload_AccumulatesHash()
    {
        var payload = "sync read test"u8.ToArray();
        using var inner = new MemoryStream(payload);
        using var stream = new OciDigestVerifyStream(inner);

        var buf = new byte[payload.Length];
        _ = stream.Read(buf, 0, buf.Length);

        Assert.Equal(Sha256Hex(payload), stream.ComputedDigest);
    }

    // ── Stream contract ────────────────────────────────────────────────────────

    [Fact]
    public void StreamProperties_AreCorrect()
    {
        using var inner = new MemoryStream(Array.Empty<byte>());
        using var stream = new OciDigestVerifyStream(inner);

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
        var stream = new OciDigestVerifyStream(inner);
        var ex = Record.Exception(() => stream.Dispose());
        Assert.Null(ex);
    }
}
