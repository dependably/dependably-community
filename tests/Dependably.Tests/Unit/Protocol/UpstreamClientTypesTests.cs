using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The staging stream and the typed exceptions the proxy fetch path throws. The stream is where a
/// chunked upstream response without a Content-Length is held to the byte cap, so its boundary
/// behaviour is pinned exactly.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamClientTypesTests
{
    private const string AbcSha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private const string AbcSha1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
    private const string AbcMd5 = "900150983cd24fb0d6963f7d28e17f72";

    private sealed class TrackingStream : MemoryStream
    {
        public int Flushes { get; private set; }
        public int AsyncFlushes { get; private set; }
        public bool Disposed { get; private set; }

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

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    // ── HashingFileStream ────────────────────────────────────────────────────

    [Fact]
    public void HashingFileStream_Sync_HashesAndForwardsWhatWasWritten()
    {
        var inner = new TrackingStream();
        using var stream = new HashingFileStream(inner, maxBytes: 100);

        stream.Write(Encoding.ASCII.GetBytes("xabcx"), 1, 3);

        Assert.Equal(AbcSha256, stream.GetSha256Hex());
        Assert.Equal(3, stream.BytesWritten);
        Assert.Equal(3, stream.Position);
        Assert.Equal("abc", Encoding.ASCII.GetString(inner.ToArray()));
    }

    [Fact]
    public async Task HashingFileStream_AsyncOverloads_HashAcrossChunks()
    {
        var inner = new TrackingStream();
        await using var stream = new HashingFileStream(inner, maxBytes: 100);

#pragma warning disable CA1835 // exercises the array-based override itself
        await stream.WriteAsync(Encoding.ASCII.GetBytes("a"), 0, 1, CancellationToken.None);
#pragma warning restore CA1835
        await stream.WriteAsync(new ReadOnlyMemory<byte>(Encoding.ASCII.GetBytes("bc")), CancellationToken.None);

        Assert.Equal(AbcSha256, stream.GetSha256Hex());
        Assert.Equal(3, stream.BytesWritten);
        Assert.Equal("abc", Encoding.ASCII.GetString(inner.ToArray()));
    }

    [Fact]
    public void HashingFileStream_MavenDigests_AreComputedAlongsideSha256()
    {
        using var stream = new HashingFileStream(new MemoryStream(), maxBytes: 100, alsoMavenDigests: true);

        stream.Write(Encoding.ASCII.GetBytes("abc"), 0, 3);

        Assert.Equal(AbcSha256, stream.GetSha256Hex());
        Assert.Equal(AbcSha1, stream.GetSha1Hex());
        Assert.Equal(AbcMd5, stream.GetMd5Hex());
    }

    [Fact]
    public async Task HashingFileStream_MavenDigests_AreUpdatedByTheAsyncPathToo()
    {
        await using var stream = new HashingFileStream(new MemoryStream(), maxBytes: 100, alsoMavenDigests: true);

        await stream.WriteAsync(new ReadOnlyMemory<byte>(Encoding.ASCII.GetBytes("abc")), CancellationToken.None);

        Assert.Equal(AbcSha1, stream.GetSha1Hex());
        Assert.Equal(AbcMd5, stream.GetMd5Hex());
    }

    [Fact]
    public void HashingFileStream_MavenDigestsNotEnabled_AccessorsThrow()
    {
        using var stream = new HashingFileStream(new MemoryStream(), maxBytes: 100);

        var sha1 = Assert.Throws<InvalidOperationException>(() => stream.GetSha1Hex());
        var md5 = Assert.Throws<InvalidOperationException>(() => stream.GetMd5Hex());

        Assert.Equal("SHA-1 not enabled", sha1.Message);
        Assert.Equal("MD5 not enabled", md5.Message);
    }

    [Fact]
    public void HashingFileStream_DigestAccessors_AreStableAcrossRepeatedCalls()
    {
        using var stream = new HashingFileStream(new MemoryStream(), maxBytes: 100, alsoMavenDigests: true);
        stream.Write(Encoding.ASCII.GetBytes("abc"), 0, 3);

        Assert.Equal(stream.GetSha256Hex(), stream.GetSha256Hex());
        Assert.Equal(stream.GetSha1Hex(), stream.GetSha1Hex());
        Assert.Equal(stream.GetMd5Hex(), stream.GetMd5Hex());
        Assert.Equal(AbcSha256, stream.GetSha256Hex());
    }

    [Fact]
    public void HashingFileStream_WriteExactlyAtTheCap_Succeeds_AndOneMoreByteIsRefusedBeforeAnyHashing()
    {
        var inner = new TrackingStream();
        using var stream = new HashingFileStream(inner, maxBytes: 3);

        stream.Write(Encoding.ASCII.GetBytes("abc"), 0, 3);

        var ex = Assert.Throws<UpstreamResponseTooLargeException>(() => stream.Write(new byte[] { 1 }, 0, 1));
        Assert.Equal("Upstream response exceeded the 3-byte limit: (staging)", ex.Message);
        Assert.Equal(3, stream.BytesWritten);
        Assert.Equal(3, inner.Length);
        Assert.Equal(AbcSha256, stream.GetSha256Hex());
    }

    [Fact]
    public async Task HashingFileStream_AsyncWriteOverTheCap_IsRefusedWithoutWritingAnything()
    {
        var inner = new TrackingStream();
        await using var stream = new HashingFileStream(inner, maxBytes: 4);

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(async () =>
            await stream.WriteAsync(new ReadOnlyMemory<byte>(new byte[5]), CancellationToken.None));

        Assert.Equal(0, stream.BytesWritten);
        Assert.Equal(0, inner.Length);
    }

    [Fact]
    public void HashingFileStream_ChunkedWritesCrossingTheCap_StopAtTheChunkThatCrosses()
    {
        var inner = new TrackingStream();
        using var stream = new HashingFileStream(inner, maxBytes: 10);

        stream.Write(new byte[6], 0, 6);
        Assert.Throws<UpstreamResponseTooLargeException>(() => stream.Write(new byte[5], 0, 5));

        Assert.Equal(6, stream.BytesWritten);
        Assert.Equal(6, inner.Length);
    }

    [Fact]
    public async Task HashingFileStream_FlushForwardsToTheInnerStream()
    {
        var inner = new TrackingStream();
        await using var stream = new HashingFileStream(inner, maxBytes: 10);

        stream.Flush();
        await stream.FlushAsync(CancellationToken.None);

        Assert.Equal(1, inner.Flushes);
        Assert.Equal(1, inner.AsyncFlushes);
    }

    [Fact]
    public void HashingFileStream_IsWriteOnlyAndForwardOnly()
    {
        using var stream = new HashingFileStream(new MemoryStream(), maxBytes: 10);

        Assert.False(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.True(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position = 1);
        Assert.Throws<NotSupportedException>(() => stream.Read(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(1));
    }

    [Fact]
    public void HashingFileStream_Dispose_ClosesTheInnerStreamAndIsIdempotent()
    {
        var inner = new TrackingStream();
        var stream = new HashingFileStream(inner, maxBytes: 10, alsoMavenDigests: true);

        stream.Dispose();
        stream.Dispose();

        Assert.True(inner.Disposed);
    }

    [Fact]
    public async Task HashingFileStream_DisposeAsync_ClosesTheInnerStreamAndIsIdempotent()
    {
        var inner = new TrackingStream();
        var stream = new HashingFileStream(inner, maxBytes: 10, alsoMavenDigests: true);

        await stream.DisposeAsync();
        await stream.DisposeAsync();
        stream.Dispose();

        Assert.True(inner.Disposed);
    }

    // ── result and response records ──────────────────────────────────────────

    [Fact]
    public void UpstreamFetchResult_LastModifiedDefaultsToNull()
    {
        var result = new UpstreamFetchResult("abc123", 42, "blob/key");

        Assert.Null(result.LastModified);
        Assert.Equal(42, result.SizeBytes);
    }

    [Fact]
    public void UpstreamMetadataResponse_DecodesTheBodyAsUtf8_AndIsNotStaleByDefault()
    {
        var response = new UpstreamMetadataResponse(200, true, "application/json", Encoding.UTF8.GetBytes("{\"name\":\"café\"}"));

        Assert.Equal("{\"name\":\"café\"}", response.BodyAsString());
        Assert.False(response.IsStale);
        Assert.True((response with { IsStale = true }).IsStale);
    }

    // ── typed exceptions ─────────────────────────────────────────────────────

    [Fact]
    public void UpstreamFetchFailedException_DefaultsToAnAnonymousNonRefusedFailure()
    {
        var ex = new UpstreamFetchFailedException();

        Assert.Equal("Upstream blob fetch failed after retries were exhausted.", ex.Message);
        Assert.Equal(string.Empty, ex.Url);
        Assert.Equal(0, ex.StatusCode);
        Assert.Null(ex.RetryAfter);
        Assert.False(ex.Transient);
        Assert.False(ex.Refused);
    }

    [Fact]
    public void UpstreamFetchFailedException_CarriesTheRefusalDetails()
    {
        var ex = new UpstreamFetchFailedException
        {
            Url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            StatusCode = 403,
            RetryAfter = TimeSpan.FromSeconds(30),
            Transient = false,
            Refused = true,
        };

        Assert.Equal(403, ex.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(30), ex.RetryAfter);
        Assert.True(ex.Refused);
    }

    [Fact]
    public void ProxyCatalogueUnavailableException_NamesTheArtefactItCouldNotRecord()
    {
        var ex = new ProxyCatalogueUnavailableException("npm", "lodash", "4.17.21");

        Assert.Equal(
            "Could not record npm/lodash@4.17.21 on the cache plane; the fetch is refused rather than served ungated.",
            ex.Message);
    }

    [Fact]
    public void ChecksumException_KeepsItsMessage()
    {
        Assert.Equal("sha256 mismatch", new ChecksumException("sha256 mismatch").Message);
    }

    [Fact]
    public void UpstreamResponseTooLargeException_NamesTheUrlAndTheLimit()
    {
        var ex = new UpstreamResponseTooLargeException("https://pypi.org/packages/requests.whl", 600);

        Assert.Equal("Upstream response exceeded the 600-byte limit: https://pypi.org/packages/requests.whl", ex.Message);
    }

    [Fact]
    public void SsrfBlockedException_NamesTheBlockedUrl()
    {
        Assert.Equal(
            "Upstream URL blocked by SSRF policy: http://169.254.169.254/latest/meta-data",
            new SsrfBlockedException("http://169.254.169.254/latest/meta-data").Message);
    }

    [Fact]
    public void AirGappedException_ExposesTheRefusedResource()
    {
        var ex = new AirGappedException("registry.npmjs.org");

        Assert.Equal("registry.npmjs.org", ex.Resource);
        Assert.Equal("Upstream fetch refused: this deployment is air-gapped (resource: registry.npmjs.org).", ex.Message);
    }

    [Fact]
    public void StagingDiskFullException_ExposesAvailableBytesAndTheFloor()
    {
        var ex = new StagingDiskFullException(1024, 4096);

        Assert.Equal(1024, ex.AvailableBytes);
        Assert.Equal(4096, ex.FloorBytes);
        Assert.Equal(
            "Staging disk too full to accept a new proxy fetch: 1024 bytes available, floor is 4096 bytes.",
            ex.Message);
    }

    [Fact]
    public void TenantStorageQuotaExceededException_ExposesTheOrgAndQuota()
    {
        var ex = new TenantStorageQuotaExceededException("org-acme", 5_000_000);

        Assert.Equal("org-acme", ex.OrgId);
        Assert.Equal(5_000_000, ex.QuotaBytes);
        Assert.Equal("Tenant storage quota (5000000 bytes) would be exceeded by this proxy cache fill.", ex.Message);
    }
}
