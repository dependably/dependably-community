using System.Net;
using Amazon.S3;
using Amazon.S3.Model;
using Dependably.Storage;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// Unit tests for <see cref="IBlobStore.GetRangeAsync"/> across all store implementations.
/// S3 and Azure tests verify the SDK is called with the correct range parameters; InMemory
/// and Local tests verify the actual bytes returned.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlobStoreRangeTests
{
    // ── InMemoryBlobStore ──────────────────────────────────────────────────────

    [Fact]
    public async Task InMemory_GetRange_ReturnsCorrectSlice()
    {
        var store = new InMemoryBlobStore();
        byte[] data = Enumerable.Range(0, 20).Select(i => (byte)i).ToArray();
        await store.PutAsync("test/key", new MemoryStream(data));

        await using var ranged = await store.GetRangeAsync("test/key", 5, 14);

        Assert.NotNull(ranged);
        Assert.Equal(5, ranged!.From);
        Assert.Equal(14, ranged.To);
        Assert.Equal(20, ranged.TotalLength);

        using var ms = new MemoryStream();
        await ranged.Content.CopyToAsync(ms);
        Assert.Equal(data[5..15], ms.ToArray());
    }

    [Fact]
    public async Task InMemory_GetRange_ClampsToEnd()
    {
        var store = new InMemoryBlobStore();
        byte[] data = new byte[10];
        await store.PutAsync("test/key", new MemoryStream(data));

        // Request range extends beyond the blob end.
        await using var ranged = await store.GetRangeAsync("test/key", 5, 999);

        Assert.NotNull(ranged);
        Assert.Equal(5, ranged!.From);
        Assert.Equal(9, ranged.To); // clamped to index 9 (last valid byte)
        Assert.Equal(10, ranged.TotalLength);
    }

    [Fact]
    public async Task InMemory_GetRange_MissingKey_ReturnsNull()
    {
        var store = new InMemoryBlobStore();
        var result = await store.GetRangeAsync("not/there", 0, 9);
        Assert.Null(result);
    }

    [Fact]
    public async Task InMemory_GetRange_PastEnd_ReturnsSentinelWithEmptyRange()
    {
        var store = new InMemoryBlobStore();
        byte[] data = new byte[10];
        await store.PutAsync("test/key", new MemoryStream(data));

        // Range starts at byte 10, which is one past the end of a 10-byte blob.
        await using var ranged = await store.GetRangeAsync("test/key", 10, 19);

        Assert.NotNull(ranged);
        // Sentinel: From > To signals an unsatisfiable range.
        Assert.True(ranged!.From > ranged.To,
            "Past-end range must return a sentinel where From > To.");
        Assert.Equal(10, ranged.TotalLength);
    }

    [Fact]
    public async Task InMemory_GetRange_OpenEnd_ReturnsToEndOfBlob()
    {
        var store = new InMemoryBlobStore();
        byte[] data = Enumerable.Range(0, 20).Select(i => (byte)i).ToArray();
        await store.PutAsync("test/key", new MemoryStream(data));

        // long.MaxValue as `to` simulates an open-ended range (bytes=5-).
        await using var ranged = await store.GetRangeAsync("test/key", 5, long.MaxValue);

        Assert.NotNull(ranged);
        Assert.Equal(5, ranged!.From);
        Assert.Equal(19, ranged.To); // clamped to last byte

        using var ms = new MemoryStream();
        await ranged.Content.CopyToAsync(ms);
        Assert.Equal(data[5..], ms.ToArray());
    }

    // ── S3BlobStore ────────────────────────────────────────────────────────────

    [Fact]
    public async Task S3_GetRange_CallsGetObjectWithByteRange()
    {
        var s3 = Substitute.For<IAmazonS3>();
        await using var sut = new S3BlobStore(s3, "bucket");

        // Metadata call returns total length.
        s3.GetObjectMetadataAsync("bucket", "key/path", Arg.Any<CancellationToken>())
            .Returns(new GetObjectMetadataResponse { ContentLength = 1000 });

        // GetObjectAsync returns a response stream.
        var responseStream = new MemoryStream(new byte[50]);
        s3.GetObjectAsync(Arg.Any<GetObjectRequest>(), Arg.Any<CancellationToken>())
            .Returns(new GetObjectResponse { ResponseStream = responseStream });

        await using var ranged = await sut.GetRangeAsync("key/path", 100, 149);

        Assert.NotNull(ranged);
        Assert.Equal(100, ranged!.From);
        Assert.Equal(149, ranged.To);
        Assert.Equal(1000, ranged.TotalLength);

        // Metadata call must have occurred.
        await s3.Received(1).GetObjectMetadataAsync("bucket", "key/path", Arg.Any<CancellationToken>());

        // GetObjectAsync must be called with a ByteRange specifying the correct range.
        await s3.Received(1).GetObjectAsync(
            Arg.Is<GetObjectRequest>(r =>
                r.BucketName == "bucket" &&
                r.Key == "key/path" &&
                r.ByteRange != null &&
                r.ByteRange.Start == 100 &&
                r.ByteRange.End == 149),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task S3_GetRange_ClampsToEndOfBlob()
    {
        var s3 = Substitute.For<IAmazonS3>();
        await using var sut = new S3BlobStore(s3, "bucket");

        s3.GetObjectMetadataAsync("bucket", "k", Arg.Any<CancellationToken>())
            .Returns(new GetObjectMetadataResponse { ContentLength = 50 });

        var responseStream = new MemoryStream(new byte[40]);
        s3.GetObjectAsync(Arg.Any<GetObjectRequest>(), Arg.Any<CancellationToken>())
            .Returns(new GetObjectResponse { ResponseStream = responseStream });

        // Request range extends past the 50-byte blob.
        await using var ranged = await sut.GetRangeAsync("k", 10, 9999);

        Assert.NotNull(ranged);
        Assert.Equal(10, ranged!.From);
        Assert.Equal(49, ranged.To); // clamped
        Assert.Equal(50, ranged.TotalLength);

        // Verify S3 was called with the clamped range (10 to 49, not 10 to 9999).
        await s3.Received(1).GetObjectAsync(
            Arg.Is<GetObjectRequest>(r =>
                r.ByteRange != null &&
                r.ByteRange.Start == 10 &&
                r.ByteRange.End == 49),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task S3_GetRange_NotFound_ReturnsNull()
    {
        var s3 = Substitute.For<IAmazonS3>();
        await using var sut = new S3BlobStore(s3, "bucket");

        s3.GetObjectMetadataAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Throws(new AmazonS3Exception("not found") { StatusCode = HttpStatusCode.NotFound });

        Assert.Null(await sut.GetRangeAsync("missing", 0, 9));
    }

    [Fact]
    public async Task S3_GetRange_PastEnd_ReturnsSentinel()
    {
        var s3 = Substitute.For<IAmazonS3>();
        await using var sut = new S3BlobStore(s3, "bucket");

        s3.GetObjectMetadataAsync("bucket", "k", Arg.Any<CancellationToken>())
            .Returns(new GetObjectMetadataResponse { ContentLength = 10 });

        // Range starts at byte 10 for a 10-byte blob — unsatisfiable.
        await using var ranged = await sut.GetRangeAsync("k", 10, 19);

        Assert.NotNull(ranged);
        Assert.True(ranged!.From > ranged.To,
            "Past-end range must return a sentinel where From > To.");
        Assert.Equal(10, ranged.TotalLength);

        // No GetObjectAsync call should occur for an unsatisfiable range.
        await s3.DidNotReceive().GetObjectAsync(
            Arg.Any<GetObjectRequest>(), Arg.Any<CancellationToken>());
    }

    // ── AzureBlobStore ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Azure_GetRange_CallsContainerWithRange()
    {
        var container = Substitute.For<IAzureBlobContainer>();
        var sut = new AzureBlobStore(container);

        var responseStream = new MemoryStream(new byte[50]);
        container.DownloadRangeOrNullAsync("key", 100, 149, Arg.Any<CancellationToken>())
            .Returns((responseStream as Stream, 1000L));

        await using var ranged = await sut.GetRangeAsync("key", 100, 149);

        Assert.NotNull(ranged);
        Assert.Equal(100, ranged!.From);
        Assert.Equal(149, ranged.To);
        Assert.Equal(1000, ranged.TotalLength);

        await container.Received(1).DownloadRangeOrNullAsync("key", 100, 149, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Azure_GetRange_ContainerReturnsNull_ReturnsNull()
    {
        var container = Substitute.For<IAzureBlobContainer>();
        var sut = new AzureBlobStore(container);

        container.DownloadRangeOrNullAsync(Arg.Any<string>(), Arg.Any<long>(), Arg.Any<long>(), Arg.Any<CancellationToken>())
            .Returns(((Stream?)null, 0L));

        Assert.Null(await sut.GetRangeAsync("missing", 0, 9));
    }

    [Fact]
    public async Task Azure_GetRange_PastEnd_ReturnsSentinel()
    {
        var container = Substitute.For<IAzureBlobContainer>();
        var sut = new AzureBlobStore(container);

        // Container returns a null stream with the total length when range is unsatisfiable.
        container.DownloadRangeOrNullAsync("k", 10, 19, Arg.Any<CancellationToken>())
            .Returns((Stream.Null as Stream, 10L));

        await using var ranged = await sut.GetRangeAsync("k", 10, 19);

        Assert.NotNull(ranged);
        Assert.True(ranged!.From > ranged.To,
            "Past-end range must return a sentinel where From > To.");
        Assert.Equal(10, ranged.TotalLength);
    }

    [Fact]
    public async Task Azure_GetRange_PropagatesCancellationToken()
    {
        var container = Substitute.For<IAzureBlobContainer>();
        var sut = new AzureBlobStore(container);

        using var cts = new CancellationTokenSource();
        container.DownloadRangeOrNullAsync("k", 0, 9, cts.Token)
            .Returns(((Stream?)null, 0L));

        await sut.GetRangeAsync("k", 0, 9, cts.Token);

        await container.Received(1).DownloadRangeOrNullAsync("k", 0, 9, cts.Token);
    }
}
