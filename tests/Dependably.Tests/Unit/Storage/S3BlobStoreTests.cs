using System.Net;
using Amazon.S3;
using Amazon.S3.Model;
using Dependably.Storage;
using NSubstitute;
using Xunit;

namespace Dependably.Tests.Unit.Storage;

[Trait("Category", "Unit")]
public sealed class S3BlobStoreTests
{
    private readonly IAmazonS3 _s3 = Substitute.For<IAmazonS3>();
    private S3BlobStore NewSut(string bucket = "test-bucket") => new(_s3, bucket);

    [Fact]
    public async Task PutAsync_PassesBucketAndKey_ToS3Sdk()
    {
        await using var sut = NewSut("the-bucket");
        await using var stream = new MemoryStream([1, 2, 3]);

        await sut.PutAsync("proxy/sha256/abc", stream);

        await _s3.Received(1).PutObjectAsync(
            Arg.Is<PutObjectRequest>(r =>
                r.BucketName == "the-bucket" &&
                r.Key == "proxy/sha256/abc" &&
                r.AutoCloseStream == false),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetAsync_NotFound_Returns404Maps_ToNull_NotException()
    {
        _s3.GetObjectAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<GetObjectResponse>>(_ => throw new AmazonS3Exception("missing") { StatusCode = HttpStatusCode.NotFound });

        await using var sut = NewSut();
        Assert.Null(await sut.GetAsync("missing/key"));
    }

    [Fact]
    public async Task ExistsAsync_404_ReturnsFalse_OtherErrorPropagates()
    {
        _s3.GetObjectMetadataAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<GetObjectMetadataResponse>>(
                _ => throw new AmazonS3Exception("404") { StatusCode = HttpStatusCode.NotFound });

        await using var sut = NewSut();
        Assert.False(await sut.ExistsAsync("missing/key"));

        // Non-404 errors must propagate so callers see the real failure (not silently treated as absent).
        _s3.GetObjectMetadataAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<GetObjectMetadataResponse>>(
                _ => throw new AmazonS3Exception("perm denied") { StatusCode = HttpStatusCode.Forbidden });
        await Assert.ThrowsAsync<AmazonS3Exception>(() => sut.ExistsAsync("any/key"));
    }

    [Fact]
    public async Task GetTotalSizeAsync_IteratesPaginationCursors()
    {
        // Page 1: two objects + a continuation; page 2: one object, no continuation.
        var page1 = new ListObjectsV2Response
        {
            S3Objects = [new() { Size = 100 }, new() { Size = 250 }],
            NextContinuationToken = "PAGE2",
            IsTruncated = true,
        };
        var page2 = new ListObjectsV2Response
        {
            S3Objects = [new() { Size = 50 }],
            NextContinuationToken = null,
            IsTruncated = false,
        };

        _s3.ListObjectsV2Async(
                Arg.Is<ListObjectsV2Request>(r => r.ContinuationToken == null),
                Arg.Any<CancellationToken>())
            .Returns(page1);
        _s3.ListObjectsV2Async(
                Arg.Is<ListObjectsV2Request>(r => r.ContinuationToken == "PAGE2"),
                Arg.Any<CancellationToken>())
            .Returns(page2);

        await using var sut = NewSut();
        Assert.Equal(400, await sut.GetTotalSizeAsync());

        // Both pages were requested — proves the continuation was threaded through.
        await _s3.Received(2).ListObjectsV2Async(Arg.Any<ListObjectsV2Request>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetTotalSizeAsync_NullSizes_TreatedAsZero()
    {
        var page = new ListObjectsV2Response
        {
            S3Objects = [new() { Size = null }, new() { Size = 100 }],
            IsTruncated = false,
        };
        _s3.ListObjectsV2Async(Arg.Any<ListObjectsV2Request>(), Arg.Any<CancellationToken>())
            .Returns(page);

        await using var sut = NewSut();
        Assert.Equal(100, await sut.GetTotalSizeAsync());
    }

    [Fact]
    public async Task DeleteAsync_DelegatesToSdkWithBucketAndKey()
    {
        await using var sut = NewSut("b");
        await sut.DeleteAsync("k");
        await _s3.Received(1).DeleteObjectAsync("b", "k", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DisposeAsync_OnInjectedClient_DoesNotDisposeIt()
    {
        // When the caller provides the IAmazonS3, the wrapper does not own its lifecycle.
        var sut = new S3BlobStore(_s3, "b");
        await sut.DisposeAsync();
        // No call to Dispose() on the injected substitute.
        _s3.DidNotReceive().Dispose();
    }

    [Fact]
    public async Task ExistsAsync_NonNotFoundAmazonS3Exception_PropagatesException()
    {
        // A 403 Forbidden should propagate — it is a real failure, not a cache-miss.
        _s3.GetObjectMetadataAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<GetObjectMetadataResponse>>(
                _ => throw new AmazonS3Exception("Access denied") { StatusCode = HttpStatusCode.Forbidden });

        await using var sut = NewSut();

        await Assert.ThrowsAsync<AmazonS3Exception>(() => sut.ExistsAsync("private/key"));
    }

    [Fact]
    public async Task GetTotalSizeAsync_SingleObject_ReturnsTotalSize()
    {
        var page = new ListObjectsV2Response
        {
            S3Objects = [new() { Size = 1234 }],
            IsTruncated = false,
        };
        _s3.ListObjectsV2Async(Arg.Any<ListObjectsV2Request>(), Arg.Any<CancellationToken>())
            .Returns(page);

        await using var sut = NewSut();
        Assert.Equal(1234, await sut.GetTotalSizeAsync());
    }

    [Fact]
    public async Task DisposeAsync_WhenOwnsClient_DisposesUnderlyingClient()
    {
        // Force _ownsClient = true via reflection so we can exercise the dispose path
        // without hitting a real AWS endpoint.
        var sut = new S3BlobStore(_s3, "b");
        var field = typeof(S3BlobStore).GetField("_ownsClient",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        field.SetValue(sut, true);

        await sut.DisposeAsync();

        _s3.Received(1).Dispose();
    }
}
