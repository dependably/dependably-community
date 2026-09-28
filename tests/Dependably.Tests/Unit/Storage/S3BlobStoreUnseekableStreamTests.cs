using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// <see cref="S3BlobStore.PutAsync"/> over a stream that cannot seek and cannot report its length
/// — the shape the OCI blob proxy hands it — driven through the real AWS SDK client against
/// <see cref="FakeS3Service"/>, so the SDK's own client-side precondition is what these tests
/// exercise rather than a substitute's idea of it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class S3BlobStoreUnseekableStreamTests : IAsyncDisposable
{
    private const int PartSize = 1024;

    private readonly FakeS3Service _s3 = new();
    private readonly AmazonS3Client _client;

    public S3BlobStoreUnseekableStreamTests()
    {
        // S3 refuses any part but the last below its minimum; hold these small parts to the same rule.
        _s3.MinPartSizeBytes = PartSize;
        _client = _s3.CreateClient();
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        return ValueTask.CompletedTask;
    }

    private S3BlobStore NewSut(int partSize = PartSize, ILogger<S3BlobStore>? logger = null)
        => new(_client, _s3.Bucket, partSize, logger);

    private static byte[] Bytes(int n)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    [Fact]
    public async Task Sdk_RefusesUnseekableBodyWithNoLength_BeforeSendingAnything()
    {
        // The root cause, pinned: the SDK itself rejects the request client-side, so it fails the
        // same way against AWS S3 as against MinIO — nothing reaches the service at all.
        var request = new PutObjectRequest
        {
            BucketName = _s3.Bucket,
            Key = "k",
            InputStream = new UnseekableStream(Bytes(10)),
            AutoCloseStream = false,
        };

        var ex = await Assert.ThrowsAsync<AmazonS3Exception>(() => _client.PutObjectAsync(request));

        Assert.Contains("Could not determine content length", ex.Message, StringComparison.Ordinal);
        Assert.Empty(_s3.Operations);
    }

    [Fact]
    public async Task PutAsync_UnseekableBodySmallerThanOnePart_StoredWithOnePutObject()
    {
        byte[] body = Bytes(PartSize - 1);
        await using var sut = NewSut();

        await sut.PutAsync("oci/_staging/small", new UnseekableStream(body));

        Assert.Equal(body, _s3.GetObject("oci/_staging/small"));
        Assert.Equal(["PutObject"], _s3.Operations);
    }

    [Fact]
    public async Task PutAsync_EmptyUnseekableBody_StoredAsEmptyObject()
    {
        await using var sut = NewSut();

        await sut.PutAsync("oci/_staging/empty", new UnseekableStream([]));

        Assert.Equal(Array.Empty<byte>(), _s3.GetObject("oci/_staging/empty"));
    }

    [Fact]
    public async Task PutAsync_UnseekableBodyLargerThanOnePart_UploadedInPartsAndReassembled()
    {
        byte[] body = Bytes((PartSize * 2) + 300);
        await using var sut = NewSut();

        await sut.PutAsync("oci/_staging/large", new UnseekableStream(body));

        Assert.Equal(body, _s3.GetObject("oci/_staging/large"));
        Assert.Equal(
            ["CreateMultipartUpload", "UploadPart", "UploadPart", "UploadPart", "CompleteMultipartUpload"],
            _s3.Operations);
        Assert.Equal(0, _s3.OpenMultipartUploads);
    }

    [Fact]
    public async Task PutAsync_UnseekableBodyExactlyWholeParts_SendsNoEmptyTrailingPart()
    {
        byte[] body = Bytes(PartSize * 2);
        await using var sut = NewSut();

        await sut.PutAsync("oci/_staging/exact", new UnseekableStream(body));

        Assert.Equal(body, _s3.GetObject("oci/_staging/exact"));
        Assert.Equal(2, _s3.Operations.Count(o => o == "UploadPart"));
    }

    [Fact]
    public async Task PutAsync_PartFailsMidUpload_AbortsTheUploadAndSurfacesTheFailure()
    {
        // A mixed outcome inside one upload: part 1 lands, part 2 is refused. The failure must
        // reach the caller (so the OCI fetch fails rather than recording a blob it never stored)
        // and the upload must be aborted so the part already sent is not left billed in the bucket.
        byte[] body = Bytes((PartSize * 3) + 1);
        _s3.FailNextUploadPart(2);
        await using var sut = NewSut();

        await Assert.ThrowsAsync<AmazonS3Exception>(
            () => sut.PutAsync("oci/_staging/fails", new UnseekableStream(body)));

        Assert.Null(_s3.GetObject("oci/_staging/fails"));
        Assert.Equal(0, _s3.OpenMultipartUploads);
        Assert.Equal("AbortMultipartUpload", _s3.Operations[^1]);
        Assert.DoesNotContain("CompleteMultipartUpload", _s3.Operations);

        // The same store then succeeds on the next attempt: the failure left nothing behind.
        await sut.PutAsync("oci/_staging/fails", new UnseekableStream(body));
        Assert.Equal(body, _s3.GetObject("oci/_staging/fails"));
    }

    [Fact]
    public async Task PutAsync_AbortItselfFailsClientSide_OriginalFailureSurfacesAndAbortIsLogged()
    {
        // Part 2 is refused, and then the abort meant to clean up after it fails too, inside the
        // SDK. The caller must still see why the upload failed, not why the cleanup did, and the
        // failed abort must be visible, because its parts now wait on the bucket's lifecycle rule.
        byte[] body = Bytes((PartSize * 3) + 1);
        _s3.FailNextUploadPart(2);
        _s3.FailNextAbortClientSide();
        var logger = new RecordingLogger();
        await using var sut = NewSut(logger: logger);

        var ex = await Assert.ThrowsAsync<AmazonS3Exception>(
            () => sut.PutAsync("oci/_staging/abort-fails", new UnseekableStream(body)));

        Assert.Equal("InternalError", ex.ErrorCode);
        Assert.Equal("AbortMultipartUpload", _s3.Operations[^1]);
        (_, string warning) = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("oci/_staging/abort-fails", warning, StringComparison.Ordinal);
        Assert.Contains("upload-1", warning, StringComparison.Ordinal);
        Assert.Contains(nameof(AmazonClientException), warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PutAsync_SourceReturnsShortReads_EveryPartButTheLastIsFull()
    {
        // A network body hands over whatever has arrived, often far less than asked for. Each part
        // must still be filled to the part size before it is sent: S3 rejects an undersized part
        // anywhere but last, and a store that sent one read per part would upload thousands of
        // tiny parts and then fail to complete.
        byte[] body = Bytes((PartSize * 3) + 123);
        await using var sut = NewSut();

        await sut.PutAsync("oci/_staging/trickle", new UnseekableStream(body, maxBytesPerRead: 7));

        Assert.Equal(body, _s3.GetObject("oci/_staging/trickle"));
        var parts = Assert.Single(_s3.CompletedPartSizes);
        Assert.Equal([PartSize, PartSize, PartSize, 123], parts);
    }

    [Fact]
    public async Task PutAsync_FromAnotherObjectsResponseStream_CopiesIt()
    {
        // The OCI proxy promotes a verified staging object by reading it back and writing it under
        // its content-addressed key; the SDK's response stream is not seekable either.
        byte[] body = Bytes((PartSize * 2) + 17);
        await using var sut = NewSut();
        await sut.PutAsync("oci/_staging/src", new MemoryStream(body));

        await using (var staged = await sut.GetAsync("oci/_staging/src"))
        {
            Assert.NotNull(staged);
            await sut.PutAsync("oci/blobs/sha256/dst", staged!);
        }

        Assert.Equal(body, _s3.GetObject("oci/blobs/sha256/dst"));
    }

    [Fact]
    public async Task PutAsync_SeekableBody_StillOnePutObjectWhateverItsSize()
    {
        byte[] body = Bytes(PartSize * 4);
        await using var sut = NewSut();

        await sut.PutAsync("proxy/sha256/seekable", new MemoryStream(body));

        Assert.Equal(body, _s3.GetObject("proxy/sha256/seekable"));
        Assert.Equal(["PutObject"], _s3.Operations);
    }

    /// <summary>A read-only body that, like a network or pass-through stream, cannot seek or report a length.</summary>
    internal sealed class UnseekableStream(byte[] data, int maxBytesPerRead = int.MaxValue) : Stream
    {
        private readonly MemoryStream _inner = new(data);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
            => _inner.Read(buffer, offset, Math.Min(count, maxBytesPerRead));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _inner.ReadAsync(buffer[..Math.Min(buffer.Length, maxBytesPerRead)], cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class RecordingLogger : ILogger<S3BlobStore>
    {
        private readonly List<(LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<(LogLevel Level, string Message)> Entries
        {
            get
            {
                lock (_entries)
                {
                    return _entries.ToArray();
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (_entries)
            {
                _entries.Add((logLevel, formatter(state, exception)));
            }
        }
    }
}
