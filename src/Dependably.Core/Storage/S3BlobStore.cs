using System.Buffers;
using System.Runtime.CompilerServices;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Storage;

public sealed class S3BlobStore : IBlobStore, IPresignedReadBlobStore, IAsyncDisposable
{
    private readonly IAmazonS3 _client;
    private readonly string _bucket;
    private readonly bool _ownsClient;
    private readonly int _partSizeBytes;
    private readonly ILogger<S3BlobStore> _logger;

    /// <summary>
    /// Part size for uploading a stream whose length is unknown. 8 MiB clears S3's 5 MiB minimum
    /// for every part but the last, bounds the memory one such upload holds, and at S3's
    /// 10,000-part ceiling admits objects of up to ~78 GiB (<see cref="MaxUnknownLengthObjectBytes"/>)
    /// — well past the default OCI blob proxy cap.
    /// </summary>
    internal const int DefaultPartSizeBytes = 8 * 1024 * 1024;

    /// <summary>S3's ceiling on the number of parts in one multipart upload.</summary>
    internal const int MaxMultipartParts = 10_000;

    /// <summary>Largest body of unknown length this store can upload: one full part per allowed part.</summary>
    internal const long MaxUnknownLengthObjectBytes = (long)DefaultPartSizeBytes * MaxMultipartParts;

    /// <summary>
    /// Test-friendly constructor: caller supplies the S3 client. Used in unit tests with
    /// an NSubstitute mock; the wrapper does not dispose externally-supplied clients.
    /// </summary>
    public S3BlobStore(IAmazonS3 client, string bucket, ILogger<S3BlobStore>? logger = null)
        : this(client, bucket, DefaultPartSizeBytes, logger)
    {
    }

    /// <summary>
    /// Test seam: a smaller <paramref name="partSizeBytes"/> lets a test drive the multipart path
    /// without allocating megabytes per case. Production always uses <see cref="DefaultPartSizeBytes"/>.
    /// </summary>
    internal S3BlobStore(IAmazonS3 client, string bucket, int partSizeBytes, ILogger<S3BlobStore>? logger = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(partSizeBytes, 1);
        _client = client;
        _bucket = bucket;
        _ownsClient = false;
        _partSizeBytes = partSizeBytes;
        _logger = logger ?? NullLogger<S3BlobStore>.Instance;
    }

    /// <summary>
    /// Production constructor. When <paramref name="endpoint"/> is null the client binds to a
    /// standard AWS region; when set it points at an S3-compatible service (Cloudflare R2,
    /// MinIO, Backblaze B2, Wasabi). R2 and MinIO require <paramref name="forcePathStyle"/>=true.
    /// <paramref name="region"/> is still passed in both modes — it flows into SigV4 signing
    /// (<c>AuthenticationRegion</c>) on the custom-endpoint path; R2 accepts "auto" there.
    /// The wrapper owns the client and disposes it on shutdown.
    /// </summary>
    public S3BlobStore(
        string bucket, string region, string? endpoint = null, bool forcePathStyle = false,
        ILogger<S3BlobStore>? logger = null)
    {
        _bucket = bucket;
        _client = string.IsNullOrWhiteSpace(endpoint)
            ? new AmazonS3Client(Amazon.RegionEndpoint.GetBySystemName(region))
            : new AmazonS3Client(new AmazonS3Config
            {
                ServiceURL = endpoint,
                ForcePathStyle = forcePathStyle,
                AuthenticationRegion = region,
            });
        _ownsClient = true;
        _partSizeBytes = DefaultPartSizeBytes;
        _logger = logger ?? NullLogger<S3BlobStore>.Instance;
    }

    /// <summary>
    /// Writes <paramref name="data"/> to <paramref name="key"/>. A seekable stream goes up as one
    /// <c>PutObject</c>, which is what every staged-file caller hands over.
    ///
    /// <para>
    /// A non-seekable stream cannot: the SDK needs the body's length before it sends the request,
    /// and when the stream cannot report one and no <c>Content-Length</c> header is set it throws
    /// <c>AmazonS3Exception("Could not determine content length")</c> client-side, before any
    /// request leaves the process — so it fails identically against AWS S3 and every
    /// S3-compatible service. The OCI blob proxy is the caller that hits this: it streams the
    /// upstream body through a digest-verifying, client-mirroring pass-through that cannot seek,
    /// and it promotes the verified staging object by re-reading it as a network stream.
    /// </para>
    ///
    /// <para>
    /// Such a stream is uploaded in fixed-size parts instead, each buffered into memory, so
    /// memory is bounded by one part regardless of blob size and the source keeps being read
    /// as the upload progresses — which is what lets the OCI proxy keep mirroring bytes to its
    /// client while caching them. A body that ends within the first part is sent as a single
    /// <c>PutObject</c>, so small blobs cost one request as before.
    /// </para>
    /// </summary>
    public async Task PutAsync(string key, Stream data, CancellationToken ct = default)
    {
        if (data.CanSeek)
        {
            await PutSingleAsync(key, data, ct);
            return;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(_partSizeBytes);
        try
        {
            int filled = await FillAsync(data, buffer, _partSizeBytes, ct);
            if (filled < _partSizeBytes)
            {
                await PutSingleAsync(key, new MemoryStream(buffer, 0, filled, writable: false), ct);
                return;
            }

            await PutMultipartAsync(key, data, buffer, filled, ct);
        }
        finally
        {
            // Cleared on return: the buffer held tenant bytes, and the shared pool hands it on to
            // whatever rents it next.
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private async Task PutSingleAsync(string key, Stream data, CancellationToken ct)
    {
        var request = new PutObjectRequest
        {
            BucketName = _bucket,
            Key = key,
            InputStream = data,
            AutoCloseStream = false
        };
        await _client.PutObjectAsync(request, ct);
    }

    // Uploads the already-read first part, then keeps refilling the same buffer until the
    // source ends. Any failure aborts the upload so S3 discards the parts already sent rather
    // than billing them indefinitely as an incomplete upload.
    private async Task PutMultipartAsync(
        string key, Stream data, byte[] buffer, int firstPartLength, CancellationToken ct)
    {
        var initiated = await _client.InitiateMultipartUploadAsync(new InitiateMultipartUploadRequest
        {
            BucketName = _bucket,
            Key = key,
            ChecksumAlgorithm = ChecksumAlgorithm.CRC32,
        }, ct);
        string uploadId = initiated.UploadId;

        try
        {
            var parts = new List<UploadPartResponse>();
            int filled = firstPartLength;
            int partNumber = 1;
            while (filled > 0)
            {
                var part = await _client.UploadPartAsync(new UploadPartRequest
                {
                    BucketName = _bucket,
                    Key = key,
                    UploadId = uploadId,
                    PartNumber = partNumber,
                    PartSize = filled,
                    InputStream = new MemoryStream(buffer, 0, filled, writable: false),
                    ChecksumAlgorithm = ChecksumAlgorithm.CRC32,
                }, ct);
                part.PartNumber ??= partNumber;
                parts.Add(part);

                partNumber++;
                filled = await FillAsync(data, buffer, _partSizeBytes, ct);
            }

            var complete = new CompleteMultipartUploadRequest
            {
                BucketName = _bucket,
                Key = key,
                UploadId = uploadId,
            };
            complete.AddPartETagsAndChecksums(parts);
            await _client.CompleteMultipartUploadAsync(complete, ct);
        }
        catch
        {
            await TryAbortMultipartAsync(key, uploadId);
            throw;
        }
    }

    // Best effort on CancellationToken.None: a cancelled or failed upload must still release its
    // parts, and a failed abort must never replace the error that caused it — so every abort
    // failure is caught, including the SDK's client-side ones (signing, credentials, checksums),
    // and logged instead. What an abort cannot reach is left to the bucket's
    // AbortIncompleteMultipartUpload lifecycle rule.
    private async Task TryAbortMultipartAsync(string key, string uploadId)
    {
        try
        {
            await _client.AbortMultipartUploadAsync(new AbortMultipartUploadRequest
            {
                BucketName = _bucket,
                Key = key,
                UploadId = uploadId,
            }, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                "{ExceptionType} aborting S3 multipart upload {UploadId} for {Key}; its parts stay in the bucket until the lifecycle rule removes them. {Message}",
                ex.GetType().Name, uploadId, key, ex.Message);
        }
    }

    // Reads until the buffer holds `count` bytes or the source ends; returns the bytes read.
    private static async Task<int> FillAsync(Stream source, byte[] buffer, int count, CancellationToken ct)
        => await source.ReadAtLeastAsync(buffer.AsMemory(0, count), count, throwOnEndOfStream: false, ct);

    public async Task<Stream?> GetAsync(string key, CancellationToken ct = default)
    {
        try
        {
            var response = await _client.GetObjectAsync(_bucket, key, ct);
            return response.ResponseStream;
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    public async Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
    {
        // Fetch object metadata first to resolve the total length and clamp the range.
        GetObjectMetadataResponse meta;
        try
        {
            meta = await _client.GetObjectMetadataAsync(_bucket, key, ct);
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }

        long totalLength = meta.ContentLength;
        long effectiveTo = Math.Min(to, totalLength - 1);

        if (from > effectiveTo || totalLength == 0)
        {
            // Requested range starts past the end — return sentinel with empty range.
            return new RangedStream(Stream.Null, from, from - 1, totalLength);
        }

        // S3 Range header is inclusive on both ends: "bytes=from-to".
        var request = new GetObjectRequest
        {
            BucketName = _bucket,
            Key = key,
            ByteRange = new ByteRange(from, effectiveTo),
        };

        try
        {
            var response = await _client.GetObjectAsync(request, ct);
            return new RangedStream(response.ResponseStream, from, effectiveTo, totalLength);
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
    {
        try
        {
            await _client.GetObjectMetadataAsync(_bucket, key, ct);
            return true;
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    /// <summary>
    /// S3 SigV4 query-string signing is always available: the same credential that reads the
    /// object signs the URL, so a client that can be served can also be redirected.
    /// </summary>
    public bool SupportsPresignedReads => true;

    /// <summary>
    /// Mints a GET-only SigV4 URL for <paramref name="key"/>. <c>GetPreSignedURL</c> signs a key
    /// whether or not an object sits at it, and a URL for an evicted blob would turn a cache miss
    /// (which the caller answers by falling through to upstream) into a 404 from S3 that the
    /// caller never sees — so <see cref="BlobPresignService"/> checks existence before it asks,
    /// and this method does not repeat that HEAD.
    /// </summary>
    public async Task<Uri?> TryCreatePresignedReadUrlAsync(
        string key, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        string url = await _client.GetPreSignedURLAsync(new GetPreSignedUrlRequest
        {
            BucketName = _bucket,
            Key = key,
            Verb = HttpVerb.GET,
            Expires = expiresAt.UtcDateTime,
            Protocol = PresignProtocolFor(_client.Config?.ServiceURL),
        });

        return Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri : null;
    }

    /// <summary>
    /// The scheme a presigned URL names. The SDK defaults a presign request to HTTPS whatever the
    /// client's endpoint, so an S3-compatible store reached over plain <c>http://</c> would be
    /// handed URLs pointing at a TLS listener it does not run. The URL follows the configured
    /// endpoint's scheme; a region-bound client (no endpoint) and an <c>https://</c> endpoint
    /// both sign HTTPS.
    /// </summary>
    private static Amazon.S3.Protocol PresignProtocolFor(string? serviceUrl)
        => Uri.TryCreate(serviceUrl, UriKind.Absolute, out var endpoint)
           && string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            ? Amazon.S3.Protocol.HTTP
            : Amazon.S3.Protocol.HTTPS;

    public async Task DeleteAsync(string key, CancellationToken ct = default)
        => await _client.DeleteObjectAsync(_bucket, key, ct);

    public async Task<long> GetTotalSizeAsync(CancellationToken ct = default)
    {
        long total = 0;
        var request = new ListObjectsV2Request { BucketName = _bucket };
        ListObjectsV2Response response;
        do
        {
            response = await _client.ListObjectsV2Async(request, ct);
            total += response.S3Objects.Sum(o => o.Size ?? 0L);
            request.ContinuationToken = response.NextContinuationToken;
        } while (response.IsTruncated ?? false);
        return total;
    }

    public async IAsyncEnumerable<BlobInfo> ListAsync(
        string prefix, [EnumeratorCancellation] CancellationToken ct = default)
    {
        var request = new ListObjectsV2Request
        {
            BucketName = _bucket,
            Prefix = prefix,
        };
        ListObjectsV2Response response;
        do
        {
            response = await _client.ListObjectsV2Async(request, ct);
            foreach (var obj in response.S3Objects)
            {
                if (ct.IsCancellationRequested)
                {
                    yield break;
                }
                // LastModified on S3 objects is server-side time; trust it for the orphan
                // grace window. Size missing on truncated metadata defaults to 0 — the
                // reconciler treats it as a candidate either way.
                yield return new BlobInfo(
                    obj.Key,
                    obj.Size ?? 0L,
                    obj.LastModified is { } lm ? new DateTimeOffset(lm, TimeSpan.Zero) : DateTimeOffset.MinValue);
            }
            request.ContinuationToken = response.NextContinuationToken;
        } while (response.IsTruncated ?? false);
    }

    public ValueTask DisposeAsync()
    {
        if (_ownsClient && _client is IDisposable d)
        {
            d.Dispose();
        }

        return ValueTask.CompletedTask;
    }
}
