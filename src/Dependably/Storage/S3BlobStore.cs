using System.Runtime.CompilerServices;
using Amazon.S3;
using Amazon.S3.Model;

namespace Dependably.Storage;

public sealed class S3BlobStore : IBlobStore, IAsyncDisposable
{
    private readonly IAmazonS3 _client;
    private readonly string _bucket;
    private readonly bool _ownsClient;

    /// <summary>
    /// Test-friendly constructor: caller supplies the S3 client. Used in unit tests with
    /// an NSubstitute mock; the wrapper does not dispose externally-supplied clients.
    /// </summary>
    public S3BlobStore(IAmazonS3 client, string bucket)
    {
        _client = client;
        _bucket = bucket;
        _ownsClient = false;
    }

    /// <summary>
    /// Production constructor. When <paramref name="endpoint"/> is null the client binds to a
    /// standard AWS region; when set it points at an S3-compatible service (Cloudflare R2,
    /// MinIO, Backblaze B2, Wasabi). R2 and MinIO require <paramref name="forcePathStyle"/>=true.
    /// <paramref name="region"/> is still passed in both modes — it flows into SigV4 signing
    /// (<c>AuthenticationRegion</c>) on the custom-endpoint path; R2 accepts "auto" there.
    /// The wrapper owns the client and disposes it on shutdown.
    /// </summary>
    public S3BlobStore(string bucket, string region, string? endpoint = null, bool forcePathStyle = false)
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
    }

    public async Task PutAsync(string key, Stream data, CancellationToken ct = default)
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
