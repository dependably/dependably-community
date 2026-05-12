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
    /// Production constructor: builds an <see cref="AmazonS3Client"/> from a region name.
    /// The wrapper owns the client and disposes it on shutdown.
    /// </summary>
    public S3BlobStore(string bucket, string region)
    {
        _bucket = bucket;
        _client = new AmazonS3Client(Amazon.RegionEndpoint.GetBySystemName(region));
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

    public ValueTask DisposeAsync()
    {
        if (_ownsClient && _client is IDisposable d) d.Dispose();
        return ValueTask.CompletedTask;
    }
}
