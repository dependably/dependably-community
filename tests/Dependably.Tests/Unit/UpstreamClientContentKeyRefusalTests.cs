using System.Net;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The refusal arms of the content-addressed proxy fetch (npm tarballs, NuGet flatcontainer): a
/// body that does not match the checksum upstream's metadata promised, a URL the SSRF policy
/// blocks, and a declared size over the artifact cap are all refused with a typed exception,
/// and nothing refused is written to the blob store.
/// </summary>
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class UpstreamClientContentKeyRefusalTests
{
    private const string Url = "https://registry.npmjs.example/express/-/express-4.19.2.tgz";

    private static byte[] Tarball() => "package/package.json: {\"name\":\"express\"}"u8.ToArray();

    private static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    [Fact]
    public async Task ABodyMatchingTheDeclaredChecksum_IsStoredUnderItsOwnHash()
    {
        byte[] body = Tarball();
        await using var up = await StubUpstream.CreateAsync(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(body),
        });

        var result = await up.Client.FetchAndCacheByUrlAsync(
            Url, new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256(body)), "npm");

        Assert.Equal(Sha256(body), result.Sha256Hex);
        Assert.Equal(BlobKeys.Proxy(Sha256(body)), result.BlobKey);
        Assert.True(await up.Blobs.ExistsAsync(result.BlobKey));
    }

    [Fact]
    public async Task ABodyNotMatchingTheDeclaredChecksum_IsRefused_AndNothingIsStored()
    {
        byte[] body = Tarball();
        await using var up = await StubUpstream.CreateAsync(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(body),
        });

        await Assert.ThrowsAsync<ChecksumException>(() => up.Client.FetchAndCacheByUrlAsync(
            Url, new ChecksumSpec(ChecksumAlgorithm.Sha256, new string('0', 64)), "npm"));

        Assert.False(await up.Blobs.ExistsAsync(BlobKeys.Proxy(Sha256(body))));
    }

    [Fact]
    public async Task AUrlTheSsrfPolicyBlocks_IsRefusedBeforeAnyRequest()
    {
        await using var up = await StubUpstream.CreateAsync(
            _ => new HttpResponseMessage(HttpStatusCode.OK), validator: new BlockAll());

        await Assert.ThrowsAsync<SsrfBlockedException>(() => up.Client.FetchAndCacheByUrlAsync(Url, null, "npm"));

        Assert.Empty(up.Requests.Urls);
    }

    [Fact]
    public async Task ADeclaredLengthOverTheArtifactCap_IsRefusedFromTheHeader_AndAudited()
    {
        await using var up = await StubUpstream.CreateAsync(
            _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new DeclaredLengthContent(UpstreamClient.MaxUpstreamResponseBytes + 1),
            },
            stagingDisk: new RoomyDisk());

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            up.Client.FetchAndCacheByUrlAsync(Url, null, "npm"));

        await using var conn = await up.Db.OpenAsync();
        int audited = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'upstream_response_too_large' AND ecosystem = 'npm'");
        Assert.Equal(1, audited);
    }

    [Fact]
    public async Task ANotFoundUpstream_PropagatesAsAnHttpFailure_ForTheNextUpstreamToTry()
    {
        await using var up = await StubUpstream.CreateAsync(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        await Assert.ThrowsAsync<HttpRequestException>(() => up.Client.FetchAndCacheByUrlAsync(Url, null, "npm"));
    }

    [Fact]
    public async Task AnUpstreamThatKeepsFailing_ExhaustsItsRetries_AsATransientFailure_NotAnAnswer()
    {
        int calls = 0;
        await using var up = await StubUpstream.CreateAsync(_ =>
        {
            calls++;
            return new HttpResponseMessage(HttpStatusCode.BadGateway);
        });

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            up.Client.FetchAndCacheByUrlAsync(Url, null, "npm"));

        Assert.True(ex.Transient);
        Assert.False(ex.Refused);
        Assert.Equal(502, ex.StatusCode);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task AnUnexpectedFault_IsRethrown_NotSwallowedIntoABlob()
    {
        await using var up = await StubUpstream.CreateAsync(_ => throw new InvalidOperationException("handler bug"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => up.Client.FetchAndCacheByUrlAsync(Url, null, "npm"));
    }

    [Fact]
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    public async Task AStagingFileThatCannotBeDeleted_DoesNotFailAFetchThatAlreadyStoredTheBlob()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        byte[] body = Tarball();
        string staging = Path.Combine(Path.GetTempPath(), $"dependably-stage-{Guid.NewGuid():N}");
        await using var up = await StubUpstream.CreateAsync(
            _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) },
            stagingPath: staging,
            wrapBlobs: inner => new StagingLockingStore(inner, staging));
        try
        {
            var result = await up.Client.FetchAndCacheByUrlAsync(Url, null, "npm");

            Assert.Equal(Sha256(body), result.Sha256Hex);
            Assert.True(await up.Blobs.ExistsAsync(result.BlobKey));
        }
        finally
        {
            if (Directory.Exists(staging))
            {
                File.SetUnixFileMode(staging, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                Directory.Delete(staging, recursive: true);
            }
        }
    }

    /// <summary>Makes the staging directory read-only once the blob write begins, so removing the staged temp file fails.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private sealed class StagingLockingStore(IBlobStore inner, string staging) : IBlobStore
    {
        public Task PutAsync(string key, Stream data, CancellationToken ct = default)
        {
            File.SetUnixFileMode(staging, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            return inner.PutAsync(key, data, ct);
        }

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => inner.GetAsync(key, ct);

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => inner.ExistsAsync(key, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default) => inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => inner.GetTotalSizeAsync(ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => inner.GetRangeAsync(key, from, to, ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => inner.ListAsync(prefix, ct);
    }

    private sealed class BlockAll : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.BlockedRange);
    }

    private sealed class RoomyDisk : IStagingDiskInfo
    {
        public long GetAvailableBytes() => long.MaxValue / 2;

        public long GetTotalBytes() => long.MaxValue / 2;

        public long GetStagingDirectoryUsedBytes() => 0;
    }

    /// <summary>Declares a Content-Length without a body: a fetch that reads it has not refused from the header.</summary>
    private sealed class DeclaredLengthContent(long declared) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => throw new InvalidOperationException("an over-cap body must be refused from its declared length");

        protected override bool TryComputeLength(out long length)
        {
            length = declared;
            return true;
        }
    }
}
