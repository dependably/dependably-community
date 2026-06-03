using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Coverage for <see cref="MavenUpstreamFetcher"/> after the routing-through-UpstreamClient
/// refactor.
///
/// The tests build a real <see cref="UpstreamClient"/> backed by a WireMock-handled
/// <see cref="IHttpClientFactory"/> so the SSRF guard, single-flight dedup, audit hook
/// and hash-and-stage path all execute. This mirrors how
/// <see cref="RpmUpstreamProxy"/>'s tests do it (which still calls IHttpClientFactory
/// directly) — we deliberately don't introduce an IUpstreamClient interface because the
/// WireMock-at-HTTP pattern exercises more of the gap-closing protections.
///
/// Coverage:
///  - HappyPath_WithSidecar: artifact + .sha256 sidecar both served → caller gets bytes,
///    UpstreamClient writes the blob at <c>BlobKeys.Proxy(sha)</c>.
///  - SecondFetch_HitsCache: blob already in the cache tier → no upstream call.
///  - NoSha256Sidecar_FallsBackToFetchThenHash: Maven Central omits .sha256 for most
///    artifacts, so we fetch-then-hash, verify against the advertised .sha1 (or .md5), and
///    cache by the computed sha256. Mismatch → ChecksumException; no advertised digest →
///    cached unverified with a warning.
///  - ChecksumMismatch_Throws: upstream-served bytes don't match the .sha256 sidecar →
///    <see cref="ChecksumException"/> propagates.
///  - PriorBlobInCache_UpstreamNotContacted: stale-fallback semantics were simplified
///    during the UpstreamClient consolidation; a previously-cached blob is served as a
///    normal cache hit (no Warning: 110 header).
///  - Upstream5xx_NoStale_ReturnsNull: no prior blob → caller gets null (controller 404).
///  - NegativeCache_HitShortCircuits: the negative-cache row blocks the call before any
///    upstream contact.
///  - AirGap_ThrowsAirGappedException: <see cref="UpstreamClient"/> raises it; the fetcher
///    lets it propagate (caller / middleware handles 503).
///  - FetchUpstreamVersionsAsync_HappyPath: maven-metadata.xml is parsed and returned.
///  - FetchUpstreamVersionsAsync_Upstream5xx_ReturnsNull: error → null (caller serves
///    local-only).
///  - FetchUpstreamVersionsAsync_AirGap_ReturnsNull: air-gap → null, no throw.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenUpstreamFetcherTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private WireMockServer _server = null!;
    private string _upstream = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
        _upstream = _server.Urls[0].TrimEnd('/');
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private MavenUpstreamFetcher BuildFetcher(
        InMemoryBlobStore? blobs = null,
        bool airGapped = false,
        bool verifyWithSha256 = true)
    {
        blobs ??= new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Maven:VerifyWithUpstreamSha256"] = verifyWithSha256 ? "true" : "false",
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-maven-test-{Guid.NewGuid():N}"),
            })
            .Build();

        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var audit = new AuditRepository(_db);
        var airGap = new StubAirGapMode(airGapped);
        var urlValidator = new AllowAllValidator();

        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, audit, urlValidator, airGap, config,
            NullLogger<UpstreamClient>.Instance);

        return new MavenUpstreamFetcher(
            upstreamClient, tiered, _db, config,
            NullLogger<MavenUpstreamFetcher>.Instance);
    }

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private void StubArtifact(string path, byte[] body)
    {
        _server.Given(Request.Create().WithPath("/" + path).UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));
    }

    private void StubSidecar(string path, string sha256)
    {
        _server.Given(Request.Create().WithPath("/" + path + ".sha256").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200)
                   .WithBody(sha256 + "  some-file.jar\n"));
    }

    private static string Sha1Hex(byte[] data)
        => Convert.ToHexString(SHA1.HashData(data)).ToLowerInvariant();

    private void StubSha1Sidecar(string path, string sha1)
    {
        _server.Given(Request.Create().WithPath("/" + path + ".sha1").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200)
                   .WithBody(sha1 + "  some-file.jar\n"));
    }

    private static string Md5Hex(byte[] data)
        => Convert.ToHexString(MD5.HashData(data)).ToLowerInvariant();

    private void StubMd5Sidecar(string path, string md5)
    {
        _server.Given(Request.Create().WithPath("/" + path + ".md5").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200)
                   .WithBody(md5 + "  some-file.jar\n"));
    }

    // ── Artifact fetch ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FetchArtifactAsync_HappyPath_WithSidecar_ReturnsBytesAndCachesBlob()
    {
        var bytes = Encoding.UTF8.GetBytes("jar-payload");
        var sha = Sha256Hex(bytes);
        var path = "com/example/lib/1.0/lib-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, sha);

        var blobs = new InMemoryBlobStore();
        var fetcher = BuildFetcher(blobs);

        var result = await fetcher.FetchArtifactAsync(_upstream, path, default);

        Assert.NotNull(result);
        Assert.Equal(bytes, result!.Bytes);
        Assert.Equal(sha, result.Sha256);
        Assert.Equal(BlobKeys.Proxy(sha), result.BlobKey);
        Assert.False(result.IsFromCache);

        // UpstreamClient wrote the blob.
        Assert.True(await blobs.ExistsAsync(BlobKeys.Proxy(sha), default));
    }

    [Fact]
    public async Task FetchArtifactAsync_SecondCall_ServesFromBlobCache_NoUpstreamCall()
    {
        var bytes = Encoding.UTF8.GetBytes("jar-payload-cached");
        var sha = Sha256Hex(bytes);
        var path = "com/example/lib/1.0/lib-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, sha);

        var blobs = new InMemoryBlobStore();
        var fetcher = BuildFetcher(blobs);

        // First call populates the cache via UpstreamClient.
        var first = await fetcher.FetchArtifactAsync(_upstream, path, default);
        Assert.NotNull(first);

        var artifactCallsAfterFirst = _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith("lib-1.0.jar") == true);

        // Second call should be a cache hit on UpstreamClient (no additional artifact request).
        var second = await fetcher.FetchArtifactAsync(_upstream, path, default);
        Assert.NotNull(second);
        Assert.True(second!.IsFromCache);

        var artifactCallsTotal = _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith("lib-1.0.jar") == true);
        Assert.Equal(artifactCallsAfterFirst, artifactCallsTotal);
    }

    [Fact]
    public async Task FetchArtifactAsync_NoSha256Sidecar_FallsBackToFetchThenHash_VerifiesViaSha1()
    {
        // Maven Central serves no .sha256 sidecar for most artifacts — only .sha1/.md5.
        // The fetcher must NOT bail: it fetches the body, derives the content-addressed key
        // locally, verifies against the .sha1 sidecar, and caches the blob.
        var bytes = Encoding.UTF8.GetBytes("no-sha256-but-sha1");
        var path = "com/example/nosha256/1.0/nosha256-1.0.jar";
        StubArtifact(path, bytes);
        StubSha1Sidecar(path, Sha1Hex(bytes));

        var blobs = new InMemoryBlobStore();
        var fetcher = BuildFetcher(blobs);

        var result = await fetcher.FetchArtifactAsync(_upstream, path, default);

        Assert.NotNull(result);
        Assert.Equal(bytes, result!.Bytes);
        Assert.Equal(Sha256Hex(bytes), result.Sha256);
        Assert.Equal(Sha1Hex(bytes), result.Sha1);
        Assert.Equal(BlobKeys.Proxy(Sha256Hex(bytes)), result.BlobKey);
        Assert.False(result.IsFromCache);
        Assert.True(await blobs.ExistsAsync(BlobKeys.Proxy(Sha256Hex(bytes)), default));
    }

    [Fact]
    public async Task FetchArtifactAsync_NoSha256Sidecar_Sha1Mismatch_ThrowsChecksumException()
    {
        // .sha1 sidecar present but wrong → supply-chain mismatch → ChecksumException (502).
        var bytes = Encoding.UTF8.GetBytes("body-that-wont-match-sha1");
        var path = "com/example/badsha1/1.0/badsha1-1.0.jar";
        StubArtifact(path, bytes);
        StubSha1Sidecar(path, new string('0', 40)); // 40 hex zeros — not Sha1(bytes)

        var fetcher = BuildFetcher();

        await Assert.ThrowsAsync<ChecksumException>(
            () => fetcher.FetchArtifactAsync(_upstream, path, default));
    }

    [Fact]
    public async Task FetchArtifactAsync_NoSha256OrSha1_VerifiesViaMd5()
    {
        // Only .md5 advertised (no .sha256, no .sha1) → verify against md5 before serving.
        var bytes = Encoding.UTF8.GetBytes("md5-only-artifact");
        var path = "com/example/md5only/1.0/md5only-1.0.jar";
        StubArtifact(path, bytes);
        StubMd5Sidecar(path, Md5Hex(bytes));

        var blobs = new InMemoryBlobStore();
        var fetcher = BuildFetcher(blobs);

        var result = await fetcher.FetchArtifactAsync(_upstream, path, default);

        Assert.NotNull(result);
        Assert.Equal(Sha256Hex(bytes), result!.Sha256);
        Assert.True(await blobs.ExistsAsync(BlobKeys.Proxy(Sha256Hex(bytes)), default));
    }

    [Fact]
    public async Task FetchArtifactAsync_Md5Mismatch_ThrowsChecksumException()
    {
        var bytes = Encoding.UTF8.GetBytes("md5-will-not-match");
        var path = "com/example/badmd5/1.0/badmd5-1.0.jar";
        StubArtifact(path, bytes);
        StubMd5Sidecar(path, new string('0', 32)); // 32 hex zeros — not Md5(bytes)

        var fetcher = BuildFetcher();

        await Assert.ThrowsAsync<ChecksumException>(
            () => fetcher.FetchArtifactAsync(_upstream, path, default));
    }

    [Fact]
    public async Task FetchArtifactAsync_NoSidecarsAtAll_CachesUnverified()
    {
        // Neither .sha256 nor .sha1 upstream — fetch-then-hash still proxies (best-effort),
        // rather than refusing an artefact that legitimately lacks sidecars.
        var bytes = Encoding.UTF8.GetBytes("no-sidecars-at-all");
        var path = "com/example/bare/1.0/bare-1.0.jar";
        StubArtifact(path, bytes);

        var blobs = new InMemoryBlobStore();
        var fetcher = BuildFetcher(blobs);

        var result = await fetcher.FetchArtifactAsync(_upstream, path, default);

        Assert.NotNull(result);
        Assert.Equal(Sha256Hex(bytes), result!.Sha256);
        Assert.True(await blobs.ExistsAsync(BlobKeys.Proxy(Sha256Hex(bytes)), default));
    }

    [Fact]
    public async Task FetchArtifactAsync_ChecksumMismatch_ThrowsChecksumException()
    {
        var bytes = Encoding.UTF8.GetBytes("real-body");
        var fakeSha = new string('0', 64); // 64 zeros — won't match Sha256(bytes)
        var path = "com/example/badhash/1.0/badhash-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, fakeSha);

        var fetcher = BuildFetcher();

        await Assert.ThrowsAsync<ChecksumException>(
            () => fetcher.FetchArtifactAsync(_upstream, path, default));
    }

    [Fact]
    public async Task FetchArtifactAsync_PriorBlobInCache_UpstreamNotContacted()
    {
        // Behavioural delta from the pre-refactor implementation: when a blob is already
        // in the cache tier UpstreamClient short-circuits BEFORE contacting upstream, so
        // there's no "5xx → serve stale" branch to test any more. The legitimate way to
        // observe a previously-fetched artifact is a normal cache hit: IsFromCache=true.
        // No Warning: 110 header is emitted on the served response.
        var bytes = Encoding.UTF8.GetBytes("previously-cached-bytes");
        var sha = Sha256Hex(bytes);
        var blobs = new InMemoryBlobStore();
        await blobs.PutAsync(BlobKeys.Proxy(sha), new MemoryStream(bytes), default);

        var path = "com/example/cached/1.0/cached-1.0.jar";

        // Sidecar must succeed so the fetcher knows the SHA. Primary 500s deliberately —
        // we want to prove it is never contacted because the cache check short-circuits.
        StubSidecar(path, sha);
        _server.Given(Request.Create().WithPath("/" + path).UsingGet())
               .RespondWith(Response.Create().WithStatusCode(500));

        var fetcher = BuildFetcher(blobs);

        var result = await fetcher.FetchArtifactAsync(_upstream, path, default);

        Assert.NotNull(result);
        Assert.True(result!.IsFromCache);
        Assert.Equal(bytes, result.Bytes);
        Assert.Equal(sha, result.Sha256);

        // Primary URL must not have been contacted.
        Assert.Equal(0, _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith("cached-1.0.jar") == true));
    }

    [Fact]
    public async Task FetchArtifactAsync_Upstream5xx_NoStaleBlob_ReturnsNull()
    {
        var sha = new string('a', 64);
        var path = "com/example/transient/1.0/transient-1.0.jar";
        StubSidecar(path, sha);
        _server.Given(Request.Create().WithPath("/" + path).UsingGet())
               .RespondWith(Response.Create().WithStatusCode(503));

        var fetcher = BuildFetcher(); // empty cache

        var result = await fetcher.FetchArtifactAsync(_upstream, path, default);

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchArtifactAsync_NegativelyCached_ReturnsNullWithoutUpstreamCall()
    {
        var path = "com/example/nope/9.9/nope-9.9.jar";
        var fetcher = BuildFetcher();

        await fetcher.RecordNegativeAsync(path, default);

        var result = await fetcher.FetchArtifactAsync(_upstream, path, default);
        Assert.Null(result);

        // No upstream call should have happened.
        Assert.Equal(0, _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.Contains("/nope-9.9.jar") == true));
    }

    [Fact]
    public async Task FetchArtifactAsync_AirGap_PropagatesAirGappedException()
    {
        // The fetcher no longer pre-checks IsEnabled — air-gap is enforced inside
        // UpstreamClient. We still expect AirGappedException to bubble up to the caller.
        var sha = new string('b', 64);
        var path = "com/example/airgap/1.0/airgap-1.0.jar";
        StubSidecar(path, sha);

        var fetcher = BuildFetcher(airGapped: true);

        await Assert.ThrowsAsync<AirGappedException>(
            () => fetcher.FetchArtifactAsync(_upstream, path, default));
    }

    // ── Metadata fetch ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FetchUpstreamVersionsAsync_HappyPath_ReturnsVersions()
    {
        var xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <metadata>
              <groupId>com.example</groupId>
              <artifactId>lib</artifactId>
              <versioning>
                <versions>
                  <version>1.0</version>
                  <version>2.0</version>
                  <version>3.1.4</version>
                </versions>
              </versioning>
            </metadata>
            """;
        var artifactPath = "com/example/lib";
        _server.Given(Request.Create().WithPath($"/{artifactPath}/maven-metadata.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(xml));

        var fetcher = BuildFetcher();
        var versions = await fetcher.FetchUpstreamVersionsAsync(_upstream, artifactPath, default);

        Assert.NotNull(versions);
        Assert.Equal(new[] { "1.0", "2.0", "3.1.4" }, versions);
    }

    [Fact]
    public async Task FetchUpstreamVersionsAsync_Upstream5xx_ReturnsNull()
    {
        var artifactPath = "com/example/broken";
        _server.Given(Request.Create().WithPath($"/{artifactPath}/maven-metadata.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(500));

        var fetcher = BuildFetcher();
        var versions = await fetcher.FetchUpstreamVersionsAsync(_upstream, artifactPath, default);

        Assert.Null(versions);
    }

    [Fact]
    public async Task FetchUpstreamVersionsAsync_AirGap_ReturnsNull()
    {
        var artifactPath = "com/example/lib";
        // Air-gapped: UpstreamClient throws AirGappedException; the fetcher swallows it
        // and returns null so callers fall back to local-only metadata.
        var fetcher = BuildFetcher(airGapped: true);

        var versions = await fetcher.FetchUpstreamVersionsAsync(_upstream, artifactPath, default);

        Assert.Null(versions);
    }

    [Fact]
    public async Task FetchUpstreamVersionsAsync_404_ReturnsNull()
    {
        var artifactPath = "com/example/missing";
        _server.Given(Request.Create().WithPath($"/{artifactPath}/maven-metadata.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(404));

        var fetcher = BuildFetcher();
        var versions = await fetcher.FetchUpstreamVersionsAsync(_upstream, artifactPath, default);

        Assert.Null(versions);
    }

    // ── Negative cache TTL ─────────────────────────────────────────────────────

    [Fact]
    public async Task NegativeCache_RecordThenRead_ReturnsTrueWithinTtl()
    {
        var fetcher = BuildFetcher();
        await fetcher.RecordNegativeAsync("com/example/x/1.0/x-1.0.jar", default);

        var hit = await fetcher.IsNegativelyCachedAsync("com/example/x/1.0/x-1.0.jar", default);
        Assert.True(hit);
    }

    [Fact]
    public async Task NegativeCache_DifferentPath_ReturnsFalse()
    {
        var fetcher = BuildFetcher();
        await fetcher.RecordNegativeAsync("com/example/a/1.0/a-1.0.jar", default);

        var hit = await fetcher.IsNegativelyCachedAsync("com/example/b/1.0/b-1.0.jar", default);
        Assert.False(hit);
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
        public StubAirGapMode(bool enabled) => IsEnabled = enabled;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(true);
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>Routes HttpClient requests through the WireMock server, preserving the path.</summary>
    private sealed class WireMockHandler : HttpMessageHandler
    {
        private readonly WireMockServer _server;
        public WireMockHandler(WireMockServer server) => _server = server;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var url = _server.Urls[0] + request.RequestUri!.PathAndQuery;
            using var innerRequest = new HttpRequestMessage(request.Method, url);
            foreach (var h in request.Headers)
                innerRequest.Headers.TryAddWithoutValidation(h.Key, h.Value);
            var inner = new HttpClient();
            return await inner.SendAsync(innerRequest, ct);
        }
    }
}
