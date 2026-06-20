using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Api;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Unit;

/// <summary>
/// Verifies that OCI HEAD requests do not download bodies or open blob streams.
///
/// OCI manifest HEAD on cache-miss: the upstream is contacted with HEAD (not GET), so
/// no manifest body is downloaded and discarded.
///
/// OCI manifest HEAD on cache-hit: the local blob store is consulted via ExistsAsync (not
/// GetAsync), so no stream is opened.
///
/// OCI blob HEAD on cache-miss: the upstream is contacted with HEAD (not GET).
///
/// Mixed scenario (house rule): HEAD followed by GET for the same manifest or blob returns
/// headers-only for HEAD and the full body for GET.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HeadRequestsHeadersOnlyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly GetAsyncCountingBlobStore _cacheBlobs = new(new InMemoryBlobStore());
    private readonly GetAsyncCountingBlobStore _registryBlobs = new(new InMemoryBlobStore());

    private string _orgId = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private OrgRepository _orgs = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "head-test-org");

        // Enable anonymous pull so authorization does not block read-path tests.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId = _orgId });

        // Seed a catch-all OCI upstream so resolver tests can find a matching upstream entry.
        string prefixJson = System.Text.Json.JsonSerializer.Serialize(new[] { "" });
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, name, url, position, auth_type, prefixes)
            VALUES (@id, @orgId, 'oci', 'dockerhub', 'registry-1.docker.io', 0, 'anonymous', @prefixes)
            ON CONFLICT (org_id, ecosystem, url) DO NOTHING
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId = _orgId, prefixes = prefixJson });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── OCI manifest HEAD: cache-miss must issue upstream HEAD, not GET ────────

    /// <summary>
    /// On a cache-miss OCI manifest HEAD, the resolver must issue a HEAD request to upstream
    /// (not a GET). No body is downloaded or discarded.
    /// </summary>
    [Fact]
    public async Task OciManifestHead_CacheMiss_IssuesUpstreamHeadNotGet()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;

        // Upstream HEAD response — headers only, no body content.
        var headResp = new HttpResponseMessage(HttpStatusCode.OK);
        headResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", digest);
        headResp.Content = new ByteArrayContent([]);
        headResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json");
        headResp.Content.Headers.ContentLength = (long)manifestBytes.Length;

        var methodRecorder = new MethodRecordingFactory(headResp);
        var ctl = BuildOciController(BuildResolver(methodRecorder));
        int getCallsBefore = _cacheBlobs.GetAsyncCallCount;

        var result = await ctl.Head("library/ubuntu/manifests/latest", default);

        Assert.IsType<OkResult>(result);
        Assert.Equal("MISS", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(digest, ctl.Response.Headers["Docker-Content-Digest"].ToString());

        // The upstream must have been called with HEAD, not GET.
        Assert.Equal(1, methodRecorder.RequestCount);
        Assert.Equal(HttpMethod.Head, methodRecorder.LastMethod);

        // No blob GetAsync was called (ExistsAsync / metadata only).
        Assert.Equal(getCallsBefore, _cacheBlobs.GetAsyncCallCount);
    }

    /// <summary>
    /// HEAD on an OCI manifest returns 404 when the upstream does not know the manifest.
    /// Auth gate is the same as GET.
    /// </summary>
    [Fact]
    public async Task OciManifestHead_CacheMiss_UpstreamNotFound_Returns404()
    {
        var notFoundFactory = new StatusFactory(HttpStatusCode.NotFound);
        var ctl = BuildOciController(BuildResolver(notFoundFactory));

        var result = await ctl.Head("library/ubuntu/manifests/unknown-tag", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, obj.StatusCode);
        Assert.Equal(0, _cacheBlobs.GetAsyncCallCount);
    }

    // ── OCI manifest HEAD: cache-hit must NOT open a blob stream ─────────────

    /// <summary>
    /// On a cache-hit OCI manifest HEAD, ExistsAsync is used — GetAsync is never called.
    /// </summary>
    [Fact]
    public async Task OciManifestHead_CacheHit_DoesNotCallGetAsync()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"hit\":true}");
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);

        await _cacheBlobs.Inner.PutAsync(blobKey, new MemoryStream(manifestBytes));

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size, @blobKey, 'proxy')
            ON CONFLICT (digest, org_id) DO NOTHING
            """,
            new { digest, orgId = _orgId, size = (long)manifestBytes.Length, blobKey });

        await conn.ExecuteAsync(
            """
            INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
            VALUES (@orgId, 'library/ubuntu', 'cached-tag', @digest,
                    strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                    strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            ON CONFLICT (org_id, repository, tag) DO NOTHING
            """,
            new { orgId = _orgId, digest });

        int getsBefore = _cacheBlobs.GetAsyncCallCount;
        var ctl = BuildOciController(BuildResolver(new NeverCallFactory()));

        var result = await ctl.Head("library/ubuntu/manifests/cached-tag", default);

        Assert.IsType<OkResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(digest, ctl.Response.Headers["Docker-Content-Digest"].ToString());

        // GetAsync must NOT have been called on the blob store.
        Assert.Equal(getsBefore, _cacheBlobs.GetAsyncCallCount);
    }

    // ── OCI manifest HEAD respects auth gate ─────────────────────────────────

    /// <summary>
    /// HEAD with anonymous-pull disabled and no token returns 401 — same as GET.
    /// </summary>
    [Fact]
    public async Task OciManifestHead_AnonymousPullDisabled_Returns401()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId",
            new { orgId = _orgId });

        try
        {
            var ctl = BuildOciController(BuildResolver(new NeverCallFactory()));
            var result = await ctl.Head("library/ubuntu/manifests/latest", default);

            var obj = Assert.IsType<ObjectResult>(result);
            Assert.Equal(401, obj.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
                new { orgId = _orgId });
        }
    }

    // ── Mixed: HEAD then GET — HEAD cheap, GET still fetches full body ─────────

    /// <summary>
    /// Mixed scenario (house rule): HEAD issues an upstream HEAD; a subsequent GET on the
    /// same path fetches the full body via GET. Two upstream calls, distinct methods.
    /// </summary>
    [Fact]
    public async Task OciManifestHead_ThenGet_HeadCheapGetStillFetches()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"mixed\":true}");
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;

        // Upstream HEAD response (no body).
        var headResp = new HttpResponseMessage(HttpStatusCode.OK);
        headResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", digest);
        headResp.Content = new ByteArrayContent([]);
        headResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json");
        headResp.Content.Headers.ContentLength = (long)manifestBytes.Length;

        // Upstream GET response (full body).
        var getResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(manifestBytes)
            {
                Headers =
                {
                    ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
                        "application/vnd.oci.image.manifest.v1+json"),
                },
            },
        };
        getResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", digest);

        var methodRecorder = new MethodRecordingFactory(headResp, getResp);
        var ctl = BuildOciController(BuildResolver(methodRecorder));

        // HEAD: upstream called with HEAD, GetAsync not invoked.
        int getsBefore = _cacheBlobs.GetAsyncCallCount;
        var headResult = await ctl.Head("library/ubuntu/manifests/latest", default);
        Assert.IsType<OkResult>(headResult);
        Assert.Equal(HttpMethod.Head, methodRecorder.LastMethod);
        Assert.Equal(getsBefore, _cacheBlobs.GetAsyncCallCount);

        // GET: upstream called with GET, body stream returned.
        var getResult = await ctl.Get("library/ubuntu/manifests/latest", default);
        Assert.IsType<FileStreamResult>(getResult);
        Assert.Equal(HttpMethod.Get, methodRecorder.LastMethod);

        Assert.Equal(2, methodRecorder.RequestCount);
    }

    // ── OCI blob HEAD: cache-miss must issue upstream HEAD, not GET ───────────

    /// <summary>
    /// HEAD on a blob on a cache-miss issues a HEAD to upstream — no blob body is downloaded.
    /// </summary>
    [Fact]
    public async Task OciBlobHead_CacheMiss_IssuesUpstreamHeadNotGet()
    {
        byte[] blobBytes = RandomBytes(256);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;

        var headContent = new ByteArrayContent([]);
        headContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        headContent.Headers.ContentLength = (long)blobBytes.Length;
        var headResp = new HttpResponseMessage(HttpStatusCode.OK) { Content = headContent };

        var methodRecorder = new MethodRecordingFactory(headResp);
        var ctl = BuildOciController(BuildResolver(methodRecorder));
        int getsBefore = _cacheBlobs.GetAsyncCallCount;

        var result = await ctl.Head($"library/ubuntu/blobs/{digest}", default);

        Assert.IsType<OkResult>(result);
        Assert.Equal("MISS", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(digest, ctl.Response.Headers["Docker-Content-Digest"].ToString());

        // Upstream must have been called with HEAD.
        Assert.Equal(1, methodRecorder.RequestCount);
        Assert.Equal(HttpMethod.Head, methodRecorder.LastMethod);

        // GetAsync must not have been called on the blob store.
        Assert.Equal(getsBefore, _cacheBlobs.GetAsyncCallCount);
    }

    /// <summary>
    /// OCI blob HEAD cache-hit (blob is in local store): ExistsAsync is used, GetAsync is not.
    /// </summary>
    [Fact]
    public async Task OciBlobHead_CacheHit_DoesNotCallGetAsync()
    {
        byte[] blobBytes = RandomBytes(128);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);

        await _cacheBlobs.Inner.PutAsync(blobKey, new MemoryStream(blobBytes));

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/octet-stream', @size, @blobKey, 'proxy')
            ON CONFLICT (digest, org_id) DO NOTHING
            """,
            new { digest, orgId = _orgId, size = (long)blobBytes.Length, blobKey });

        int getsBefore = _cacheBlobs.GetAsyncCallCount;
        var ctl = BuildOciController(BuildResolver(new NeverCallFactory()));

        var result = await ctl.Head($"library/ubuntu/blobs/{digest}", default);

        Assert.IsType<OkResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(getsBefore, _cacheBlobs.GetAsyncCallCount);
    }

    /// <summary>
    /// Mixed scenario (house rule) for blobs: HEAD on cache-miss is cheap (upstream HEAD);
    /// a subsequent GET fetches the full blob body and caches it.
    /// </summary>
    [Fact]
    public async Task OciBlobHead_ThenGet_HeadCheapGetStreams()
    {
        byte[] blobBytes = RandomBytes(128);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;

        // HEAD response: headers only.
        var blobHeadContent = new ByteArrayContent([]);
        blobHeadContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        blobHeadContent.Headers.ContentLength = (long)blobBytes.Length;
        var headResp = new HttpResponseMessage(HttpStatusCode.OK) { Content = blobHeadContent };

        // GET response: full body (fresh copy for each waiter).
        var getResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(blobBytes)),
        };
        getResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var methodRecorder = new MethodRecordingFactory(headResp, getResp);
        var ctl = BuildOciController(BuildResolver(methodRecorder));

        // HEAD: should be handled via upstream HEAD, no GetAsync on the blob store.
        int getsBefore = _cacheBlobs.GetAsyncCallCount;
        var headResult = await ctl.Head($"library/ubuntu/blobs/{digest}", default);
        Assert.IsType<OkResult>(headResult);
        Assert.Equal(HttpMethod.Head, methodRecorder.LastMethod);
        Assert.Equal(getsBefore, _cacheBlobs.GetAsyncCallCount);

        // GET: full upstream fetch, body served.
        var getResult = await ctl.Get($"library/ubuntu/blobs/{digest}", default);
        Assert.IsType<FileStreamResult>(getResult);
        Assert.Equal(HttpMethod.Get, methodRecorder.LastMethod);

        // Two upstream calls: one HEAD, one GET.
        Assert.Equal(2, methodRecorder.RequestCount);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static byte[] RandomBytes(int n = 128)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    // ── OCI controller builder ─────────────────────────────────────────────────

    private OciController BuildOciController(OciUpstreamResolver upstream)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("head-test-org.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "head-test-org");

        var services = new ServiceCollection();
        services.AddLogging();
        http.RequestServices = services.BuildServiceProvider();

        var svc = new OciControllerServices(
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            BlobStore: new TieredBlobStorage(_cacheBlobs, _registryBlobs),
            Db: _db,
            Upstream: upstream,
            Uploads: new OciUploadService(new OciUploadService.Dependencies(
                _db,
                new TieredBlobStorage(_cacheBlobs, _registryBlobs),
                _orgs,
                new UnlimitedDisk(),
                new StagingOptions(Path.GetTempPath(), FloorBytes: 0),
                new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build(),
                NullLogger<OciUploadService>.Instance,
                TimeProvider.System)));

        return new OciController(svc, NullLogger<OciController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private OciUpstreamResolver BuildResolver(IHttpClientFactory http, OciOptions? opts = null)
    {
        var options = Options.Create(opts ?? new OciOptions
        {
            ManifestTagTtl = TimeSpan.FromMinutes(5),
        });

        var authSvc = new OciUpstreamAuthService(
            http, options, new DisabledAirGap(),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, _registryBlobs);
        return new OciUpstreamResolver(
            http, authSvc, options, blobs, _db,
            new DisabledAirGap(), NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System);
    }

    // ── Test stubs ────────────────────────────────────────────────────────────

    /// <summary>
    /// Wraps an inner blob store and counts calls to GetAsync. Used to assert that HEAD
    /// handlers do not open blob streams.
    /// </summary>
    private sealed class GetAsyncCountingBlobStore : IBlobStore
    {
        public InMemoryBlobStore Inner { get; }
        public int GetAsyncCallCount { get; private set; }

        public GetAsyncCountingBlobStore(InMemoryBlobStore inner) => Inner = inner;

        public Task PutAsync(string key, Stream data, CancellationToken ct = default)
            => Inner.PutAsync(key, data, ct);

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
        {
            GetAsyncCallCount++;
            return Inner.GetAsync(key, ct);
        }

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
            => Inner.ExistsAsync(key, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default)
            => Inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
            => Inner.GetTotalSizeAsync(ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => Inner.GetRangeAsync(key, from, to, ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => Inner.ListAsync(prefix, ct);
    }

    /// <summary>
    /// Returns pre-canned responses in order, recording the HTTP method of each call.
    /// </summary>
    private sealed class MethodRecordingFactory : IHttpClientFactory
    {
        private readonly Queue<HttpResponseMessage> _responses;

        public MethodRecordingFactory(params HttpResponseMessage[] responses)
            => _responses = new Queue<HttpResponseMessage>(responses);

        public int RequestCount { get; private set; }
        public HttpMethod? LastMethod { get; private set; }

        public HttpClient CreateClient(string name) => new(new RecordingHandler(this));

        private sealed class RecordingHandler : HttpMessageHandler
        {
            private readonly MethodRecordingFactory _recorder;

            public RecordingHandler(MethodRecordingFactory recorder) => _recorder = recorder;

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                _recorder.RequestCount++;
                _recorder.LastMethod = request.Method;

                var resp = _recorder._responses.Count > 0
                    ? _recorder._responses.Dequeue()
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
                return Task.FromResult(resp);
            }
        }
    }

    /// <summary>Returns a fresh response with the given status on every call (safe for retry loops).</summary>
    private sealed class StatusFactory : IHttpClientFactory
    {
        private readonly HttpStatusCode _status;

        public StatusFactory(HttpStatusCode status) => _status = status;

        public HttpClient CreateClient(string name) => new(new Handler(_status));

        private sealed class Handler : HttpMessageHandler
        {
            private readonly HttpStatusCode _status;
            public Handler(HttpStatusCode status) => _status = status;

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
                => Task.FromResult(new HttpResponseMessage(_status));
        }
    }

    private sealed class NeverCallFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new NeverCallHandler());

        private sealed class NeverCallHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
                => throw new InvalidOperationException(
                    $"HTTP call must not be made in this test (URL={request.RequestUri})");
        }
    }

    private sealed class DisabledAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}

/// <summary>Unlimited disk stub — floor check always passes.</summary>
file sealed class UnlimitedDisk : IStagingDiskInfo
{
    public long GetAvailableBytes() => long.MaxValue;
    public long GetTotalBytes() => long.MaxValue;
    public long GetStagingDirectoryUsedBytes() => 0;
}
