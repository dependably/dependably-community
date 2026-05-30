using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Proxy-path coverage for <see cref="OciController"/> (#103).
///
/// Coverage targets:
///  - GET manifest: local cache HIT → X-Cache: HIT, no upstream call
///  - GET manifest: local miss → upstream proxy → X-Cache: MISS, DB row written
///  - GET manifest: no upstream configured → 404
///  - GET blob: local cache HIT → X-Cache: HIT
///  - GET blob: local miss → upstream proxy → bytes served
///  - GET blob: no upstream → 404
///  - ListTags: local has tags → returns from DB
///  - ListTags: local empty → falls back to upstream
///  - ListTags: neither has tags → 404
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciControllerProxyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _cacheBlobs = new();
    private readonly InMemoryBlobStore _registryBlobs = new();

    private string _orgId = null!;
    private string _userId = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private OrgRepository _orgs = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgs   = new OrgRepository(_db);
        _tokens = new TokenRepository(_db);
        _audit  = new AuditRepository(_db);

        _orgId  = await OrgSeeder.InsertAsync(_db, "oci-proxy-org");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "dev@oci.test", "admin");

        // Enable anonymous pull for all tests.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId = _orgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static byte[] RandomBytes(int n = 128)
    {
        var b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private async Task<string> SeedManifestAsync(
        byte[] manifestBytes,
        string? tag = null,
        string origin = "proxy")
    {
        var sha256 = Sha256Hex(manifestBytes);
        var digest = "sha256:" + sha256;
        var blobKey = BlobKeys.OciBlob("sha256", sha256);

        var targetStore = origin == "proxy" ? _cacheBlobs : _registryBlobs;
        await targetStore.PutAsync(blobKey, new MemoryStream(manifestBytes), default);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size, @blobKey, @origin)
            ON CONFLICT (digest, org_id) DO NOTHING
            """,
            new { digest, orgId = _orgId, size = (long)manifestBytes.Length, blobKey, origin });

        if (tag is not null)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
                VALUES (@orgId, 'library/ubuntu', @tag, @digest,
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                ON CONFLICT (org_id, repository, tag) DO UPDATE SET
                    digest = excluded.digest, updated_at = excluded.updated_at,
                    last_revalidated = excluded.last_revalidated
                """,
                new { orgId = _orgId, tag, digest });
        }

        return digest;
    }

    private async Task<string> SeedBlobAsync(byte[] blobBytes, string origin = "proxy")
    {
        var sha256 = Sha256Hex(blobBytes);
        var digest = "sha256:" + sha256;
        var blobKey = BlobKeys.OciBlob("sha256", sha256);

        var targetStore = origin == "proxy" ? _cacheBlobs : _registryBlobs;
        await targetStore.PutAsync(blobKey, new MemoryStream(blobBytes), default);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/octet-stream', @size, @blobKey, @origin)
            ON CONFLICT (digest, org_id) DO NOTHING
            """,
            new { digest, orgId = _orgId, size = (long)blobBytes.Length, blobKey, origin });

        return digest;
    }

    private OciController BuildController(OciUpstreamResolver upstream)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("oci-proxy-org.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "oci-proxy-org");

        var services = new ServiceCollection();
        services.AddLogging();
        http.RequestServices = services.BuildServiceProvider();

        var svc = new OciControllerServices(
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            BlobStore: new TieredBlobStorage(_cacheBlobs, _registryBlobs),
            Db: _db,
            Upstream: upstream);

        return new OciController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private OciUpstreamResolver BuildResolver(
        IHttpClientFactory? http = null,
        OciOptions? opts = null)
    {
        var options = Options.Create(opts ?? new OciOptions
        {
            ManifestTagTtl = TimeSpan.FromMinutes(5),
            Upstreams =
            [
                new OciUpstreamRegistryOptions
                {
                    Name     = "dockerhub",
                    Host     = "registry-1.docker.io",
                    AuthType = OciAuthType.Anonymous,
                    Prefixes = [""],
                }
            ],
        });

        http ??= new NeverCallFactory();
        var authSvc = new OciUpstreamAuthService(
            http, options, new DisabledAirGap(), NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, _registryBlobs);
        return new OciUpstreamResolver(
            http, authSvc, options, blobs, _db,
            new DisabledAirGap(), NullLogger<OciUpstreamResolver>.Instance);
    }

    private OciUpstreamResolver BuildResolverNoUpstream()
        => BuildResolver(opts: new OciOptions { Upstreams = [] });

    // ── GET manifest — local cache HIT ────────────────────────────────────────

    [Fact]
    public async Task GetManifest_LocalCacheHit_ReturnsXCacheHit()
    {
        var manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        var digest = await SeedManifestAsync(manifestBytes, tag: "latest");

        var ctl = BuildController(BuildResolver());
        var result = await ctl.Get($"library/ubuntu/manifests/latest", default);

        var fileResult = Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task GetManifest_DigestRef_LocalCacheHit_ReturnsXCacheHit()
    {
        var manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"digest\":true}");
        var digest = await SeedManifestAsync(manifestBytes);

        var ctl = BuildController(BuildResolver());
        var result = await ctl.Get($"library/ubuntu/manifests/{digest}", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    // ── GET manifest — local miss → upstream ─────────────────────────────────

    [Fact]
    public async Task GetManifest_LocalMiss_ProxyFetches_ReturnsXCacheMiss()
    {
        var manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"proxied\":true}");
        var sha256 = Sha256Hex(manifestBytes);
        var digest = "sha256:" + sha256;

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(manifestBytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
                    "application/vnd.oci.image.manifest.v1+json") }
            },
        };
        upstreamResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", digest);

        var http = new SingleResponseFactory(upstreamResp);
        var ctl = BuildController(BuildResolver(http));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("MISS", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(digest, ctl.Response.Headers["Docker-Content-Digest"].ToString());

        // DB row should be written.
        await using var conn = await _db.OpenAsync();
        var row = await conn.QuerySingleOrDefaultAsync<dynamic>(
            "SELECT digest FROM oci_blobs WHERE org_id = @orgId AND origin = 'proxy' LIMIT 1",
            new { orgId = _orgId });
        Assert.NotNull(row);
    }

    // ── GET manifest — no upstream ────────────────────────────────────────────

    [Fact]
    public async Task GetManifest_NoUpstream_Returns404()
    {
        var ctl = BuildController(BuildResolverNoUpstream());
        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, obj.StatusCode);
    }

    // ── GET blob — local cache HIT ────────────────────────────────────────────

    [Fact]
    public async Task GetBlob_LocalCacheHit_ReturnsXCacheHit()
    {
        var blobBytes = RandomBytes(256);
        var digest = await SeedBlobAsync(blobBytes);

        var ctl = BuildController(BuildResolver());
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task GetBlob_ProxyOrigin_ServedFromCacheTier()
    {
        var blobBytes = RandomBytes(128);
        var digest = await SeedBlobAsync(blobBytes, origin: "proxy");

        var ctl = BuildController(BuildResolver());
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var fsr = Assert.IsType<FileStreamResult>(result);
        using var ms = new MemoryStream();
        await fsr.FileStream.CopyToAsync(ms);
        Assert.Equal(blobBytes, ms.ToArray());
    }

    // ── GET blob — local miss → upstream ──────────────────────────────────────

    [Fact]
    public async Task GetBlob_LocalMiss_ProxyFetches_ServesBytes()
    {
        var blobBytes = RandomBytes(256);
        var sha256 = Sha256Hex(blobBytes);
        var digest = "sha256:" + sha256;

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(blobBytes)),
        };
        upstreamResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var http = new SingleResponseFactory(upstreamResp);
        var ctl = BuildController(BuildResolver(http));

        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("MISS", ctl.Response.Headers["X-Cache"].ToString());
    }

    // ── GET blob — no upstream ────────────────────────────────────────────────

    [Fact]
    public async Task GetBlob_NoUpstream_Returns404()
    {
        var sha256 = Sha256Hex(RandomBytes());
        var digest = "sha256:" + sha256;

        var ctl = BuildController(BuildResolverNoUpstream());
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, obj.StatusCode);
    }

    // ── ListTags ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ListTags_LocalHasTags_ReturnsFromDb()
    {
        var manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        await SeedManifestAsync(manifestBytes, tag: "stable");

        var ctl = BuildController(BuildResolver()); // NeverCallFactory — no HTTP

        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var json = Assert.IsType<JsonResult>(result);
        var obj = json.Value!;
        var tagsProperty = obj.GetType().GetProperty("tags");
        Assert.NotNull(tagsProperty);
        var tags = tagsProperty!.GetValue(obj) as IEnumerable<string>;
        Assert.Contains("stable", tags!);
    }

    [Fact]
    public async Task ListTags_LocalEmpty_FallsBackToUpstream()
    {
        var tags = new[] { "latest", "22.04" };
        var json = JsonSerializer.Serialize(new { name = "library/ubuntu", tags });

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

        var http = new SingleResponseFactory(upstreamResp);
        var ctl = BuildController(BuildResolver(http));

        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var jsonResult = Assert.IsType<JsonResult>(result);
        var obj = jsonResult.Value!;
        var tagsProperty = obj.GetType().GetProperty("tags");
        Assert.NotNull(tagsProperty);
        var returnedTags = tagsProperty!.GetValue(obj) as IEnumerable<string>;
        Assert.Contains("latest", returnedTags!);
    }

    [Fact]
    public async Task ListTags_NeitherLocalNorUpstream_Returns404()
    {
        // Upstream returns 404.
        var upstreamResp = new HttpResponseMessage(HttpStatusCode.NotFound);
        var http = new SingleResponseFactory(upstreamResp);
        var ctl = BuildController(BuildResolver(http));

        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, obj.StatusCode);
    }

    // ── HEAD requests ─────────────────────────────────────────────────────────

    [Fact]
    public async Task HeadManifest_LocalCacheHit_Returns200WithHeaders()
    {
        var manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        var digest = await SeedManifestAsync(manifestBytes, tag: "latest");

        var ctl = BuildController(BuildResolver());
        var result = await ctl.Head("library/ubuntu/manifests/latest", default);

        // HEAD returns Ok() (no body), with headers set on Response.
        Assert.IsType<OkResult>(result);
        Assert.Equal(digest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    private sealed class SingleResponseFactory : IHttpClientFactory
    {
        private readonly HttpResponseMessage _response;
        public SingleResponseFactory(HttpResponseMessage response) => _response = response;
        public HttpClient CreateClient(string name) => new(new FixedHandler(_response));

        private sealed class FixedHandler : HttpMessageHandler
        {
            private readonly HttpResponseMessage _resp;
            public FixedHandler(HttpResponseMessage resp) => _resp = resp;
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
                => Task.FromResult(_resp);
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
    }
}
