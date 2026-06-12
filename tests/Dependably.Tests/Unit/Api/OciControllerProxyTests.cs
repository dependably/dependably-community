using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Proxy-path coverage for <see cref="OciController"/>.
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
        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db);
        _audit = new AuditRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "oci-proxy-org");
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
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private async Task<string> SeedManifestAsync(
        byte[] manifestBytes,
        string? tag = null,
        string origin = "proxy")
    {
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);

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
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);

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
        => BuildControllerForOrg(_orgId, upstream);

    private OciController BuildControllerForOrgWithAuth(string orgId, string bearerToken, OciUpstreamResolver upstream)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("oci-proxy-org.example.test");
        http.Request.Headers.Authorization = $"Bearer {bearerToken}";
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "oci-proxy-org");

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
            Uploads: new OciUploadService(
                _db,
                new TieredBlobStorage(_cacheBlobs, _registryBlobs),
                new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<OciUploadService>.Instance));

        return new OciController(svc, NullLogger<OciController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private OciController BuildControllerForOrg(string orgId, OciUpstreamResolver upstream)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("oci-proxy-org.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "oci-proxy-org");

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
            Uploads: new OciUploadService(
                _db,
                new TieredBlobStorage(_cacheBlobs, _registryBlobs),
                new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<OciUploadService>.Instance));

        return new OciController(svc, NullLogger<OciController>.Instance)
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
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        _ = await SeedManifestAsync(manifestBytes, tag: "latest");

        var ctl = BuildController(BuildResolver());
        var result = await ctl.Get($"library/ubuntu/manifests/latest", default);
        _ = Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task GetManifest_DigestRef_LocalCacheHit_ReturnsXCacheHit()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"digest\":true}");
        string digest = await SeedManifestAsync(manifestBytes);

        var ctl = BuildController(BuildResolver());
        var result = await ctl.Get($"library/ubuntu/manifests/{digest}", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    // ── GET manifest — local miss → upstream ─────────────────────────────────

    [Fact]
    public async Task GetManifest_LocalMiss_ProxyFetches_ReturnsXCacheMiss()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"proxied\":true}");
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;

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
        byte[] blobBytes = RandomBytes(256);
        string digest = await SeedBlobAsync(blobBytes);

        var ctl = BuildController(BuildResolver());
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task GetBlob_ProxyOrigin_ServedFromCacheTier()
    {
        byte[] blobBytes = RandomBytes(128);
        string digest = await SeedBlobAsync(blobBytes, origin: "proxy");

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
        byte[] blobBytes = RandomBytes(256);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;

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
        string sha256 = Sha256Hex(RandomBytes());
        string digest = "sha256:" + sha256;

        var ctl = BuildController(BuildResolverNoUpstream());
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, obj.StatusCode);
    }

    // ── ListTags ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ListTags_LocalHasTags_ReturnsLocalTags()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        await SeedManifestAsync(manifestBytes, tag: "stable");

        // Use no-upstream resolver: local tags are returned without an upstream call.
        var ctl = BuildController(BuildResolverNoUpstream());

        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var json = Assert.IsType<JsonResult>(result);
        object obj = json.Value!;
        var tagsProperty = obj.GetType().GetProperty("tags");
        Assert.NotNull(tagsProperty);
        var tags = tagsProperty!.GetValue(obj) as IEnumerable<string>;
        Assert.Contains("stable", tags!);
    }

    [Fact]
    public async Task ListTags_LocalEmpty_FallsBackToUpstream()
    {
        string[] tags = new[] { "latest", "22.04" };
        string json = JsonSerializer.Serialize(new { name = "library/ubuntu", tags });

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

        var http = new SingleResponseFactory(upstreamResp);
        var ctl = BuildController(BuildResolver(http));

        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var jsonResult = Assert.IsType<JsonResult>(result);
        object obj = jsonResult.Value!;
        var tagsProperty = obj.GetType().GetProperty("tags");
        Assert.NotNull(tagsProperty);
        var returnedTags = tagsProperty!.GetValue(obj) as IEnumerable<string>;
        Assert.Contains("latest", returnedTags!);
    }

    [Fact]
    public async Task ListTags_LocalAndUpstream_ReturnsMergedSortedDeduped()
    {
        // Seed one local tag.
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        await SeedManifestAsync(manifestBytes, tag: "local-only");

        // Upstream returns two tags; "local-only" overlaps with the local tag.
        string[] upstreamTags = ["local-only", "upstream-only"];
        string json = JsonSerializer.Serialize(new { name = "library/ubuntu", tags = upstreamTags });
        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        var http = new SingleResponseFactory(upstreamResp);
        var ctl = BuildController(BuildResolver(http));

        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var jsonResult = Assert.IsType<JsonResult>(result);
        object obj = jsonResult.Value!;
        var tagsProperty = obj.GetType().GetProperty("tags");
        Assert.NotNull(tagsProperty);
        var returnedTags = (tagsProperty!.GetValue(obj) as IEnumerable<string>)!.ToList();

        // Both tags present, no duplicate, sorted lexically.
        Assert.Contains("local-only", returnedTags);
        Assert.Contains("upstream-only", returnedTags);
        Assert.Equal(returnedTags.Distinct().OrderBy(t => t, StringComparer.Ordinal).ToList(), returnedTags);
        // Exactly two entries (deduped).
        Assert.Equal(2, returnedTags.Count);
    }

    [Fact]
    public async Task ListTags_NZero_ReturnsEmptyListWithoutLinkHeader()
    {
        // Seed a tag so there are results to potentially return.
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        await SeedManifestAsync(manifestBytes, tag: "exists");

        var ctl = BuildController(BuildResolverNoUpstream());
        // Simulate ?n=0
        ctl.ControllerContext.HttpContext.Request.QueryString = new QueryString("?n=0");

        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var json = Assert.IsType<JsonResult>(result);
        object obj = json.Value!;
        var tagsProperty = obj.GetType().GetProperty("tags");
        Assert.NotNull(tagsProperty);
        var tags = (tagsProperty!.GetValue(obj) as IEnumerable<string>)!.ToList();

        // OCI spec: n=0 returns an empty list.
        Assert.Empty(tags);
        // No Link header.
        Assert.False(ctl.Response.Headers.ContainsKey("Link"));
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
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        string digest = await SeedManifestAsync(manifestBytes, tag: "latest");

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
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class EnabledAirGap : IAirGapMode
    {
        public bool IsEnabled => true;
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    // ── Shared-digest refcount: physical blob survives single-org delete ──────

    /// <summary>
    /// Two orgs reference the same content-addressed blob_key in <c>oci_blobs</c>.
    /// When org A deletes its manifest, the controller must check that org B still holds a
    /// row for the same blob_key and therefore must NOT delete the physical blob from the
    /// Registry tier.  Org B's subsequent pull must succeed.
    /// </summary>
    [Fact]
    public async Task DeleteManifest_SharedDigest_PhysicalBlobSurvivesWhenOtherOrgRefExists()
    {
        // ── Seed ──────────────────────────────────────────────────────────────
        string orgBId = await OrgSeeder.InsertAsync(_db, "oci-shared-org-b");

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"shared\":true}");
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);
        const string repo = "library/shared-img";

        // Write the physical blob into the registry tier.
        await _registryBlobs.PutAsync(blobKey, new MemoryStream(manifestBytes), default);

        // Insert oci_blobs rows for BOTH orgs referencing the same blob_key.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size, @blobKey, 'uploaded')
            """,
            new { digest, orgId = _orgId, size = (long)manifestBytes.Length, blobKey });
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size, @blobKey, 'uploaded')
            """,
            new { digest, orgId = orgBId, size = (long)manifestBytes.Length, blobKey });

        // Insert a tag for org A so the manifest is findable.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
            VALUES (@orgId, @repo, 'v1', @digest, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { orgId = _orgId, repo, digest });

        // Create a yank token so AuthorizeYankAsync passes.
        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "yank-shared", """["yank:oci","read:artifact"]""", expiresAt: null);

        // ── Delete as org A ───────────────────────────────────────────────────
        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolverNoUpstream());
        var result = await ctl.Delete($"{repo}/manifests/{digest}", default);

        var objResult = Assert.IsAssignableFrom<StatusCodeResult>(result);
        Assert.Equal(StatusCodes.Status204NoContent, objResult.StatusCode);

        // ── Physical blob must still exist (org B still references it) ────────
        Assert.True(await _registryBlobs.ExistsAsync(blobKey),
            "Physical blob must not be deleted while another org still references it.");

        // ── Org A's DB row must be gone ───────────────────────────────────────
        int orgACount = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId = _orgId });
        Assert.Equal(0, orgACount);

        // ── Org B's DB row must still exist ───────────────────────────────────
        int orgBCount = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId = orgBId });
        Assert.Equal(1, orgBCount);
    }

    [Fact]
    public async Task DeleteManifest_LastRefHolder_PhysicalBlobIsRemoved()
    {
        // Only one org references the blob — physical delete must proceed.
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"sole\":true}");
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);
        const string repo = "library/sole-img";

        await _registryBlobs.PutAsync(blobKey, new MemoryStream(manifestBytes), default);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size, @blobKey, 'uploaded')
            """,
            new { digest, orgId = _orgId, size = (long)manifestBytes.Length, blobKey });
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
            VALUES (@orgId, @repo, 'sole', @digest, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { orgId = _orgId, repo, digest });

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "yank-sole", """["yank:oci","read:artifact"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolverNoUpstream());
        var result = await ctl.Delete($"{repo}/manifests/{digest}", default);

        Assert.IsAssignableFrom<StatusCodeResult>(result);

        // Only org — blob must have been physically deleted.
        Assert.False(await _registryBlobs.ExistsAsync(blobKey),
            "Physical blob must be deleted when no org rows remain.");
    }

    // ── Air-gap: tags/list degrades to local-only ──────────────────────────────

    /// <summary>
    /// In air-gap mode <see cref="OciUpstreamResolver.FetchTagsAsync"/> throws
    /// <see cref="AirGappedException"/>. The controller must catch it and return local tags
    /// rather than propagating a 503.
    /// </summary>
    [Fact]
    public async Task ListTags_AirGapMode_ReturnsLocalTagsOnly()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        await SeedManifestAsync(manifestBytes, tag: "air-local");

        var options = Options.Create(new OciOptions
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

        // Air-gap mode: any call to the upstream HTTP client would fail, but the controller
        // must not reach it — AirGappedException is thrown before any network attempt and
        // must be caught so the local listing is still returned.
        var airGap = new EnabledAirGap();
        var authSvc = new OciUpstreamAuthService(
            new NeverCallFactory(), options, airGap, NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, _registryBlobs);
        var resolver = new OciUpstreamResolver(
            new NeverCallFactory(), authSvc, options, blobs, _db,
            airGap, NullLogger<OciUpstreamResolver>.Instance);

        var ctl = BuildController(resolver);
        var result = await ctl.Get("library/ubuntu/tags/list", default);

        // Must be 200 with the local tag — not a 503.
        var json = Assert.IsType<JsonResult>(result);
        object obj = json.Value!;
        var tagsProperty = obj.GetType().GetProperty("tags");
        Assert.NotNull(tagsProperty);
        var tags = tagsProperty!.GetValue(obj) as IEnumerable<string>;
        Assert.Contains("air-local", tags!);
    }
}
