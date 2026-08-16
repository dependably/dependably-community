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
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly OciBlobKeyLock _blobKeyLock = new();

    private string _orgId = null!;
    private string _emptyOrgId = null!; // org with no OCI upstreams — for "no upstream" tests
    private string _userId = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private OrgRepository _orgs = null!;

    public OciControllerProxyTests()
    {
        _cacheArtifacts = new CacheArtifactRepository(_db);
        _cacheRecorder = new CacheAccessRecorder(
            _cacheArtifacts, new TenantArtifactAccessRepository(_db),
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
    }

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "oci-proxy-org");
        _emptyOrgId = await OrgSeeder.InsertAsync(_db, "oci-proxy-no-upstream-org");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "dev@oci.test", "admin");

        await using var conn = await _db.OpenAsync();

        // Enable anonymous pull for both orgs.
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId = _orgId });
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId = _emptyOrgId });

        // Seed a catch-all OCI upstream for _orgId so proxy tests can resolve library/ubuntu.
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

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static byte[] RandomBytes(int n = 128)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    // lastRevalidated: when supplied, stamps oci_tags.last_revalidated at that exact instant
    // instead of the wall clock, so a test pairing this with a FakeTimeProvider controls tag
    // freshness deterministically rather than racing strftime('now').
    private async Task<string> SeedManifestAsync(
        byte[] manifestBytes,
        string? tag = null,
        string origin = "proxy",
        DateTimeOffset? lastRevalidated = null,
        bool nullRevalidated = false)
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
            // A push writes last_revalidated = NULL (OciUploadService); a proxy fetch always
            // stamps it. nullRevalidated reproduces the pushed-tag shape.
            string? stamp = lastRevalidated?.ToUtcIso();
            string sql = nullRevalidated
                ? """
                  INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
                  VALUES (@orgId, 'library/ubuntu', @tag, @digest,
                          strftime('%Y-%m-%dT%H:%M:%SZ','now'), NULL)
                  ON CONFLICT (org_id, repository, tag) DO UPDATE SET
                      digest = excluded.digest, updated_at = excluded.updated_at,
                      last_revalidated = NULL
                  """
                : """
                  INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
                  VALUES (@orgId, 'library/ubuntu', @tag, @digest,
                          COALESCE(@stamp, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                          COALESCE(@stamp, strftime('%Y-%m-%dT%H:%M:%SZ','now')))
                  ON CONFLICT (org_id, repository, tag) DO UPDATE SET
                      digest = excluded.digest, updated_at = excluded.updated_at,
                      last_revalidated = excluded.last_revalidated
                  """;
            await conn.ExecuteAsync(sql, new { orgId = _orgId, tag, digest, stamp });
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

    private OciUploadService BuildUploads()
    {
        var tiered = new TieredBlobStorage(_cacheBlobs, _registryBlobs);
        return new OciUploadService(new OciUploadService.Dependencies(
            _db,
            tiered,
            _orgs,
            new UnlimitedDisk(),
            new StagingOptions(Path.GetTempPath(), FloorBytes: 0),
            new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build(),
            new OciImageLicenseRecorder(_db, tiered, TimeProvider.System, NullLogger<OciImageLicenseRecorder>.Instance,
                new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db))),
            _blobKeyLock,
            NullLogger<OciUploadService>.Instance,
            TimeProvider.System));
    }

    private BlockGateService BuildBlockGate()
    {
        var normalizer = new LicenseNormalizer(_db, NullLogger<LicenseNormalizer>.Instance);
        return new BlockGateService(
            new VulnerabilityRepository(_db, TimeProvider.System),
            _audit,
            new QuarantineRepository(_db, TimeProvider.System),
            new Dependably.Infrastructure.Alerts.AlertService(
                new Dependably.Infrastructure.Alerts.AlertRepository(_db, TimeProvider.System),
                new Dependably.Infrastructure.Alerts.NoOpAlertNotifier(),
                NullLogger<Dependably.Infrastructure.Alerts.AlertService>.Instance),
            new InstallScriptAllowlistService(
                _db,
                new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()),
                TimeProvider.System),
            new LicenseRepository(_db, TimeProvider.System, normalizer),
            new StubPerOrgTrustAnchorStore(),
            NullLogger<BlockGateService>.Instance,
            TimeProvider.System);
    }

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
            Uploads: BuildUploads(),
            OrphanBlobs: new OciOrphanBlobDeleter(
                _db, new TieredBlobStorage(_cacheBlobs, _registryBlobs), _blobKeyLock),
            BlockGate: BuildBlockGate(),
            EdgeGuard: Dependably.Tests.Infrastructure.TestEdgeMode.DisabledPublishGuard(),
            Packages: new PackageRepository(_db),
            TenantArtifactAccess: new TenantArtifactAccessRepository(_db),
            DenialAudit: new AuthDenialAuditCoalescer(TimeProvider.System));

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
            Uploads: BuildUploads(),
            OrphanBlobs: new OciOrphanBlobDeleter(
                _db, new TieredBlobStorage(_cacheBlobs, _registryBlobs), _blobKeyLock),
            BlockGate: BuildBlockGate(),
            EdgeGuard: Dependably.Tests.Infrastructure.TestEdgeMode.DisabledPublishGuard(),
            Packages: new PackageRepository(_db),
            TenantArtifactAccess: new TenantArtifactAccessRepository(_db),
            DenialAudit: new AuthDenialAuditCoalescer(TimeProvider.System));

        return new OciController(svc, NullLogger<OciController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private OciUpstreamResolver BuildResolver(
        IHttpClientFactory? http = null,
        OciOptions? opts = null,
        TimeProvider? time = null)
    {
        time ??= TimeProvider.System;
        var options = Options.Create(opts ?? new OciOptions
        {
            ManifestTagTtl = TimeSpan.FromMinutes(5),
        });

        http ??= new NeverCallFactory();
        var authSvc = new OciUpstreamAuthService(
            http, options, new DisabledAirGap(), NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, _registryBlobs);
        var recorder = new OciImageLicenseRecorder(_db, blobs, time, NullLogger<OciImageLicenseRecorder>.Instance,
                new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)));
        return new OciUpstreamResolver(
            http, authSvc, options, blobs, _db,
            new DisabledAirGap(), recorder, _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, time, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());
    }

    // Returns a controller that uses _emptyOrgId (no OCI upstreams in the DB) so that
    // upstream-routed operations return null (no upstream configured).
    private OciController BuildControllerNoUpstream()
        => BuildControllerForOrg(_emptyOrgId, BuildResolver());

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
        var ctl = BuildControllerNoUpstream();
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

        var ctl = BuildControllerNoUpstream();
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

        // Local tags are returned first, before any upstream call is attempted.
        // NeverCallFactory ensures no upstream HTTP call is issued.
        var ctl = BuildController(BuildResolver());

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

        // n=0 must return an empty list regardless of local tags; no upstream call needed.
        var ctl = BuildController(BuildResolver());
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

    // ── Pull authorization: capability gate ────────────────────────────────────
    //
    // AuthorizePullAsync is the sole gate for manifest, blob, and tag-list reads. A
    // presented token must carry pull:oci or read:artifact; a token active in the org
    // but scoped to something unrelated (e.g. publish:npm) must be forbidden rather
    // than silently treated the same as an unauthenticated request.

    [Fact]
    public async Task GetManifest_TokenWithUnrelatedCapability_ReturnsForbidden()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gated\":true}");
        _ = await SeedManifestAsync(manifestBytes, tag: "latest");

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "npm-only", """["publish:npm"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    [Fact]
    public async Task GetManifest_TokenWithReadArtifact_Succeeds()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"read-artifact\":true}");
        _ = await SeedManifestAsync(manifestBytes, tag: "latest");

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "reader", """["read:artifact"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task GetBlob_TokenWithPullOciCapability_Succeeds()
    {
        byte[] blobBytes = RandomBytes(64);
        string digest = await SeedBlobAsync(blobBytes);

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "pull-oci-only", """["pull:oci"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task ListTags_TokenWithUnrelatedCapability_ReturnsForbidden()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"tags-gated\":true}");
        _ = await SeedManifestAsync(manifestBytes, tag: "v1");

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "npm-only-tags", """["publish:npm"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    /// <summary>
    /// Mixed partial-failure coverage: the same org grants two tokens, one properly scoped
    /// for OCI reads and one scoped to an unrelated ecosystem. Both are exercised across all
    /// three read surfaces (manifest, blob, tags) in a single test — the capable token must
    /// succeed on every surface and the incapable token must be forbidden on every surface,
    /// with neither outcome masking the other.
    /// </summary>
    [Fact]
    public async Task PullAuthorization_MixedCapabilityTokens_CapableSucceedsIncapableForbiddenAcrossSurfaces()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"mixed\":true}");
        _ = await SeedManifestAsync(manifestBytes, tag: "mixed");
        byte[] blobBytes = RandomBytes(32);
        string blobDigest = await SeedBlobAsync(blobBytes);

        var (capableToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "mixed-capable", """["read:artifact"]""", expiresAt: null);
        var (incapableToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "mixed-incapable", """["publish:pypi"]""", expiresAt: null);

        // Capable token: every surface succeeds.
        var capableCtl = BuildControllerForOrgWithAuth(_orgId, capableToken, BuildResolver());
        Assert.IsType<FileStreamResult>(
            await capableCtl.Get("library/ubuntu/manifests/mixed", default));
        var capableBlobCtl = BuildControllerForOrgWithAuth(_orgId, capableToken, BuildResolver());
        Assert.IsType<FileStreamResult>(
            await capableBlobCtl.Get($"library/ubuntu/blobs/{blobDigest}", default));
        var capableTagsCtl = BuildControllerForOrgWithAuth(_orgId, capableToken, BuildResolver());
        Assert.IsType<JsonResult>(
            await capableTagsCtl.Get("library/ubuntu/tags/list", default));

        // Incapable token: every surface is forbidden, not silently allowed.
        var incapableCtl = BuildControllerForOrgWithAuth(_orgId, incapableToken, BuildResolver());
        var manifestResult = Assert.IsType<ObjectResult>(
            await incapableCtl.Get("library/ubuntu/manifests/mixed", default));
        Assert.Equal(StatusCodes.Status403Forbidden, manifestResult.StatusCode);

        var incapableBlobCtl = BuildControllerForOrgWithAuth(_orgId, incapableToken, BuildResolver());
        var blobResult = Assert.IsType<ObjectResult>(
            await incapableBlobCtl.Get($"library/ubuntu/blobs/{blobDigest}", default));
        Assert.Equal(StatusCodes.Status403Forbidden, blobResult.StatusCode);

        var incapableTagsCtl = BuildControllerForOrgWithAuth(_orgId, incapableToken, BuildResolver());
        var tagsResult = Assert.IsType<ObjectResult>(
            await incapableTagsCtl.Get("library/ubuntu/tags/list", default));
        Assert.Equal(StatusCodes.Status403Forbidden, tagsResult.StatusCode);
    }

    // ── Push-probe authorization: publish:oci's narrow read exception ─────────
    //
    // The OCI push protocol itself reads through AuthorizePullAsync: docker/BuildKit HEAD a
    // blob's digest before uploading it (skip-if-present), and HEAD or GET a manifest
    // reference to resolve a tag or read back what was just pushed. dependably ships
    // publish-only OCI tokens (the web token modal's "push" preset mints exactly
    // publish:*) with no read capability, so AuthorizePullAsync admits publish:oci (and the
    // publish:* wildcard that grants it) on exactly those two probes — manifest GET/HEAD and
    // blob HEAD — and nowhere else: blob GET (the actual layer bytes), tags list, and the
    // referrers list stay gated behind pull:oci/read:artifact, so a publish-only token cannot
    // use the exception as a general pull/enumerate licence.

    [Fact]
    public async Task HeadBlob_PublishOciOnlyToken_Succeeds()
    {
        byte[] blobBytes = RandomBytes(64);
        string digest = await SeedBlobAsync(blobBytes);

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "publish-oci-only", """["publish:oci"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Head($"library/ubuntu/blobs/{digest}", default);

        Assert.IsType<OkResult>(result);
        Assert.Equal(digest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    [Fact]
    public async Task HeadBlob_PublishWildcardToken_Succeeds()
    {
        byte[] blobBytes = RandomBytes(64);
        string digest = await SeedBlobAsync(blobBytes);

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "publish-wildcard", """["publish:*"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Head($"library/ubuntu/blobs/{digest}", default);

        Assert.IsType<OkResult>(result);
        Assert.Equal(digest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    [Fact]
    public async Task GetBlob_PublishOciOnlyToken_ReturnsForbidden()
    {
        // A publish-only token may probe existence (HEAD, above) but must not gain a general
        // licence to download the actual layer bytes (GET) — push never reads them back.
        byte[] blobBytes = RandomBytes(64);
        string digest = await SeedBlobAsync(blobBytes);

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "publish-oci-only-getblob", """["publish:oci"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    [Fact]
    public async Task HeadManifest_PublishOciOnlyToken_Succeeds()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"push-probe-head\":true}");
        string digest = await SeedManifestAsync(manifestBytes, tag: "push-probe-head");

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "publish-oci-only-headmanifest", """["publish:oci"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Head("library/ubuntu/manifests/push-probe-head", default);

        Assert.IsType<OkResult>(result);
        Assert.Equal(digest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    [Fact]
    public async Task GetManifest_PublishOciOnlyToken_Succeeds()
    {
        // A publish-only token must be able to GET a manifest too: docker/BuildKit fall back
        // to GET on registries that answer HEAD unreliably when resolving a tag before push.
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"push-probe-get\":true}");
        _ = await SeedManifestAsync(manifestBytes, tag: "push-probe-get");

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "publish-oci-only-getmanifest", """["publish:oci"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Get("library/ubuntu/manifests/push-probe-get", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task GetManifest_PublishWildcardToken_Succeeds()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"push-probe-wildcard\":true}");
        _ = await SeedManifestAsync(manifestBytes, tag: "push-probe-wildcard");

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "publish-wildcard-getmanifest", """["publish:*"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Get("library/ubuntu/manifests/push-probe-wildcard", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task ListTags_PublishOciOnlyToken_ReturnsForbidden()
    {
        // Tag-list enumeration is not a step the push protocol performs; a publish-only token
        // must not gain it as a side effect of the manifest/blob push-probe exception.
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"push-probe-tags\":true}");
        _ = await SeedManifestAsync(manifestBytes, tag: "v1");

        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "publish-oci-only-tags", """["publish:oci"]""", expiresAt: null);

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
        var result = await ctl.Get("library/ubuntu/tags/list", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    /// <summary>
    /// Mixed partial-failure coverage for the push-probe exception: in one org, a publish-only
    /// token completes exactly the read probes a push performs (manifest HEAD, manifest GET,
    /// blob HEAD) while a token with neither read nor publish capability is forbidden on those
    /// same surfaces plus tags list — proving the exception is scoped to the presented token's
    /// own capability, not to the route.
    /// </summary>
    [Fact]
    public async Task PushProbeAuthorization_MixedTokens_PublishCapableProbesSucceedIncapableForbiddenAcrossSurfaces()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"push-probe-mixed\":true}");
        string manifestDigest = await SeedManifestAsync(manifestBytes, tag: "push-probe-mixed");
        byte[] blobBytes = RandomBytes(32);
        string blobDigest = await SeedBlobAsync(blobBytes);

        var (publishToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "push-probe-mixed-capable", """["publish:oci"]""", expiresAt: null);
        var (incapableToken, _) = await _tokens.CreateServiceTokenAsync(
            _orgId, "push-probe-mixed-incapable", """["publish:pypi"]""", expiresAt: null);

        // Publish-capable token: manifest HEAD, manifest GET, and blob HEAD all succeed.
        var publishHeadManifestCtl = BuildControllerForOrgWithAuth(_orgId, publishToken, BuildResolver());
        var headManifestResult = await publishHeadManifestCtl.Head("library/ubuntu/manifests/push-probe-mixed", default);
        Assert.IsType<OkResult>(headManifestResult);
        Assert.Equal(manifestDigest, publishHeadManifestCtl.Response.Headers["Docker-Content-Digest"].ToString());

        var publishGetManifestCtl = BuildControllerForOrgWithAuth(_orgId, publishToken, BuildResolver());
        Assert.IsType<FileStreamResult>(
            await publishGetManifestCtl.Get("library/ubuntu/manifests/push-probe-mixed", default));

        var publishHeadBlobCtl = BuildControllerForOrgWithAuth(_orgId, publishToken, BuildResolver());
        var headBlobResult = await publishHeadBlobCtl.Head($"library/ubuntu/blobs/{blobDigest}", default);
        Assert.IsType<OkResult>(headBlobResult);
        Assert.Equal(blobDigest, publishHeadBlobCtl.Response.Headers["Docker-Content-Digest"].ToString());

        // Incapable token (unrelated ecosystem, no read/publish OCI capability): every one of
        // the same surfaces, plus tags list, is forbidden rather than silently allowed.
        var incapableHeadManifestCtl = BuildControllerForOrgWithAuth(_orgId, incapableToken, BuildResolver());
        var incapableHeadManifest = Assert.IsType<ObjectResult>(
            await incapableHeadManifestCtl.Head("library/ubuntu/manifests/push-probe-mixed", default));
        Assert.Equal(StatusCodes.Status403Forbidden, incapableHeadManifest.StatusCode);

        var incapableGetManifestCtl = BuildControllerForOrgWithAuth(_orgId, incapableToken, BuildResolver());
        var incapableGetManifest = Assert.IsType<ObjectResult>(
            await incapableGetManifestCtl.Get("library/ubuntu/manifests/push-probe-mixed", default));
        Assert.Equal(StatusCodes.Status403Forbidden, incapableGetManifest.StatusCode);

        var incapableHeadBlobCtl = BuildControllerForOrgWithAuth(_orgId, incapableToken, BuildResolver());
        var incapableHeadBlob = Assert.IsType<ObjectResult>(
            await incapableHeadBlobCtl.Head($"library/ubuntu/blobs/{blobDigest}", default));
        Assert.Equal(StatusCodes.Status403Forbidden, incapableHeadBlob.StatusCode);

        var incapableTagsCtl = BuildControllerForOrgWithAuth(_orgId, incapableToken, BuildResolver());
        var incapableTags = Assert.IsType<ObjectResult>(
            await incapableTagsCtl.Get("library/ubuntu/tags/list", default));
        Assert.Equal(StatusCodes.Status403Forbidden, incapableTags.StatusCode);
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

    // ── Mutable-tag TTL revalidation ──────────────────────────────────────────
    //
    // A tag is a mutable reference by the Distribution Spec: the upstream may repoint it at any
    // time. Oci:ManifestTagTtl bounds how long a cached tag → digest mapping may be served before
    // it must be re-checked. These tests pin that the bound is actually enforced on the serve
    // path — the controller answers from local state first, so a TTL honoured only inside
    // OciUpstreamResolver would never run at all.

    // Builds the upstream response for a manifest fetch (GET body + the headers a HEAD reads).
    private static HttpResponseMessage UpstreamManifestResponse(byte[] bytes)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(bytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
                    "application/vnd.oci.image.manifest.v1+json") },
            },
        };
        resp.Headers.Add("Docker-Content-Digest", "sha256:" + Sha256Hex(bytes));
        return resp;
    }

    [Fact]
    public async Task GetManifest_ProxiedTag_StaleBeyondTtl_RevalidatesUpstreamAndServesNewDigest()
    {
        var clock = TestTime.Frozen();

        // Cached ten minutes ago against a five-minute TTL, so the mapping is stale.
        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gen\":\"old\"}");
        string cachedDigest = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: clock.GetUtcNow().AddMinutes(-10));

        // Upstream has since repointed :latest at different content.
        byte[] repointedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gen\":\"new\"}");
        string repointedDigest = "sha256:" + Sha256Hex(repointedBytes);
        Assert.NotEqual(cachedDigest, repointedDigest);

        // Revalidation observes with a HEAD, then fetches the new body by digest — two
        // upstream requests, each needing its own response instance.
        var ctl = BuildController(BuildResolver(
            new RepeatFactory(_ => UpstreamManifestResponse(repointedBytes)), time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("MISS", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(repointedDigest, ctl.Response.Headers["Docker-Content-Digest"].ToString());

        // The repoint must be durable, not merely reflected in response headers: the tag row
        // now maps to the new digest and the successful revalidation refreshed the stamp.
        await using var conn = await _db.OpenAsync();
        var (Digest, LastRevalidated, PendingDigest) = await conn.QuerySingleAsync<(string Digest, string? LastRevalidated, string? PendingDigest)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated, pending_digest AS PendingDigest " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = 'library/ubuntu' AND tag = 'latest'",
            new { orgId = _orgId });
        Assert.Equal(repointedDigest, Digest);
        Assert.Equal(clock.GetUtcNow().ToUtcIso(), LastRevalidated);
        Assert.Null(PendingDigest);
    }

    [Fact]
    public async Task GetManifest_ProxiedTag_WithinTtl_ServesCachedDigest_WithoutUpstreamCall()
    {
        var clock = TestTime.Frozen();

        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gen\":\"fresh\"}");
        string cachedDigest = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: clock.GetUtcNow().AddMinutes(-1));

        // NeverCallFactory throws on any HTTP call, so this asserts the absence of a round-trip
        // rather than merely that the cached digest came back.
        var ctl = BuildController(BuildResolver(new NeverCallFactory(), time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(cachedDigest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    [Fact]
    public async Task GetManifest_HostedTag_IsServedLocally_RegardlessOfAge()
    {
        var clock = TestTime.Frozen();

        // A pushed tag is authoritative here — no upstream can disagree with it — so age is not a
        // reason to revalidate. A push leaves last_revalidated NULL, which is what marks it.
        byte[] hostedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"hosted\":true}");
        string hostedDigest = await SeedManifestAsync(
            hostedBytes, tag: "latest", origin: "uploaded", nullRevalidated: true);

        var ctl = BuildController(BuildResolver(new NeverCallFactory(), time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(hostedDigest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    [Fact]
    public async Task GetManifest_PushedTag_WhoseBlobRowIsProxyOrigin_IsStillServedLocally()
    {
        var clock = TestTime.Frozen();

        // oci_blobs is content-addressed and shared, so a manifest pushed here keeps
        // origin = 'proxy' when the same bytes were proxied first. Origin therefore describes the
        // bytes, not the tag — keying revalidation on it sends a hosted tag upstream and 404s a
        // fully round-trippable image. OciPushTests.DeleteManifest_ByDigest_WhenOriginIsProxy_StillDeletes
        // pins the same dedup state end to end; this is its unit-level twin.
        byte[] pushedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"dedup\":\"proxy-origin\"}");
        string pushedDigest = await SeedManifestAsync(
            pushedBytes, tag: "latest", origin: "proxy", nullRevalidated: true);

        var ctl = BuildController(BuildResolver(new NeverCallFactory(), time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(pushedDigest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    [Fact]
    public async Task GetManifest_ProxiedTag_StaleAndUpstreamUnreachable_ServesLastAcceptedDigestWithinGrace()
    {
        var clock = TestTime.Frozen();

        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gen\":\"stale\"}");
        var seededStamp = clock.GetUtcNow().AddMinutes(-10);
        string cachedDigest = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: seededStamp);

        var ctl = BuildController(BuildResolver(new ThrowingFactory(), time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        // Bounded serve-stale. The old hard fail argued that serving the stale digest would
        // let an upstream outage silently extend the TTL to forever — and the grace bound is
        // precisely what answers that objection: the last accepted digest serves only until
        // last_revalidated + ManifestTagTtl + ManifestTagStaleGrace, a failed revalidation
        // never refreshes the stamp (asserted below), so the deadline cannot slide, and past
        // it the pull fails 502 (GetManifest_ProxiedTag_StaleBeyondGrace_Returns502). Within
        // the bound, an upstream blip must not break every `docker pull` of a moving tag.
        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("STALE", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(cachedDigest, ctl.Response.Headers["Docker-Content-Digest"].ToString());

        // The failed revalidation must not be recorded as a successful one.
        await using var conn = await _db.OpenAsync();
        string? stamp = await conn.ExecuteScalarAsync<string>(
            "SELECT last_revalidated FROM oci_tags WHERE org_id = @orgId AND repository = 'library/ubuntu' AND tag = 'latest'",
            new { orgId = _orgId });
        Assert.Equal(seededStamp.ToUtcIso(), stamp);
    }

    [Fact]
    public async Task GetManifest_ProxiedTag_StaleBeyondGrace_Returns502()
    {
        var clock = TestTime.Frozen();

        // Stale onset was last_revalidated + 5m TTL; the 24h grace expired hours ago.
        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gen\":\"exhausted\"}");
        _ = await SeedManifestAsync(
            cachedBytes, tag: "latest",
            lastRevalidated: clock.GetUtcNow() - (TimeSpan.FromMinutes(5) + TimeSpan.FromHours(30)));

        var ctl = BuildController(BuildResolver(new ThrowingFactory(), time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status502BadGateway, obj.StatusCode);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task GetManifest_ProxiedTag_Stale_UpstreamErrorStatus_ServesStaleWithinGrace_Never404(
        HttpStatusCode upstreamStatus)
    {
        var clock = TestTime.Frozen();

        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gen\":\"rate-limited\"}");
        string cachedDigest = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: clock.GetUtcNow().AddMinutes(-10));

        // A Docker Hub 429 (or a 5xx) told the old code "not found", which told `docker pull`
        // the image does not exist — while the manifest and every layer sat cached locally.
        var http = new RepeatFactory(_ => new HttpResponseMessage(upstreamStatus));
        var ctl = BuildController(BuildResolver(http, time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("STALE", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(cachedDigest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task GetManifest_ProxiedTag_StaleBeyondGrace_UpstreamErrorStatus_Returns502_Never404(
        HttpStatusCode upstreamStatus)
    {
        var clock = TestTime.Frozen();

        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gen\":\"429-exhausted\"}");
        _ = await SeedManifestAsync(
            cachedBytes, tag: "latest",
            lastRevalidated: clock.GetUtcNow() - (TimeSpan.FromMinutes(5) + TimeSpan.FromHours(30)));

        var http = new RepeatFactory(_ => new HttpResponseMessage(upstreamStatus));
        var ctl = BuildController(BuildResolver(http, time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        // Past the grace the answer is "upstream failed" — never "the image does not exist".
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status502BadGateway, obj.StatusCode);
    }

    [Fact]
    public async Task GetManifest_ProxiedTag_GraceMeasuredFromStaleOnset_NotResetByRepeatedFailures()
    {
        var clock = TestTime.Frozen();

        // Stale onset = seeded last_revalidated + 5m TTL; grace deadline = onset + 24h.
        var seededStamp = clock.GetUtcNow().AddMinutes(-10);
        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"gen\":\"no-reset\"}");
        string cachedDigest = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: seededStamp);

        // Two failed revalidations inside the window both serve stale...
        var first = BuildController(BuildResolver(new ThrowingFactory(), time: clock));
        Assert.IsType<FileStreamResult>(await first.Get("library/ubuntu/manifests/latest", default));
        Assert.Equal(cachedDigest, first.Response.Headers["Docker-Content-Digest"].ToString());

        clock.Advance(TimeSpan.FromHours(12));
        var second = BuildController(BuildResolver(new ThrowingFactory(), time: clock));
        Assert.IsType<FileStreamResult>(await second.Get("library/ubuntu/manifests/latest", default));

        // ...and neither failure moved the deadline: 13h later (25h past onset, but only 13h
        // after the most recent failed attempt) the tag expires at the ORIGINAL deadline. If
        // the grace were re-anchored on each failed attempt, this request would still be
        // inside a fresh 24h window and serve stale — silently forever across an outage.
        clock.Advance(TimeSpan.FromHours(13));
        var third = BuildController(BuildResolver(new ThrowingFactory(), time: clock));
        var expired = Assert.IsType<ObjectResult>(await third.Get("library/ubuntu/manifests/latest", default));
        Assert.Equal(StatusCodes.Status502BadGateway, expired.StatusCode);

        await using var conn = await _db.OpenAsync();
        string? stamp = await conn.ExecuteScalarAsync<string>(
            "SELECT last_revalidated FROM oci_tags WHERE org_id = @orgId AND repository = 'library/ubuntu' AND tag = 'latest'",
            new { orgId = _orgId });
        Assert.Equal(seededStamp.ToUtcIso(), stamp);
    }

    [Fact]
    public async Task GetManifest_TokenExchangeFailure_Returns502_Not500()
    {
        // OciUnauthorizedException (token-exchange failure — e.g. auth.docker.io down, or the
        // unimplemented ECR exchange refusing) previously escaped as an unhandled 500. It is an
        // upstream-availability failure and must answer 502. The aws_ecr auth type throws it
        // before any HTTP call, which makes it a hermetic stand-in for the whole class.
        await using (var conn = await _db.OpenAsync())
        {
            string prefixJson = System.Text.Json.JsonSerializer.Serialize(new[] { "" });
            await conn.ExecuteAsync(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, name, url, position, auth_type, prefixes)
                VALUES (@id, @orgId, 'oci', 'ecr', 'ecr.example.test', 0, 'aws_ecr', @prefixes)
                ON CONFLICT (org_id, ecosystem, url) DO NOTHING
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId = _emptyOrgId, prefixes = prefixJson });
        }

        var ctl = BuildControllerForOrg(_emptyOrgId, BuildResolver(new NeverCallFactory()));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status502BadGateway, obj.StatusCode);
    }

    [Fact]
    public async Task HeadManifest_ProxiedTag_StaleBeyondTtl_RevalidatesUpstream()
    {
        var clock = TestTime.Frozen();

        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"head\":\"old\"}");
        string cachedDigest = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: clock.GetUtcNow().AddMinutes(-10));

        byte[] repointedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"head\":\"new\"}");
        string repointedDigest = "sha256:" + Sha256Hex(repointedBytes);

        var ctl = BuildController(BuildResolver(
            new SingleResponseFactory(UpstreamManifestResponse(repointedBytes)), time: clock));

        var result = await ctl.Head("library/ubuntu/manifests/latest", default);

        // HEAD and GET must agree about staleness, or a client that probes with HEAD and then
        // pulls sees two different answers for the same reference.
        Assert.IsType<OkResult>(result);
        Assert.Equal("MISS", ctl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(repointedDigest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
        Assert.NotEqual(cachedDigest, ctl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    [Fact]
    public async Task HeadManifest_ProxiedTag_StaleWithUnchangedDigest_RefreshesStampDurably_NextPullIsCacheHit()
    {
        var clock = TestTime.Frozen();

        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"head\":\"unchanged\"}");
        string cachedDigest = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: clock.GetUtcNow().AddMinutes(-10));

        // Upstream still advertises the same digest.
        var http = new RepeatFactory(_ => UpstreamManifestResponse(cachedBytes));
        var headCtl = BuildController(BuildResolver(http, time: clock));

        var headResult = await headCtl.Head("library/ubuntu/manifests/latest", default);

        Assert.IsType<OkResult>(headResult);
        Assert.Equal(cachedDigest, headCtl.Response.Headers["Docker-Content-Digest"].ToString());
        Assert.Equal(1, http.CallCount);

        // The confirmation must persist: last_revalidated is refreshed by the HEAD itself, so a
        // HEAD-then-GET-by-digest client (containerd snapshotter, BuildKit) regains the fresh
        // window instead of paying an upstream round-trip on every pull after the first expiry.
        await using (var conn = await _db.OpenAsync())
        {
            string? stamp = await conn.ExecuteScalarAsync<string>(
                "SELECT last_revalidated FROM oci_tags WHERE org_id = @orgId AND repository = 'library/ubuntu' AND tag = 'latest'",
                new { orgId = _orgId });
            Assert.Equal(clock.GetUtcNow().ToUtcIso(), stamp);
        }

        // The immediately-following pull is a local cache HIT with zero upstream dependency —
        // NeverCallFactory throws on any HTTP call, so this asserts the absence of a round-trip.
        var getCtl = BuildController(BuildResolver(new NeverCallFactory(), time: clock));
        var getResult = await getCtl.Get("library/ubuntu/manifests/latest", default);
        Assert.IsType<FileStreamResult>(getResult);
        Assert.Equal("HIT", getCtl.Response.Headers["X-Cache"].ToString());
        Assert.Equal(cachedDigest, getCtl.Response.Headers["Docker-Content-Digest"].ToString());
    }

    // ── Promotion gate: min_release_age_hours holds a too-young repoint ───────

    [Fact]
    public async Task GetManifest_TagRepointedToYoungDigest_KeepsServingAcceptedDigest_ThenPromotesAfterAging()
    {
        var clock = TestTime.Frozen();

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET min_release_age_hours = 24 WHERE org_id = @orgId",
                new { orgId = _orgId });
        }

        byte[] acceptedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"age\":\"accepted\"}");
        string acceptedDigest = await SeedManifestAsync(
            acceptedBytes, tag: "latest", lastRevalidated: clock.GetUtcNow().AddMinutes(-10));

        byte[] youngBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"age\":\"young\"}");
        string youngDigest = "sha256:" + Sha256Hex(youngBytes);

        // First revalidation: upstream advertises a digest observed for the first time NOW —
        // younger than min_release_age_hours. The tag must NOT advance, and it must NOT become
        // unavailable either (no 404, no 403): min_release_age gates promotion, never
        // availability. The previously accepted digest keeps serving.
        var firstHttp = new RepeatFactory(_ => UpstreamManifestResponse(youngBytes));
        var firstCtl = BuildController(BuildResolver(firstHttp, time: clock));
        var firstResult = await firstCtl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(firstResult);
        Assert.Equal(acceptedDigest, firstCtl.Response.Headers["Docker-Content-Digest"].ToString());
        // Observation HEAD only — the young body is never fetched while it is held pending.
        Assert.Equal(1, firstHttp.CallCount);

        await using (var conn = await _db.OpenAsync())
        {
            var (Digest, PendingDigest, PendingFirstSeenAt, LastRevalidated) = await conn.QuerySingleAsync<(string Digest, string? PendingDigest, string? PendingFirstSeenAt, string? LastRevalidated)>(
                "SELECT digest AS Digest, pending_digest AS PendingDigest, pending_first_seen_at AS PendingFirstSeenAt, last_revalidated AS LastRevalidated " +
                "FROM oci_tags WHERE org_id = @orgId AND repository = 'library/ubuntu' AND tag = 'latest'",
                new { orgId = _orgId });
            Assert.Equal(acceptedDigest, Digest);                       // not advanced
            Assert.Equal(youngDigest, PendingDigest);                    // observed, pending
            Assert.Equal(clock.GetUtcNow().ToUtcIso(), PendingFirstSeenAt);
            Assert.Equal(clock.GetUtcNow().ToUtcIso(), LastRevalidated); // successful revalidation
        }

        // 30 hours later (well past the 24h threshold, far from the boundary) the next
        // successful revalidation promotes: body fetched by digest, tag repointed, pending
        // cleared.
        clock.Advance(TimeSpan.FromHours(30));
        var secondHttp = new RepeatFactory(_ => UpstreamManifestResponse(youngBytes));
        var secondCtl = BuildController(BuildResolver(secondHttp, time: clock));
        var secondResult = await secondCtl.Get("library/ubuntu/manifests/latest", default);

        Assert.IsType<FileStreamResult>(secondResult);
        Assert.Equal(youngDigest, secondCtl.Response.Headers["Docker-Content-Digest"].ToString());

        await using (var conn = await _db.OpenAsync())
        {
            var (Digest, PendingDigest, PendingFirstSeenAt, LastRevalidated) = await conn.QuerySingleAsync<(string Digest, string? PendingDigest, string? PendingFirstSeenAt, string? LastRevalidated)>(
                "SELECT digest AS Digest, pending_digest AS PendingDigest, pending_first_seen_at AS PendingFirstSeenAt, last_revalidated AS LastRevalidated " +
                "FROM oci_tags WHERE org_id = @orgId AND repository = 'library/ubuntu' AND tag = 'latest'",
                new { orgId = _orgId });
            Assert.Equal(youngDigest, Digest);
            Assert.Null(PendingDigest);
            Assert.Null(PendingFirstSeenAt);
            Assert.Equal(clock.GetUtcNow().ToUtcIso(), LastRevalidated);
        }
    }

    [Fact]
    public async Task GetManifest_TagRepointedToBlockedLicenseDigest_IsDeniedOnTheRevalidatingRequest()
    {
        var clock = TestTime.Frozen();

        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"lic\":\"old\"}");
        _ = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: clock.GetUtcNow().AddMinutes(-10));

        // The digest :latest now points at — already held and already stamped by this org, the
        // state an earlier by-digest pull leaves behind. The stamp is what the serve path reads;
        // seeding it stands in for OciImageLicenseRecorder having run on the config label.
        byte[] repointedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"lic\":\"gpl\"}");
        string repointedDigest = "sha256:" + Sha256Hex(repointedBytes);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin,
                                       license_spdx, license_checked_at)
                VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size,
                        @blobKey, 'proxy', 'GPL-3.0-only', @checkedAt)
                ON CONFLICT (digest, org_id) DO NOTHING
                """,
                new
                {
                    digest = repointedDigest,
                    orgId = _orgId,
                    size = (long)repointedBytes.Length,
                    blobKey = BlobKeys.OciBlob("sha256", Sha256Hex(repointedBytes)),
                    checkedAt = clock.GetUtcNow().ToUtcIso(),
                });
        }

        await LicensePolicySeeder.SetModeAsync(_db, _orgId, "block");
        await LicensePolicySeeder.AddBlocklistEntryAsync(_db, _orgId, "GPL-3.0-only");

        var ctl = BuildController(BuildResolver(
            new RepeatFactory(_ => UpstreamManifestResponse(repointedBytes)), time: clock));

        var result = await ctl.Get("library/ubuntu/manifests/latest", default);

        // Without the arm on the upstream path, the repointed image serves once before the next
        // request denies it — and a tag that keeps moving keeps re-arming that window.
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    [Fact]
    public async Task HeadManifest_TagRepointedToBlockedLicenseDigest_IsDeniedLikeGet()
    {
        var clock = TestTime.Frozen();

        byte[] cachedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"lic\":\"head-old\"}");
        _ = await SeedManifestAsync(
            cachedBytes, tag: "latest", lastRevalidated: clock.GetUtcNow().AddMinutes(-10));

        byte[] repointedBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"lic\":\"head-gpl\"}");
        string repointedDigest = "sha256:" + Sha256Hex(repointedBytes);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin,
                                       license_spdx, license_checked_at)
                VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size,
                        @blobKey, 'proxy', 'GPL-3.0-only', @checkedAt)
                ON CONFLICT (digest, org_id) DO NOTHING
                """,
                new
                {
                    digest = repointedDigest,
                    orgId = _orgId,
                    size = (long)repointedBytes.Length,
                    blobKey = BlobKeys.OciBlob("sha256", Sha256Hex(repointedBytes)),
                    checkedAt = clock.GetUtcNow().ToUtcIso(),
                });
        }

        await LicensePolicySeeder.SetModeAsync(_db, _orgId, "block");
        await LicensePolicySeeder.AddBlocklistEntryAsync(_db, _orgId, "GPL-3.0-only");

        var ctl = BuildController(BuildResolver(
            new SingleResponseFactory(UpstreamManifestResponse(repointedBytes)), time: clock));

        var result = await ctl.Head("library/ubuntu/manifests/latest", default);

        // HEAD must answer the licence arm the same way GET does. A client that probes with HEAD
        // and pulls on 200 would otherwise be told the blocked image is available.
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
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

    // Builds a FRESH response per upstream request from the supplied responder, counting calls.
    // Needed by the revalidation flows, which may make two upstream calls (an observation HEAD
    // followed by a by-digest GET) — SingleResponseFactory's shared instance is disposed by the
    // first caller.
    private sealed class RepeatFactory : IHttpClientFactory
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        private readonly RepeatCallCounter _counter = new();

        public RepeatFactory(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;

        public int CallCount => _counter.Value;

        public HttpClient CreateClient(string name) => new(new RepeatHandler(this));

        private sealed class RepeatCallCounter
        {
            private int _count;
            public int Value => _count;
            public void Increment() => Interlocked.Increment(ref _count);
        }

        private sealed class RepeatHandler : HttpMessageHandler
        {
            private readonly RepeatFactory _owner;
            public RepeatHandler(RepeatFactory owner) => _owner = owner;
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                _owner._counter.Increment();
                return Task.FromResult(_owner._responder(request));
            }
        }
    }

    // Upstream that fails at the transport layer — the shape IsUpstreamFailure classifies.
    private sealed class ThrowingFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new ThrowingHandler());
        private sealed class ThrowingHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
                => throw new HttpRequestException("upstream unreachable");
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
        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
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

        var ctl = BuildControllerForOrgWithAuth(_orgId, rawToken, BuildResolver());
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
        });

        // Air-gap mode: any call to the upstream HTTP client would fail, but the controller
        // must not reach it — AirGappedException is thrown before any network attempt and
        // must be caught so the local listing is still returned.
        var airGap = new EnabledAirGap();
        var authSvc = new OciUpstreamAuthService(
            new NeverCallFactory(), options, airGap, NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, _registryBlobs);
        var recorder = new OciImageLicenseRecorder(_db, blobs, TimeProvider.System, NullLogger<OciImageLicenseRecorder>.Instance,
                new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)));
        var resolver = new OciUpstreamResolver(
            new NeverCallFactory(), authSvc, options, blobs, _db,
            airGap, recorder, _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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

/// <summary>Unlimited disk stub for tests — floor check always passes.</summary>
file sealed class UnlimitedDisk : IStagingDiskInfo
{
    public long GetAvailableBytes() => long.MaxValue;
    public long GetTotalBytes() => long.MaxValue;
    public long GetStagingDirectoryUsedBytes() => 0;
}
