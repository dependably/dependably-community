using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Api;
using Dependably.Api.NpmProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Proves that per-request metadata rebuilds are collapsed onto a cache after the first call
/// for each ecosystem, and that the npm packument path does not serialize twice.
///
/// RPM local-repodata tests:
///  1. Second request for primary/filelists/other.xml.gz is served from cache (no rebuild).
///  2. Upload evicts all three doc-type cache entries for the org.
///  3. repomd.xml populates primary, filelists, and other caches in one call.
///  4. Mixed scenario: some docs warm, some cold in the same burst.
///
/// npm double-serialize test:
///  5. ServePackumentJson returns FileContentResult (bytes only — no re-serialize on cache store).
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetadataRebuildCachingTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private string _orgId = null!;
    private TokenRepository _tokens = null!;
    private RenderedResponseCache<RpmLocalRepodataKey> _localRepodataCache = null!;
    private MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache> _mergedRepodataCache = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _orgId, slug = "cache-test-org" });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id, anonymous_pull) VALUES (@id, 1)",
            new { id = _orgId });
        _tokens = new TokenRepository(_db, _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── RPM local repodata cache ──────────────────────────────────────────────

    [Fact]
    public async Task RpmLocalRepodata_SecondRequest_ServedFromCache()
    {
        // Arrange: publish one RPM so there is content to rebuild.
        var ctrl = BuildRpmController();
        string raw = await SeedRpmTokenAsync();
        byte[] rpmBytes = RpmControllerUnitTests.BuildSyntheticRpm("curl", "7.86.0", "1.el9", "x86_64");
        SetRpmBody(ctrl, rpmBytes, $"Bearer {raw}");
        await ctrl.Upload(CancellationToken.None);

        // First GET — cache miss — triggers rebuild.
        SetEmptyRequest(ctrl);
        var first = await ctrl.Repodata("primary.xml.gz", CancellationToken.None);
        var firstFile = Assert.IsType<FileContentResult>(first);

        // Cache must now hold primary bytes.
        Assert.True(_localRepodataCache.TryGet(
            new RpmLocalRepodataKey(_orgId, "primary"), out byte[]? cached));
        Assert.NotNull(cached);
        Assert.NotEmpty(cached);

        // Second GET — cache hit — must return byte-identical content.
        SetEmptyRequest(ctrl);
        var second = await ctrl.Repodata("primary.xml.gz", CancellationToken.None);
        var secondFile = Assert.IsType<FileContentResult>(second);

        Assert.Equal(firstFile.FileContents, secondFile.FileContents);
    }

    [Fact]
    public async Task RpmLocalRepodata_UploadEvictsCache_NextRequestRebuildsWithNewPackage()
    {
        // Arrange: prime the primary cache with an empty-repo document.
        var ctrl = BuildRpmController();
        SetEmptyRequest(ctrl);
        var before = (FileContentResult)(await ctrl.Repodata("primary.xml.gz", CancellationToken.None));
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _));

        // Act: upload an RPM — must evict all three document entries.
        string raw = await SeedRpmTokenAsync();
        byte[] rpmBytes = RpmControllerUnitTests.BuildSyntheticRpm("libz", "1.2.13", "2.el9", "x86_64");
        SetRpmBody(ctrl, rpmBytes, $"Bearer {raw}");
        await ctrl.Upload(CancellationToken.None);

        // Primary entry must be gone.
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _));

        // Next GET rebuilds and the new primary.xml.gz is larger than the empty-repo one.
        SetEmptyRequest(ctrl);
        var after = (FileContentResult)(await ctrl.Repodata("primary.xml.gz", CancellationToken.None));
        Assert.True(after.FileContents.Length > before.FileContents.Length,
            "primary.xml.gz must grow after publishing an RPM");
    }

    [Fact]
    public async Task RpmLocalRepodata_RepomdXml_PopulatesAllThreeDocCaches()
    {
        // repomd.xml seals SHA-256 of primary/filelists/other. The controller fetches all
        // three from the per-document cache in one repomd request so they stay consistent
        // across a parallel primary.xml.gz fetch. All three must be cached after repomd.xml.
        var ctrl = BuildRpmController();
        string raw = await SeedRpmTokenAsync();
        byte[] rpmBytes = RpmControllerUnitTests.BuildSyntheticRpm("bash", "5.1.8", "6.el9", "x86_64");
        SetRpmBody(ctrl, rpmBytes, $"Bearer {raw}");
        await ctrl.Upload(CancellationToken.None);

        SetEmptyRequest(ctrl);
        await ctrl.Repodata("repomd.xml", CancellationToken.None);

        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _),
            "primary must be cached after repomd.xml");
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "filelists"), out _),
            "filelists must be cached after repomd.xml");
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"), out _),
            "other must be cached after repomd.xml");
    }

    [Fact]
    public async Task RpmLocalRepodata_Mixed_WarmFilelistsColdOther_BothServedCorrectly()
    {
        // House rule: mixed scenario — filelists is warm, other is cold in the same burst.
        // Warm hit returns identical bytes; cold miss builds and caches.
        var ctrl = BuildRpmController();

        // Prime only filelists.
        SetEmptyRequest(ctrl);
        await ctrl.Repodata("filelists.xml.gz", CancellationToken.None);
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "filelists"),
            out byte[]? warmFilelists));
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"), out _),
            "other must not be cached yet");

        // Request both in the same burst.
        SetEmptyRequest(ctrl);
        var filelistsResult = (FileContentResult)(await ctrl.Repodata("filelists.xml.gz", CancellationToken.None));
        SetEmptyRequest(ctrl);
        var otherResult = await ctrl.Repodata("other.xml.gz", CancellationToken.None);
        Assert.IsType<FileContentResult>(otherResult);

        // Warm filelists bytes are byte-identical to the pre-cached value.
        Assert.Equal(warmFilelists, filelistsResult.FileContents);

        // Cold other is now cached after rebuild.
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"),
            out byte[]? nowCachedOther));
        Assert.NotNull(nowCachedOther);
    }

    [Fact]
    public async Task RpmLocalRepodata_Upload_EvictsAllThreeDocTypes()
    {
        // Upload must evict primary, filelists, and other — not just the one that was
        // requested most recently.
        var ctrl = BuildRpmController();

        SetEmptyRequest(ctrl);
        await ctrl.Repodata("primary.xml.gz", CancellationToken.None);
        SetEmptyRequest(ctrl);
        await ctrl.Repodata("filelists.xml.gz", CancellationToken.None);
        SetEmptyRequest(ctrl);
        await ctrl.Repodata("other.xml.gz", CancellationToken.None);

        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _));
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "filelists"), out _));
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"), out _));

        // Upload one RPM — all three must be evicted.
        string raw = await SeedRpmTokenAsync();
        SetRpmBody(ctrl,
            RpmControllerUnitTests.BuildSyntheticRpm("glibc", "2.34", "60.el9", "x86_64"),
            $"Bearer {raw}");
        await ctrl.Upload(CancellationToken.None);

        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _));
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "filelists"), out _));
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"), out _));
    }

    // ── npm double-serialize elimination ──────────────────────────────────────

    [Fact]
    public void NpmServePackumentJson_ReturnsFileContentResult_NotJsonResult()
    {
        // The rebuild path extracts bytes via FileContentResult.FileContents. If
        // ServePackumentJson returned JsonResult the rebuild would have to re-serialize.
        // This test verifies the return type is FileContentResult, pinning the contract.
        var node = JsonNode.Parse("""{"name":"left-pad","versions":{}}""")!;
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant("org1", "slug");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("org1.example.test");

        var result = NpmPackumentHandler.ServePackumentJson(http, node, "private, max-age=60");

        // Must be FileContentResult (bytes already serialized once) — not JsonResult
        // (which would require a second serialize in the rebuild capture path).
        Assert.IsType<FileContentResult>(result);
        var fcr = (FileContentResult)result!;
        Assert.Equal("application/json", fcr.ContentType);
        Assert.NotEmpty(fcr.FileContents);
    }

    [Fact]
    public void NpmServePackumentJson_FileContentBytesMatchUtf8Encoding()
    {
        // The bytes in FileContentResult must exactly match UTF-8(metadata.ToJsonString()).
        // Both the ETag (computed from those bytes) and the cache entry depend on this.
        var node = JsonNode.Parse("""{"name":"lodash","versions":{"4.17.21":{"dist":{}}}}""")!;
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant("org1", "slug");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("org1.example.test");

        var result = (FileContentResult)NpmPackumentHandler.ServePackumentJson(http, node, "private, max-age=60");

        byte[] expected = Encoding.UTF8.GetBytes(node.ToJsonString());
        Assert.Equal(expected, result.FileContents);
    }

    [Fact]
    public void NpmServePackumentJson_IfNoneMatchHit_Returns304()
    {
        // When the client's If-None-Match header matches the computed ETag, the response
        // must be 304 (not the FileContentResult path).
        var node = JsonNode.Parse("""{"name":"react","versions":{}}""")!;
        byte[] bytes = Encoding.UTF8.GetBytes(node.ToJsonString());

        // Compute the expected ETag by mirroring NpmSharedHelpers.ComputeETag: first 16 hex chars
        // of SHA-256, quoted.
        string expectedETag =
            $"\"{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))[..16].ToLowerInvariant()}\"";

        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant("org1", "slug");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("org1.example.test");
        http.Request.Headers.IfNoneMatch = expectedETag;

        var result = NpmPackumentHandler.ServePackumentJson(http, node, "private, max-age=60");

        // ETag match → 304, not the bytes result.
        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(304, status.StatusCode);
    }

    // ── RPM delete-eviction (yank) ────────────────────────────────────────────

    [Fact]
    public async Task RpmDeleteVersion_OrgController_EvictsAllLocalAndMergedCacheEntries()
    {
        // Arrange: upload one RPM, then warm all three local-repodata cache entries plus
        // a stub merged-repodata entry. This proves the cache IS populated before the yank.
        var rpmCtrl = BuildRpmController();
        string raw = await SeedRpmTokenAsync();
        byte[] rpmBytes = RpmControllerUnitTests.BuildSyntheticRpm("curl", "7.86.0", "1.el9", "x86_64");
        SetRpmBody(rpmCtrl, rpmBytes, $"Bearer {raw}");
        await rpmCtrl.Upload(CancellationToken.None);

        // Warm all three local doc entries via repomd.xml (populates primary, filelists, other).
        SetEmptyRequest(rpmCtrl);
        await rpmCtrl.Repodata("repomd.xml", CancellationToken.None);

        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _),
            "primary must be cached before yank");
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "filelists"), out _),
            "filelists must be cached before yank");
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"), out _),
            "other must be cached before yank");

        // Seed a stub merged-repodata entry to verify that arm is also evicted.
        var stub = new MergedRepodataCache(new byte[] { 1 }, new byte[] { 2 }, []);
        _mergedRepodataCache.Set(new RpmMergedRepodataKey(_orgId), stub, TimeSpan.FromMinutes(1), size: 2);
        Assert.True(_mergedRepodataCache.TryGet(new RpmMergedRepodataKey(_orgId), out _),
            "merged entry must be cached before yank");

        // Act: yank the version through OrgController.
        string ownerId = await SeedOwnerForDeleteAsync();
        var orgCtrl = BuildOrgControllerForDelete(ownerId);
        var result = await orgCtrl.DeleteVersion("rpm", "curl", "7.86.0-1.el9", CancellationToken.None);

        // Assert: the call must succeed and all cache entries must be gone.
        Assert.IsType<NoContentResult>(result);
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _),
            "primary must be evicted after yank");
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "filelists"), out _),
            "filelists must be evicted after yank");
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"), out _),
            "other must be evicted after yank");
        Assert.False(_mergedRepodataCache.TryGet(new RpmMergedRepodataKey(_orgId), out _),
            "merged entry must be evicted after yank");
    }

    [Fact]
    public async Task RpmDeleteVersion_Mixed_OnlyPrimaryWarm_AllCachedEntriesEvicted()
    {
        // House rule: mixed partial-cache scenario — only primary is warm when the yank fires.
        // Proves the eviction set covers all three doc types unconditionally, not just the ones
        // that happen to be cached (a no-op Evict on a cold key must not prevent eviction of
        // the keys that ARE warm).
        var rpmCtrl = BuildRpmController();
        string raw = await SeedRpmTokenAsync();
        byte[] rpmBytes = RpmControllerUnitTests.BuildSyntheticRpm("bash", "5.1.8", "6.el9", "x86_64");
        SetRpmBody(rpmCtrl, rpmBytes, $"Bearer {raw}");
        await rpmCtrl.Upload(CancellationToken.None);

        // Warm only primary.
        SetEmptyRequest(rpmCtrl);
        await rpmCtrl.Repodata("primary.xml.gz", CancellationToken.None);
        Assert.True(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _),
            "primary must be cached");
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "filelists"), out _),
            "filelists must NOT be cached (mixed scenario)");
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"), out _),
            "other must NOT be cached (mixed scenario)");

        // Act: yank.
        string ownerId = await SeedOwnerForDeleteAsync();
        var orgCtrl = BuildOrgControllerForDelete(ownerId);
        var result = await orgCtrl.DeleteVersion("rpm", "bash", "5.1.8-6.el9", CancellationToken.None);

        // Assert: the warm primary entry must be evicted; cold entries remain absent.
        Assert.IsType<NoContentResult>(result);
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "primary"), out _),
            "primary must be evicted after yank");
        // filelists and other were never cached — they stay absent, not an error.
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "filelists"), out _));
        Assert.False(_localRepodataCache.TryGet(new RpmLocalRepodataKey(_orgId, "other"), out _));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private RpmController BuildRpmController()
    {
        _localRepodataCache = new RenderedResponseCache<RpmLocalRepodataKey>(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 50 * 1024 * 1024 }),
            MetadataCacheKeys.RpmLocalRepodata);
        _mergedRepodataCache = new MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache>(
            new MemoryCache(new MemoryCacheOptions()),
            MetadataCacheKeys.RpmMergedRepodata);

        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var orgs = new OrgRepository(_db);
        var repodata = new RpmRepodataService(_db, NullLogger<RpmRepodataService>.Instance, _clock);
        var svc = new RpmControllerServices(
            packages, _tokens, audit, orgs,
            new TieredBlobStorage(_blobs, _blobs),
            _db, repodata,
            new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock)),
            _mergedRepodataCache,
            _localRepodataCache,
            _clock);
        return new RpmController(svc) { ControllerContext = BuildRpmContext() };
    }

    private ControllerContext BuildRpmContext()
    {
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "cache-test-org");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("cache-test-org.example.test");
        return new ControllerContext { HttpContext = http };
    }

    private void SetEmptyRequest(RpmController ctrl) =>
        ctrl.ControllerContext = BuildRpmContext();

    private void SetRpmBody(RpmController ctrl, byte[] bytes, string authHeader)
    {
        ctrl.ControllerContext = BuildRpmContext();
        ctrl.Request.Body = new MemoryStream(bytes);
        ctrl.Request.ContentLength = bytes.Length;
        ctrl.Request.Headers.Authorization = authHeader;
    }

    private async Task<string> SeedRpmTokenAsync()
    {
        string raw = $"raw-{Guid.NewGuid():N}";
        string hash = TokenRepository.HashToken(raw);
        string userId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @t, @e, 'x', 'owner')",
            new { id = userId, t = _orgId, e = $"{userId}@rpm-cache-test" });
        await conn.ExecuteAsync("""
            INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, created_at)
            VALUES (@id, @o, @u, @h, @c, @ts)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                o = _orgId,
                u = userId,
                h = hash,
                c = """["publish:rpm"]""",
                ts = _clock.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
        return raw;
    }

    // Seeds an owner-role user (no token needed — ClaimsPrincipal carries the role claim).
    // Returns the userId so the caller can embed it in the JWT principal.
    private async Task<string> SeedOwnerForDeleteAsync()
    {
        string userId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @t, @e, 'x', 'owner')",
            new { id = userId, t = _orgId, e = $"{userId}@del-test" });
        return userId;
    }

    // Builds a minimal OrgController that shares the live _localRepodataCache and
    // _mergedRepodataCache instances so delete-eviction tests observe the same entries that
    // the RpmController warmed. Only the fields touched by DeleteVersion are non-null.
    private OrgController BuildOrgControllerForDelete(string ownerId)
    {
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "cache-test-org");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("cache-test-org.example.test");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, ownerId),
            new Claim("sub", ownerId),
            new Claim("org_id", _orgId),
            new Claim("tid", _orgId),
            new Claim("role", "owner"),
            new Claim("scope", "tenant"),
        ], authenticationType: "test"));

        var svc = new OrgControllerServices(
            Orgs: new OrgRepository(_db),
            Packages: new PackageRepository(_db),
            PackageAnalytics: null!,
            StatsSnapshots: null!,
            Tokens: null!,
            Invites: null!,
            Allowlist: null!,
            Blocklist: null!,
            Audit: new AuditRepository(_db),
            Guard: new OrgAccessGuard(_db),
            Blobs: _blobs,
            BlobStorage: null!,
            Config: null!,
            Logger: NullLogger<OrgController>.Instance,
            Problems: null!,
            Licenses: null!,
            Vulns: null!,
            Urls: null!,
            AuditEmitter: null!,
            Cache: null!,
            RpmMergedCache: _mergedRepodataCache,
            RpmLocalCache: _localRepodataCache);

        return new OrgController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

}
