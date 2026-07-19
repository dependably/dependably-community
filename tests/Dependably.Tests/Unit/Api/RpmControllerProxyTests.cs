using System.Security.Claims;
using System.Security.Cryptography;
using System.Xml.Linq;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Proxy-path coverage for <see cref="RpmController"/>.
///
/// Coverage targets:
///  - GET package: local miss → proxy resolves → UpstreamClient fetches → DB row written → bytes served
///  - GET package: local miss → resolution null → 404 + negative cache written
///  - GET package: local miss → negative cache hit → 404 without resolve
///  - GET package: proxy null (no upstream) → 404
///  - GET package: passthrough disabled → 404
///  - GET repodata/repomd.xml: passthrough → 200 with ETag
///  - GET repodata/repomd.xml: passthrough → 304 (If-None-Match matches)
///  - GET repodata/{hash}-primary.xml.gz: served from proxy
///  - GET repodata/RPM-GPG-KEY: returns key bytes with pgp-keys content type
///  - GET repodata/repomd.xml: no upstream → local generation
///  - PUT upload: passthrough mode → 409 with ProblemDetails
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmControllerProxyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    private string _orgId = null!;
    private string _userId = null!;

    private OrgRepository _orgs = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private PackageRepository _packages = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);
        _packages = new PackageRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "rpm-proxy-org");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "dev@rpm.test", "admin");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ────────────────────────────────────────────────────────────────

    private async Task EnableAnonPullAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId = _orgId });
    }

    /// <summary>
    /// Seeds one rpm upstream registry for the test org so the controller's
    /// <see cref="UpstreamRegistryResolver"/> returns a non-empty list and the proxy path runs.
    /// Without this the org has zero configured rpm registries (proxying disabled = 404).
    /// </summary>
    private async Task SeedRpmRegistryAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @orgId, 'rpm', 'https://rpm.example.test/repo', 0)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId = _orgId });
    }

    /// <summary>
    /// Sets the per-org RPM upstream mode override directly in the DB. null clears the override
    /// back to "inherit the instance Rpm:UpstreamMode env value".
    /// </summary>
    private async Task SetRpmUpstreamModeAsync(string? mode)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET rpm_upstream_mode = @mode WHERE org_id = @orgId",
            new { mode, orgId = _orgId });
    }

    // ── Package proxy ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Download_LocalMiss_FetchesFromUpstreamAndCachesInDb()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        byte[] bytes = RandomBytes(256);
        string sha256 = Sha256Hex(bytes);
        string filename = "tree-2.1.1-1.fc40.x86_64.rpm";
        var resolution = new PackageResolution(
            PackageUrl: $"https://mirror.example.com/Packages/t/{filename}",
            Sha256: sha256,
            Name: "tree",
            Epoch: 0,
            Version: "2.1.1",
            Release: "1.fc40",
            Arch: "x86_64",
            Summary: "A recursive directory listing command",
            Description: "tree is a recursive...",
            License: "GPLv2+");

        // Pre-stage the blob in the cache tier so UpstreamClient.GetOrFetchAsync returns a hit.
        await _blobs.PutAsync(BlobKeys.Proxy(sha256), new MemoryStream(bytes), default);

        var stubProxy = new StubProxy(resolution: resolution);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download(filename, default);

        // Should serve bytes (the proxy path returns FileStreamResult via File(MemoryStream,...)).
        var fsr = Assert.IsType<FileStreamResult>(result);
        using var ms = new MemoryStream();
        await fsr.FileStream.CopyToAsync(ms);
        Assert.Equal(bytes, ms.ToArray());
        Assert.Equal("application/x-rpm", fsr.ContentType);

        // The proxy first-fetch must NOT write a package_versions row — the global plane
        // (cache_artifact + tenant_artifact_access) is now authoritative for proxy RPMs.
        await using var conn = await _db.OpenAsync();
        long pvCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'rpm' AND p.purl_name = 'tree'
            """,
            new { orgId = _orgId });
        Assert.Equal(0, pvCount);

        // A cache_artifact row must be written for the fetched RPM.
        var caRow = await conn.QuerySingleOrDefaultAsync(
            """
            SELECT ca.content_hash, ca.ecosystem, ca.name, ca.version
            FROM cache_artifact ca
            WHERE ca.ecosystem = 'rpm' AND ca.name = 'tree'
            LIMIT 1
            """);
        Assert.NotNull(caRow);
        Assert.Equal(sha256, (string)caRow!.content_hash);

        // A tenant_artifact_access row must tie the cache_artifact to this org.
        long taaCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'rpm' AND ca.name = 'tree'
            """,
            new { orgId = _orgId });
        Assert.Equal(1, taaCount);

        // First-fetch mirrors the RPM header's Fedora short license tag ("GPLv2+") into
        // license governance against the global cache_artifact row, mapped to its SPDX
        // identifier so the review queue speaks the same vocabulary as every other
        // ecosystem.
        var licenseRow = await conn.QuerySingleOrDefaultAsync(
            """
            SELECT pvl.license_spdx, pvl.source
            FROM package_version_licenses pvl
            JOIN cache_artifact ca ON ca.id = pvl.cache_artifact_id
            WHERE pvl.owner_kind = 'cache_artifact' AND ca.ecosystem = 'rpm' AND ca.name = 'tree'
            """);
        Assert.NotNull(licenseRow);
        Assert.Equal("GPL-2.0-or-later", (string)licenseRow!.license_spdx);
        Assert.Equal("upstream", (string)licenseRow.source);
    }

    [Fact]
    public async Task Download_LocalMiss_NonSeekableCacheStream_RecordsExactSizeNotZero()
    {
        // S3BlobStore/AzureBlobStore return a non-seekable network stream from GetAsync, so
        // body.CanSeek is false for essentially every RPM proxy fetch on those backends. The
        // recorded size_bytes must still equal the real blob length, not silently fall back
        // to 0 (which corrupts org storage totals and quota accounting).
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        byte[] bytes = RandomBytes(4096);
        string sha256 = Sha256Hex(bytes);
        string filename = "tree-2.1.1-1.fc40.x86_64.rpm";
        var resolution = new PackageResolution(
            PackageUrl: $"https://mirror.example.com/Packages/t/{filename}",
            Sha256: sha256,
            Name: "tree",
            Epoch: 0,
            Version: "2.1.1",
            Release: "1.fc40",
            Arch: "x86_64",
            Summary: "A recursive directory listing command",
            Description: "tree is a recursive...",
            License: "GPLv2+");

        await _blobs.PutAsync(BlobKeys.Proxy(sha256), new MemoryStream(bytes), default);

        var stubProxy = new StubProxy(resolution: resolution);
        var ctl = BuildController(proxy: stubProxy, cacheOverride: new NonSeekableBlobStore(_blobs));

        var result = await ctl.Download(filename, default);
        Assert.IsType<FileStreamResult>(result);

        await using var conn = await _db.OpenAsync();
        long? sizeBytes = await conn.ExecuteScalarAsync<long?>(
            """
            SELECT ca.size_bytes FROM cache_artifact ca
            WHERE ca.ecosystem = 'rpm' AND ca.name = 'tree'
            LIMIT 1
            """);
        Assert.Equal(bytes.Length, sizeBytes);
    }

    [Fact]
    public async Task Download_LocalMiss_OversizedSeekableStream_RecordsExactSizeWithoutInt32Wrap()
    {
        // A seekable stream whose Length exceeds int.MaxValue (a plausible size for large
        // driver/firmware/CUDA RPMs) must record the true long size_bytes rather than
        // silently wrapping to a negative 32-bit value via a narrowing (int) cast.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        const long hugeLength = 2_500_000_000L; // > int.MaxValue (2,147,483,647)
        string sha256 = Sha256Hex(RandomBytes(32));
        string filename = "cuda-toolkit-12.4-1.x86_64.rpm";
        var resolution = new PackageResolution(
            PackageUrl: $"https://mirror.example.com/Packages/c/{filename}",
            Sha256: sha256,
            Name: "cuda-toolkit",
            Epoch: 0,
            Version: "12.4",
            Release: "1",
            Arch: "x86_64",
            Summary: "A large driver package",
            Description: "cuda-toolkit sample",
            License: "Proprietary");

        var stubProxy = new StubProxy(resolution: resolution);
        var ctl = BuildController(proxy: stubProxy, cacheOverride: new FixedLengthSeekableBlobStore(hugeLength));

        var result = await ctl.Download(filename, default);
        Assert.IsType<FileStreamResult>(result);

        await using var conn = await _db.OpenAsync();
        long? sizeBytes = await conn.ExecuteScalarAsync<long?>(
            """
            SELECT ca.size_bytes FROM cache_artifact ca
            WHERE ca.ecosystem = 'rpm' AND ca.name = 'cuda-toolkit'
            LIMIT 1
            """);
        Assert.Equal(hugeLength, sizeBytes);
    }

    [Fact]
    public async Task Download_LocalMiss_UnmappedLicenseTag_MirrorsVerbatimToCacheArtifact()
    {
        // Mixed partial-failure coverage alongside the mapped-tag case above: a compound
        // Fedora boolean expression has no unambiguous SPDX mapping, so the ingest site
        // mirrors it verbatim rather than dropping it — it must still reach the review
        // queue.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        byte[] bytes = RandomBytes(256);
        string sha256 = Sha256Hex(bytes);
        string filename = "dual-licensed-1.0-1.fc40.x86_64.rpm";
        var resolution = new PackageResolution(
            PackageUrl: $"https://mirror.example.com/Packages/d/{filename}",
            Sha256: sha256,
            Name: "dual-licensed",
            Epoch: 0,
            Version: "1.0",
            Release: "1.fc40",
            Arch: "x86_64",
            Summary: "A dual-licensed package",
            Description: "dual-licensed sample",
            License: "GPLv2+ and BSD");

        await _blobs.PutAsync(BlobKeys.Proxy(sha256), new MemoryStream(bytes), default);

        var stubProxy = new StubProxy(resolution: resolution);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download(filename, default);
        Assert.IsType<FileStreamResult>(result);

        await using var conn = await _db.OpenAsync();
        var licenseRow = await conn.QuerySingleOrDefaultAsync(
            """
            SELECT pvl.license_spdx
            FROM package_version_licenses pvl
            JOIN cache_artifact ca ON ca.id = pvl.cache_artifact_id
            WHERE pvl.owner_kind = 'cache_artifact' AND ca.ecosystem = 'rpm' AND ca.name = 'dual-licensed'
            """);
        Assert.NotNull(licenseRow);
        Assert.Equal("GPLv2+ and BSD", (string)licenseRow!.license_spdx);
    }

    [Fact]
    public async Task Download_GlobalPlaneOnly_NoPackageVersionsRow_Serves200()
    {
        // After delete_migrated_proxy_package_versions removes proxy rows from package_versions,
        // proxy artifacts exist only in cache_artifact + tenant_artifact_access. This test verifies
        // the download path serves a proxy RPM that has NO package_versions row — the global
        // plane is the sole source of truth.
        await EnableAnonPullAsync();
        byte[] bytes = RandomBytes(256);
        string sha256 = Sha256Hex(bytes);
        string filename = "curl-8.0.1-1.fc40.x86_64.rpm";
        string caId = Guid.NewGuid().ToString("N");

        // Seed the blob in the cache tier (simulates a previously fetched proxy artifact).
        await _blobs.PutAsync(BlobKeys.Proxy(sha256), new MemoryStream(bytes), default);

        // Seed only global-plane rows — no package_versions row.
        await using var conn = await _db.OpenAsync();
        string pkgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@pkgId, @orgId, 'rpm', 'curl', 'curl', 1)
            """, new { pkgId, orgId = _orgId });
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES (@caId, 'rpm', 'curl', '8.0.1-1.fc40', @filename,
                    @blobKey, @sha256, @size, 'pkg:rpm/curl@8.0.1-1.fc40?arch=x86_64')
            """, new { caId, filename, blobKey = $"proxy/{sha256}", sha256, size = bytes.Length });
        await conn.ExecuteAsync("""
            INSERT INTO tenant_artifact_access
                (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count)
            VALUES (@orgId, @caId, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 1)
            """, new { orgId = _orgId, caId });

        var ctl = BuildController(proxy: null);

        var result = await ctl.Download(filename, default);

        // Global-plane lookup succeeds — artifact served.
        var fsr = Assert.IsType<FileStreamResult>(result);
        Assert.Equal("application/x-rpm", fsr.ContentType);
        using var ms = new MemoryStream();
        await fsr.FileStream.CopyToAsync(ms);
        Assert.Equal(bytes, ms.ToArray());
    }

    [Fact]
    public async Task Download_LegacyProxyFallbackRemoved_ProxyRowNotFound_GoesToGlobalPlane()
    {
        // Regression guard: the legacy fallback (FindVersionByBlobKeySuffixAsync with uploadedOnly=false
        // for proxy rows) was removed in P4. A proxy artifact that no longer has a package_versions row
        // must be served via the global-plane coordinate lookup (ParseNevra → GetServeFactsByCoordinateAsync)
        // and not produce a 404 that would have been a cache-hit if the legacy path were still present.
        await EnableAnonPullAsync();
        byte[] bytes = RandomBytes(256);
        string sha256 = Sha256Hex(bytes);
        string filename = "bash-5.2.15-3.fc40.x86_64.rpm";
        string caId = Guid.NewGuid().ToString("N");

        await _blobs.PutAsync(BlobKeys.Proxy(sha256), new MemoryStream(bytes), default);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES (@caId, 'rpm', 'bash', '5.2.15-3.fc40', @filename,
                    @blobKey, @sha256, @size, 'pkg:rpm/bash@5.2.15-3.fc40?arch=x86_64')
            """, new { caId, filename, blobKey = $"proxy/{sha256}", sha256, size = bytes.Length });
        await conn.ExecuteAsync("""
            INSERT INTO tenant_artifact_access
                (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count)
            VALUES (@orgId, @caId, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 1)
            """, new { orgId = _orgId, caId });

        // No package_versions row — the legacy fallback path would have found nothing;
        // the global-plane path must serve it correctly.
        var ctl = BuildController(proxy: null);
        var result = await ctl.Download(filename, default);

        Assert.IsType<FileStreamResult>(result);
    }

    [Fact]
    public async Task DownloadNested_UpstreamHrefPath_ResolvesViaFlatFilename()
    {
        // dnf composes baseurl + the upstream <location href> ("Packages/t/<file>"),
        // so the nested route must resolve to the same flat-filename download flow.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        byte[] bytes = RandomBytes(256);
        string sha256 = Sha256Hex(bytes);
        string filename = "tree-2.1.1-1.fc40.x86_64.rpm";
        var resolution = new PackageResolution(
            PackageUrl: $"https://mirror.example.com/Packages/t/{filename}",
            Sha256: sha256,
            Name: "tree",
            Epoch: 0,
            Version: "2.1.1",
            Release: "1.fc40",
            Arch: "x86_64",
            Summary: "A recursive directory listing command",
            Description: "tree is a recursive...",
            License: "GPLv2+");

        await _blobs.PutAsync(BlobKeys.Proxy(sha256), new MemoryStream(bytes), default);

        var stubProxy = new StubProxy(resolution: resolution);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.DownloadNested("t", filename, default);

        var fsr = Assert.IsType<FileStreamResult>(result);
        using var ms = new MemoryStream();
        await fsr.FileStream.CopyToAsync(ms);
        Assert.Equal(bytes, ms.ToArray());
        Assert.Equal("application/x-rpm", fsr.ContentType);

        // The proxy must have been asked to resolve the flat filename, not the nested path.
        Assert.Equal(filename, stubProxy.LastResolvedFilename);
    }

    [Fact]
    public async Task DownloadNested_NonRpm_ReturnsBadRequest()
    {
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: new StubProxy(resolution: null));

        var result = await ctl.DownloadNested("r", "repomd.xml", default);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Download_LocalMiss_ResolutionNull_Returns404AndRecordsNegative()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        var stubProxy = new StubProxy(resolution: null);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download("nonexistent-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.True(stubProxy.NegativeRecorded);
    }

    [Fact]
    public async Task Download_LocalMiss_NegativelyCached_Returns404WithoutResolve()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        var stubProxy = new StubProxy(resolution: null, negativeCache: true);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download("cached-neg-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.False(stubProxy.ResolveWasCalled);
    }

    [Fact]
    public async Task Download_NoProxy_Returns404()
    {
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        var result = await ctl.Download("pkg-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_PassthroughDisabled_Returns404()
    {
        await EnableAnonPullAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = _orgId });

        var stubProxy = new StubProxy(resolution: null, assertNotCalled: true);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download("pkg-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.False(stubProxy.ResolveWasCalled);
    }

    [Fact]
    public async Task Download_NoRpmRegistryConfigured_Returns404()
    {
        // Empty upstream list = proxying disabled for the ecosystem, even with the proxy
        // in passthrough mode. The controller must 404 without consulting the proxy.
        await EnableAnonPullAsync();
        // Deliberately no SeedRpmRegistryAsync(): the org has zero configured rpm registries.
        var stubProxy = new StubProxy(resolution: null, assertNotCalled: true);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download("pkg-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.False(stubProxy.ResolveWasCalled);
    }

    // ── Repodata proxy ────────────────────────────────────────────────────────

    [Fact]
    public async Task Repodata_RepomdXml_Passthrough_Returns200WithETag()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        byte[] repomdBytes = System.Text.Encoding.UTF8.GetBytes("<repomd/>");
        var repodata = new RepodataResult(new MemoryStream(repomdBytes), "application/xml", "\"abc\"", null, NotModified: false);
        var stubProxy = new StubProxy(repodataResult: repodata);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Repodata("repomd.xml", default);

        var fc = Assert.IsType<FileStreamResult>(result);
        Assert.Equal(repomdBytes, await ReadAllAsync(fc.FileStream));
        Assert.Equal("application/xml", fc.ContentType);
    }

    [Fact]
    public async Task Repodata_RepomdXml_Passthrough_304Propagated()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        var repodata = new RepodataResult(Stream.Null, "application/xml", "\"abc\"", null, NotModified: true);
        var stubProxy = new StubProxy(repodataResult: repodata);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Headers.IfNoneMatch = "\"abc\"";

        var result = await ctl.Repodata("repomd.xml", default);

        Assert.Equal(304, ((StatusCodeResult)result).StatusCode);
    }

    [Fact]
    public async Task Repodata_HashPrefixedFile_PassthroughServes()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        string sha256 = new('a', 64);
        string filename = $"{sha256}-primary.xml.gz";
        byte[] body = new byte[] { 1, 2, 3 };
        var repodata = new RepodataResult(new MemoryStream(body), "application/x-gzip", null, null, NotModified: false);
        var stubProxy = new StubProxy(repodataResult: repodata);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Repodata(filename, default);

        var fc = Assert.IsType<FileStreamResult>(result);
        Assert.Equal(body, await ReadAllAsync(fc.FileStream));
        Assert.Equal("application/x-gzip", fc.ContentType);
    }

    [Fact]
    public async Task Repodata_NoUpstream_ServesLocalRepomd()
    {
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        // With an empty org (no packages), local repomd.xml should still return 200.
        var result = await ctl.Repodata("repomd.xml", default);

        var fc = Assert.IsType<FileContentResult>(result);
        Assert.Equal("application/xml", fc.ContentType);
    }

    // ── GPG key ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GpgKey_ProxyReturnsKey_Returns200WithCorrectContentType()
    {
        await SeedRpmRegistryAsync();
        byte[] keyBytes = System.Text.Encoding.ASCII.GetBytes("-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
        var stubProxy = new StubProxy(gpgKey: keyBytes);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.GpgKey(default);

        var fc = Assert.IsType<FileContentResult>(result);
        Assert.Equal(keyBytes, fc.FileContents);
        Assert.Equal("application/pgp-keys", fc.ContentType);
    }

    [Fact]
    public async Task GpgKey_NoProxy_Returns404()
    {
        var ctl = BuildController(proxy: null);
        var result = await ctl.GpgKey(default);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Upload passthrough refusal ────────────────────────────────────────────

    [Fact]
    public async Task Upload_PassthroughMode_Returns409WithProblemDetails()
    {
        await SeedRpmRegistryAsync();
        var stubProxy = new StubProxy(isPassthrough: true);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream();

        var result = await ctl.Upload(default);

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        var problem = Assert.IsType<ProblemDetails>(conflict.Value);
        Assert.Equal(409, problem.Status);
        Assert.Contains("passthrough", problem.Detail, StringComparison.OrdinalIgnoreCase);
        // The detail points the operator at the per-org Settings → Proxy control, not the env var.
        Assert.Contains("Settings", problem.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("merged", problem.Detail, StringComparison.OrdinalIgnoreCase);
    }

    // ── Per-org upstream-mode override ───────────────────────────────────────────

    [Fact]
    public async Task Upload_InstancePassthrough_OrgMerged_NotBlockedByPassthroughGuard()
    {
        // The instance env mode is passthrough (stub IsPassthroughModeSelected=true), yet the org
        // has opted into 'merged' via its per-org setting. The publish guard must honor the per-org
        // setting and let the request through — hosted publish enabled without an instance restart.
        await SeedRpmRegistryAsync();
        await SetRpmUpstreamModeAsync("merged");
        string raw = await SeedPublishTokenAsync();
        var stubProxy = new StubProxy(isPassthrough: true, isMerged: false);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {raw}";
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream(new byte[10]);

        var result = await ctl.Upload(default);

        Assert.IsNotType<ConflictObjectResult>(result);
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("too small", bad.Value?.ToString() ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Upload_InstancePassthrough_OrgPassthrough_Returns409()
    {
        // Both the instance env and the per-org setting are passthrough with an upstream configured
        // — the guard returns 409. Setting the org back to passthrough re-arms the block.
        await SeedRpmRegistryAsync();
        await SetRpmUpstreamModeAsync("passthrough");
        var stubProxy = new StubProxy(isPassthrough: true, isMerged: false);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream();

        var result = await ctl.Upload(default);

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        Assert.Equal(409, Assert.IsType<ProblemDetails>(conflict.Value).Status);
    }

    [Fact]
    public async Task Upload_InstanceMerged_OrgPassthrough_Returns409()
    {
        // Pins the override-not-floor semantics: the instance env is 'merged' (stub
        // IsMergedModeSelected=true), yet the org has explicitly overridden to 'passthrough'. The
        // explicit org value must win in EITHER direction, so hosted publish is refused here even
        // though the instance-wide default is merged. Under the old OR-floor composition
        // (effective = env-merged OR org-merged) this returned success — the org could never
        // downgrade below a merged instance. That is the regression this test pins.
        await SeedRpmRegistryAsync();
        await SetRpmUpstreamModeAsync("passthrough");
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream();

        var result = await ctl.Upload(default);

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        Assert.Equal(409, Assert.IsType<ProblemDetails>(conflict.Value).Status);
    }

    [Fact]
    public async Task Upload_InstanceMerged_OrgUnset_InheritsEnv_NotBlocked()
    {
        // No per-org override (NULL) on a merged instance inherits the env value — hosted
        // publish succeeds. Confirms NULL means "inherit", not "passthrough".
        await SeedRpmRegistryAsync();
        await SetRpmUpstreamModeAsync(null);
        string raw = await SeedPublishTokenAsync();
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {raw}";
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream(new byte[10]);

        var result = await ctl.Upload(default);

        Assert.IsNotType<ConflictObjectResult>(result);
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("too small", bad.Value?.ToString() ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Upload_InstancePassthrough_OrgUnset_InheritsEnv_Returns409()
    {
        // No per-org override (NULL) on a passthrough instance inherits the env value — hosted
        // publish is refused, matching pre-migration behaviour for an org that never opts in.
        await SeedRpmRegistryAsync();
        await SetRpmUpstreamModeAsync(null);
        var stubProxy = new StubProxy(isPassthrough: true, isMerged: false);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream();

        var result = await ctl.Upload(default);

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        Assert.Equal(409, Assert.IsType<ProblemDetails>(conflict.Value).Status);
    }

    // ── Merged mode ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Repodata_MergedMode_RepomdAndPrimary_UnionLocalAndUpstream_Consistent()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        await SeedLocalRpmAsync("hello", "2.10", "1.el9", "x86_64");

        // Upstream advertises a colliding hello (must be shadowed) + a unique tree (must survive).
        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("hello", "2.10", "1.el9", "x86_64", "Packages/h/hello-2.10-1.el9.x86_64.rpm"),
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true, upstreamPrimaryGz: upstreamGz);

        // Same controller instance for both calls so they share the merged-primary cache —
        // dnf fetches repomd.xml first, then the primary.xml.gz it points at.
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var primaryResult = Assert.IsType<FileContentResult>(await ctl.Repodata("primary.xml.gz", default));

        // The SHA-256 repomd seals must match the exact primary.xml.gz bytes served.
        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var repomd = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));
        string sealedSha = repomd.Descendants(repo + "checksum").First().Value;
        Assert.Equal(Sha256Hex(primaryResult.FileContents), sealedSha);

        // The served primary unions local hello (flat href, shadowing upstream) + upstream tree.
        XNamespace common = "http://linux.duke.edu/metadata/common";
        var primaryDoc = XDocument.Parse(Gunzip(primaryResult.FileContents));
        var names = primaryDoc.Root!.Elements(common + "package")
            .Select(p => p.Element(common + "name")!.Value).OrderBy(n => n).ToList();
        Assert.Equal(new[] { "hello", "tree" }, names);

        var hello = primaryDoc.Root.Elements(common + "package")
            .Single(p => p.Element(common + "name")!.Value == "hello");
        Assert.Equal("packages/hello-2.10-1.el9.x86_64.rpm",
            hello.Element(common + "location")!.Attribute("href")!.Value);
        var tree = primaryDoc.Root.Elements(common + "package")
            .Single(p => p.Element(common + "name")!.Value == "tree");
        Assert.Equal("packages/tree-2.1.1-1.el9.x86_64.rpm",
            tree.Element(common + "location")!.Attribute("href")!.Value);
    }

    [Fact]
    public async Task Repodata_MergedMode_UpstreamUnreachable_FallsBackToLocalRepomd()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        // upstreamPrimaryGz null ⇒ GetUpstreamPrimaryXmlGzAsync returns null ⇒ fall back to local.
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true, upstreamPrimaryGz: null);
        var ctl = BuildController(proxy: stubProxy);

        var result = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        Assert.Equal("application/xml", result.ContentType);
    }

    [Fact]
    public async Task Repodata_MergedMode_RepomdContainsPrimaryAndFilelistsEntries()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        await SeedLocalRpmAsync("hello", "2.10", "1.el9", "x86_64");

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true, upstreamPrimaryGz: upstreamGz);
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var filelistsResult = Assert.IsType<FileContentResult>(await ctl.Repodata("filelists.xml.gz", default));

        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.Contains("primary", types);
        Assert.Contains("filelists", types);

        // The filelists sha256 in repomd must match the actual bytes served.
        var filelistsEntry = repomdDoc.Root.Elements(repo + "data")
            .Single(e => (string?)e.Attribute("type") == "filelists");
        string sealedSha = filelistsEntry.Element(repo + "checksum")!.Value;
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(filelistsResult.FileContents)).ToLowerInvariant(),
            sealedSha);
    }

    [Fact]
    public async Task Repodata_MergedMode_UpstreamNonPrimaryEntriesPreserved()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();

        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var updateinfoEntry = new XElement(repo + "data",
            new XAttribute("type", "updateinfo"),
            new XElement(repo + "location",
                new XAttribute("href", $"repodata/{new string('a', 64)}-updateinfo.xml.gz")));

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));
        var stubProxy = new StubProxy(
            isPassthrough: false,
            isMerged: true,
            upstreamPrimaryGz: upstreamGz,
            upstreamNonPrimaryEntries: new[] { updateinfoEntry });
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.Contains("updateinfo", types);
    }

    [Fact]
    public async Task Repodata_MergedMode_AdvertisedHrefs_AllServable_UpstreamEntryProxied()
    {
        // Merged repomd advertises an upstream updateinfo entry. dnf fetches repomd.xml and then
        // follows every advertised href — none may 404, and the hash-prefixed updateinfo href
        // must be proxied through the upstream fetch path with the upstream's exact bytes.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();

        string sha256 = new('c', 64);
        string updateinfoFilename = $"{sha256}-updateinfo.xml.gz";
        byte[] updateinfoBytes = System.Text.Encoding.UTF8.GetBytes("<updates/>");

        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var updateinfoEntry = new XElement(repo + "data",
            new XAttribute("type", "updateinfo"),
            new XElement(repo + "location",
                new XAttribute("href", $"repodata/{updateinfoFilename}")));

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));

        // The stub returns the updateinfo bytes for hash-prefixed GetRepodataAsync calls only,
        // mirroring the real proxy's filename gate.
        var repodataResult = new RepodataResult(new MemoryStream(updateinfoBytes), "application/x-gzip", null, null, NotModified: false);
        var stubProxy = new StubProxy(
            isPassthrough: false,
            isMerged: true,
            upstreamPrimaryGz: upstreamGz,
            upstreamNonPrimaryEntries: new[] { updateinfoEntry },
            repodataResult: repodataResult);
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var hrefs = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => e.Element(repo + "location")!.Attribute("href")!.Value)
            .ToList();
        Assert.Contains($"repodata/{updateinfoFilename}", hrefs);

        // Every advertised href must be fetchable — the contract dnf relies on.
        foreach (string href in hrefs)
        {
            string filename = href[(href.LastIndexOf('/') + 1)..];
            var fetched = await ctl.Repodata(filename, default);
            Assert.IsNotType<NotFoundResult>(fetched);
        }

        // The advertised updateinfo href serves the upstream stub's exact bytes.
        var result = Assert.IsType<FileStreamResult>(await ctl.Repodata(updateinfoFilename, default));
        Assert.Equal("application/x-gzip", result.ContentType);
        Assert.Equal(updateinfoBytes, await ReadAllAsync(result.FileStream));
    }

    [Fact]
    public async Task Repodata_MergedMode_PlainNamedUpstreamEntry_DroppedFromMergedRepomd()
    {
        // An upstream entry with a plain (non-content-addressed) href — e.g. classic-createrepo
        // comps.xml.gz — cannot be proxied by the repodata dispatch. It must be dropped from the
        // merged repomd rather than advertised as an href that would 404; dnf treats absent
        // supplemental metadata as non-fatal.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();

        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var compsEntry = new XElement(repo + "data",
            new XAttribute("type", "group"),
            new XElement(repo + "location",
                new XAttribute("href", "repodata/comps.xml.gz")));

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));
        var stubProxy = new StubProxy(
            isPassthrough: false,
            isMerged: true,
            upstreamPrimaryGz: upstreamGz,
            upstreamNonPrimaryEntries: new[] { compsEntry });
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.DoesNotContain("group", types);
    }

    [Fact]
    public async Task Repodata_LocalMode_ServesFilelistsAndOtherXmlGz()
    {
        await EnableAnonPullAsync();

        var ctl = BuildController(proxy: null);

        var filelistsResult = Assert.IsType<FileContentResult>(await ctl.Repodata("filelists.xml.gz", default));
        Assert.Equal("application/x-gzip", filelistsResult.ContentType);

        var otherResult = Assert.IsType<FileContentResult>(await ctl.Repodata("other.xml.gz", default));
        Assert.Equal("application/x-gzip", otherResult.ContentType);
    }

    [Fact]
    public async Task Repodata_LocalMode_RepomdContainsPrimaryFilelistsOther()
    {
        await EnableAnonPullAsync();

        var ctl = BuildController(proxy: null);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var doc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = doc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).OrderBy(t => t).ToList();
        Assert.Equal(new[] { "filelists", "other", "primary" }, types);
    }

    [Fact]
    public async Task Upload_MergedMode_NotBlockedByPassthroughGuard()
    {
        // Merged mode must NOT trip the passthrough publish guard. With a valid token the request
        // flows past the guard into the normal upload pipeline (here a too-small body → 400),
        // proving it is no longer the 409 conflict passthrough returns.
        await SeedRpmRegistryAsync();
        string raw = await SeedPublishTokenAsync();
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {raw}";
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream(new byte[10]);

        var result = await ctl.Upload(default);

        Assert.IsNotType<ConflictObjectResult>(result);
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("too small", bad.Value?.ToString() ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // ── Group/module metadata limitation ─────────────────────────────────────

    [Fact]
    public async Task Repodata_LocalMode_CompsXmlGz_Returns404_NoBrokenDocumentServed()
    {
        // Dependably does not generate comps (group) metadata for locally published RPMs.
        // A request for comps.xml.gz in local-only mode must return 404, not an empty or
        // malformed XML document. dnf treats absent supplemental metadata as non-fatal.
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        var result = await ctl.Repodata("comps.xml.gz", default);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Repodata_LocalMode_ModulesYaml_Returns404_NoBrokenDocumentServed()
    {
        // Same limitation for modulemd — modular (AppStream) metadata is not generated by
        // Dependably for locally published RPMs.
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        var result = await ctl.Repodata("modules.yaml.gz", default);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Repodata_LocalMode_RepomdDoesNotAdvertiseGroupOrModules()
    {
        // The locally generated repomd.xml must not advertise group, modules, or any supplemental
        // metadata entry — only primary, filelists, and other are generated locally.
        // Advertising an entry that returns 404 would break dnf's metadata integrity check.
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var doc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = doc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.DoesNotContain("group", types);
        Assert.DoesNotContain("modules", types);
        Assert.DoesNotContain("comps", types);
    }

    [Fact]
    public async Task Repodata_MergedMode_MixedPartialResult_LocalPackageAndUpstreamGroupBothHandled()
    {
        // Mixed partial-failure scenario (house rule): merged mode where the repo contains a
        // locally published package (appears in primary/filelists as expected), the upstream
        // has a hash-prefixed group entry (forwarded verbatim), AND the upstream has a
        // plain-named comps entry (dropped). All three outcomes must hold in the same response.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        await SeedLocalRpmAsync("myapp", "1.0", "1.el9", "x86_64");

        string groupSha = new('e', 64);
        string groupFilename = $"{groupSha}-comps.xml.gz";

        XNamespace repo = "http://linux.duke.edu/metadata/repo";

        // Upstream provides two supplemental entries:
        //   1. hash-prefixed group — servable, must appear in merged repomd
        //   2. plain-named comps — not servable, must be dropped from merged repomd
        var hashPrefixedGroupEntry = new XElement(repo + "data",
            new XAttribute("type", "group"),
            new XElement(repo + "location",
                new XAttribute("href", $"repodata/{groupFilename}")));
        var plainCompsEntry = new XElement(repo + "data",
            new XAttribute("type", "group"),
            new XElement(repo + "location",
                new XAttribute("href", "repodata/comps.xml.gz")));

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("upstream-lib", "2.0", "1.el9", "x86_64", "Packages/u/upstream-lib-2.0-1.el9.x86_64.rpm"));

        var stubProxy = new StubProxy(
            isPassthrough: false,
            isMerged: true,
            upstreamPrimaryGz: upstreamGz,
            upstreamNonPrimaryEntries: new[] { hashPrefixedGroupEntry, plainCompsEntry });
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var primaryResult = Assert.IsType<FileContentResult>(await ctl.Repodata("primary.xml.gz", default));

        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));
        var advertisedTypes = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();

        // Local package appears in primary union.
        XNamespace common = "http://linux.duke.edu/metadata/common";
        var primaryDoc = XDocument.Parse(Gunzip(primaryResult.FileContents));
        var names = primaryDoc.Root!.Elements(common + "package")
            .Select(p => p.Element(common + "name")!.Value).OrderBy(n => n).ToList();
        Assert.Contains("myapp", names);
        Assert.Contains("upstream-lib", names);

        // Hash-prefixed group entry is forwarded — it appears in the merged repomd.
        Assert.Contains("group", advertisedTypes);
        var groupEntry = repomdDoc.Root.Elements(repo + "data")
            .Single(e => (string?)e.Attribute("type") == "group");
        Assert.Contains(groupFilename, groupEntry.Element(repo + "location")!.Attribute("href")!.Value);

        // Plain-named comps entry is dropped — only one group entry (the hash-prefixed one).
        Assert.Single(repomdDoc.Root.Elements(repo + "data"),
            e => (string?)e.Attribute("type") == "group");

        // comps.xml.gz (plain-named, not content-addressed) returns 404 — not a broken document.
        var compsResult = await ctl.Repodata("comps.xml.gz", default);
        Assert.IsType<NotFoundResult>(compsResult);
    }

    private async Task<string> SeedPublishTokenAsync()
    {
        var (raw, _) = await _tokens.CreateUserTokenAsync(
            _orgId, _userId, """["publish:rpm"]""", expiresAt: null);
        return raw;
    }

    private async Task SeedLocalRpmAsync(string name, string ver, string rel, string arch)
    {
        string pkgId = await PackageSeeder.InsertAsync(_db, _orgId, "rpm", name, purlName: name);
        string pvId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId,
            version: $"{ver}-{rel}",
            purl: $"pkg:rpm/{name}@{ver}-{rel}?arch={arch}",
            blobKey: $"rpm/registry/{name}-{ver}-{rel}.{arch}.rpm",
            checksumSha256: new string('a', 64));
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, package_version_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, installed_size, archive_size, header_start, header_end, rpm_license)
            VALUES (lower(hex(randomblob(16))), @pvId, 'package_version',
                    @name, 0, @ver, @rel, @arch, 'sum', 'desc', 1, 1, 0, 1, 'MIT')
            """,
            new { pvId, name, ver, rel, arch });
    }

    private static byte[] BuildUpstreamPrimaryGz(
        params (string Name, string Ver, string Rel, string Arch, string Href)[] pkgs)
    {
        XNamespace common = "http://linux.duke.edu/metadata/common";
        XNamespace rpm = "http://linux.duke.edu/metadata/rpm";
        var doc = new XDocument(
            new XElement(common + "metadata",
                new XAttribute(XNamespace.Xmlns + "rpm", rpm.NamespaceName),
                new XAttribute("packages", pkgs.Length),
                pkgs.Select(p => new XElement(common + "package",
                    new XAttribute("type", "rpm"),
                    new XElement(common + "name", p.Name),
                    new XElement(common + "arch", p.Arch),
                    new XElement(common + "version",
                        new XAttribute("epoch", 0), new XAttribute("ver", p.Ver), new XAttribute("rel", p.Rel)),
                    new XElement(common + "checksum",
                        new XAttribute("type", "sha256"), new XAttribute("pkgid", "YES"), new string('b', 64)),
                    new XElement(common + "size",
                        new XAttribute("package", 1), new XAttribute("installed", 1), new XAttribute("archive", 1)),
                    new XElement(common + "location", new XAttribute("href", p.Href)),
                    new XElement(common + "format", new XElement(rpm + "license", "MIT"))))));
        return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(doc.ToString()));
    }

    private static string Gunzip(byte[] gz)
    {
        using var input = new System.IO.Compression.GZipStream(
            new MemoryStream(gz), System.IO.Compression.CompressionMode.Decompress);
        using var ms = new MemoryStream();
        input.CopyTo(ms);
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }

    // ── Controller builder ────────────────────────────────────────────────────

    private RpmController BuildController(IRpmUpstreamProxy? proxy = null, IBlobStore? cacheOverride = null)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("rpm-proxy-org.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "rpm-proxy-org");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, _userId),
                new Claim("sub", _userId),
                new Claim("org_id", _orgId),
                new Claim("tid", _orgId),
                new Claim("role", "admin"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var services = new ServiceCollection();
        services.AddLogging();
        http.RequestServices = services.BuildServiceProvider();

        // Build a real UpstreamClient that reads from _blobs (cache tier), or from
        // cacheOverride when a test needs to control the exact Stream shape (e.g.
        // non-seekable) returned from the cache-tier lookup.
        var cacheStore = cacheOverride ?? _blobs;
        var upstreamClient = BuildRealUpstreamClient(cacheStore);

        var cacheArtifacts = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var cacheRecorder = new CacheAccessRecorder(cacheArtifacts, tenantAccess,
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var svc = new RpmControllerServices(
            Packages: _packages,
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            BlobStore: new TieredBlobStorage(cacheStore, _blobs),
            Db: _db,
            Repodata: new RpmRepodataService(_db, NullLogger<RpmRepodataService>.Instance, TimeProvider.System),
            Registries: new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured())),
            MergedRepodataCache: new MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache>(
                new MemoryCache(new MemoryCacheOptions()), MetadataCacheKeys.RpmMergedRepodata),
            LocalRepodataCache: new RenderedResponseCache<RpmLocalRepodataKey>(
                new MemoryCache(new MemoryCacheOptions()), MetadataCacheKeys.RpmLocalRepodata),
            Time: TimeProvider.System,
            CacheRecorder: cacheRecorder,
            CacheArtifacts: cacheArtifacts,
            TenantAccess: tenantAccess,
            // No trust anchors seeded — IsConfiguredForAsync returns false, provenance skipped.
            RpmProvenance: new Dependably.Protocol.Provenance.RpmProvenanceVerifier(
                new StubPerOrgTrustAnchorStore(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.RpmProvenanceVerifier>.Instance),
            EdgeGuard: Dependably.Tests.Infrastructure.TestEdgeMode.DisabledPublishGuard(),
            BlockGate: Dependably.Tests.Infrastructure.TestBlockGate.Create(_db, TimeProvider.System),
            Staging: new Dependably.Infrastructure.StagingOptions(System.IO.Path.GetTempPath(), 0),
            Licenses: new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)),
            UpstreamClient: upstreamClient,
            Proxy: proxy);

        return new RpmController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private UpstreamClient BuildRealUpstreamClient(IBlobStore? cacheOverride = null)
    {
        // UpstreamClient with no-op HttpClient (should not be called — blobs are pre-staged).
        var httpFactory = new NullHttpClientFactory();
        return new UpstreamClient(
            httpFactory,
            new TieredBlobStorage(cacheOverride ?? _blobs, _blobs),
            _audit,
            new AllowAllValidator(),
            new DisabledAirGap(),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(Path.GetTempPath()),
            Dependably.Infrastructure.StagingOptions.Resolve(new ConfigurationBuilder().Build()),
            NullLogger<UpstreamClient>.Instance);
    }

    private static byte[] RandomBytes(int n = 64)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] d)
        => Convert.ToHexString(SHA256.HashData(d)).ToLowerInvariant();

    private static async Task<byte[]> ReadAllAsync(Stream stream)
    {
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms);
        return ms.ToArray();
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    /// <summary>
    /// Stub implementation of <see cref="IRpmUpstreamProxy"/> for controller unit tests.
    /// All methods return the pre-configured values; call tracking lets tests assert
    /// that methods were (or were not) called.
    /// </summary>
    private sealed class StubProxy : IRpmUpstreamProxy
    {
        private readonly PackageResolution? _resolution;
        private readonly bool _negativeCache;
        private readonly RepodataResult? _repodataResult;
        private readonly byte[]? _gpgKey;
        private readonly byte[]? _upstreamPrimaryGz;
        private readonly bool _assertNotCalled;
        private readonly IReadOnlyList<XElement> _upstreamNonPrimaryEntries;

        public bool NegativeRecorded { get; private set; }
        public bool ResolveWasCalled { get; private set; }
        public string? LastResolvedFilename { get; private set; }
        public string? LastUpstreamBase { get; private set; }

        public StubProxy(
            PackageResolution? resolution = null,
            bool negativeCache = false,
            RepodataResult? repodataResult = null,
            byte[]? gpgKey = null,
            bool isPassthrough = true,
            bool isMerged = false,
            byte[]? upstreamPrimaryGz = null,
            bool assertNotCalled = false,
            IReadOnlyList<XElement>? upstreamNonPrimaryEntries = null)
        {
            _resolution = resolution;
            _negativeCache = negativeCache;
            _repodataResult = repodataResult;
            _gpgKey = gpgKey;
            IsPassthroughModeSelected = isPassthrough;
            IsMergedModeSelected = isMerged;
            _upstreamPrimaryGz = upstreamPrimaryGz;
            _assertNotCalled = assertNotCalled;
            _upstreamNonPrimaryEntries = upstreamNonPrimaryEntries ?? Array.Empty<XElement>();
        }

        public bool IsPassthroughModeSelected { get; }
        public bool IsMergedModeSelected { get; }

        public Task<byte[]?> GetUpstreamPrimaryXmlGzAsync(string orgId, string upstreamBase, CancellationToken ct)
        {
            LastUpstreamBase = upstreamBase;
            return Task.FromResult(_upstreamPrimaryGz);
        }

        public Task<byte[]?> GetUpstreamFilelistsXmlGzAsync(string orgId, string upstreamBase, CancellationToken ct)
            => Task.FromResult<byte[]?>(null);

        public Task<IReadOnlyList<XElement>> GetUpstreamNonPrimaryRepomdEntriesAsync(string orgId, string upstreamBase, CancellationToken ct)
            => Task.FromResult(_upstreamNonPrimaryEntries);

        public Task<PackageResolution?> ResolvePackageUrlAsync(string orgId, string upstreamBase, string filename, CancellationToken ct)
        {
            if (_assertNotCalled)
            {
                throw new InvalidOperationException($"ResolvePackageUrlAsync must not be called (filename={filename})");
            }

            ResolveWasCalled = true;
            LastResolvedFilename = filename;
            LastUpstreamBase = upstreamBase;
            return Task.FromResult(_resolution);
        }

        public Task<bool> IsNegativelyCachedAsync(string path, CancellationToken ct)
            => Task.FromResult(_negativeCache);

        public Task RecordNegativeAsync(string path, CancellationToken ct)
        {
            NegativeRecorded = true;
            return Task.CompletedTask;
        }

        public Task<RepodataResult?> GetRepodataAsync(string upstreamBase, string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct)
        {
            LastUpstreamBase = upstreamBase;

            // Mirror the real proxy's filename gate: only repomd passthrough names and
            // hash-prefixed (content-addressed) filenames are fetchable upstream.
            bool servable = filename.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase)
                || filename.Equals("repomd.xml.asc", StringComparison.OrdinalIgnoreCase)
                || RpmUpstreamProxy.IsHashPrefixedFilename(filename);
            return Task.FromResult(servable ? _repodataResult : null);
        }

        public Task<byte[]?> GetGpgKeyAsync(string upstreamBase, CancellationToken ct)
        {
            LastUpstreamBase = upstreamBase;
            return Task.FromResult(_gpgKey);
        }
    }

    private sealed class NullHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new NullHandler());

        private sealed class NullHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
                => throw new InvalidOperationException("HTTP calls should not be made in proxy controller tests — pre-stage blobs instead.");
        }
    }

    private sealed class DisabledAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    /// <summary>
    /// Wraps a real <see cref="IBlobStore"/> but returns a non-seekable stream from
    /// <see cref="GetAsync"/>, mirroring S3BlobStore/AzureBlobStore's network response
    /// streams. <see cref="GetRangeAsync"/> still delegates to the inner store, matching
    /// the real object-store backends where a range/metadata lookup is a distinct,
    /// seekable-independent operation.
    /// </summary>
    private sealed class NonSeekableBlobStore(IBlobStore inner) : IBlobStore
    {
        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => inner.PutAsync(key, data, ct);

        public async Task<Stream?> GetAsync(string key, CancellationToken ct = default)
        {
            var stream = await inner.GetAsync(key, ct);
            return stream is null ? null : new NonSeekableStreamWrapper(stream);
        }

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => inner.ExistsAsync(key, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default) => inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => inner.GetTotalSizeAsync(ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => inner.GetRangeAsync(key, from, to, ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => inner.ListAsync(prefix, ct);
    }

    /// <summary>Forces <see cref="CanSeek"/>/<see cref="Length"/> to behave like a non-seekable
    /// network stream (AWS SDK / Azure SDK download streams) while still delegating reads.</summary>
    private sealed class NonSeekableStreamWrapper(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
            => inner.ReadAsync(buffer, offset, count, ct);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
            => inner.ReadAsync(buffer, ct);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync() => inner.DisposeAsync();
    }

    /// <summary>
    /// Returns a seekable stream that reports a fixed <see cref="Stream.Length"/> above
    /// <see cref="int.MaxValue"/> without allocating real backing bytes, so a >2 GiB RPM
    /// can be simulated cheaply. <see cref="GetRangeAsync"/> reports the same length so the
    /// non-seekable fallback path (not exercised for a seekable stream) would also agree.
    /// Reads are never exercised by these tests — the controller only inspects
    /// <see cref="Stream.CanSeek"/>/<see cref="Stream.Length"/> before handing the stream to
    /// <c>File(...)</c> without copying it.
    /// </summary>
    private sealed class FixedLengthSeekableBlobStore(long length) : IBlobStore
    {
        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Task.CompletedTask;

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
            => Task.FromResult<Stream?>(new FixedLengthSeekableStream(length));

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => Task.FromResult(true);

        public Task DeleteAsync(string key, CancellationToken ct = default) => Task.CompletedTask;

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Task.FromResult(length);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => Task.FromResult<RangedStream?>(new RangedStream(Stream.Null, from, to, length));

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => Empty();

        private static async IAsyncEnumerable<BlobInfo> Empty()
        {
            await Task.Yield();
            yield break;
        }

        private sealed class FixedLengthSeekableStream(long length) : Stream
        {
            private long _position;

            public override bool CanRead => true;
            public override bool CanSeek => true;
            public override bool CanWrite => false;
            public override long Length { get; } = length;
            public override long Position
            {
                get => _position;
                set => _position = value;
            }

            public override int Read(byte[] buffer, int offset, int count)
                => throw new InvalidOperationException("Bytes are never read from a size-only fake stream.");
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => _position = offset;
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
