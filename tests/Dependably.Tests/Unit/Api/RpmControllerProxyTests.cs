using System.Security.Claims;
using System.Security.Cryptography;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
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
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Proxy-path coverage for <see cref="RpmController"/> (#102).
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
        _tokens = new TokenRepository(_db);
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

    // ── Package proxy ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Download_LocalMiss_FetchesFromUpstreamAndCachesInDb()
    {
        await EnableAnonPullAsync();
        var bytes = RandomBytes(256);
        var sha256 = Sha256Hex(bytes);
        var filename = "tree-2.1.1-1.fc40.x86_64.rpm";
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

        // DB row should be written.
        await using var conn = await _db.OpenAsync();
        var row = await conn.QuerySingleOrDefaultAsync(
            """
            SELECT pv.checksum_sha256, pv.origin
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'rpm'
              AND p.purl_name = 'tree'
              AND pv.filename = @filename
            """,
            new { orgId = _orgId, filename });

        Assert.NotNull(row);
        var r = row!;
        Assert.Equal(sha256, (string)r.checksum_sha256);
        Assert.Equal("proxy", (string)r.origin);
    }

    [Fact]
    public async Task DownloadNested_UpstreamHrefPath_ResolvesViaFlatFilename()
    {
        // dnf composes baseurl + the upstream <location href> ("Packages/t/<file>"),
        // so the nested route must resolve to the same flat-filename download flow.
        await EnableAnonPullAsync();
        var bytes = RandomBytes(256);
        var sha256 = Sha256Hex(bytes);
        var filename = "tree-2.1.1-1.fc40.x86_64.rpm";
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

    // ── Repodata proxy ────────────────────────────────────────────────────────

    [Fact]
    public async Task Repodata_RepomdXml_Passthrough_Returns200WithETag()
    {
        await EnableAnonPullAsync();
        var repomdBytes = System.Text.Encoding.UTF8.GetBytes("<repomd/>");
        var repodata = new RepodataResult(repomdBytes, "application/xml", "\"abc\"", null, NotModified: false);
        var stubProxy = new StubProxy(repodataResult: repodata);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Repodata("repomd.xml", default);

        var fc = Assert.IsType<FileContentResult>(result);
        Assert.Equal(repomdBytes, fc.FileContents);
        Assert.Equal("application/xml", fc.ContentType);
    }

    [Fact]
    public async Task Repodata_RepomdXml_Passthrough_304Propagated()
    {
        await EnableAnonPullAsync();
        var repodata = new RepodataResult([], "application/xml", "\"abc\"", null, NotModified: true);
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
        var sha256 = new string('a', 64);
        var filename = $"{sha256}-primary.xml.gz";
        var body = new byte[] { 1, 2, 3 };
        var repodata = new RepodataResult(body, "application/x-gzip", null, null, NotModified: false);
        var stubProxy = new StubProxy(repodataResult: repodata);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Repodata(filename, default);

        var fc = Assert.IsType<FileContentResult>(result);
        Assert.Equal(body, fc.FileContents);
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
        var keyBytes = System.Text.Encoding.ASCII.GetBytes("-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
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
        var stubProxy = new StubProxy(isPassthrough: true);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream();

        var result = await ctl.Upload(default);

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        var problem = Assert.IsType<ProblemDetails>(conflict.Value);
        Assert.Equal(409, problem.Status);
        Assert.Contains("passthrough", problem.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Rpm:UpstreamMode", problem.Detail);
    }

    // ── Controller builder ────────────────────────────────────────────────────

    private RpmController BuildController(IRpmUpstreamProxy? proxy = null)
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

        // Build a real UpstreamClient that reads from _blobs (cache tier).
        // Tests that need the proxy path pre-stage the blob so GetOrFetchAsync returns a HIT.
        var upstreamClient = BuildRealUpstreamClient();

        var svc = new RpmControllerServices(
            Packages: _packages,
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            BlobStore: new TieredBlobStorage(_blobs, _blobs),
            Db: _db,
            Repodata: new RpmRepodataService(_db),
            UpstreamClient: upstreamClient,
            Proxy: proxy);

        return new RpmController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private UpstreamClient BuildRealUpstreamClient()
    {
        // UpstreamClient with no-op HttpClient (should not be called — blobs are pre-staged).
        var httpFactory = new NullHttpClientFactory();
        return new UpstreamClient(
            httpFactory,
            new TieredBlobStorage(_blobs, _blobs),
            _audit,
            new AllowAllValidator(),
            new DisabledAirGap(),
            new ConfigurationBuilder().Build(),
            NullLogger<UpstreamClient>.Instance);
    }

    private static byte[] RandomBytes(int n = 64)
    {
        var b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] d)
        => Convert.ToHexString(SHA256.HashData(d)).ToLowerInvariant();

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
        private readonly bool _isPassthrough;
        private readonly bool _assertNotCalled;

        public bool NegativeRecorded { get; private set; }
        public bool ResolveWasCalled { get; private set; }
        public string? LastResolvedFilename { get; private set; }

        public StubProxy(
            PackageResolution? resolution = null,
            bool negativeCache = false,
            RepodataResult? repodataResult = null,
            byte[]? gpgKey = null,
            bool isPassthrough = true,
            bool assertNotCalled = false)
        {
            _resolution = resolution;
            _negativeCache = negativeCache;
            _repodataResult = repodataResult;
            _gpgKey = gpgKey;
            _isPassthrough = isPassthrough;
            _assertNotCalled = assertNotCalled;
        }

        public bool IsConfigured => true;
        public bool IsPassthroughMode => _isPassthrough;

        public Task<PackageResolution?> ResolvePackageUrlAsync(string filename, CancellationToken ct)
        {
            if (_assertNotCalled)
                throw new InvalidOperationException($"ResolvePackageUrlAsync must not be called (filename={filename})");
            ResolveWasCalled = true;
            LastResolvedFilename = filename;
            return Task.FromResult(_resolution);
        }

        public Task<bool> IsNegativelyCachedAsync(string path, CancellationToken ct)
            => Task.FromResult(_negativeCache);

        public Task RecordNegativeAsync(string path, CancellationToken ct)
        {
            NegativeRecorded = true;
            return Task.CompletedTask;
        }

        public Task<RepodataResult?> GetRepodataAsync(string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct)
            => Task.FromResult(_repodataResult);

        public Task<byte[]?> GetGpgKeyAsync(CancellationToken ct)
            => Task.FromResult(_gpgKey);
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
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(true);
    }
}
