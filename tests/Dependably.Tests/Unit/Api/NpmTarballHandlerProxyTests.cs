using System.Text;
using Dapper;
using Dependably.Api.NpmProtocol;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Exercises <see cref="NpmTarballHandler"/>'s proxy tarball path directly (no
/// <c>NpmController</c> wrapper is needed — the handler methods take <see cref="HttpContext"/>
/// and return <see cref="IActionResult"/> on their own): a cache-miss fetch through a
/// WireMock-backed <see cref="UpstreamClient"/>, then a second request for the same
/// coordinate, which resolves through <see cref="NpmTarballHandler.TryServeCacheHitTarballAsync"/>
/// via the global-plane <see cref="CacheArtifactRepository"/> rather than re-hitting upstream.
///
/// Tagged Unit (not Integration) to match its sibling <c>MavenControllerProxyTests</c>: both
/// drive a real <see cref="UpstreamClient"/> over a loopback WireMock server rather than the
/// WebApplicationFactory harness the Integration category uses.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmTarballHandlerProxyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private WireMockServer _server = null!;
    private string _upstream = null!;
    private string _orgId = null!;

    private OrgRepository _orgs = null!;
    private PackageRepository _packages = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
        _upstream = _server.Urls[0].TrimEnd('/');

        _orgs = new OrgRepository(_db);
        _packages = new PackageRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "acme");
        await SetAnonymousPullAsync(true);
        await SeedNpmRegistryAsync(_upstream);
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    private async Task SeedNpmRegistryAsync(string url)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @org, 'npm', @url, 0)
            """,
            new { id = Guid.NewGuid().ToString("N"), org = _orgId, url });
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @flag WHERE org_id = @org",
            new { flag = enabled ? 1 : 0, org = _orgId });
    }

    private void StubPackument(string fullName, string version, byte[] tarballBytes)
    {
        string sha1 = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(tarballBytes)).ToLowerInvariant();
        string json = $$"""
            {
                "name": "{{fullName}}",
                "time": { "{{version}}": "2026-01-01T00:00:00.000Z" },
                "versions": {
                    "{{version}}": {
                        "dist": { "shasum": "{{sha1}}" }
                    }
                }
            }
            """;
        _server.Given(Request.Create().WithPath("/" + fullName).UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200)
                   .WithHeader("Content-Type", "application/json").WithBody(json));
    }

    private void StubTarball(string fullName, string file, byte[] bytes)
        => _server.Given(Request.Create().WithPath($"/{fullName}/-/{file}").UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(bytes));

    private long TarballGetCount(string file)
        => _server.LogEntries.Count(e => e.RequestMessage?.Path?.EndsWith("/-/" + file) == true);

    private NpmTarballHandler BuildHandler()
    {
        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-npm-proxytest-{Guid.NewGuid():N}"),
            })
            .Build();
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, _audit, new AllowAllValidator(), new StubAirGapMode(),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(Path.GetTempPath()),
            Dependably.Infrastructure.StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);

        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System);
        var osv = Substitute.For<IOsvSource>();
        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult(new List<OsvAdvisory>()));
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, _audit, config, new StubAirGapMode(),
            NullLogger<VulnerabilityScanService>.Instance, TimeProvider.System));

        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var proxyVersions = new ProxyVersionRecorder(_packages, _audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var installScriptAllowlist = new InstallScriptAllowlistService(
            _db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var blockGate = new BlockGateService(
            vulns, _audit, new QuarantineRepository(_db, TimeProvider.System),
            installScriptAllowlist, NullLogger<BlockGateService>.Instance, TimeProvider.System);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess, NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate,
            _packages, _audit, TimeProvider.System);

        var allowlist = new AllowlistService(_db, _audit);
        var blocklist = new BlocklistRepository(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var claimResolver = new ClaimResolver(new ClaimRepository(_db), new StubAirGapMode());
        var reserved = new ReservedNamespaceService(
            _db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured()));
        var provenance = new NpmProvenanceVerifier(new NpmSignatureKeyStore(new StubPerOrgTrustAnchorStore()));

        return new NpmTarballHandler(
            _orgs, _packages, cacheArtifact, tenantAccess, _tokens, _audit, tiered.Cache,
            upstreamClient, allowlist, blocklist, blockGate, claimResolver, reserved,
            proxyFetch, registries, provenance, TimeProvider.System);
    }

    private static DefaultHttpContext BuildHttpContext(string orgId)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "acme");
        return http;
    }

    [Fact]
    public async Task ProxyMiss_CleanTarball_Serves_ThenSecondRequestIsCacheHit_NoSecondUpstreamFetch()
    {
        const string fullName = "left-pad";
        const string version = "1.2.3";
        string file = $"{fullName}-{version}.tgz";
        byte[] bytes = Encoding.UTF8.GetBytes("clean-npm-tarball-payload");
        StubPackument(fullName, version, bytes);
        StubTarball(fullName, file, bytes);

        var handler1 = BuildHandler();
        var http1 = BuildHttpContext(_orgId);
        var first = await handler1.GetTarballAsync(http1, _orgId, fullName, file, CancellationToken.None);
        var fileResult = Assert.IsType<FileStreamResult>(first);
        fileResult.FileStream.Dispose();
        Assert.Equal("MISS", http1.Response.Headers["X-Cache"].ToString());

        long tarballCallsAfterMiss = TarballGetCount(file);
        Assert.Equal(1, tarballCallsAfterMiss);

        // Second request for the same coordinate resolves through the cache-hit path
        // (TryServeCacheHitTarballAsync) against the global-plane cache_artifact row, with no
        // further upstream tarball fetch.
        var handler2 = BuildHandler();
        var http2 = BuildHttpContext(_orgId);
        var second = await handler2.GetTarballAsync(http2, _orgId, fullName, file, CancellationToken.None);
        var secondFile = Assert.IsType<FileStreamResult>(second);
        secondFile.FileStream.Dispose();
        Assert.Equal("HIT", http2.Response.Headers["X-Cache"].ToString());

        Assert.Equal(tarballCallsAfterMiss, TarballGetCount(file));
    }

    [Fact]
    public async Task ProxyCacheHit_AnonymousPullDisabled_NoToken_Returns401()
    {
        const string fullName = "left-pad-private";
        const string version = "1.0.0";
        string file = $"{fullName}-{version}.tgz";
        byte[] bytes = Encoding.UTF8.GetBytes("private-npm-tarball-payload");
        StubPackument(fullName, version, bytes);
        StubTarball(fullName, file, bytes);

        var handler1 = BuildHandler();
        var http1 = BuildHttpContext(_orgId);
        var first = await handler1.GetTarballAsync(http1, _orgId, fullName, file, CancellationToken.None);
        Assert.IsType<FileStreamResult>(first).FileStream.Dispose();

        // Flip AnonymousPull off after the miss is cached, then request again anonymously —
        // the cache-hit path must gate on AnonymousPull exactly like the miss path.
        await SetAnonymousPullAsync(false);

        var handler2 = BuildHandler();
        var http2 = BuildHttpContext(_orgId);
        var second = await handler2.GetTarballAsync(http2, _orgId, fullName, file, CancellationToken.None);
        Assert.IsType<UnauthorizedResult>(second);
    }

    // ── test doubles (mirror MavenControllerProxyTests) ─────────────────────────

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
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

    private sealed class WireMockHandler : HttpMessageHandler
    {
        private readonly WireMockServer _server;
        public WireMockHandler(WireMockServer server) => _server = server;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            string url = _server.Urls[0] + request.RequestUri!.PathAndQuery;
            using var innerRequest = new HttpRequestMessage(request.Method, url);
            foreach (var h in request.Headers)
            {
                innerRequest.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }

            using var inner = new HttpClient();
            return await inner.SendAsync(innerRequest, ct);
        }
    }
}
