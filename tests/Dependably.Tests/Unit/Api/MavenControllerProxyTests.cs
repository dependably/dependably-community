using System.Security.Cryptography;
using System.Text;
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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// End-to-end coverage of the Maven proxy cache-miss download path through the real stack:
/// <see cref="MavenController"/> → WireMock-backed <see cref="MavenUpstreamFetcher"/> /
/// <see cref="UpstreamClient"/> (so the SSRF guard, hash-and-stage, and sidecar pre-fetch all
/// run) → the shared <see cref="ProxyFetchService"/> (record → synchronous OSV scan →
/// <see cref="BlockGateService"/>). The OSV source is the only stub — it decides whether the
/// freshly-fetched version is vulnerable. This is the integration test for the gate the unit
/// tests in <see cref="MavenControllerUnitTests"/> can only exercise on the cache-hit side.
///
/// Tagged Unit (not Integration) to match its sibling <see cref="MavenUpstreamFetcherTests"/>:
/// both drive a real UpstreamClient over a loopback WireMock server rather than the
/// WebApplicationFactory harness the Integration category uses, so they belong in the fast suite.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenControllerProxyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private WireMockServer _server = null!;
    private string _upstream = null!;

    private string _orgId = null!;
    private string _userId = null!;

    private OrgRepository _orgs = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private PackageRepository _packages = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
        _upstream = _server.Urls[0].TrimEnd('/');

        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db);
        _audit = new AuditRepository(_db);
        _packages = new PackageRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "acme");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "owner@acme.test", "owner");
        await SetAnonymousPullAsync(true);
        // The controller now resolves the upstream from the per-org registry list rather than
        // Maven:Upstream config — seed one pointing at the WireMock server so proxy paths fire.
        await SeedMavenRegistryAsync(_upstream);
    }

    private async Task SeedMavenRegistryAsync(string url)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @org, 'maven', @url, 0)
            """,
            new { id = Guid.NewGuid().ToString("N"), org = _orgId, url });
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private void StubArtifact(string path, byte[] body)
        => _server.Given(Request.Create().WithPath("/" + path).UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

    private void StubSidecar(string path, string sha256)
        => _server.Given(Request.Create().WithPath("/" + path + ".sha256").UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(sha256 + "  some-file.jar\n"));

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @flag WHERE org_id = @org",
            new { flag = enabled ? 1 : 0, org = _orgId });
    }

    private async Task SetMaxOsvToleranceAsync(double tolerance)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_osv_score_tolerance = @t WHERE org_id = @org",
            new { t = tolerance, org = _orgId });
    }

    private static IOsvSource CleanOsv()
    {
        var osv = Substitute.For<IOsvSource>();
        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult(new List<OsvAdvisory>()));
        return osv;
    }

    private static IOsvSource VulnOsv(double cvssScore)
    {
        var osv = Substitute.For<IOsvSource>();
        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult(new List<OsvAdvisory>
           {
               new("GHSA-test-0001", ["CVE-2024-0001"], "critical RCE", "CRITICAL",
                   CvssScore: cvssScore, AffectedPackages: [], Published: null, Modified: null, IsHydrated: true),
           }));
        return osv;
    }

    private long ArtifactGetCount(string filename)
        => _server.LogEntries.Count(e => e.RequestMessage?.Path?.EndsWith(filename) == true);

    private MavenController BuildController(IOsvSource osv)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Maven:Upstream"] = _upstream,
                ["Maven:VerifyWithUpstreamSha256"] = "true",
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-maven-proxytest-{Guid.NewGuid():N}"),
            })
            .Build();

        // Single blob store seen by both the UpstreamClient (which writes the proxied blob at
        // BlobKeys.Proxy(sha)) and the controller (which reads it back on a cache hit).
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, _audit, new AllowAllValidator(), new StubAirGapMode(false),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(Path.GetTempPath()),
            config, NullLogger<UpstreamClient>.Instance);
        var upstream = new MavenUpstreamFetcher(
            upstreamClient, tiered, _db, config, NullLogger<MavenUpstreamFetcher>.Instance);

        var vulns = new VulnerabilityRepository(_db);
        var licenses = new LicenseRepository(_db);
        var scanner = new VulnerabilityScanService(
            _db, osv, vulns, _audit, config,
            new StubAirGapMode(false),
            NullLogger<VulnerabilityScanService>.Instance);
        var proxyVersions = new ProxyVersionRecorder(_packages, _audit, licenses);
        var blockGate = new BlockGateService(vulns, _audit, new QuarantineRepository(_db), Microsoft.Extensions.Logging.Abstractions.NullLogger<BlockGateService>.Instance);
        var cacheRecorder = new CacheAccessRecorder(
            new CacheArtifactRepository(_db), new TenantArtifactAccessRepository(_db),
            NullLogger<CacheAccessRecorder>.Instance);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, scanner, blockGate, _packages, _audit);

        var svc = new MavenControllerServices(
            Packages: _packages, Tokens: _tokens, Audit: _audit, Orgs: _orgs,
            Blobs: _blobs, Db: _db, Upstream: upstream, Config: config,
            ProxyFetch: proxyFetch, BlockGate: blockGate,
            ReservedNamespaces: new ReservedNamespaceService(
                _db, new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions())),
            Registries: new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db)));

        return new MavenController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ProxyMiss_VulnerableArtifactOverTolerance_Returns403_AndRecordsNoServeRow()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("vulnerable-jar-payload");
        string path = "com/example/vuln/1.0/vuln-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));
        await SetMaxOsvToleranceAsync(4.0);

        var ctl = BuildController(VulnOsv(9.8));
        var result = await ctl.Download(path, CancellationToken.None);

        Assert.Equal(403, Assert.IsType<StatusCodeResult>(result).StatusCode);

        // Refused on the very first fetch: the shared pipeline recorded the package_versions
        // row (scan target) but the controller left no maven_version_files serve-row, so a
        // later attempt re-fetches and re-gates rather than serving from cache.
        await using var conn = await _db.OpenAsync();
        long fileRows = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND p.purl_name = 'com.example:vuln'
            """,
            new { org = _orgId });
        Assert.Equal(0, fileRows);
    }

    [Fact]
    public async Task ProxyMiss_VulnScoreWithinTolerance_Serves()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("tolerable-jar-payload");
        string path = "com/example/tolerable/1.0/tolerable-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));
        await SetMaxOsvToleranceAsync(10.0);

        var ctl = BuildController(VulnOsv(5.0));
        var result = await ctl.Download(path, CancellationToken.None);

        var file = Assert.IsType<FileContentResult>(result);
        Assert.Equal(bytes, file.FileContents);
    }

    [Fact]
    public async Task ProxyMiss_CleanArtifact_Serves_ThenSecondRequestIsCacheHit_NoSecondUpstreamFetch()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("clean-jar-payload");
        string path = "com/example/clean/1.0/clean-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));

        var ctl1 = BuildController(CleanOsv());
        var first = await ctl1.Download(path, CancellationToken.None);
        var file = Assert.IsType<FileContentResult>(first);
        Assert.Equal(bytes, file.FileContents);
        Assert.Equal("MISS", ctl1.Response.Headers["X-Cache"].ToString());

        long artifactCallsAfterMiss = ArtifactGetCount("clean-1.0.jar");

        // Second request resolves the recorded maven_version_files row → served from the blob
        // store as a cache HIT, with no further upstream artifact fetch.
        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download(path, CancellationToken.None);
        Assert.IsType<FileStreamResult>(second).FileStream.Dispose();
        Assert.Equal("HIT", ctl2.Response.Headers["X-Cache"].ToString());

        Assert.Equal(artifactCallsAfterMiss, ArtifactGetCount("clean-1.0.jar"));
    }

    // ── test doubles (mirror MavenUpstreamFetcherTests) ─────────────────────────

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

            var inner = new HttpClient();
            return await inner.SendAsync(innerRequest, ct);
        }
    }
}
