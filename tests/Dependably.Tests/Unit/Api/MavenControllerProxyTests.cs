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

    // Shared across BuildController calls so the metadata cache (single-flight + TTL) persists
    // between the first and second GET — that's what makes the second metadata poll a cache hit.
    private readonly Dependably.Infrastructure.Caching.RenderedResponseCache<Dependably.Infrastructure.Caching.MavenMetadataKey> _metadataCache =
        new(new Microsoft.Extensions.Caching.Memory.MemoryCache(
                new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions { SizeLimit = 8 * 1024 * 1024 }),
            Dependably.Infrastructure.Caching.MetadataCacheKeys.MavenMetadata);

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
        _upstream = _server.Urls[0].TrimEnd('/');

        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
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

    private void StubUpstreamMetadata(string artifactPath, params string[] versions)
    {
        string versionXml = string.Concat(versions.Select(v => $"<version>{v}</version>"));
        string xml =
            "<metadata><groupId>com.example</groupId><artifactId>meta</artifactId>" +
            $"<versioning><versions>{versionXml}</versions></versioning></metadata>";
        _server.Given(Request.Create().WithPath("/" + artifactPath + "/maven-metadata.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(xml));
    }

    private long UpstreamMetadataGetCount(string artifactPath)
        => _server.LogEntries.Count(e =>
            e.RequestMessage?.Path?.EndsWith(artifactPath + "/maven-metadata.xml") == true);

    private async Task PublishLocalVersionAsync(string groupId, string artifactId, string version)
    {
        string purlName = $"{groupId}:{artifactId}";
        var pkg = await _packages.GetOrCreateAsync(_orgId, "maven", purlName, purlName, isProxy: false);
        await using var conn = await _db.OpenAsync();
        string pvId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
            VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, 1, 'deadbeef', 'uploaded')
            """,
            new
            {
                id = pvId,
                pkgId = pkg.Id,
                version,
                purl = PurlNormalizer.Maven(groupId, artifactId, version),
                blobKey = $"hosted/{_orgId}/maven/{groupId}/{artifactId}/{version}/{artifactId}-{version}.jar",
                filename = $"{artifactId}-{version}.jar",
            });
    }

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
            Dependably.Infrastructure.StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);
        var upstream = new MavenUpstreamFetcher(
            upstreamClient, tiered, _db, config, NullLogger<MavenUpstreamFetcher>.Instance, TimeProvider.System);

        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System);
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, _audit, config,
            new StubAirGapMode(false),
            NullLogger<VulnerabilityScanService>.Instance,
            TimeProvider.System));
        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var proxyVersions = new ProxyVersionRecorder(_packages, _audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var blockGate = new BlockGateService(vulns, _audit, new QuarantineRepository(_db, TimeProvider.System), new InstallScriptAllowlistService(_db, new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), TimeProvider.System), Microsoft.Extensions.Logging.Abstractions.NullLogger<BlockGateService>.Instance, TimeProvider.System);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess,
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate, _packages, _audit, TimeProvider.System);

        var svc = new MavenControllerServices(
            Packages: _packages, Tokens: _tokens, Audit: _audit, Orgs: _orgs,
            Blobs: _blobs, Db: _db, Upstream: upstream, Config: config,
            ProxyFetch: proxyFetch, BlockGate: blockGate,
            ReservedNamespaces: new ReservedNamespaceService(
                _db, new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), TimeProvider.System),
            Registries: new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured())),
            MetadataCache: _metadataCache,
            Log: NullLogger<MavenController>.Instance,
            CacheArtifacts: cacheArtifact,
            TenantAccess: tenantAccess,
            Time: TimeProvider.System,
            CacheRecorder: cacheRecorder,
            // No Maven trust anchors configured — IsConfiguredForAsync returns false, provenance skipped.
            MavenProvenance: new Dependably.Protocol.Provenance.MavenProvenanceVerifier(
                new Dependably.Tests.Infrastructure.StubPerOrgTrustAnchorStore(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.MavenProvenanceVerifier>.Instance));

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

    [Fact]
    public async Task Metadata_SecondGet_IsCacheHit_NoSecondUpstreamMetadataFetch()
    {
        const string artifactPath = "com/example/meta";
        StubUpstreamMetadata(artifactPath, "1.0", "2.0");

        var ctl1 = BuildController(CleanOsv());
        var first = await ctl1.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        var content1 = Assert.IsType<ContentResult>(first);
        Assert.Contains("2.0", content1.Content);
        Assert.Equal(1, UpstreamMetadataGetCount(artifactPath));

        // Second poll is served from the rendered-body cache — no further upstream metadata fetch.
        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        var content2 = Assert.IsType<ContentResult>(second);
        Assert.Equal(content1.Content, content2.Content);
        Assert.Equal(1, UpstreamMetadataGetCount(artifactPath));
    }

    [Fact]
    public async Task Metadata_PublishEvictsCache_NewVersionAppearsImmediately()
    {
        // No upstream stub for this coordinate → local-only metadata; isolates eviction from TTL.
        await PublishLocalVersionAsync("com.example", "evict", "1.0");

        var ctl1 = BuildController(CleanOsv());
        var first = await ctl1.Download("com/example/evict/maven-metadata.xml", CancellationToken.None);
        var content1 = Assert.IsType<ContentResult>(first);
        Assert.Contains("1.0", content1.Content);
        Assert.DoesNotContain("2.0", content1.Content);

        // Publishing a second version through the controller must evict the warmed cache entry.
        var (raw, _) = await _tokens.CreateUserTokenAsync(
            _orgId, _userId, """["publish:maven"]""", expiresAt: null);
        var ctlPub = BuildController(CleanOsv());
        ctlPub.Request.Headers.Authorization = $"Bearer {raw}";
        ctlPub.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("jar-bytes-v2"));
        ctlPub.Request.ContentLength = 12;
        var put = await ctlPub.Publish(
            "com/example/evict/2.0/evict-2.0.jar", CancellationToken.None);
        Assert.Equal(201, Assert.IsType<StatusCodeResult>(put).StatusCode);

        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download("com/example/evict/maven-metadata.xml", CancellationToken.None);
        var content2 = Assert.IsType<ContentResult>(second);
        Assert.Contains("2.0", content2.Content);
    }

    [Fact]
    public async Task Metadata_SidecarHashesSameServedBytes()
    {
        const string artifactPath = "com/example/meta";
        StubUpstreamMetadata(artifactPath, "1.0", "2.0");

        var ctl1 = BuildController(CleanOsv());
        var doc = Assert.IsType<ContentResult>(
            await ctl1.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None));
        byte[] served = Encoding.UTF8.GetBytes(doc.Content!);

        var ctl2 = BuildController(CleanOsv());
        var sidecar = Assert.IsType<ContentResult>(
            await ctl2.Download(artifactPath + "/maven-metadata.xml.sha1", CancellationToken.None));

        string expected = Convert.ToHexString(SHA1.HashData(served)).ToLowerInvariant();
        Assert.Equal(expected, sidecar.Content);
    }

    [Fact]
    public async Task Metadata_ETag_HonorsIfNoneMatch_AgainstCachedBody()
    {
        const string artifactPath = "com/example/meta";
        StubUpstreamMetadata(artifactPath, "1.0", "2.0");

        var ctl1 = BuildController(CleanOsv());
        await ctl1.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        string etag = ctl1.Response.Headers.ETag.ToString();
        Assert.False(string.IsNullOrEmpty(etag));

        var ctl2 = BuildController(CleanOsv());
        ctl2.Request.Headers.IfNoneMatch = etag;
        var second = await ctl2.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        Assert.Equal(304, Assert.IsType<StatusCodeResult>(second).StatusCode);
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
