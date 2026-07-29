using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Regression coverage for the SSRF-adjacent credential leak in
/// <see cref="PyPiProxyFetcher.ResolveProxyUpstreamUrlAsync"/>: a configured upstream's simple
/// index may name an absolute href to any host (PEP 503 permits it, and mirror/proxy upstreams
/// commonly link straight to <c>files.pythonhosted.org</c>). The resolver must attach that
/// upstream's stored Authorization header only when the resolved artefact URL stays on the
/// upstream's own host — never to whatever third-party host the upstream's own response named.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiProxyUpstreamAuthHostPinningTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private WireMockServer _server = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    private PyPiProxyFetcher BuildFetcher()
    {
        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var upstreamBlobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(upstreamBlobs, upstreamBlobs);
        var audit = new AuditRepository(_db);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-pypi-authpin-{Guid.NewGuid():N}"),
            })
            .Build();
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, audit, new AllowAllValidator(), new StubAirGapMode(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);

        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess, NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);

        var packages = new PackageRepository(_db);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var proxyVersions = new ProxyVersionRecorder(packages, audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var osv = TestOsvSource.Create();
        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, audit, config, new StubAirGapMode(),
            NullLogger<VulnerabilityScanService>.Instance, TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, TimeProvider.System)));
        var blockGate = TestBlockGate.Create(_db, TimeProvider.System);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate,
            audit, TimeProvider.System,
            new SourcePinRepository(_db, new ConfigurationBuilder().Build()));

        var allowlist = new AllowlistService(_db, audit);
        var blocklist = new BlocklistRepository(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured()));
        var provenance = new PyPiProvenanceVerifier(
            new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        return new PyPiProxyFetcher(
            audit, upstreamBlobs, upstreamClient, allowlist, blocklist,
            cacheRecorder, proxyFetch, registries, provenance, NullLogger<PyPiProxyFetcher>.Instance);
    }

    [Fact]
    public async Task ResolveProxyUpstreamUrl_AbsoluteHrefOnDifferentHost_DoesNotAttachUpstreamAuthHeader()
    {
        // Mixed fan-out across two configured upstreams: the first (private, credentialed) does
        // not carry the package at all — its simple index 404s — so resolution falls through to
        // the second upstream. The second upstream's own simple index names an absolute href on a
        // THIRD host entirely (modeling a mirror/Artifactory-style upstream that links straight to
        // files.pythonhosted.org, or a compromised/malicious upstream). The second upstream's
        // stored credential must never ride along to that third-party host.
        const string pkgName = "widget";
        const string version = "1.0.0";
        const string file = "widget-1.0.0-py3-none-any.whl";
        const string sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        var source1 = new UpstreamSource("https://private-upstream-one.test", "Bearer token-one-secret");
        var source2 = new UpstreamSource("https://private-upstream-two.test", "Bearer token-two-secret");

        _server.Given(Request.Create().WithPath($"/simple/{pkgName}/")
                .WithHeader("Authorization", "Bearer token-one-secret").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(404));

        string html = $"<a href=\"https://attacker-controlled-mirror.example/packages/{file}#sha256={sha}\">{file}</a>";
        _server.Given(Request.Create().WithPath($"/simple/{pkgName}/")
                .WithHeader("Authorization", "Bearer token-two-secret").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "text/html").WithBody(html));

        var fetcher = BuildFetcher();
        var parsed = new PyPiFilename(pkgName, version);

        var result = await fetcher.ResolveProxyUpstreamUrlAsync(
            file, parsed, pkgVersions: null, bases: [source1, source2], CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal($"https://attacker-controlled-mirror.example/packages/{file}", result.Value.Url);
        Assert.Equal(sha, result.Value.Sha256Hex);
        Assert.Null(result.Value.AuthorizationHeader);
    }

    [Fact]
    public async Task ResolveProxyUpstreamUrl_HrefOnSameHost_StillAttachesUpstreamAuthHeader()
    {
        // Baseline: when the resolved href stays on the configured upstream's own host (whether
        // absolute or root-relative), the upstream's credential must still ride along — otherwise
        // a legitimate authenticated private PyPI upstream would break.
        const string pkgName = "widget";
        const string version = "1.0.0";
        const string file = "widget-1.0.0-py3-none-any.whl";
        const string sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        var source = new UpstreamSource("https://private-upstream.test", "Bearer own-host-secret");

        string html = $"<a href=\"https://private-upstream.test/packages/{file}#sha256={sha}\">{file}</a>";
        _server.Given(Request.Create().WithPath($"/simple/{pkgName}/")
                .WithHeader("Authorization", "Bearer own-host-secret").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "text/html").WithBody(html));

        var fetcher = BuildFetcher();
        var parsed = new PyPiFilename(pkgName, version);

        var result = await fetcher.ResolveProxyUpstreamUrlAsync(
            file, parsed, pkgVersions: null, bases: [source], CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal($"https://private-upstream.test/packages/{file}", result.Value.Url);
        Assert.Equal(sha, result.Value.Sha256Hex);
        Assert.Equal("Bearer own-host-secret", result.Value.AuthorizationHeader);
    }

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
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
