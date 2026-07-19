using System.Security.Cryptography;
using System.Text;
using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
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
/// Regression test for <see cref="PyPiProxyFetcher.FetchAndCacheUpstreamAsync"/>'s trailing
/// catch-all: an unclassified exception (not <c>DbException</c>, not any of the proxy-specific
/// carve-outs, not <c>OperationCanceledException</c>) must be logged and answered as a retryable
/// 502, not the blanket 404 that would make pip report a real package as nonexistent.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiProxyFetcherUnclassifiedExceptionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _upstreamBlobs = new();
    private WireMockServer _server = null!;
    private string _upstream = null!;
    private string _orgId = null!;
    private AuditRepository _audit = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
        _upstream = _server.Urls[0].TrimEnd('/');
        _audit = new AuditRepository(_db);
        _orgId = await OrgSeeder.InsertAsync(_db, "acme");
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    private PyPiProxyFetcher BuildFetcher(IBlobStore serveStore)
    {
        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var tiered = new TieredBlobStorage(_upstreamBlobs, _upstreamBlobs);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-pypi-unclassified-{Guid.NewGuid():N}"),
            })
            .Build();
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, _audit, new AllowAllValidator(), new StubAirGapMode(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);

        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess, NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);

        var packages = new PackageRepository(_db);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var proxyVersions = new ProxyVersionRecorder(packages, _audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var osv = Substitute.For<IOsvSource>();
        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult(new List<OsvAdvisory>()));
        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, _audit, config, new StubAirGapMode(),
            NullLogger<VulnerabilityScanService>.Instance, TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, TimeProvider.System)));
        var blockGate = TestBlockGate.Create(_db, TimeProvider.System);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate,
            _audit, TimeProvider.System,
            new SourcePinRepository(_db, new ConfigurationBuilder().Build()));

        var allowlist = new AllowlistService(_db, _audit);
        var blocklist = new BlocklistRepository(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured()));
        var provenance = new PyPiProvenanceVerifier(
            new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        return new PyPiProxyFetcher(
            _audit, serveStore, upstreamClient, allowlist, blocklist,
            cacheRecorder, proxyFetch, registries, provenance, NullLogger<PyPiProxyFetcher>.Instance);
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
    public async Task FetchAndCacheUpstream_UnclassifiedException_MapsTo502_NotSilent404()
    {
        // An unclassified failure re-opening the just-cached blob for the response body — e.g.
        // an IOException from a misbehaving blob backend — is not any of the carved-out exception
        // types (DbException, ChecksumException, UpstreamResponseTooLargeException,
        // ProxyCatalogueUnavailableException, UpstreamFetchFailedException,
        // OperationCanceledException), so it falls through to the trailing catch-all, which must
        // log and answer a retryable 5xx instead of masking the failure as "package does not exist".
        const string name = "unclassified-pypi-pkg";
        const string version = "1.0.0";
        const string file = "unclassified_pypi_pkg-1.0.0-py3-none-any.whl";
        byte[] wheelBytes = Encoding.UTF8.GetBytes("unclassified-fault-pypi-wheel-payload");
        string sha256Hex = Convert.ToHexString(SHA256.HashData(wheelBytes)).ToLowerInvariant();

        _server.Given(Request.Create().WithPath($"/files/{file}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200)
                   .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        var fetcher = BuildFetcher(new ThrowUnclassifiedExceptionBlobStore());
        var http = BuildHttpContext(_orgId);

        var package = new Package { Id = "pkg-1", OrgId = _orgId, Ecosystem = "pypi", Name = name, PurlName = name };
        var pkgVersion = new PackageVersion
        {
            Id = "ver-1",
            PackageId = package.Id,
            Version = version,
            Purl = PurlNormalizer.PyPi(name, version),
            ChecksumSha256 = sha256Hex,
        };

        var download = new PyPiProxyDownload(
            File: file,
            UpstreamUrl: $"{_upstream}/files/{file}",
            UpstreamSha256: sha256Hex,
            Parsed: new PyPiFilename(name, version),
            PkgVersions: (package, pkgVersion));

        var gate = new ProxyContext(_orgId, UserId: null, ActorKind: null,
            Settings: new OrgSettings { OrgId = _orgId });

        var result = await fetcher.FetchAndCacheUpstreamAsync(http, download, gate, CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(StatusCodes.Status502BadGateway, status.StatusCode);
    }

    // Blob store whose GetAsync raises an exception type not carved out by any of the
    // fetch-and-cache handler's specific catch clauses — models a bug or infra fault that falls
    // through to the trailing catch-all.
    private sealed class ThrowUnclassifiedExceptionBlobStore : IBlobStore
    {
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
            => throw new InvalidOperationException("unclassified blob read fault");
        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Task.CompletedTask;
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => Task.FromResult(true);
        public Task DeleteAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Task.FromResult(0L);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => throw new InvalidOperationException("unclassified blob range-read fault");
        public async IAsyncEnumerable<BlobInfo> ListAsync(
            string prefix, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            await Task.CompletedTask;
            yield break;
        }
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
