using System.Text;
using Dapper;
using Dependably.Api.NuGetProtocol;
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
/// Exercises <see cref="NuGetFlatContainerHandler"/>'s proxy download path directly, mirroring
/// its sibling <c>NpmTarballHandlerProxyTests</c>: a real <see cref="UpstreamClient"/> driven
/// over a loopback WireMock server rather than the WebApplicationFactory harness.
///
/// Pins the proxy first-fetch error-handling contract: a database-provider failure inside the
/// fetch-and-cache try block is infrastructure, not a missing artefact, and must propagate to a
/// 5xx instead of being swallowed by the trailing blanket <c>catch { return NotFoundResult(); }</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetFlatContainerHandlerProxyTests : IAsyncLifetime
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
        await SeedNuGetRegistryAsync(_upstream);
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    private async Task SeedNuGetRegistryAsync(string url)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @org, 'nuget', @url, 0)
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

    // Stubs the flatcontainer download coordinate the handler builds:
    // {upstream}/flatcontainer/{lower-id}/{version}/{file}
    private void StubNupkg(string id, string version, string file, byte[] bytes)
        => _server.Given(Request.Create()
                      .WithPath($"/flatcontainer/{id.ToLowerInvariant()}/{version}/{file}").UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(bytes));

    private NuGetFlatContainerHandler BuildHandler(IBlobStore? serveStoreOverride = null)
    {
        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-nuget-proxytest-{Guid.NewGuid():N}"),
            })
            .Build();
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, _audit, new AllowAllValidator(), new StubAirGapMode(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);

        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var osv = TestOsvSource.Create();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, _audit, config, new StubAirGapMode(),
            NullLogger<VulnerabilityScanService>.Instance, TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, TimeProvider.System)));

        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var proxyVersions = new ProxyVersionRecorder(_packages, _audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var blockGate = TestBlockGate.Create(_db, TimeProvider.System);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess, NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate,
            _audit, TimeProvider.System,
            new SourcePinRepository(_db, new ConfigurationBuilder().Build()));

        var allowlist = new AllowlistService(_db, _audit);
        var blocklist = new BlocklistRepository(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var claimResolver = new ClaimResolver(new ClaimRepository(_db), new StubAirGapMode());
        var reserved = new ReservedNamespaceService(
            _db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured()));
        var inventory = new ArtifactInventoryRepository(_db, _packages, cacheArtifact, vulns);
        var provenance = new NuGetProvenanceVerifier(
            new NuGetSignatureTrustStore(new StubPerOrgTrustAnchorStore()),
            NullLogger<NuGetProvenanceVerifier>.Instance);

        return new NuGetFlatContainerHandler(
            _orgs, _packages, new PackageVersionFilesRepository(_db), cacheArtifact, tenantAccess, _tokens, _audit,
            serveStoreOverride ?? tiered.Cache, upstreamClient, registries, allowlist, blocklist,
            blockGate, vulns, inventory, claimResolver, reserved, proxyFetch, provenance,
            TimeProvider.System, NullLogger<NuGetFlatContainerHandler>.Instance);
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
    public async Task ProxyMiss_CleanNupkg_Serves()
    {
        const string id = "Newtonsoft.Json";
        const string version = "13.0.3";
        string file = $"{id.ToLowerInvariant()}.{version}.nupkg";
        byte[] bytes = Encoding.UTF8.GetBytes("clean-nupkg-payload");
        StubNupkg(id, version, file, bytes);

        var handler = BuildHandler();
        var http = BuildHttpContext(_orgId);
        var result = await handler.FlatcontainerDownloadAsync(
            http, _orgId, id, version, file, CancellationToken.None);

        var fileResult = Assert.IsType<FileStreamResult>(result);
        fileResult.FileStream.Dispose();
        Assert.Equal("MISS", http.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task ProxyFetch_DbProviderException_Propagates_NotMaskedAs404()
    {
        // A database-provider failure inside the fetch-and-cache try block must propagate so the
        // middleware maps it to a retryable 5xx — it must never be swallowed into a blanket 404.
        // A 404 here makes the NuGet client report a real package as nonexistent (NU1102) and,
        // because a 404 is not retried, fails the restore outright.
        //
        // The injected fault is a DbException that is NOT a SqliteException — the exact shape a
        // Postgres deployment raises (NpgsqlException on pool exhaustion / failover / "too many
        // clients"). A SQLite-only guard (catch SqliteException) does not catch it and falls
        // through to the blanket 404, so this test pins that the guard is provider-neutral rather
        // than inert under DB_PROVIDER=postgres.
        const string id = "Newtonsoft.Json";
        const string version = "13.0.3";
        string file = $"{id.ToLowerInvariant()}.{version}.nupkg";
        byte[] bytes = Encoding.UTF8.GetBytes("db-fault-nupkg");
        StubNupkg(id, version, file, bytes);

        // Serve-side blob reads throw a provider DbException that is NOT a SqliteException. The
        // coordinate is uncached, so the cache-hit probe never reads a blob — the first read this
        // store sees is inside the fetch-and-cache try block.
        var throwingServeStore = new ThrowOnGetBlobStore();
        var handler = BuildHandler(throwingServeStore);
        var http = BuildHttpContext(_orgId);

        await Assert.ThrowsAsync<FakeProviderDbException>(
            () => handler.FlatcontainerDownloadAsync(
                http, _orgId, id, version, file, CancellationToken.None));
    }

    [Fact]
    public async Task ProxyFetch_UnclassifiedException_MapsTo502_NotSilent404()
    {
        // An unclassified failure (e.g. an IOException from a misbehaving blob backend, or a bug
        // in first-fetch metadata/provenance resolution) must not be swallowed into a silent,
        // non-retryable 404 — none of the carved-out exception types above matched, so it falls
        // through to the trailing catch-all, which must log and answer a retryable 5xx instead of
        // masking the failure as "package does not exist" (NuGet's NU1102).
        const string id = "Newtonsoft.Json";
        const string version = "13.0.3";
        string file = $"{id.ToLowerInvariant()}.{version}.nupkg";
        byte[] bytes = Encoding.UTF8.GetBytes("unclassified-fault-nupkg");
        StubNupkg(id, version, file, bytes);

        var handler = BuildHandler(new ThrowUnclassifiedExceptionBlobStore());
        var http = BuildHttpContext(_orgId);

        var result = await handler.FlatcontainerDownloadAsync(
            http, _orgId, id, version, file, CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(StatusCodes.Status502BadGateway, status.StatusCode);
    }

    [Fact]
    public async Task ProxyFetch_OperationCanceled_Propagates_NotMaskedAs404()
    {
        // A client disconnect or host shutdown inside the fetch-and-cache try block is control
        // flow, not a missing artefact: it must propagate rather than be swallowed into a 404
        // that would cache-poison intermediaries and misreport the package as nonexistent.
        const string id = "Newtonsoft.Json";
        const string version = "13.0.3";
        string file = $"{id.ToLowerInvariant()}.{version}.nupkg";
        byte[] bytes = Encoding.UTF8.GetBytes("cancelled-nupkg");
        StubNupkg(id, version, file, bytes);

        var handler = BuildHandler(new ThrowOnGetBlobStore(cancel: true));
        var http = BuildHttpContext(_orgId);

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => handler.FlatcontainerDownloadAsync(
                http, _orgId, id, version, file, CancellationToken.None));
    }

    // ── test doubles (mirror NpmTarballHandlerProxyTests) ───────────────────────

    // A non-SQLite DbException standing in for a Postgres provider fault (NpgsqlException).
    private sealed class FakeProviderDbException : System.Data.Common.DbException
    {
        public FakeProviderDbException(string message) : base(message) { }
    }

    // Blob store whose GetAsync raises a provider DbException — models a DB-provider fault
    // surfacing on the serve read path so the fetch-and-cache guard's rethrow can be pinned.
    // With cancel: true it raises OperationCanceledException instead, modelling a client
    // disconnect on the same read.
    private sealed class ThrowOnGetBlobStore(bool cancel = false) : IBlobStore
    {
        private Exception Fault(string where) => cancel
            ? new OperationCanceledException($"client disconnect on {where}")
            : new FakeProviderDbException($"provider fault on {where}");

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
            => throw Fault("blob read");
        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Task.CompletedTask;
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => Task.FromResult(true);
        public Task DeleteAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Task.FromResult(0L);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => throw Fault("blob range read");
        public async IAsyncEnumerable<BlobInfo> ListAsync(
            string prefix, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            await Task.CompletedTask;
            yield break;
        }
    }

    // Blob store whose GetAsync raises an exception type not carved out by any of the
    // fetch-and-cache handler's specific catch clauses (not a DbException, not any of the
    // proxy-specific exceptions, not OperationCanceledException) — models a bug or infra fault
    // that falls through to the trailing catch-all.
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
