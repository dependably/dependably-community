using System.Security.Claims;
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

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Proxy-path SSRF coverage for <see cref="ApkController"/>'s <c>.apk</c> artifact fetch loop
/// (<see cref="ApkController.HandleApkRequest"/> → <c>FetchApkArtifactFromUpstreamsAsync</c>).
///
/// Constructs a real <see cref="UpstreamClient"/> wired to a validator that blocks the
/// configured upstream URL, so <c>GetOrFetchToBlobKeyAsync</c> throws
/// <see cref="SsrfBlockedException"/> exactly as it would for an operator-configured upstream
/// that resolves to a blocked address — no HTTP call is ever made (the SSRF check runs before
/// any request), so the HTTP factory here fails loudly if it's ever invoked.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ApkControllerProxyTests : IAsyncLifetime
{
    private const string UpstreamBaseUrl = "https://blocked-upstream.example.test";

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

        _orgId = await OrgSeeder.InsertAsync(_db, "apk-proxy-org");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "dev@apk.test", "admin");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>
    /// Enables anonymous pull for the test org. Without this the request-side AnonymousPull
    /// gate returns 401 before the controller ever reaches the artifact-fetch loop, since this
    /// test drives the controller directly with no Authorization header.
    /// </summary>
    private async Task EnableAnonPullAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId = _orgId });
    }

    /// <summary>
    /// Seeds one apk upstream registry row for the test org so
    /// <see cref="UpstreamRegistryResolver"/> returns a non-empty list and the artifact-fetch
    /// loop runs. Without this the org has zero configured apk registries (404 before any fetch).
    /// </summary>
    private async Task SeedApkRegistryAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @orgId, 'apk', @url, 0)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId = _orgId, url = UpstreamBaseUrl });
    }

    [Fact]
    public async Task HandleApkRequest_ArtifactFetch_SsrfBlockedUpstream_Returns502NotFiveHundred()
    {
        await EnableAnonPullAsync();
        await SeedApkRegistryAsync();
        var ctl = BuildController();

        var result = await ctl.HandleApkRequest("v3.22/main/x86_64/curl-8.9.0-r0.apk", default);

        // Before the fix, SsrfBlockedException propagated uncaught out of the artifact-fetch
        // loop — ASP.NET's default exception handling surfaces that as a 500, not a status
        // result the controller test can even observe (it would throw here instead of
        // returning). Asserting the typed 502 result pins the fix; on the old code this line
        // throws SsrfBlockedException instead of returning.
        var statusResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status502BadGateway, statusResult.StatusCode);
    }

    // ── Controller construction ──────────────────────────────────────────────

    private ApkController BuildController()
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("apk-proxy-org.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "apk-proxy-org");
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

        var upstreamClient = BuildRealUpstreamClient();

        var cacheArtifacts = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var cacheRecorder = new CacheAccessRecorder(cacheArtifacts, tenantAccess,
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var memCache = new MemoryCache(new MemoryCacheOptions());

        var svc = new ApkControllerServices(
            Orgs: _orgs,
            Tokens: _tokens,
            Audit: _audit,
            Packages: _packages,
            Blobs: new TieredBlobStorage(_blobs, _blobs).Cache,
            Upstream: upstreamClient,
            Registries: new UpstreamRegistryResolver(
                new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured())),
            Db: _db,
            CacheRecorder: cacheRecorder,
            CacheArtifacts: cacheArtifacts,
            TenantAccess: tenantAccess,
            Time: TimeProvider.System,
            Logger: NullLogger<ApkController>.Instance,
            Reserved: new ReservedNamespaceService(_db, memCache, TimeProvider.System),
            BlockGate: TestBlockGate.Create(_db, TimeProvider.System),
            IndexCoordinator: new ApkIndexFetchCoordinator(
                new NullHttpClientFactory(),
                memCache,
                new DisabledAirGap(),
                new BlockingValidator(),
                new StubPerOrgTrustAnchorStore(),
                new ConfigurationBuilder().Build(),
                NullLogger<ApkIndexFetchCoordinator>.Instance),
            NegativeCacheTtl: TimeSpan.FromMinutes(5));

        return new ApkController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private UpstreamClient BuildRealUpstreamClient()
    {
        // No-op HTTP factory: the SSRF check runs before any HTTP request is made, so a call
        // reaching the handler means the fix regressed to actually dialing the blocked upstream.
        var httpFactory = new NullHttpClientFactory();
        return new UpstreamClient(
            httpFactory,
            new TieredBlobStorage(_blobs, _blobs),
            _audit,
            new BlockingValidator(),
            new DisabledAirGap(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(new ConfigurationBuilder().Build()),
            NullLogger<UpstreamClient>.Instance);
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    private sealed class NullHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new NullHandler());

        private sealed class NullHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
                => throw new InvalidOperationException(
                    "HTTP calls should not be made — SSRF blocking must short-circuit before the request.");
        }
    }

    private sealed class DisabledAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    /// <summary>
    /// Blocks every URL — simulates an operator-configured upstream that resolves to a
    /// blocked address (link-local, RFC1918, etc.), matching the finding's scenario without
    /// depending on real DNS/socket-level SSRF enforcement inside a unit test.
    /// </summary>
    private sealed class BlockingValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.BlockedRange);
    }
}
