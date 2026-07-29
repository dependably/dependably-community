using System.Text;
using Dapper;
using Dependably.Api.NpmProtocol;
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

    private async Task SetAllowlistModeAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET allowlist_mode = @flag WHERE org_id = @org",
            new { flag = enabled ? 1 : 0, org = _orgId });
    }

    private async Task AddBlocklistPatternAsync(string pattern)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO blocklist (id, org_id, pattern) VALUES (@id, @org, @pattern)",
            new { id = Guid.NewGuid().ToString("N"), org = _orgId, pattern });
    }

    private async Task AddAllowlistPatternAsync(string purlPattern)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO allowlist (id, org_id, purl_pattern) VALUES (@id, @org, @pattern)",
            new { id = Guid.NewGuid().ToString("N"), org = _orgId, pattern = purlPattern });
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

    private NpmTarballHandler BuildHandler(IBlobStore? serveStoreOverride = null)
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
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var osv = TestOsvSource.Create();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, _audit, config, new StubAirGapMode(),
            NullLogger<VulnerabilityScanService>.Instance, TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            Dependably.Tests.Infrastructure.TestAlerts.NoOp(_db, TimeProvider.System)));

        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var proxyVersions = new ProxyVersionRecorder(_packages, _audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var blockGate = Dependably.Tests.Infrastructure.TestBlockGate.Create(_db, TimeProvider.System);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess, NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate,
            _audit, TimeProvider.System,
            new Dependably.Infrastructure.SourcePinRepository(_db, new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()));

        var allowlist = new AllowlistService(_db, _audit);
        var blocklist = new BlocklistRepository(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var claimResolver = new ClaimResolver(new ClaimRepository(_db), new StubAirGapMode());
        var reserved = new ReservedNamespaceService(
            _db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured()));
        var provenance = new NpmProvenanceVerifier(new NpmSignatureKeyStore(new StubPerOrgTrustAnchorStore()));

        return new NpmTarballHandler(
            _orgs, _packages, cacheArtifact, tenantAccess, _tokens, _audit, serveStoreOverride ?? tiered.Cache,
            upstreamClient, allowlist, blocklist, blockGate, claimResolver, reserved,
            proxyFetch, registries, provenance, TimeProvider.System, NullLogger<NpmTarballHandler>.Instance);
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

    [Fact]
    public async Task ProxyMiss_ScopedPackage_OnBlocklist_Returns403_NotServed()
    {
        // A scoped package whose full name is on the blocklist must be blocked on the miss/fetch
        // path. The gate builds a name-only PURL for the blocklist regex; when that PURL collapses
        // to the bare "pkg:npm/" prefix for every scoped name, the entry never matches and a
        // blocked scoped package is served anyway (dependency-confusion bypass).
        const string scope = "evil";
        const string pkg = "pkg";
        const string version = "1.0.0";
        string fullName = $"@{scope}/{pkg}";
        string file = $"{pkg}-{version}.tgz";
        byte[] bytes = Encoding.UTF8.GetBytes("blocked-scoped-npm-tarball");
        StubPackument(fullName, version, bytes);
        StubTarball(fullName, file, bytes);

        // Blocklist regex matches the exact scoped name-only PURL.
        await AddBlocklistPatternAsync("pkg:npm/@evil/pkg");

        var handler = BuildHandler();
        var http = BuildHttpContext(_orgId);
        var result = await handler.GetScopedTarballAsync(http, _orgId, scope, pkg, file, CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, status.StatusCode);
    }

    [Fact]
    public async Task ProxyMiss_ScopedPackage_AllowlistMode_ScopedNameAllowlisted_Serves()
    {
        // Allowlist mode with an allowlist entry for the scoped name must let the fetch through.
        // When the name-only PURL collapses to "pkg:npm/" for every scoped name, the allowlist
        // entry never matches and every scoped package is locked out with a 403.
        const string scope = "myco";
        const string pkg = "widget";
        const string version = "2.1.0";
        string fullName = $"@{scope}/{pkg}";
        string file = $"{pkg}-{version}.tgz";
        byte[] bytes = Encoding.UTF8.GetBytes("allowlisted-scoped-npm-tarball");
        StubPackument(fullName, version, bytes);
        StubTarball(fullName, file, bytes);

        await SetAllowlistModeAsync(true);
        await AddAllowlistPatternAsync("pkg:npm/@myco/widget");

        var handler = BuildHandler();
        var http = BuildHttpContext(_orgId);
        var result = await handler.GetScopedTarballAsync(http, _orgId, scope, pkg, file, CancellationToken.None);

        var fileResult = Assert.IsType<FileStreamResult>(result);
        fileResult.FileStream.Dispose();
    }

    [Fact]
    public async Task ProxyFetch_DbProviderException_Propagates_NotMaskedAs404()
    {
        // A database-provider failure inside the fetch-and-cache try block must propagate so the
        // middleware maps it to a 5xx — it must never be swallowed into a blanket 404. The guard
        // must be provider-neutral (catch DbException), not tied to the SQLite exception type,
        // or the guard is inert on the Postgres provider.
        const string fullName = "flaky-pkg";
        const string version = "3.0.0";
        string file = $"{fullName}-{version}.tgz";
        byte[] bytes = Encoding.UTF8.GetBytes("db-fault-npm-tarball");
        StubPackument(fullName, version, bytes);
        StubTarball(fullName, file, bytes);

        // Serve-side blob reads throw a provider DbException that is NOT a SqliteException.
        var throwingServeStore = new ThrowOnGetBlobStore();
        var handler = BuildHandler(throwingServeStore);
        var http = BuildHttpContext(_orgId);

        await Assert.ThrowsAsync<FakeProviderDbException>(
            () => handler.GetTarballAsync(http, _orgId, fullName, file, CancellationToken.None));
    }

    [Fact]
    public async Task ProxyFetch_UnclassifiedException_MapsTo502_NotSilent404()
    {
        // An unclassified failure (e.g. an IOException from a misbehaving blob backend, or a bug
        // in metadata/provenance resolution) must not be swallowed into a silent, non-retryable
        // 404 — none of the carved-out exception types above matched, so it falls through to the
        // trailing catch-all, which must log and answer a retryable 5xx instead of masking the
        // failure as "package does not exist".
        const string fullName = "unclassified-fault-pkg";
        const string version = "3.0.0";
        string file = $"{fullName}-{version}.tgz";
        byte[] bytes = Encoding.UTF8.GetBytes("unclassified-fault-npm-tarball");
        StubPackument(fullName, version, bytes);
        StubTarball(fullName, file, bytes);

        var handler = BuildHandler(new ThrowUnclassifiedExceptionBlobStore());
        var http = BuildHttpContext(_orgId);

        var result = await handler.GetTarballAsync(http, _orgId, fullName, file, CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(StatusCodes.Status502BadGateway, status.StatusCode);
    }

    [Fact]
    public async Task ProxyFetch_OperationCanceled_Propagates_NotMaskedAs404()
    {
        // A client disconnect or host shutdown inside the fetch-and-cache try block is control
        // flow, not a missing artefact: it must propagate rather than be swallowed into a 404
        // that would misreport the package as nonexistent.
        const string fullName = "cancelled-pkg";
        const string version = "3.0.0";
        string file = $"{fullName}-{version}.tgz";
        byte[] bytes = Encoding.UTF8.GetBytes("cancelled-npm-tarball");
        StubPackument(fullName, version, bytes);
        StubTarball(fullName, file, bytes);

        var handler = BuildHandler(new ThrowOnGetBlobStore(cancel: true));
        var http = BuildHttpContext(_orgId);

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => handler.GetTarballAsync(http, _orgId, fullName, file, CancellationToken.None));
    }

    // ── test doubles (mirror MavenControllerProxyTests) ─────────────────────────

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
