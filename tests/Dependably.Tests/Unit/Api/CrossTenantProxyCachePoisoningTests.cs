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
/// Two tenants on one instance, each with its own upstream registry, fetching the same npm
/// coordinate. Configuring an upstream is a tenant-admin capability, so a tenant can point its own
/// at a host it controls; <c>cache_artifact</c> is keyed by (ecosystem, name, version, filename)
/// alone and carries no org or upstream discriminator, so one row stands for whichever bytes
/// arrived first. What must not follow from that is the other tenant being served those bytes.
///
/// Both upstreams here are internally consistent — each serves a tarball together with the
/// <c>dist.shasum</c> that matches it — so checksum verification passes for both fetches. The
/// verification is against metadata from the same host as the bytes, which is why it is no defence
/// against this at all, and why the defence has to live on the tenant's own cache-plane row.
///
/// Tagged Unit like its sibling <c>NpmTarballHandlerProxyTests</c>: it drives a real
/// <see cref="UpstreamClient"/> over loopback WireMock servers rather than the
/// WebApplicationFactory harness the Integration category uses.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CrossTenantProxyCachePoisoningTests : IAsyncLifetime
{
    private const string PackageName = "left-pad";
    private const string Version = "4.17.21";
    private const string File = "left-pad-4.17.21.tgz";

    private static readonly byte[] HostileBytes = Encoding.UTF8.GetBytes("attacker-controlled-tarball-payload");
    private static readonly byte[] GenuineBytes = Encoding.UTF8.GetBytes("genuine-registry-tarball-payload");

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    private WireMockServer _hostileUpstream = null!;
    private WireMockServer _genuineUpstream = null!;
    private string _attackerOrgId = null!;
    private string _victimOrgId = null!;

    private OrgRepository _orgs = null!;
    private PackageRepository _packages = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _hostileUpstream = WireMockServer.Start();
        _genuineUpstream = WireMockServer.Start();

        _orgs = new OrgRepository(_db);
        _packages = new PackageRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);

        _attackerOrgId = await OrgSeeder.InsertAsync(_db, "attacker");
        _victimOrgId = await OrgSeeder.InsertAsync(_db, "victim");
        await AllowAnonymousPullAsync(_attackerOrgId);
        await AllowAnonymousPullAsync(_victimOrgId);
    }

    public async Task DisposeAsync()
    {
        _hostileUpstream.Stop();
        _genuineUpstream.Stop();
        await _db.DisposeAsync();
    }

    /// <summary>
    /// The poisoning itself. The attacker's org fetches the coordinate from the upstream it
    /// controls, creating the shared row with its bytes. The victim's org then fetches the same
    /// coordinate from the genuine registry: its first response is its own bytes (the miss path
    /// streams what it just fetched), and the request that matters is the SECOND one, which is
    /// served off the cache-hit path. That path must hand back the victim's bytes and the victim's
    /// ETag — never the attacker's, whose hash the victim's client would then verify against and
    /// accept.
    /// </summary>
    [Fact]
    public async Task VictimSecondRequest_AfterHostileOrgCachedTheCoordinate_ServesVictimBytesAndEtag()
    {
        StubUpstream(_hostileUpstream, HostileBytes);
        StubUpstream(_genuineUpstream, GenuineBytes);
        await SeedRegistryAsync(_attackerOrgId, _hostileUpstream);
        await SeedRegistryAsync(_victimOrgId, _genuineUpstream);

        // The hostile org gets there first and plants the shared row.
        (byte[] attackerBytes, _, string attackerCache) = await FetchAsync(_attackerOrgId);
        Assert.Equal(HostileBytes, attackerBytes);
        Assert.Equal("MISS", attackerCache);

        // The victim's own first fetch: its bytes, off the miss path.
        (byte[] victimFirst, _, string victimFirstCache) = await FetchAsync(_victimOrgId);
        Assert.Equal(GenuineBytes, victimFirst);
        Assert.Equal("MISS", victimFirstCache);

        // The second request is the one served from the shared cache plane.
        (byte[] victimSecond, string? victimEtag, string victimSecondCache) = await FetchAsync(_victimOrgId);
        Assert.Equal("HIT", victimSecondCache);
        Assert.Equal(GenuineBytes, victimSecond);
        Assert.NotEqual(HostileBytes, victimSecond);
        Assert.Equal($"\"sha256:{Sha256Hex(GenuineBytes)}\"", victimEtag);
        Assert.NotEqual($"\"sha256:{Sha256Hex(HostileBytes)}\"", victimEtag);

        // And the attacker's own org keeps reading its own bytes: neither tenant's binding
        // displaces the other's.
        (byte[] attackerSecond, string? attackerEtag, string attackerSecondCache) = await FetchAsync(_attackerOrgId);
        Assert.Equal("HIT", attackerSecondCache);
        Assert.Equal(HostileBytes, attackerSecond);
        Assert.Equal($"\"sha256:{Sha256Hex(HostileBytes)}\"", attackerEtag);
    }

    /// <summary>
    /// No un-remediable cross-tenant denial of service. A bare "refuse on divergence" also stops
    /// the victim being served the attacker's bytes — by stopping it being served anything at all,
    /// permanently, for any coordinate the attacker chooses to reach first. The victim must get a
    /// 200 with its own bytes on every request, not a 503, and repeat requests must keep working
    /// rather than degrading into a permanent re-fetch.
    /// </summary>
    [Fact]
    public async Task VictimIsNeverDeniedTheCoordinate_AfterHostileOrgCachedDivergentBytes()
    {
        StubUpstream(_hostileUpstream, HostileBytes);
        StubUpstream(_genuineUpstream, GenuineBytes);
        await SeedRegistryAsync(_attackerOrgId, _hostileUpstream);
        await SeedRegistryAsync(_victimOrgId, _genuineUpstream);

        await FetchAsync(_attackerOrgId);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            var handler = BuildHandler();
            var http = BuildHttpContext(_victimOrgId);
            var result = await handler.GetTarballAsync(
                http, _victimOrgId, PackageName, File, CancellationToken.None);

            // Not a 503 (ProxyCatalogueUnavailableException's mapping), not a 403, not a 404.
            var stream = Assert.IsType<FileStreamResult>(result);
            byte[] bytes = await ReadAllAsync(stream);
            Assert.Equal(GenuineBytes, bytes);
        }

        // Exactly one upstream tarball fetch across the three requests: the divergence is not paid
        // for with a permanent re-fetch either, which is what "treat a diverging tenant as a
        // perpetual cache miss" would have cost.
        Assert.Equal(1, TarballFetchCount(_genuineUpstream));
    }

    /// <summary>
    /// Adversarial twin: when both tenants resolve identical bytes — the overwhelmingly common
    /// case — they must go on sharing one <c>cache_artifact</c> row and one blob. Answering the
    /// poisoning by giving every tenant its own row would pass the test above and silently
    /// duplicate the whole proxy cache per tenant.
    /// </summary>
    [Fact]
    public async Task TwoOrgsResolvingIdenticalBytes_ShareOneCacheArtifactRowAndOneBlob()
    {
        StubUpstream(_hostileUpstream, GenuineBytes);
        StubUpstream(_genuineUpstream, GenuineBytes);
        await SeedRegistryAsync(_attackerOrgId, _hostileUpstream);
        await SeedRegistryAsync(_victimOrgId, _genuineUpstream);

        await FetchAsync(_attackerOrgId);
        await FetchAsync(_victimOrgId);
        (byte[] secondOrgHit, string? etag, string cacheHeader) = await FetchAsync(_victimOrgId);

        Assert.Equal("HIT", cacheHeader);
        Assert.Equal(GenuineBytes, secondOrgHit);
        Assert.Equal($"\"sha256:{Sha256Hex(GenuineBytes)}\"", etag);

        await using var conn = await _db.OpenAsync();
        long rows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = @name",
            new { name = PackageName });
        Assert.Equal(1, rows);

        long distinctBlobKeys = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(DISTINCT blob_key) FROM (
                SELECT ca.blob_key AS blob_key FROM cache_artifact ca WHERE ca.name = @name
                UNION
                SELECT taa.blob_key AS blob_key FROM tenant_artifact_access taa
                JOIN cache_artifact ca2 ON ca2.id = taa.cache_artifact_id
                WHERE ca2.name = @name AND taa.blob_key IS NOT NULL
            ) keys
            """,
            new { name = PackageName });
        Assert.Equal(1, distinctBlobKeys);
    }

    // ── Harness ──────────────────────────────────────────────────────────────

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();

    private static async Task<byte[]> ReadAllAsync(FileStreamResult result)
    {
        using var buffer = new MemoryStream();
        await using (result.FileStream)
        {
            await result.FileStream.CopyToAsync(buffer);
        }
        return buffer.ToArray();
    }

    private async Task<(byte[] Bytes, string? ETag, string CacheHeader)> FetchAsync(string orgId)
    {
        var handler = BuildHandler();
        var http = BuildHttpContext(orgId);
        var result = await handler.GetTarballAsync(http, orgId, PackageName, File, CancellationToken.None);
        var fileResult = Assert.IsType<FileStreamResult>(result);
        byte[] bytes = await ReadAllAsync(fileResult);
        string? etag = http.Response.Headers.ETag.Count > 0 ? http.Response.Headers.ETag.ToString() : null;
        return (bytes, etag, http.Response.Headers["X-Cache"].ToString());
    }

    private static long TarballFetchCount(WireMockServer server) =>
        server.LogEntries.Count(e => e.RequestMessage?.Path?.EndsWith("/-/" + File) == true);

    private static void StubUpstream(WireMockServer server, byte[] tarballBytes)
    {
        string sha1 = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(tarballBytes))
            .ToLowerInvariant();
        string json = $$"""
            {
                "name": "{{PackageName}}",
                "time": { "{{Version}}": "2026-01-01T00:00:00.000Z" },
                "versions": {
                    "{{Version}}": {
                        "dist": { "shasum": "{{sha1}}" }
                    }
                }
            }
            """;
        server.Given(Request.Create().WithPath("/" + PackageName).UsingGet())
              .RespondWith(Response.Create().WithStatusCode(200)
                  .WithHeader("Content-Type", "application/json").WithBody(json));
        server.Given(Request.Create().WithPath($"/{PackageName}/-/{File}").UsingGet())
              .RespondWith(Response.Create().WithStatusCode(200).WithBody(tarballBytes));
    }

    private async Task SeedRegistryAsync(string orgId, WireMockServer server)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @org, 'npm', @url, 0)
            """,
            new { id = Guid.NewGuid().ToString("N"), org = orgId, url = server.Urls[0].TrimEnd('/') });
    }

    private async Task AllowAnonymousPullAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @org", new { org = orgId });
    }

    private static DefaultHttpContext BuildHttpContext(string orgId)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("tenant.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "tenant");
        return http;
    }

    private NpmTarballHandler BuildHandler()
    {
        // Both upstreams are real loopback listeners, so the client dials the absolute URL each
        // org's upstream_registry row carries — which is the whole premise: two tenants, two hosts.
        var httpFactory = new StaticHttpClientFactory(new HttpClient());
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(
                    Path.GetTempPath(), $"dependably-xtenant-poison-{Guid.NewGuid():N}"),
            })
            .Build();
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, _audit, new AllowAllValidator(), new StubAirGapMode(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);

        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, TestOsvSource.Create(), vulns, _audit, config, new StubAirGapMode(),
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

        return new NpmTarballHandler(
            _orgs, _packages, cacheArtifact, tenantAccess, _tokens, _audit, tiered.Cache,
            upstreamClient,
            new AllowlistService(_db, _audit),
            new BlocklistRepository(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System),
            blockGate,
            new ClaimResolver(new ClaimRepository(_db), new StubAirGapMode()),
            new ReservedNamespaceService(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System),
            proxyFetch,
            new UpstreamRegistryResolver(
                new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured())),
            new NpmProvenanceVerifier(new NpmSignatureKeyStore(new StubPerOrgTrustAnchorStore())),
            TimeProvider.System, NullLogger<NpmTarballHandler>.Instance);
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
}
