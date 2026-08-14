using System.Net;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the versions-behind operational-risk count computed by
/// <see cref="DeprecationRefreshService"/>: per-ecosystem counting against the resolver's
/// stable-versions list, dual-plane parity (cache_artifact and package_versions both carry the
/// count for a package that is both proxied and hosted), NULL-never-0 on an unreachable upstream,
/// and a mixed pass where one group succeeds while a sibling group's upstream call fails.
/// </summary>
[Trait("Category", "Unit")]
public sealed class VersionsBehindRefreshTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Npm_ComputesCountAgainstStableUpstreamVersions()
    {
        var (orgId, _, ca1, _) = await SeedProxyVersionAsync("npm", "multi-pkg", "1.0.0");
        await SeedUpstreamRegistryAsync(orgId, "npm", "http://npm.test");
        string ca2 = await SeedAdditionalCacheVersionAsync("npm", "multi-pkg", "2.0.0");

        string packument = NpmPackument("multi-pkg", new[] { "1.0.0", "2.0.0", "3.0.0" });
        var service = BuildService(new FixedResponseHandler(packument));
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        int? behind1 = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = ca1 });
        int? behind2 = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = ca2 });

        Assert.Equal(2, behind1); // 2.0.0 and 3.0.0 are newer than 1.0.0
        Assert.Equal(1, behind2); // 3.0.0 is newer than 2.0.0
    }

    [Fact]
    public async Task Npm_UpToDateVersionCountsAsZero_NotUnknown()
    {
        var (orgId, _, ca, _) = await SeedProxyVersionAsync("npm", "current-pkg", "3.0.0");
        await SeedUpstreamRegistryAsync(orgId, "npm", "http://npm.test");
        string packument = NpmPackument("current-pkg", new[] { "1.0.0", "2.0.0", "3.0.0" });
        var service = BuildService(new FixedResponseHandler(packument));
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        int? behind = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = ca });
        Assert.Equal(0, behind);
    }

    [Fact]
    public async Task DualPlane_MirrorsCountOntoHostedPackageVersionsRow()
    {
        // A package that is both proxied (cache_artifact, org auto-discovers the group) and
        // carries a hosted override (package_versions, origin='uploaded') under the same
        // package_id — the refresh pass must recompute both planes from the one upstream fetch.
        var (orgId, packageId, caId, _) = await SeedProxyVersionAsync("npm", "mixed-plane-pkg", "1.0.0");
        await SeedUpstreamRegistryAsync(orgId, "npm", "http://npm.test");
        string hostedVersionId = await SeedHostedVersionAsync(packageId, "npm", "mixed-plane-pkg", "1.5.0");

        string packument = NpmPackument("mixed-plane-pkg", new[] { "1.0.0", "1.5.0", "2.0.0" });
        var service = BuildService(new FixedResponseHandler(packument));
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        int? proxyBehind = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caId });
        int? hostedBehind = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM package_versions WHERE id = @id", new { id = hostedVersionId });

        Assert.Equal(2, proxyBehind);  // 1.5.0 and 2.0.0 newer than 1.0.0
        Assert.Equal(1, hostedBehind); // 2.0.0 newer than 1.5.0
    }

    [Fact]
    public async Task NuGet_UnreachableUpstream_SetsNullNeverZero()
    {
        var (orgId, _, caId, _) = await SeedProxyVersionAsync("nuget", "unreachable.pkg", "1.0.0");
        await SeedUpstreamRegistryAsync(orgId, "nuget", "http://nuget.test/v3");

        // Pre-seed a stale non-null value to prove the refresh pass actively resets it to
        // unknown, rather than merely leaving the schema default in place.
        await using (var seedConn = await _db.OpenAsync())
        {
            await seedConn.ExecuteAsync(
                "UPDATE cache_artifact SET versions_behind = 99 WHERE id = @id", new { id = caId });
        }

        var service = BuildService(new FixedResponseHandler("not found", HttpStatusCode.NotFound));
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        int? behind = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Null(behind);
    }

    [Fact]
    public async Task MixedPass_OneGroupSucceedsWhileSiblingGroupUpstreamFails()
    {
        // Two independent npm groups refreshed in the SAME pass: "good-pkg" gets a normal
        // packument; "bad-pkg" gets a 500 from upstream. The failing group must not prevent the
        // healthy group from updating, and must itself reset to unknown rather than being skipped
        // silently with a stale value left behind.
        var (orgGood, _, caGood, _) = await SeedProxyVersionAsync("npm", "good-pkg", "1.0.0");
        await SeedUpstreamRegistryAsync(orgGood, "npm", "http://npm.test");
        var (orgBad, _, caBad, _) = await SeedProxyVersionAsync("npm", "bad-pkg", "1.0.0");
        await SeedUpstreamRegistryAsync(orgBad, "npm", "http://npm.test");
        await using (var seedConn = await _db.OpenAsync())
        {
            await seedConn.ExecuteAsync(
                "UPDATE cache_artifact SET versions_behind = 7 WHERE id = @id", new { id = caBad });
        }

        string goodPackument = NpmPackument("good-pkg", new[] { "1.0.0", "2.0.0" });
        var handler = new RoutingHandler(url =>
            url.Contains("bad-pkg", StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("boom") }
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(goodPackument, Encoding.UTF8, "application/json")
                });
        var service = BuildService(handler);

        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        int? behindGood = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caGood });
        int? behindBad = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caBad });

        Assert.Equal(1, behindGood);
        Assert.Null(behindBad);
    }

    // ── Seeding helpers (self-contained — mirrors DeprecationRefreshServiceTests' shape) ──────

    private async Task<(string OrgId, string PackageId, string CacheArtifactId, string Purl)> SeedProxyVersionAsync(
        string ecosystem, string name, string version)
    {
        await using var conn = await _db.OpenAsync();
        string orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = $"org-{orgId[..6]}" });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });

        string packageId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @orgId, @eco, @name, @name, 1)",
            new { id = packageId, orgId, eco = ecosystem, name });

        string caId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:{ecosystem}/{name}@{version}";
        string blobKey = $"proxy/{caId}/{name}-{version}.tgz";
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, 'h', @purl)
            """,
            new { id = caId, ecosystem, name, version, filename = $"{name}-{version}.tgz", blobKey, purl });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });

        return (orgId, packageId, caId, purl);
    }

    private async Task<string> SeedAdditionalCacheVersionAsync(string ecosystem, string name, string version)
    {
        await using var conn = await _db.OpenAsync();
        // Reuse the org already attached to the existing group via tenant_artifact_access.
        string orgId = await conn.QuerySingleAsync<string>(
            """
            SELECT taa.org_id FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE ca.ecosystem = @ecosystem AND ca.name = @name
            LIMIT 1
            """,
            new { ecosystem, name });

        string caId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:{ecosystem}/{name}@{version}";
        string blobKey = $"proxy/{caId}/{name}-{version}.tgz";
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, 'h', @purl)
            """,
            new { id = caId, ecosystem, name, version, filename = $"{name}-{version}.tgz", blobKey, purl });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
        return caId;
    }

    private async Task<string> SeedHostedVersionAsync(string packageId, string ecosystem, string name, string version)
    {
        await using var conn = await _db.OpenAsync();
        string versionId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:{ecosystem}/{name}@{version}";
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin)
            VALUES (@id, @packageId, @version, @purl, @blobKey, 'uploaded')
            """,
            new { id = versionId, packageId, version, purl, blobKey = $"hosted/{versionId}" });
        return versionId;
    }

    private async Task SeedUpstreamRegistryAsync(string orgId, string ecosystem, string url)
    {
        var repo = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        await repo.AddAsync(orgId, new NewUpstreamRegistry(ecosystem, url));
    }

    // Minimal npm packument builder: every listed version is published (non-deprecated, non-yanked).
    private static string NpmPackument(string name, IEnumerable<string> versions)
    {
        var versionsObj = new Dictionary<string, object>();
        foreach (string v in versions)
        {
            versionsObj[v] = new { name, version = v };
        }
        var root = new Dictionary<string, object?> { ["name"] = name, ["versions"] = versionsObj };
        return JsonSerializer.Serialize(root);
    }

    private DeprecationRefreshService BuildService(HttpMessageHandler handler)
    {
        var factory = new SingleHandlerFactory(handler);
        var blobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);
        var audit = new AuditRepository(_db);
        var validator = new AllowAllValidator();
        string stagingDir = Path.Combine(Path.GetTempPath(), $"vb-refresh-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = stagingDir,
                ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0",
                ["DEPRECATION_REFRESH_AGE_HOURS"] = "24",
                ["DEPRECATION_REFRESH_BATCH_SIZE"] = "100",
                ["Npm:Upstream"] = "http://npm.test",
                ["PyPI:Upstream"] = "http://pypi.test",
            })
            .Build();
        var airGap = new StubAirGap();
        var upstream = new UpstreamClient(
            factory, tiered, new AuditRepository(_db), validator, airGap,
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        var packages = new PackageRepository(_db, time: _clock);
        var cacheArtifacts = new CacheArtifactRepository(_db);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        var latestResolver = new UpstreamLatestVersionResolver(upstream, registries);
        return new DeprecationRefreshService(
            packages, cacheArtifacts, audit, upstream, latestResolver, registries, airGap, config,
            NullLogger<DeprecationRefreshService>.Instance,
            _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));
    }

    private sealed class FixedResponseHandler : HttpMessageHandler
    {
        private readonly string _body;
        private readonly HttpStatusCode _status;
        public FixedResponseHandler(string body, HttpStatusCode status = HttpStatusCode.OK)
        {
            _body = body;
            _status = status;
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(_status)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            });
    }

    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly Func<string, HttpResponseMessage> _router;
        public RoutingHandler(Func<string, HttpResponseMessage> router) => _router = router;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(_router(request.RequestUri!.ToString()));
    }

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(HttpMessageHandler h) => _client = new HttpClient(h);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
