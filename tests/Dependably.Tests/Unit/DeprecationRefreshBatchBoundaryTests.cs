using System.Net;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// Scheduling of the deprecation refresh when several orgs cache the same name. The orgs share the
/// <c>cache_artifact</c> rows but each has its own (ecosystem, name, org) group, and the pass
/// takes a fixed batch of groups. These cases put the batch boundary between two orgs' groups for
/// one shared row (batch size 1) and pin that processing the admitted org's group — refreshed,
/// failed, unconfigured, or reserved — leaves the other org's group due for the very next pass
/// rather than one age window later, while a group that keeps failing or is reserved still cannot
/// hold the head of the queue.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeprecationRefreshBatchBoundaryTests : IAsyncLifetime
{
    private const string Name = "shared-pkg";
    private const string HealthyUpstream = "http://up.test";
    private const string DownUpstream = "http://down.test";

    // Fixed ids so the tie between the two orgs' groups (same shared rows, same staleness) breaks
    // the same way every run: org A's group sorts first and is the one the batch admits.
    private const string OrgA = "00000000000000000000000000000a0a";
    private const string OrgB = "00000000000000000000000000000b0b";

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private ReservedNamespaceService _reserved = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _reserved = new ReservedNamespaceService(_db, new MemoryCache(new MemoryCacheOptions()), _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task SharedRow_BatchAdmitsOneOrg_OtherOrgIsStillDue_AndRefreshedOnTheNextPass()
    {
        var shared = await SeedSharedRowAsync(orgBUpstream: HealthyUpstream, orgAUpstream: HealthyUpstream);
        var handler = new RecordingHandler();
        var service = BuildService(handler, batchSize: 1);

        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal($"{HealthyUpstream}/{Name}", Assert.Single(handler.Urls));
        Assert.Equal("2.0.0", await UpstreamLatestAsync(shared.PackageA));
        Assert.Null(await UpstreamLatestAsync(shared.PackageB));
        // The pass stamped the shared row on A's behalf, but B's group must still be due.
        Assert.Equal(new[] { OrgB }, await DueOrgsAsync());

        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(2, handler.Urls.Count);
        Assert.Equal("2.0.0", await UpstreamLatestAsync(shared.PackageB));
        Assert.Empty(await DueOrgsAsync());

        await service.RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(2, handler.Urls.Count);
    }

    [Fact]
    public async Task SingleOrg_OnePassSettlesTheGroup_UntilTheAgeWindowElapses()
    {
        // Adversarial twin: with one org there is no other group to defer; the group is refreshed
        // once and is not due again until the age window has passed.
        string pkg = await SeedOrgWithCachedRowAsync(OrgA, HealthyUpstream);
        var handler = new RecordingHandler();
        var service = BuildService(handler, batchSize: 1);

        await service.RunRefreshPassAsync(CancellationToken.None);
        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Single(handler.Urls);
        Assert.Equal("2.0.0", await UpstreamLatestAsync(pkg));
        Assert.Empty(await DueOrgsAsync());

        _clock.Advance(TimeSpan.FromHours(25));
        Assert.Equal(new[] { OrgA }, await DueOrgsAsync());
    }

    [Fact]
    public async Task SharedRow_BothOrgsInsideTheBatch_BothRefreshedInOnePass()
    {
        // Adversarial twin: with the batch wide enough for both groups nothing is deferred and
        // nothing is left due.
        var shared = await SeedSharedRowAsync(orgBUpstream: HealthyUpstream, orgAUpstream: HealthyUpstream);
        var handler = new RecordingHandler();
        var service = BuildService(handler, batchSize: 2);

        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(2, handler.Urls.Count);
        Assert.Equal("2.0.0", await UpstreamLatestAsync(shared.PackageA));
        Assert.Equal("2.0.0", await UpstreamLatestAsync(shared.PackageB));
        Assert.Empty(await DueOrgsAsync());

        await service.RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(2, handler.Urls.Count);
    }

    [Theory]
    [InlineData("throws")]
    [InlineData("no-upstream")]
    public async Task SharedRow_AdmittedOrgYields_ItDoesNotHoldTheHead_AndOtherOrgIsRefreshedNextPass(string failure)
    {
        // The yield path: A's upstream throws (or A has no upstream configured). A's group must
        // move off the head of the queue — the next pass reaches B, not A again — and B's group
        // must not have been made to look fresh by A's attempt.
        var shared = await SeedSharedRowAsync(
            orgBUpstream: HealthyUpstream,
            orgAUpstream: failure == "throws" ? DownUpstream : null);
        await SetUpstreamLatestAsync(shared.PackageA, "9.9.9");
        var handler = new RecordingHandler();
        var service = BuildService(handler, batchSize: 1);

        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.All(handler.Urls, u => Assert.StartsWith(DownUpstream, u, StringComparison.Ordinal));
        // A yielded: its recorded baseline survives, and the shared rows are not written.
        Assert.Equal("9.9.9", await UpstreamLatestAsync(shared.PackageA));
        Assert.Null(await SharedCheckedAtAsync(shared.CacheArtifactId));
        Assert.Equal(new[] { OrgB }, await DueOrgsAsync());

        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Single(handler.Urls, u => u.StartsWith(HealthyUpstream, StringComparison.Ordinal));
        Assert.Equal("2.0.0", await UpstreamLatestAsync(shared.PackageB));
        Assert.Equal("9.9.9", await UpstreamLatestAsync(shared.PackageA));
        Assert.Empty(await DueOrgsAsync());

        // The yield is an attempt stamp, not a verdict: A is retried once its window elapses.
        _clock.Advance(TimeSpan.FromHours(25));
        Assert.Equal(new[] { OrgA, OrgB }, await DueOrgsAsync());
    }

    [Fact]
    public async Task SharedRow_AdmittedOrgReservedTheName_ItDoesNotHoldTheHead_AndOtherOrgIsRefreshedNextPass()
    {
        // The reserved path: A has reserved the name, so its group asks upstream nothing and
        // clears its own upstream baseline. It must move off the head of the queue, and B — which
        // does consult upstream for the same shared row — must be refreshed on the next pass.
        var shared = await SeedSharedRowAsync(orgBUpstream: HealthyUpstream, orgAUpstream: HealthyUpstream);
        await _reserved.AddAsync(OrgA, "npm", "shared-*", createdBy: null);
        await SetUpstreamLatestAsync(shared.PackageA, "9.9.9");
        var handler = new RecordingHandler();
        var service = BuildService(handler, batchSize: 1);

        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Empty(handler.Urls);
        Assert.Null(await UpstreamLatestAsync(shared.PackageA));
        Assert.Null(await SharedCheckedAtAsync(shared.CacheArtifactId));
        Assert.Equal(new[] { OrgB }, await DueOrgsAsync());

        await service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal($"{HealthyUpstream}/{Name}", Assert.Single(handler.Urls));
        Assert.Equal("2.0.0", await UpstreamLatestAsync(shared.PackageB));
        Assert.Null(await UpstreamLatestAsync(shared.PackageA));
        Assert.Empty(await DueOrgsAsync());
    }

    [Fact]
    public async Task ProcessingOneOrgsGroup_StampsOnlyThatOrgsAccessRows()
    {
        // Tenant isolation of the per-org stamp: A's pass moves A's access rows and A's packages
        // row only. B's access rows and packages row are untouched until B's own group is
        // processed, and a third org caching an unrelated name is never touched.
        var shared = await SeedSharedRowAsync(orgBUpstream: HealthyUpstream, orgAUpstream: HealthyUpstream);
        const string orgC = "00000000000000000000000000000c0c";
        await SeedOrgWithCachedRowAsync(orgC, HealthyUpstream, name: "unrelated-pkg");
        string now = _clock.GetUtcNow().ToUtcIso();

        int stamped = await new CacheArtifactRepository(_db)
            .StampRefreshCheckedAtForOrgAsync(OrgA, "npm", Name, _clock);

        Assert.Equal(1, stamped);
        Assert.Equal(now, await AccessStampAsync(OrgA, shared.CacheArtifactId));
        Assert.Null(await AccessStampAsync(OrgB, shared.CacheArtifactId));
        Assert.Null(await SharedCheckedAtAsync(shared.CacheArtifactId));
        Assert.Equal(new[] { OrgB, orgC }, await DueOrgsAsync());

        await BuildService(new RecordingHandler(), batchSize: 1).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(now, await AccessStampAsync(OrgB, shared.CacheArtifactId));
        Assert.Null(await UpstreamLatestAsync(shared.PackageA));
        Assert.Equal("2.0.0", await UpstreamLatestAsync(shared.PackageB));
        Assert.Equal(new[] { orgC }, await DueOrgsAsync());
    }

    [Fact]
    public async Task NeverProcessedGroup_IsSelectedAheadOfAStaleOne()
    {
        // A group with a never-processed access row leads the batch, whatever the provider's own
        // NULL ordering; a stale-but-processed group waits behind it.
        await SeedOrgWithCachedRowAsync(OrgA, HealthyUpstream, name: "a-stale");
        await SeedOrgWithCachedRowAsync(OrgB, HealthyUpstream, name: "b-new");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE tenant_artifact_access SET refresh_checked_at = @stale WHERE org_id = @orgId",
                new { orgId = OrgA, stale = _clock.GetUtcNow().AddDays(-30).ToUtcIso() });
        }

        var groups = await new CacheArtifactRepository(_db).ListGroupsNeedingDeprecationRefreshAsync(24, 1, _clock);

        Assert.Equal(("npm", "b-new", OrgB), Assert.Single(groups));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private sealed record SharedRow(string PackageA, string PackageB, string CacheArtifactId);

    /// <summary>
    /// Two orgs caching the same npm row: one <c>cache_artifact</c> row, one access row per org,
    /// and a packages row per org. A null upstream means the org has none configured.
    /// </summary>
    private async Task<SharedRow> SeedSharedRowAsync(string? orgBUpstream, string? orgAUpstream)
    {
        string packageA = await SeedOrgAsync(OrgA, orgAUpstream, Name);
        string packageB = await SeedOrgAsync(OrgB, orgBUpstream, Name);
        string caId = await SeedCacheArtifactAsync(Name);
        await GrantAccessAsync(OrgA, caId);
        await GrantAccessAsync(OrgB, caId);
        return new SharedRow(packageA, packageB, caId);
    }

    private async Task<string> SeedOrgWithCachedRowAsync(string orgId, string? upstream, string name = Name)
    {
        string packageId = await SeedOrgAsync(orgId, upstream, name);
        string caId = await SeedCacheArtifactAsync(name);
        await GrantAccessAsync(orgId, caId);
        return packageId;
    }

    private async Task<string> SeedOrgAsync(string orgId, string? upstream, string name)
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@orgId, @slug)",
                new { orgId, slug = $"org-{orgId[^4..]}" });
        }

        if (upstream is not null)
        {
            var registries = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
            await registries.AddAsync(orgId, new NewUpstreamRegistry("npm", upstream));
        }

        string packageId = Guid.NewGuid().ToString("N");
        await using var seed = await _db.OpenAsync();
        await seed.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@id, @orgId, 'npm', @name, @name, 1)
            """,
            new { id = packageId, orgId, name });
        return packageId;
    }

    private async Task<string> SeedCacheArtifactAsync(string name)
    {
        string caId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES (@id, 'npm', @name, '1.0.0', @filename, @blobKey, 'h', @purl)
            """,
            new
            {
                id = caId,
                name,
                filename = $"{name}-1.0.0.tgz",
                blobKey = $"proxy/{caId}/{name}-1.0.0.tgz",
                purl = $"pkg:npm/{name}@1.0.0",
            });
        return caId;
    }

    private async Task GrantAccessAsync(string orgId, string caId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
    }

    private async Task SetUpstreamLatestAsync(string packageId, string version)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE packages SET upstream_latest_version = @version WHERE id = @id",
            new { id = packageId, version });
    }

    private async Task<string?> UpstreamLatestAsync(string packageId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId });
    }

    private async Task<string?> SharedCheckedAtAsync(string caId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM cache_artifact WHERE id = @id", new { id = caId });
    }

    private async Task<string?> AccessStampAsync(string orgId, string caId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<string?>(
            "SELECT refresh_checked_at FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId, caId });
    }

    /// <summary>The orgs with a group the next pass would select, in selection order.</summary>
    private async Task<List<string>> DueOrgsAsync()
    {
        var groups = await new CacheArtifactRepository(_db).ListGroupsNeedingDeprecationRefreshAsync(24, 10, _clock);
        return groups.Select(g => g.OrgId).ToList();
    }

    private DeprecationRefreshService BuildService(HttpMessageHandler handler, int batchSize)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-refresh-boundary-{Guid.NewGuid():N}"),
                ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0",
                ["DEPRECATION_REFRESH_AGE_HOURS"] = "24",
                ["DEPRECATION_REFRESH_BATCH_SIZE"] = batchSize.ToString(System.Globalization.CultureInfo.InvariantCulture),
            })
            .Build();
        var blobs = new InMemoryBlobStore();
        var urlValidator = Substitute.For<IUpstreamUrlValidator>();
        urlValidator.CheckAsync(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(UpstreamUrlBlock.None));
        var airGap = Substitute.For<IAirGapMode>();
        var upstream = new UpstreamClient(
            new SingleHandlerFactory(handler), new TieredBlobStorage(blobs, blobs), new AuditRepository(_db),
            urlValidator, airGap, new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        return new DeprecationRefreshService(
            new PackageRepository(_db, time: _clock), new CacheArtifactRepository(_db), new AuditRepository(_db),
            upstream, new UpstreamLatestVersionResolver(upstream, registries, _reserved), registries, airGap, config,
            NullLogger<DeprecationRefreshService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock), _reserved, new Dependably.Infrastructure.Hex.HexReleaseRepository(_db));
    }

    /// <summary>
    /// Records every outbound request URL. Requests to the down upstream throw, standing in for an
    /// unreachable registry; every other request is answered with an npm packument declaring
    /// versions 1.0.0 and 2.0.0 with 2.0.0 as latest.
    /// </summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<string> Urls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string url = request.RequestUri!.ToString();
            lock (Urls)
            {
                Urls.Add(url);
            }

            return url.StartsWith(DownUpstream, StringComparison.Ordinal)
                ? throw new HttpRequestException("upstream unreachable")
                : Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        """{"dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{},"2.0.0":{}}}""",
                        Encoding.UTF8, "application/json"),
                });
        }
    }

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }
}
