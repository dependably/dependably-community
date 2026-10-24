using System.Net;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// The daily deprecation refresh never asks upstream about a name its org has reserved. npm and
/// PyPI fetch their metadata directly rather than through the upstream-latest resolver, so these
/// cases pin the refresh's own gate, not the resolver's; NuGet goes through the resolver. Every
/// outbound request is recorded: a reserved name makes none, while a name that only shares the
/// reserved prefix, or the same cached row refreshed for an org without the reservation, makes
/// exactly one. A reserved group records no upstream fact, and leaves the shared
/// <c>cache_artifact</c> facts (versions behind, deprecation) as an org that does consult upstream
/// last wrote them.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeprecationRefreshReservationTests : IAsyncLifetime
{
    private const string UpstreamUrl = "http://upstream.test";

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private ReservedNamespaceService _reserved = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _reserved = new ReservedNamespaceService(_db, new MemoryCache(new MemoryCacheOptions()), _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>Ecosystem, reserved pattern, a cached name it covers, and a twin it does not.</summary>
    public static TheoryData<string, string, string, string> Cases() => new()
    {
        { "npm", "@acme/*", "@acme/internal-tool", "@acmecorp/x" },
        { "pypi", "acme-*", "acme-internal", "acmecorp-tool" },
        { "nuget", "Acme.*", "acme.internal", "acmecorp.tool" },
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ReservedCachedName_MakesNoRequest_AndRecordsNoUpstreamFact(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        _ = twin;
        string orgId = await SeedOrgAsync(ecosystem);
        var (packageId, caId) = await SeedCachedAsync(orgId, ecosystem, reservedName, "1.0.0");
        await _reserved.AddAsync(orgId, ecosystem, pattern, createdBy: null);
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "UPDATE packages SET upstream_latest_version = '9.9.9' WHERE id = @id", new { id = packageId });
            await seed.ExecuteAsync(
                "UPDATE cache_artifact SET versions_behind = 4, deprecated = 'old notice' WHERE id = @id", new { id = caId });
        }

        var handler = new RecordingHandler(ecosystem);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Empty(handler.Urls);
        await using var conn = await _db.OpenAsync();
        Assert.Null(await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId }));
        var (versionsBehind, deprecated, checkedAt, revokedAt) =
            await conn.QuerySingleAsync<(int? VersionsBehind, string? Deprecated, string? CheckedAt, string? RevokedAt)>(
                "SELECT versions_behind, deprecated, deprecation_checked_at, revoked_at FROM cache_artifact WHERE id = @id",
                new { id = caId });
        Assert.Equal(4, versionsBehind);
        Assert.Equal("old notice", deprecated);
        Assert.Null(revokedAt);
        // The slot moves on through this org's own refresh stamp, so the group cannot hold the
        // queue head; the shared row's verdict timestamp is not written.
        Assert.Null(checkedAt);
        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), await conn.QuerySingleAsync<string?>(
            "SELECT refresh_checked_at FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId, caId }));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task PrefixTwin_IsRefreshedFromUpstream(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        _ = reservedName;
        string orgId = await SeedOrgAsync(ecosystem);
        var (packageId, _) = await SeedCachedAsync(orgId, ecosystem, twin, "1.0.0");
        await _reserved.AddAsync(orgId, ecosystem, pattern, createdBy: null);

        var handler = new RecordingHandler(ecosystem);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.NotEmpty(handler.Urls);
        Assert.All(handler.Urls, u => Assert.StartsWith(UpstreamUrl, u, StringComparison.Ordinal));
        await using var conn = await _db.OpenAsync();
        Assert.Equal("2.0.0", await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId }));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task SharedRow_ReservedInOneOrgOnly_OtherOrgRefreshesIt(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        // Mixed pass over one shared cached row: the reserving org's group sends nothing and
        // records nothing, the other org's group is refreshed from upstream and writes the shared
        // versions_behind, and the reserving org's pass does not clear it whichever runs first.
        _ = twin;
        string openOrg = await SeedOrgAsync(ecosystem);
        var (openPkg, caId) = await SeedCachedAsync(openOrg, ecosystem, reservedName, "1.0.0");
        string reservingOrg = await SeedOrgAsync(ecosystem);
        string reservingPkg = await SeedPackageRowAsync(reservingOrg, ecosystem, reservedName, upstreamLatest: "9.9.9");
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
                new { orgId = reservingOrg, caId });
        }
        await _reserved.AddAsync(reservingOrg, ecosystem, pattern, createdBy: null);

        var handler = new RecordingHandler(ecosystem);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.NotEmpty(handler.Urls);
        await using var conn = await _db.OpenAsync();
        Assert.Null(await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = reservingPkg }));
        Assert.Equal("2.0.0", await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = openPkg }));
        Assert.Equal(1, await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caId }));
    }

    [Fact]
    public async Task NpmSharedRow_ReservedInOneOrgOnly_ExactlyOneRequest()
    {
        // The npm packument is one request, so the mixed pass's request count is exact: one for
        // the open org, none for the reserving org.
        string openOrg = await SeedOrgAsync("npm");
        var (_, caId) = await SeedCachedAsync(openOrg, "npm", "@acme/internal-tool", "1.0.0");
        string reservingOrg = await SeedOrgAsync("npm");
        await SeedPackageRowAsync(reservingOrg, "npm", "@acme/internal-tool", upstreamLatest: null);
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
                new { orgId = reservingOrg, caId });
        }
        await _reserved.AddAsync(reservingOrg, "npm", "@acme/*", createdBy: null);

        var handler = new RecordingHandler("npm");
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal($"{UpstreamUrl}/@acme/internal-tool", Assert.Single(handler.Urls));
    }

    [Fact]
    public async Task HostedOnlyReservedNpmName_MakesNoRequest_AndReadsAsUnknown()
    {
        // A hosted-only group (proxied once, proxy rows since evicted) under a reserved name:
        // no request, and its hosted versions_behind reads as unknown rather than a count derived
        // from an upstream answer.
        string orgId = await SeedOrgAsync("npm");
        string packageId = await SeedPackageRowAsync(orgId, "npm", "@acme/internal-tool", upstreamLatest: "3.0.0");
        string versionId = Guid.NewGuid().ToString("N");
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "UPDATE packages SET upstream_latest_checked_at = @stale WHERE id = @id",
                new { id = packageId, stale = _clock.GetUtcNow().AddDays(-30).ToUtcIso() });
            await seed.ExecuteAsync(
                """
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, versions_behind)
                VALUES (@id, @pkgId, '1.0.0', 'pkg:npm/@acme/internal-tool@1.0.0', @blobKey, 'uploaded', 2)
                """,
                new { id = versionId, pkgId = packageId, blobKey = $"blobs/{versionId}" });
        }
        await _reserved.AddAsync(orgId, "npm", "@acme/*", createdBy: null);

        var handler = new RecordingHandler("npm");
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Empty(handler.Urls);
        await using var conn = await _db.OpenAsync();
        Assert.Null(await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId }));
        Assert.Null(await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM package_versions WHERE id = @id", new { id = versionId }));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private async Task<string> SeedOrgAsync(string ecosystem)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        await registries.AddAsync(orgId, new NewUpstreamRegistry(ecosystem, UpstreamUrl));
        return orgId;
    }

    private async Task<string> SeedPackageRowAsync(string orgId, string ecosystem, string name, string? upstreamLatest)
    {
        string packageId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, upstream_latest_version)
            VALUES (@id, @orgId, @ecosystem, @name, @name, 1, @upstreamLatest)
            """,
            new { id = packageId, orgId, ecosystem, name, upstreamLatest });
        return packageId;
    }

    private async Task<(string PackageId, string CacheArtifactId)> SeedCachedAsync(
        string orgId, string ecosystem, string name, string version)
    {
        string packageId = await SeedPackageRowAsync(orgId, ecosystem, name, upstreamLatest: null);
        string caId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, 'h', @purl)
            """,
            new
            {
                id = caId,
                ecosystem,
                name,
                version,
                filename = $"artifact-{version}",
                blobKey = $"proxy/{caId}/artifact-{version}",
                purl = $"pkg:{ecosystem}/{name}@{version}",
            });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
        return (packageId, caId);
    }

    private DeprecationRefreshService BuildService(HttpMessageHandler handler)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-refresh-reserved-{Guid.NewGuid():N}"),
                ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0",
                ["DEPRECATION_REFRESH_AGE_HOURS"] = "24",
                ["DEPRECATION_REFRESH_BATCH_SIZE"] = "100",
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
    /// Records every outbound request URL and answers with a metadata document declaring versions
    /// 1.0.0 and 2.0.0 in the ecosystem's own shape (npm packument, PyPI JSON API, NuGet
    /// flatcontainer and registration leaf).
    /// </summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly string _ecosystem;
        public RecordingHandler(string ecosystem) => _ecosystem = ecosystem;

        public List<string> Urls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string url = request.RequestUri!.ToString();
            lock (Urls)
            {
                Urls.Add(url);
            }

            string body = _ecosystem switch
            {
                "npm" => """{"dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{},"2.0.0":{}}}""",
                "pypi" => """{"info":{"version":"2.0.0"},"releases":{"1.0.0":[],"2.0.0":[]},"urls":[]}""",
                _ when url.Contains("/flatcontainer/", StringComparison.Ordinal) => """{"versions":["1.0.0","2.0.0"]}""",
                _ => """{"published":"2026-01-02T03:04:05Z"}""",
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
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
