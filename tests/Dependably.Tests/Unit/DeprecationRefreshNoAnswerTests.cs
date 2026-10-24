using System.Net;
using System.Text;
using System.Text.Json;
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

namespace Dependably.Tests.Unit;

/// <summary>
/// A refresh pass in which no configured upstream gives a 2xx answer records nothing for the
/// group: the recorded <c>deprecated</c>, <c>deprecation_checked_at</c>,
/// <c>upstream_latest_version</c> and <c>versions_behind</c> survive, and only this org's queue
/// stamps move. A non-2xx status is not a verdict, so it cannot clear a deprecation that a
/// <c>block_deprecated=block_all</c> org is blocking on. A 200 is a verdict, including one that
/// carries no deprecation, and a later source's 200 is used when an earlier source fails.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeprecationRefreshNoAnswerTests : IAsyncLifetime
{
    private const string PrimaryUrl = "http://primary.test";
    private const string MirrorUrl = "http://mirror.test";
    private const string RecordedDeprecation = "recorded upstream deprecation";
    private const string RecordedLatest = "9.9.9";
    private const int RecordedVersionsBehind = 3;
    private const int RecordedHostedVersionsBehind = 2;

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private ReservedNamespaceService _reserved = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _reserved = new ReservedNamespaceService(_db, new MemoryCache(new MemoryCacheOptions()), _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private string StaleStamp => _clock.GetUtcNow().AddDays(-30).ToUtcIso();
    private string Now => _clock.GetUtcNow().ToUtcIso();

    // ── npm / PyPI: every source fails ─────────────────────────────────────────

    [Theory]
    [InlineData("npm", HttpStatusCode.ServiceUnavailable)]
    [InlineData("npm", HttpStatusCode.Unauthorized)]
    [InlineData("npm", HttpStatusCode.Forbidden)]
    [InlineData("npm", HttpStatusCode.TooManyRequests)]
    [InlineData("pypi", HttpStatusCode.ServiceUnavailable)]
    [InlineData("pypi", HttpStatusCode.Unauthorized)]
    [InlineData("pypi", HttpStatusCode.Forbidden)]
    [InlineData("pypi", HttpStatusCode.TooManyRequests)]
    public async Task EverySourceFails_RecordsNothing_AndYieldsTheSlot(string ecosystem, HttpStatusCode status)
    {
        var seeded = await SeedGroupAsync(ecosystem, "outage-pkg", "1.0.0", RecordedDeprecation);
        var handler = new RoutingHandler(_ => Status(status));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        // Both configured sources were tried before the pass gave up on the group.
        Assert.Equal(2, handler.Requests.Count);
        await AssertNothingRecordedAsync(seeded);
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    public async Task EverySourceAnswers404_IsNoAnswer_AndRecordsNothing(string ecosystem)
    {
        // A package that every upstream reports as absent is treated like the Hex refresh treats
        // it: no verified answer, so the recorded facts are kept rather than cleared.
        var seeded = await SeedGroupAsync(ecosystem, "gone-pkg", "1.0.0", RecordedDeprecation);

        await BuildService(new RoutingHandler(_ => Status(HttpStatusCode.NotFound))).RunRefreshPassAsync(CancellationToken.None);

        await AssertNothingRecordedAsync(seeded);
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    public async Task OneSource404_OtherSource503_RecordsNothing(string ecosystem)
    {
        var seeded = await SeedGroupAsync(ecosystem, "mixed-fail-pkg", "1.0.0", RecordedDeprecation);
        var handler = new RoutingHandler(url => url.StartsWith(PrimaryUrl, StringComparison.Ordinal)
            ? Status(HttpStatusCode.NotFound)
            : Status(HttpStatusCode.ServiceUnavailable));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        await AssertNothingRecordedAsync(seeded);
    }

    [Theory]
    [InlineData("npm", HttpStatusCode.ServiceUnavailable)]
    [InlineData("npm", HttpStatusCode.Unauthorized)]
    [InlineData("npm", HttpStatusCode.TooManyRequests)]
    [InlineData("pypi", HttpStatusCode.ServiceUnavailable)]
    [InlineData("pypi", HttpStatusCode.Forbidden)]
    [InlineData("pypi", HttpStatusCode.TooManyRequests)]
    public async Task VersionBlockedUnderBlockAll_StaysBlocked_AcrossAPassWhereEverySourceFails(
        string ecosystem, HttpStatusCode status)
    {
        var seeded = await SeedGroupAsync(ecosystem, "blocked-pkg", "1.0.0", RecordedDeprecation);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded.OrgId, ecosystem, "blocked-pkg"));

        await BuildService(new RoutingHandler(_ => Status(status))).RunRefreshPassAsync(CancellationToken.None);

        Assert.True(await IsBlockedUnderBlockAllAsync(seeded.OrgId, ecosystem, "blocked-pkg"));
    }

    // ── npm / PyPI: a 2xx answer is a verdict ──────────────────────────────────

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    public async Task SourceAnswers200WithNoDeprecation_ClearsDeprecated_AndUnblocks(string ecosystem)
    {
        var seeded = await SeedGroupAsync(ecosystem, "cleared-pkg", "1.0.0", RecordedDeprecation);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded.OrgId, ecosystem, "cleared-pkg"));
        string body = Document(ecosystem, "cleared-pkg", deprecatedVersion: null, versions: ["1.0.0", "1.1.0"]);

        await BuildService(new RoutingHandler(_ => Ok(body))).RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(seeded.CacheArtifactId);
        Assert.Null(row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.Equal(1, row.VersionsBehind);
        Assert.Equal("1.1.0", (await ReadPackageAsync(seeded.PackageId)).Latest);
        Assert.False(await IsBlockedUnderBlockAllAsync(seeded.OrgId, ecosystem, "cleared-pkg"));
    }

    [Theory]
    [InlineData("npm", HttpStatusCode.ServiceUnavailable)]
    [InlineData("npm", HttpStatusCode.Unauthorized)]
    [InlineData("pypi", HttpStatusCode.TooManyRequests)]
    [InlineData("pypi", HttpStatusCode.NotFound)]
    public async Task FirstSourceFails_SecondAnswers200_TheSecondAnswerIsRecorded(string ecosystem, HttpStatusCode status)
    {
        var seeded = await SeedGroupAsync(ecosystem, "fallback-pkg", "1.0.0", deprecated: null);
        string body = Document(ecosystem, "fallback-pkg", deprecatedVersion: "1.0.0", versions: ["1.0.0", "2.0.0"]);
        var handler = new RoutingHandler(url => url.StartsWith(PrimaryUrl, StringComparison.Ordinal) ? Status(status) : Ok(body));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
        Assert.StartsWith(PrimaryUrl, handler.Requests[0], StringComparison.Ordinal);
        Assert.StartsWith(MirrorUrl, handler.Requests[1], StringComparison.Ordinal);
        var row = await ReadCacheRowAsync(seeded.CacheArtifactId);
        Assert.NotNull(row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.Equal(1, row.VersionsBehind);
        Assert.Equal("2.0.0", (await ReadPackageAsync(seeded.PackageId)).Latest);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded.OrgId, ecosystem, "fallback-pkg"));
    }

    // ── npm / PyPI: a 2xx body that is not a version document is no answer ─────

    [Theory]
    [InlineData("npm", "{}")]
    [InlineData("npm", """{"error":"not_found"}""")]
    [InlineData("npm", """{"versions":[]}""")]
    [InlineData("npm", """{"versions":{}}""")]
    [InlineData("pypi", "{}")]
    [InlineData("pypi", """{"error":"not_found"}""")]
    [InlineData("pypi", """{"releases":null}""")]
    [InlineData("pypi", """{"releases":{}}""")]
    public async Task SourceAnswers200WithNoVersionObject_IsNoAnswer_AndRecordsNothing(string ecosystem, string body)
    {
        var seeded = await SeedGroupAsync(ecosystem, "hollow-pkg", "1.0.0", RecordedDeprecation);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded.OrgId, ecosystem, "hollow-pkg"));

        await BuildService(new RoutingHandler(_ => Ok(body))).RunRefreshPassAsync(CancellationToken.None);

        await AssertNothingRecordedAsync(seeded);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded.OrgId, ecosystem, "hollow-pkg"));
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    public async Task FirstSourceAnswersHollow200_SecondSourceRealDocument_TheRealDocumentIsRecorded(string ecosystem)
    {
        var seeded = await SeedGroupAsync(ecosystem, "hollow-then-real", "1.0.0", RecordedDeprecation);
        string real = Document(ecosystem, "hollow-then-real", deprecatedVersion: null, versions: ["1.0.0", "1.1.0"]);
        var handler = new RoutingHandler(url => Ok(url.StartsWith(PrimaryUrl, StringComparison.Ordinal) ? "{}" : real));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(seeded.CacheArtifactId);
        Assert.Null(row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.Equal("1.1.0", (await ReadPackageAsync(seeded.PackageId)).Latest);
    }

    // ── Version identity: the cached spelling is matched the way the ecosystem compares it ──

    [Fact]
    public async Task Npm_VersionsDifferingOnlyInCase_AreDistinctVersions()
    {
        var seeded = await SeedGroupAsync("npm", "case-pkg", "1.0.0-rc.1", deprecated: null);
        const string body = """
            {"dist-tags":{"latest":"1.0.0-rc.1"},
             "versions":{"1.0.0-rc.1":{"deprecated":"bad build"},"1.0.0-RC.1":{}}}
            """;

        await BuildService(new RoutingHandler(_ => Ok(body))).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal("bad build", (await ReadCacheRowAsync(seeded.CacheArtifactId)).Deprecated);
    }

    [Fact]
    public async Task PyPi_CachedSpellingDifferingFromTheJsonKey_StillMatchesTheRelease()
    {
        var seeded = await SeedGroupAsync("pypi", "spelling-pkg", "1.0.0.rc1", deprecated: null);
        string body = Document("pypi", "spelling-pkg", deprecatedVersion: "1.0.0rc1", versions: ["1.0.0rc1", "1.0.0"]);

        await BuildService(new RoutingHandler(_ => Ok(body))).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal("yanked", (await ReadCacheRowAsync(seeded.CacheArtifactId)).Deprecated);
        await using var conn = await _db.OpenAsync();
        Assert.Null(await conn.ExecuteScalarAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = seeded.CacheArtifactId }));
    }

    // ── NuGet / Maven: upstream-latest through the resolver ────────────────────

    [Theory]
    [InlineData("nuget", HttpStatusCode.ServiceUnavailable)]
    [InlineData("nuget", HttpStatusCode.Unauthorized)]
    [InlineData("nuget", HttpStatusCode.Forbidden)]
    [InlineData("nuget", HttpStatusCode.TooManyRequests)]
    [InlineData("nuget", HttpStatusCode.NotFound)]
    [InlineData("maven", HttpStatusCode.ServiceUnavailable)]
    [InlineData("maven", HttpStatusCode.Unauthorized)]
    [InlineData("maven", HttpStatusCode.Forbidden)]
    [InlineData("maven", HttpStatusCode.TooManyRequests)]
    [InlineData("maven", HttpStatusCode.NotFound)]
    public async Task ResolverEcosystem_EverySourceFails_RecordsNothing_AndYieldsTheSlot(string ecosystem, HttpStatusCode status)
    {
        string name = ecosystem == "maven" ? "org.example:widget" : "example.widget";
        var seeded = await SeedGroupAsync(ecosystem, name, "1.0.0",
            deprecated: ecosystem == "nuget" ? "Unlisted upstream" : null);

        await BuildService(new RoutingHandler(_ => Status(status))).RunRefreshPassAsync(CancellationToken.None);

        await AssertNothingRecordedAsync(seeded);
    }

    [Fact]
    public async Task NuGetUnlistedVersion_StaysBlocked_AcrossASuccessfulPass()
    {
        // Every URL answers this flatcontainer-shaped body, so the registration index read gets a
        // 2xx that is not a registration index (no items array): no listing answer, so the
        // "Unlisted upstream" recorded at first fetch is kept, and the upstream-latest facts the
        // pass did read are written.
        var seeded = await SeedGroupAsync("nuget", "example.unlisted", "1.0.0", "Unlisted upstream");
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded.OrgId, "nuget", "example.unlisted"));

        await BuildService(new RoutingHandler(_ => Ok("""{"versions":["1.0.0","2.0.0"]}""")))
            .RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(seeded.CacheArtifactId);
        Assert.Equal("Unlisted upstream", row.Deprecated);
        Assert.Equal(StaleStamp, row.DeprecationCheckedAt);
        Assert.Equal(1, row.VersionsBehind);
        Assert.Equal("2.0.0", (await ReadPackageAsync(seeded.PackageId)).Latest);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded.OrgId, "nuget", "example.unlisted"));
    }

    [Fact]
    public async Task MavenFirstSourceFails_SecondAnswers200_TheSecondAnswerIsRecorded()
    {
        var seeded = await SeedGroupAsync("maven", "org.example:gadget", "1.0.0", deprecated: null);
        const string metadata = """
            <metadata><versioning><release>2.0.0</release>
            <versions><version>1.0.0</version><version>2.0.0</version></versions></versioning></metadata>
            """;
        var handler = new RoutingHandler(url => url.StartsWith(PrimaryUrl, StringComparison.Ordinal)
            ? Status(HttpStatusCode.ServiceUnavailable)
            : Ok(metadata));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(1, (await ReadCacheRowAsync(seeded.CacheArtifactId)).VersionsBehind);
        Assert.Equal("2.0.0", (await ReadPackageAsync(seeded.PackageId)).Latest);
    }

    // ── Assertions ─────────────────────────────────────────────────────────────

    private async Task AssertNothingRecordedAsync(SeededGroup seeded)
    {
        var row = await ReadCacheRowAsync(seeded.CacheArtifactId);
        Assert.Equal(seeded.Deprecated, row.Deprecated);
        Assert.Equal(StaleStamp, row.DeprecationCheckedAt);
        Assert.Equal(RecordedVersionsBehind, row.VersionsBehind);

        var pkg = await ReadPackageAsync(seeded.PackageId);
        Assert.Equal(RecordedLatest, pkg.Latest);
        Assert.Equal(RecordedHostedVersionsBehind, pkg.HostedVersionsBehind);

        // The slot is yielded: this org's queue stamps move to now, off the head of the queue.
        Assert.Equal(Now, pkg.LatestCheckedAt);
        await using var conn = await _db.OpenAsync();
        Assert.Equal(Now, await conn.QuerySingleAsync<string?>(
            "SELECT refresh_checked_at FROM tenant_artifact_access WHERE cache_artifact_id = @id",
            new { id = seeded.CacheArtifactId }));
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND event_type IN ('deprecation_refresh', 'version_revoked')",
            new { orgId = seeded.OrgId }));
    }

    // The stored-state block check the listing and index renderers apply to a cached version,
    // under block_deprecated=block_all.
    private async Task<bool> IsBlockedUnderBlockAllAsync(string orgId, string ecosystem, string name)
    {
        var entry = Assert.Single(await new CacheArtifactRepository(_db).ListServeFactsForNameAsync(orgId, ecosystem, name));
        return BlockGateService.IsHardBlockedByCacheEntry(
            entry, new OrgSettings { BlockDeprecated = "block_all" }, signals: null, _clock.GetUtcNow());
    }

    // ── Seeding and reading ────────────────────────────────────────────────────

    private sealed record SeededGroup(string OrgId, string PackageId, string CacheArtifactId, string? Deprecated);

    // One cached version carrying a recorded verdict, an org whose packages row carries a recorded
    // upstream latest, a hosted version with a recorded versions-behind, and two configured
    // upstream sources (primary first, mirror second). Every stamp is 30 days stale.
    private async Task<SeededGroup> SeedGroupAsync(string ecosystem, string name, string version, string? deprecated)
    {
        await using var conn = await _db.OpenAsync();
        string orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)", new { id = orgId, slug = $"org-{orgId[..8]}" });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });

        string packageId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, upstream_latest_version, upstream_latest_checked_at)
            VALUES (@id, @orgId, @ecosystem, @name, @name, 1, @latest, @stale)
            """,
            new { id = packageId, orgId, ecosystem, name, latest = RecordedLatest, stale = StaleStamp });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, versions_behind)
            VALUES (@id, @packageId, '0.1.0-internal', @purl, @blobKey, 'uploaded', @behind)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                packageId,
                purl = $"pkg:{ecosystem}/{name}@0.1.0-internal",
                blobKey = $"blobs/{Guid.NewGuid():N}",
                behind = RecordedHostedVersionsBehind,
            });

        string caId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, purl,
                 deprecated, deprecation_checked_at, versions_behind)
            VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, 'h', @purl,
                    @deprecated, @stale, @behind)
            """,
            new
            {
                id = caId,
                ecosystem,
                name,
                version,
                filename = $"{name}-{version}.tgz",
                blobKey = $"proxy/{caId}/{name}-{version}.tgz",
                purl = $"pkg:{ecosystem}/{name}@{version}",
                deprecated,
                stale = StaleStamp,
                behind = RecordedVersionsBehind,
            });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, refresh_checked_at) VALUES (@orgId, @caId, @stale)",
            new { orgId, caId, stale = StaleStamp });

        var registries = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        await registries.AddAsync(orgId, new NewUpstreamRegistry(ecosystem, PrimaryUrl));
        await registries.AddAsync(orgId, new NewUpstreamRegistry(ecosystem, MirrorUrl));

        return new SeededGroup(orgId, packageId, caId, deprecated);
    }

    private sealed record CacheRow(string? Deprecated, string? DeprecationCheckedAt, int? VersionsBehind);

    private sealed record PackageRow(string? Latest, string? LatestCheckedAt, int? HostedVersionsBehind);

    private async Task<CacheRow> ReadCacheRowAsync(string caId)
    {
        await using var conn = await _db.OpenAsync();
        var (deprecated, checkedAt, behind) = await conn.QuerySingleAsync<(string?, string?, int?)>(
            "SELECT deprecated, deprecation_checked_at, versions_behind FROM cache_artifact WHERE id = @id",
            new { id = caId });
        return new CacheRow(deprecated, checkedAt, behind);
    }

    private async Task<PackageRow> ReadPackageAsync(string packageId)
    {
        await using var conn = await _db.OpenAsync();
        var (latest, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT upstream_latest_version, upstream_latest_checked_at FROM packages WHERE id = @id",
            new { id = packageId });
        int? hosted = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM package_versions WHERE package_id = @id AND origin = 'uploaded'",
            new { id = packageId });
        return new PackageRow(latest, checkedAt, hosted);
    }

    // An npm packument or PyPI project document listing the given versions, the last as latest,
    // with deprecatedVersion (if any) marked deprecated (npm) or yanked (PyPI).
    private static string Document(string ecosystem, string name, string? deprecatedVersion, string[] versions)
    {
        if (ecosystem == "npm")
        {
            var entries = versions.ToDictionary(
                v => v,
                v => v == deprecatedVersion
                    ? (object)new { name, version = v, deprecated = "do not use" }
                    : new { name, version = v });
            return JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["name"] = name,
                ["dist-tags"] = new { latest = versions[^1] },
                ["versions"] = entries,
            });
        }

        var releases = versions.ToDictionary(
            v => v,
            v => new object[] { new { filename = $"{name}-{v}.tar.gz", yanked = v == deprecatedVersion, yanked_reason = (string?)null } });
        return JsonSerializer.Serialize(new { info = new { name, version = versions[^1] }, releases, urls = Array.Empty<object>() });
    }

    private static HttpResponseMessage Status(HttpStatusCode status) => new(status) { Content = new StringContent("") };

    private static HttpResponseMessage Ok(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private DeprecationRefreshService BuildService(HttpMessageHandler handler)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-refresh-noanswer-{Guid.NewGuid():N}"),
                ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0",
                ["DEPRECATION_REFRESH_AGE_HOURS"] = "24",
                ["DEPRECATION_REFRESH_BATCH_SIZE"] = "100",
            })
            .Build();
        var blobs = new InMemoryBlobStore();
        var airGap = new StubAirGap();
        var upstream = new UpstreamClient(
            new SingleHandlerFactory(handler), new TieredBlobStorage(blobs, blobs), new AuditRepository(_db),
            new AllowAllValidator(), airGap,
            new DriveInfoStagingDiskInfo(Path.GetTempPath()), StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        return new DeprecationRefreshService(
            new PackageRepository(_db, time: _clock), new CacheArtifactRepository(_db), new AuditRepository(_db), upstream,
            new UpstreamLatestVersionResolver(upstream, registries, _reserved), registries, airGap, config,
            NullLogger<DeprecationRefreshService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            _reserved, new Dependably.Infrastructure.Hex.HexReleaseRepository(_db));
    }

    private sealed class RoutingHandler(Func<string, HttpResponseMessage> router) : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string url = request.RequestUri!.ToString();
            lock (Requests)
            {
                Requests.Add(url);
            }

            return Task.FromResult(router(url));
        }
    }

    private sealed class SingleHandlerFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        private readonly HttpClient _client = new(handler);
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
