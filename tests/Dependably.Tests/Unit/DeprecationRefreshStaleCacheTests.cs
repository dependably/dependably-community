using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// With the metadata cache on (the edge default: a short TTL plus a 24 h serve-stale window), a
/// body the cache serves past its TTL because the upstream failed is not a verdict for the
/// deprecation refresh. Each scenario caches an upstream answer in which the version is not
/// deprecated, unlisted or retired, then records the mark, then runs a pass while the upstream
/// fails and the cache serves the old body stale: the mark is kept and the group yields. The
/// twins show that a live 2xx still clears the mark, that a live mirror answer is used when the
/// primary is served stale, and that the request-serving reads still relay the stale body.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeprecationRefreshStaleCacheTests : IAsyncLifetime
{
    private const string PrimaryUrl = "http://primary.test";
    private const string MirrorUrl = "http://mirror.test";
    private const string RecordedMark = "recorded upstream deprecation";
    private const string RecordedLatest = "9.9.9";
    private const int RecordedVersionsBehind = 3;
    private const string NuGetId = "example.widget";
    private const string Unlisted = "Unlisted upstream";
    private static readonly TimeSpan PastTheTtl = TimeSpan.FromMinutes(10);
    private static readonly HexRetirementStatus SecurityRetirement = new(HexRetirementReason.Security, "CVE-2026-9");

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly RSA _hexKey = RSA.Create(2048);
    private ReservedNamespaceService _reserved = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _reserved = new ReservedNamespaceService(_db, new MemoryCache(new MemoryCacheOptions()), _clock);
    }

    public async Task DisposeAsync()
    {
        _hexKey.Dispose();
        await _db.DisposeAsync();
    }

    // Fixed at construction: the scenarios advance the clock past the cache TTL, and every
    // recorded stamp must still read as the same 30-day-old instant afterwards.
    private string StaleStamp { get; }

    public DeprecationRefreshStaleCacheTests() => StaleStamp = _clock.GetUtcNow().AddDays(-30).ToUtcIso();

    private string Now => _clock.GetUtcNow().ToUtcIso();

    public enum Outage
    {
        ServerError,
        TransportFault,
    }

    // ── npm / PyPI ─────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("npm", Outage.ServerError)]
    [InlineData("npm", Outage.TransportFault)]
    [InlineData("pypi", Outage.ServerError)]
    [InlineData("pypi", Outage.TransportFault)]
    public async Task CachedUnmarkedBody_ServedStaleDuringAnOutage_KeepsTheMark_AndYields(string ecosystem, Outage outage)
    {
        var scenario = await WarmThenMarkAsync(ecosystem, "stale-pkg", Document(ecosystem, "stale-pkg", null, ["1.0.0", "2.0.0"]));
        Assert.True(await IsBlockedUnderBlockAllAsync(scenario.Group, ecosystem, "stale-pkg"));

        scenario.Upstream.Route = _ => Fail(outage);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains(scenario.Upstream.Requests, u => u.StartsWith(PrimaryUrl, StringComparison.Ordinal));
        await AssertNothingRecordedAsync(scenario.Group, RecordedMark);
        Assert.True(await IsBlockedUnderBlockAllAsync(scenario.Group, ecosystem, "stale-pkg"));
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    public async Task CachedUnmarkedBody_LiveAnswerWithNoDeprecation_StillClearsTheMark(string ecosystem)
    {
        string body = Document(ecosystem, "live-pkg", null, ["1.0.0", "2.0.0"]);
        var scenario = await WarmThenMarkAsync(ecosystem, "live-pkg", body);

        scenario.Upstream.Route = url => IsPrimary(url) ? Ok(body) : Status(HttpStatusCode.ServiceUnavailable);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(scenario.Group.CacheArtifactIds[0]);
        Assert.Null(row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.Equal(1, row.VersionsBehind);
        Assert.Equal("2.0.0", await ReadLatestAsync(scenario.Group.PackageId));
        Assert.False(await IsBlockedUnderBlockAllAsync(scenario.Group, ecosystem, "live-pkg"));
    }

    [Theory]
    [InlineData("npm", Outage.ServerError, "do not use")]
    [InlineData("npm", Outage.TransportFault, "do not use")]
    [InlineData("pypi", Outage.ServerError, "yanked")]
    [InlineData("pypi", Outage.TransportFault, "yanked")]
    public async Task PrimaryServedStale_MirrorAnswersLive_TheMirrorVerdictIsRecorded(
        string ecosystem, Outage outage, string mirrorVerdict)
    {
        var scenario = await WarmThenMarkAsync(ecosystem, "mirror-pkg", Document(ecosystem, "mirror-pkg", null, ["1.0.0", "2.0.0"]));
        string mirrorBody = Document(ecosystem, "mirror-pkg", "1.0.0", ["1.0.0", "3.0.0"]);

        scenario.Upstream.Route = url => IsPrimary(url) ? Fail(outage) : Ok(mirrorBody);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains(scenario.Upstream.Requests, u => u.StartsWith(MirrorUrl, StringComparison.Ordinal));
        var row = await ReadCacheRowAsync(scenario.Group.CacheArtifactIds[0]);
        Assert.Equal(mirrorVerdict, row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.Equal(1, row.VersionsBehind);
        Assert.Equal("3.0.0", await ReadLatestAsync(scenario.Group.PackageId));
    }

    [Fact]
    public async Task NpmStaleBody_DoesNotRevokeAVersionCachedAfterIt()
    {
        // The stale packument predates 2.0.0, which was published and cached afterwards. Read as
        // an answer it would revoke 2.0.0; read as no answer it records nothing.
        var scenario = await WarmThenMarkAsync("npm", "late-pkg", Document("npm", "late-pkg", null, ["1.0.0"]));
        string lateId = await SeedCacheArtifactAsync(scenario.Group.OrgId, "npm", "late-pkg", "2.0.0", deprecated: null);

        scenario.Upstream.Route = _ => Fail(Outage.ServerError);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        Assert.Null(await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = lateId }));
    }

    // ── NuGet ──────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Outage.ServerError)]
    [InlineData(Outage.TransportFault)]
    public async Task NuGetCachedListedIndex_ServedStale_KeepsTheUnlistedMark_WhileTheLiveLatestIsRecorded(Outage outage)
    {
        var scenario = await WarmThenMarkNuGetAsync(Index(Page(Leaf("1.0.0", listed: true), Leaf("2.0.0", listed: true))));
        Assert.True(await IsBlockedUnderBlockAllAsync(scenario.Group, "nuget", NuGetId));

        // The flatcontainer answers live, so the resolver has an answer; the registration index
        // fails and the cache serves the old "listed" index stale.
        scenario.Upstream.Route = url => IsFlatContainer(url) ? Ok(FlatContainer) : Fail(outage);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(scenario.Group.CacheArtifactIds[0]);
        Assert.Equal(Unlisted, row.Deprecated);
        Assert.Equal(StaleStamp, row.DeprecationCheckedAt);
        Assert.Equal(1, row.VersionsBehind);
        Assert.Equal("2.0.0", await ReadLatestAsync(scenario.Group.PackageId));
        Assert.True(await IsBlockedUnderBlockAllAsync(scenario.Group, "nuget", NuGetId));
    }

    [Theory]
    [InlineData(Outage.ServerError)]
    [InlineData(Outage.TransportFault)]
    public async Task NuGetEverythingServedStale_RecordsNothing_AndYields(Outage outage)
    {
        var scenario = await WarmThenMarkNuGetAsync(Index(Page(Leaf("1.0.0", listed: true), Leaf("2.0.0", listed: true))));

        scenario.Upstream.Route = _ => Fail(outage);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        await AssertNothingRecordedAsync(scenario.Group, Unlisted);
        Assert.True(await IsBlockedUnderBlockAllAsync(scenario.Group, "nuget", NuGetId));
    }

    [Fact]
    public async Task NuGetCachedListedIndex_LiveListedAnswer_StillClearsTheMark()
    {
        string index = Index(Page(Leaf("1.0.0", listed: true), Leaf("2.0.0", listed: true)));
        var scenario = await WarmThenMarkNuGetAsync(index);

        scenario.Upstream.Route = url => IsFlatContainer(url) ? Ok(FlatContainer) : Ok(index);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(scenario.Group.CacheArtifactIds[0]);
        Assert.Null(row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.False(await IsBlockedUnderBlockAllAsync(scenario.Group, "nuget", NuGetId));
    }

    [Fact]
    public async Task NuGetPrimaryIndexServedStale_MirrorAnswersLive_TheMirrorVerdictIsRecorded()
    {
        var scenario = await WarmThenMarkNuGetAsync(Index(Page(Leaf("1.0.0", listed: true), Leaf("2.0.0", listed: true))));
        string mirrorIndex = Index(Page(Leaf("1.0.0", listed: false), Leaf("2.0.0", listed: true)));

        scenario.Upstream.Route = url => IsFlatContainer(url)
            ? Ok(FlatContainer)
            : IsPrimary(url) ? Fail(Outage.ServerError) : Ok(mirrorIndex);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains(scenario.Upstream.Requests, u => u.StartsWith($"{MirrorUrl}/registration5-gz-semver2/", StringComparison.Ordinal));
        var row = await ReadCacheRowAsync(scenario.Group.CacheArtifactIds[0]);
        Assert.Equal(Unlisted, row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
    }

    [Fact]
    public async Task NuGetExternalizedPageServedStale_GivesItsVersionsNoVerdict()
    {
        // The index itself answers live, but its externalized page fails and the cache serves the
        // old page, in which 1.0.0 is listed.
        string pageUrl = $"{PrimaryUrl}/registration5-gz-semver2/{NuGetId}/page/1.0.0/2.0.0.json";
        string index = Index(ExternalPage(pageUrl));
        string page = Page(Leaf("1.0.0", listed: true), Leaf("2.0.0", listed: true)).ToJsonString();
        var scenario = await WarmThenMarkNuGetAsync(index, url => url == pageUrl ? Ok(page) : null);

        scenario.Upstream.Route = url => IsFlatContainer(url)
            ? Ok(FlatContainer)
            : url == pageUrl ? Fail(Outage.ServerError) : Ok(index);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains(pageUrl, scenario.Upstream.Requests);
        var row = await ReadCacheRowAsync(scenario.Group.CacheArtifactIds[0]);
        Assert.Equal(Unlisted, row.Deprecated);
        Assert.Equal(StaleStamp, row.DeprecationCheckedAt);
    }

    // ── Maven (upstream latest through the resolver) ───────────────────────────

    [Fact]
    public async Task MavenCachedMetadata_ServedStale_RecordsNoLatest_AndYields()
    {
        var scenario = await WarmThenMarkAsync("maven", "org.example:widget", MavenMetadata("2.0.0", "1.0.0", "2.0.0"));

        scenario.Upstream.Route = _ => Fail(Outage.ServerError);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        await AssertNothingRecordedAsync(scenario.Group, RecordedMark);
    }

    [Fact]
    public async Task MavenPrimaryServedStale_MirrorAnswersLive_TheMirrorLatestIsRecorded()
    {
        var scenario = await WarmThenMarkAsync("maven", "org.example:gadget", MavenMetadata("2.0.0", "1.0.0", "2.0.0"));

        scenario.Upstream.Route = url => IsPrimary(url) ? Fail(Outage.TransportFault) : Ok(MavenMetadata("3.0.0", "1.0.0", "3.0.0"));
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal("3.0.0", await ReadLatestAsync(scenario.Group.PackageId));
        Assert.Equal(1, (await ReadCacheRowAsync(scenario.Group.CacheArtifactIds[0])).VersionsBehind);
    }

    // ── Hex ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Outage.ServerError)]
    [InlineData(Outage.TransportFault)]
    public async Task HexCachedUnretiredResource_ServedStale_KeepsTheRetirement_AndYields(Outage outage)
    {
        var scenario = await WarmThenRetireHexAsync(withMirror: false);

        scenario.Upstream.Route = _ => Fail(outage);
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        string caId = scenario.Group.CacheArtifactIds[0];
        var row = await ReadCacheRowAsync(caId);
        Assert.Equal(HexIndexBuilder.RetirementAsDeprecation(SecurityRetirement), row.Deprecated);
        Assert.Equal(StaleStamp, row.DeprecationCheckedAt);
        Assert.Equal(RecordedVersionsBehind, row.VersionsBehind);
        Assert.Equal(("security", "CVE-2026-9"), await ReadHexRetirementAsync(caId));
        Assert.Equal(RecordedLatest, await ReadLatestAsync(scenario.Group.PackageId));
        Assert.True(await IsBlockedUnderBlockAllAsync(scenario.Group, "hex", "jason"));
    }

    [Fact]
    public async Task HexCachedUnretiredResource_LiveUnretiredAnswer_StillClearsTheRetirement()
    {
        var scenario = await WarmThenRetireHexAsync(withMirror: false);

        scenario.Upstream.Route = _ => Ok(HexResource(retired: false));
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        string caId = scenario.Group.CacheArtifactIds[0];
        var row = await ReadCacheRowAsync(caId);
        Assert.Null(row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.Equal((null, null), await ReadHexRetirementAsync(caId));
        Assert.False(await IsBlockedUnderBlockAllAsync(scenario.Group, "hex", "jason"));
    }

    [Fact]
    public async Task HexPrimaryServedStale_MirrorAnswersLive_TheMirrorVerdictIsRecorded()
    {
        var scenario = await WarmThenRetireHexAsync(withMirror: true);

        scenario.Upstream.Route = url => IsPrimary(url) ? Fail(Outage.ServerError) : Ok(HexResource(retired: true));
        await scenario.Service.RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains($"{MirrorUrl}/packages/jason", scenario.Upstream.Requests);
        string caId = scenario.Group.CacheArtifactIds[0];
        var row = await ReadCacheRowAsync(caId);
        Assert.Equal(HexIndexBuilder.RetirementAsDeprecation(SecurityRetirement), row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.Equal(("security", "CVE-2026-9"), await ReadHexRetirementAsync(caId));
        Assert.Equal("1.2.0", await ReadLatestAsync(scenario.Group.PackageId));
    }

    // ── The request-serving reads still relay a stale body ─────────────────────

    [Fact]
    public async Task RequestServingReads_StillRelayTheStaleBody_OnlyTheFreshResolveDeclinesIt()
    {
        string orgId = await SeedOrgWithSourcesAsync("nuget", PrimaryUrl);
        var upstreamHandler = new SwitchableUpstream { Route = url => IsFlatContainer(url) ? Ok(FlatContainer) : Status(HttpStatusCode.NotFound) };
        var upstream = BuildUpstream(upstreamHandler);
        var resolver = new UpstreamLatestVersionResolver(upstream, Registries(), _reserved);
        string url = $"{PrimaryUrl}/flatcontainer/{NuGetId}/index.json";

        var live = await upstream.GetOrFetchMetadataAsync(url);
        Assert.False(live.IsStale);

        _clock.Advance(PastTheTtl);
        upstreamHandler.Route = _ => Fail(Outage.ServerError);

        // The proxy path's read: the cached 200 is relayed with its body, as before.
        var stale = await upstream.GetOrFetchMetadataAsync(url);
        Assert.Equal(200, stale.StatusCode);
        Assert.True(stale.IsSuccessStatusCode);
        Assert.Equal(FlatContainer, stale.BodyAsString());
        Assert.True(stale.IsStale);

        // The lookup service resolves through ResolveAsync, which keeps reading the stale body;
        // the refresh and the first-fetch seed record the answer, so their fresh-only resolve
        // gets none.
        Assert.Equal("2.0.0", (await resolver.ResolveAsync("nuget", orgId, NuGetId)).Version);
        Assert.Null((await resolver.ResolveFreshAsync("nuget", orgId, NuGetId)).Version);
    }

    [Fact]
    public async Task HexReadPlaneFetch_StillReadsTheStaleResource_OnlyARequireFreshFetchDeclinesIt()
    {
        string orgId = await SeedOrgWithSourcesAsync("hex", PrimaryUrl);
        var upstreamHandler = new SwitchableUpstream { Route = _ => Ok(HexResource(retired: false)) };
        var upstream = BuildUpstream(upstreamHandler);
        var registries = Registries();

        Assert.NotNull((await HexUpstreamPackageFetcher.FetchAsync(
            upstream, registries, orgId, "jason", NullLogger.Instance, null, CancellationToken.None)).Package);

        _clock.Advance(PastTheTtl);
        upstreamHandler.Route = _ => Fail(Outage.ServerError);

        var readPlane = await HexUpstreamPackageFetcher.FetchAsync(
            upstream, registries, orgId, "jason", NullLogger.Instance, null, CancellationToken.None);
        Assert.Equal(HexUpstreamOutcome.Ok, readPlane.Outcome);
        Assert.NotNull(readPlane.Package);

        var fresh = await HexUpstreamPackageFetcher.FetchAsync(
            upstream, registries, orgId, "jason", NullLogger.Instance, null, requireFresh: true, CancellationToken.None);
        Assert.Null(fresh.Package);
        Assert.Equal(HexUpstreamOutcome.Fault, fresh.Outcome);
    }

    // ── Scenarios ──────────────────────────────────────────────────────────────

    private sealed record SeededGroup(string OrgId, string PackageId, IReadOnlyList<string> CacheArtifactIds, int ActivityRows);

    private sealed record Scenario(SeededGroup Group, SwitchableUpstream Upstream, DeprecationRefreshService Service);

    // One cached version 1.0.0 with no mark and two sources (primary, mirror). A first pass reads
    // the primary's live body, which the metadata cache keeps; then the mark is recorded and every
    // fact and stamp is reset to a recorded, 30-day-old state, and the clock moves past the TTL
    // but inside the serve-stale window.
    private async Task<Scenario> WarmThenMarkAsync(string ecosystem, string name, string primaryBody)
    {
        string orgId = await SeedOrgWithSourcesAsync(ecosystem, PrimaryUrl, MirrorUrl);
        string packageId = await SeedPackageAsync(orgId, ecosystem, name);
        string caId = await SeedCacheArtifactAsync(orgId, ecosystem, name, "1.0.0", deprecated: null);

        var upstream = new SwitchableUpstream { Route = url => IsPrimary(url) ? Ok(primaryBody) : Status(HttpStatusCode.ServiceUnavailable) };
        var service = BuildService(upstream);
        await service.RunRefreshPassAsync(CancellationToken.None);

        return await MarkAndAgeAsync(orgId, packageId, [caId], RecordedMark, upstream, service);
    }

    private async Task<Scenario> WarmThenMarkNuGetAsync(string primaryIndex, Func<string, HttpResponseMessage?>? pages = null)
    {
        string orgId = await SeedOrgWithSourcesAsync("nuget", PrimaryUrl, MirrorUrl);
        string packageId = await SeedPackageAsync(orgId, "nuget", NuGetId);
        string caId = await SeedCacheArtifactAsync(orgId, "nuget", NuGetId, "1.0.0", deprecated: null);

        var upstream = new SwitchableUpstream
        {
            Route = url => !IsPrimary(url)
                ? Status(HttpStatusCode.ServiceUnavailable)
                : IsFlatContainer(url) ? Ok(FlatContainer)
                : url.EndsWith($"/registration5-gz-semver2/{NuGetId}/index.json", StringComparison.Ordinal) ? Ok(primaryIndex)
                : pages?.Invoke(url) ?? Status(HttpStatusCode.NotFound),
        };
        var service = BuildService(upstream);
        await service.RunRefreshPassAsync(CancellationToken.None);
        Assert.Null((await ReadCacheRowAsync(caId)).Deprecated);

        return await MarkAndAgeAsync(orgId, packageId, [caId], Unlisted, upstream, service);
    }

    // A cached Hex release 1.1.0 whose upstream resource is first read unretired, then the
    // retirement is recorded in cache_artifact and hex_release.
    private async Task<Scenario> WarmThenRetireHexAsync(bool withMirror)
    {
        string orgId = withMirror
            ? await SeedOrgWithSourcesAsync("hex", PrimaryUrl, MirrorUrl)
            : await SeedOrgWithSourcesAsync("hex", PrimaryUrl);
        string packageId = await SeedPackageAsync(orgId, "hex", "jason");
        string caId = await SeedCacheArtifactAsync(orgId, "hex", "jason", "1.1.0", deprecated: null);
        await new HexReleaseRepository(_db).UpsertCachedAsync(caId, new HexReleaseFacts(
            new string('b', 64), [], "jason", ["mix"], null, null, null, false, null));

        var upstream = new SwitchableUpstream { Route = url => IsPrimary(url) ? Ok(HexResource(retired: false)) : Status(HttpStatusCode.ServiceUnavailable) };
        var service = BuildService(upstream);
        await service.RunRefreshPassAsync(CancellationToken.None);
        Assert.Null((await ReadCacheRowAsync(caId)).Deprecated);

        await new HexReleaseRepository(_db).SetCachedRetirementAsync(caId, SecurityRetirement.Reason, SecurityRetirement.Message);
        return await MarkAndAgeAsync(
            orgId, packageId, [caId], HexIndexBuilder.RetirementAsDeprecation(SecurityRetirement), upstream, service);
    }

    private async Task<Scenario> MarkAndAgeAsync(
        string orgId, string packageId, IReadOnlyList<string> caIds, string mark,
        SwitchableUpstream upstream, DeprecationRefreshService service)
    {
        await using var conn = await _db.OpenAsync();
        foreach (string caId in caIds)
        {
            await conn.ExecuteAsync(
                """
                UPDATE cache_artifact SET deprecated = @mark, deprecation_checked_at = @stale, versions_behind = @behind
                WHERE id = @id
                """,
                new { id = caId, mark, stale = StaleStamp, behind = RecordedVersionsBehind });
            await conn.ExecuteAsync(
                "UPDATE tenant_artifact_access SET refresh_checked_at = @stale WHERE org_id = @orgId AND cache_artifact_id = @caId",
                new { orgId, caId, stale = StaleStamp });
        }

        await conn.ExecuteAsync(
            "UPDATE packages SET upstream_latest_version = @latest, upstream_latest_checked_at = @stale WHERE id = @id",
            new { id = packageId, latest = RecordedLatest, stale = StaleStamp });
        int activity = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId", new { orgId });

        _clock.Advance(PastTheTtl);
        upstream.Requests.Clear();
        return new Scenario(new SeededGroup(orgId, packageId, caIds, activity), upstream, service);
    }

    // ── Assertions ─────────────────────────────────────────────────────────────

    private async Task AssertNothingRecordedAsync(SeededGroup group, string mark)
    {
        var row = await ReadCacheRowAsync(group.CacheArtifactIds[0]);
        Assert.Equal(mark, row.Deprecated);
        Assert.Equal(StaleStamp, row.DeprecationCheckedAt);
        Assert.Equal(RecordedVersionsBehind, row.VersionsBehind);
        Assert.Equal(RecordedLatest, await ReadLatestAsync(group.PackageId));

        // The slot is yielded: this org's queue stamps move to now.
        await using var conn = await _db.OpenAsync();
        Assert.Equal(Now, await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_checked_at FROM packages WHERE id = @id", new { id = group.PackageId }));
        Assert.Equal(Now, await conn.QuerySingleAsync<string?>(
            "SELECT refresh_checked_at FROM tenant_artifact_access WHERE cache_artifact_id = @id",
            new { id = group.CacheArtifactIds[0] }));
        Assert.Equal(group.ActivityRows, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId", new { orgId = group.OrgId }));
    }

    private async Task<bool> IsBlockedUnderBlockAllAsync(SeededGroup group, string ecosystem, string name)
    {
        var entries = await new CacheArtifactRepository(_db).ListServeFactsForNameAsync(group.OrgId, ecosystem, name);
        var entry = Assert.Single(entries, e => e.Version == (ecosystem == "hex" ? "1.1.0" : "1.0.0"));
        return BlockGateService.IsHardBlockedByCacheEntry(
            entry, new OrgSettings { BlockDeprecated = "block_all" }, signals: null, _clock.GetUtcNow());
    }

    // ── Seeding and reading ────────────────────────────────────────────────────

    private async Task<string> SeedOrgWithSourcesAsync(string ecosystem, params string[] urls)
    {
        await using var conn = await _db.OpenAsync();
        string orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)", new { id = orgId, slug = $"org-{orgId[..8]}" });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });

        var registries = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        foreach (string url in urls)
        {
            await registries.AddAsync(orgId, new NewUpstreamRegistry(
                ecosystem, url, PublicKeyPem: ecosystem == "hex" ? HexRegistrySigner.ExportPublicKeyPem(_hexKey) : null));
        }

        return orgId;
    }

    private async Task<string> SeedPackageAsync(string orgId, string ecosystem, string name)
    {
        string packageId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, upstream_latest_version, upstream_latest_checked_at)
            VALUES (@id, @orgId, @ecosystem, @name, @name, 1, @latest, @stale)
            """,
            new { id = packageId, orgId, ecosystem, name, latest = RecordedLatest, stale = StaleStamp });
        return packageId;
    }

    private async Task<string> SeedCacheArtifactAsync(string orgId, string ecosystem, string name, string version, string? deprecated)
    {
        string caId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, purl,
                 deprecated, deprecation_checked_at, versions_behind)
            VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, @hash, @purl,
                    @deprecated, @stale, @behind)
            """,
            new
            {
                id = caId,
                ecosystem,
                name,
                version,
                filename = $"{name}-{version}.pkg",
                blobKey = $"proxy/{caId}/{name}-{version}.pkg",
                hash = new string('a', 64),
                purl = $"pkg:{ecosystem}/{name}@{version}",
                deprecated,
                stale = StaleStamp,
                behind = RecordedVersionsBehind,
            });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, refresh_checked_at) VALUES (@orgId, @caId, @stale)",
            new { orgId, caId, stale = StaleStamp });
        return caId;
    }

    private sealed record CacheRow(string? Deprecated, string? DeprecationCheckedAt, int? VersionsBehind);

    private async Task<CacheRow> ReadCacheRowAsync(string caId)
    {
        await using var conn = await _db.OpenAsync();
        var (deprecated, checkedAt, behind) = await conn.QuerySingleAsync<(string?, string?, int?)>(
            "SELECT deprecated, deprecation_checked_at, versions_behind FROM cache_artifact WHERE id = @id",
            new { id = caId });
        return new CacheRow(deprecated, checkedAt, behind);
    }

    private async Task<string?> ReadLatestAsync(string packageId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId });
    }

    private async Task<(string? Reason, string? Message)> ReadHexRetirementAsync(string caId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<(string? Reason, string? Message)>(
            "SELECT retired_reason, retired_message FROM hex_release WHERE owner_kind = 'cache_artifact' AND cache_artifact_id = @caId",
            new { caId });
    }

    // ── Documents ──────────────────────────────────────────────────────────────

    private const string FlatContainer = """{"versions":["1.0.0","2.0.0"]}""";

    private static bool IsPrimary(string url) => url.StartsWith(PrimaryUrl, StringComparison.Ordinal);

    private static bool IsFlatContainer(string url) => url.Contains("/flatcontainer/", StringComparison.Ordinal);

    // An npm packument or PyPI project document listing the given versions, the last as latest,
    // with deprecatedVersion (if any) marked deprecated "do not use" (npm) or yanked (PyPI).
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

    private static string MavenMetadata(string release, params string[] versions) =>
        $"<metadata><versioning><release>{release}</release><versions>"
        + string.Concat(versions.Select(v => $"<version>{v}</version>"))
        + "</versions></versioning></metadata>";

    private static JsonObject Leaf(string version, bool listed) => new()
    {
        ["@id"] = $"{PrimaryUrl}/registration5-gz-semver2/{NuGetId}/{version}.json",
        ["catalogEntry"] = new JsonObject
        {
            ["@id"] = $"{PrimaryUrl}/catalog0/data/{NuGetId}.{version}.json",
            ["id"] = "Example.Widget",
            ["version"] = version,
            ["listed"] = listed,
            ["published"] = listed ? "2024-01-01T00:00:00+00:00" : "1900-01-01T00:00:00+00:00",
        },
    };

    private static JsonObject Page(params JsonObject[] leaves) => new()
    {
        ["@id"] = $"{PrimaryUrl}/registration5-gz-semver2/{NuGetId}/index.json#page",
        ["count"] = leaves.Length,
        ["items"] = new JsonArray(leaves.Select(l => (JsonNode)l).ToArray()),
    };

    private static JsonObject ExternalPage(string url) => new()
    {
        ["@id"] = url,
        ["count"] = 2,
        ["lower"] = "1.0.0",
        ["upper"] = "2.0.0",
    };

    private static string Index(params JsonObject[] pages) => new JsonObject
    {
        ["count"] = pages.Length,
        ["items"] = new JsonArray(pages.Select(p => (JsonNode)p).ToArray()),
    }.ToJsonString();

    // The signed /packages/jason resource: 1.0.0, 1.1.0 (retired for security when retired is
    // true) and 1.2.0, so the latest stable, non-retired release is 1.2.0.
    private byte[] HexResource(bool retired)
    {
        static HexRelease Release(string v, int day, HexRetirementStatus? r = null) =>
            new(v, new byte[32], Array.Empty<HexDependency>(), r, new byte[32], null,
                HexTimestamp.FromDateTimeOffset(new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero).AddDays(day)));
        var package = new HexPackage("jason", "upstream-repo", new[]
        {
            Release("1.0.0", 1),
            Release("1.1.0", 2, retired ? SecurityRetirement : null),
            Release("1.2.0", 4),
        }, Array.Empty<HexSecurityAdvisory>());
        return HexRegistrySigner.BuildResource(HexRegistryCodec.EncodePackage(package), _hexKey);
    }

    private static HttpResponseMessage Fail(Outage outage) => outage == Outage.ServerError
        ? Status(HttpStatusCode.ServiceUnavailable)
        : throw new HttpRequestException("connection refused");

    private static HttpResponseMessage Status(HttpStatusCode status) => new(status) { Content = new StringContent("") };

    private static HttpResponseMessage Ok(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Ok(byte[] body) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };

    // ── Wiring ─────────────────────────────────────────────────────────────────

    private UpstreamRegistryResolver Registries() =>
        new(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));

    // The UpstreamClient with the metadata cache on at the edge defaults: a 120 s TTL and a 24 h
    // serve-stale window.
    private UpstreamClient BuildUpstream(HttpMessageHandler handler)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-refresh-stale-{Guid.NewGuid():N}"),
            })
            .Build();
        var cache = new MetadataResponseCache(
            new MetadataCacheOptions(
                PositiveTtl: TimeSpan.FromSeconds(MetadataCacheOptions.EdgeDefaultTtlSeconds),
                MaxStale: TimeSpan.FromSeconds(MetadataCacheOptions.DefaultMaxStaleSeconds),
                NegativeTtl: TimeSpan.FromSeconds(MetadataCacheOptions.DefaultNegativeTtlSeconds),
                MaxBytes: MetadataCacheOptions.DefaultMaxBytes),
            _clock);
        var blobs = new InMemoryBlobStore();
        return new UpstreamClient(
            new SingleHandlerFactory(handler), new TieredBlobStorage(blobs, blobs), new AuditRepository(_db),
            new AllowAllValidator(), new StubAirGap(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()), StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance, lifetime: null, metadataCache: cache);
    }

    private DeprecationRefreshService BuildService(HttpMessageHandler handler)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0",
                ["DEPRECATION_REFRESH_AGE_HOURS"] = "24",
                ["DEPRECATION_REFRESH_BATCH_SIZE"] = "100",
            })
            .Build();
        var upstream = BuildUpstream(handler);
        var registries = Registries();
        return new DeprecationRefreshService(
            new PackageRepository(_db, time: _clock), new CacheArtifactRepository(_db), new AuditRepository(_db), upstream,
            new UpstreamLatestVersionResolver(upstream, registries, _reserved), registries, new StubAirGap(), config,
            NullLogger<DeprecationRefreshService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            _reserved, new HexReleaseRepository(_db));
    }

    private sealed class SwitchableUpstream : HttpMessageHandler
    {
        public Func<string, HttpResponseMessage> Route { get; set; } = _ => Status(HttpStatusCode.NotFound);

        public List<string> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string url = request.RequestUri!.ToString();
            lock (Requests)
            {
                Requests.Add(url);
            }

            return Task.FromResult(Route(url));
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
