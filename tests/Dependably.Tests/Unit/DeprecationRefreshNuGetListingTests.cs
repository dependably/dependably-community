using System.Net;
using System.Text;
using Dapper;
using Dependably.Api.NuGetProtocol;
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
/// The deprecation refresh reads each cached NuGet version's listing state from the upstream
/// registration index and records it: a version unlisted upstream after it was cached is marked
/// "Unlisted upstream" (and so blocked under <c>block_deprecated=block_all</c>), and a relisted
/// version is cleared. Only a version whose registration leaf was read gets a verdict: when no
/// index source answers 2xx, or the page holding a version cannot be fetched, the recorded value
/// and its <c>deprecation_checked_at</c> are kept.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeprecationRefreshNuGetListingTests : IAsyncLifetime
{
    private const string PrimaryUrl = "http://primary.test/v3";
    private const string MirrorUrl = "http://mirror.test/v3";
    private const string Id = "example.widget";
    private const string Unlisted = "Unlisted upstream";

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

    // ── A 2xx registration index is a verdict per version ──────────────────────

    [Fact]
    public async Task CachedListedVersion_UnlistedUpstream_IsMarked_AndBlockedUnderBlockAll()
    {
        var seeded = await SeedGroupAsync(("1.0.0", null));
        Assert.False(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
        string index = Index(Page(Leaf("1.0.0", listed: false), Leaf("2.0.0", listed: true)));

        await BuildService(Router(registrationIndex: _ => Ok(index))).RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(seeded.Rows["1.0.0"]);
        Assert.Equal(Unlisted, row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
    }

    [Fact]
    public async Task VersionThatStaysListed_IsNotMarked_WhileItsUnlistedSibling_Is()
    {
        var seeded = await SeedGroupAsync(("1.0.0", null), ("1.1.0", null));
        string index = Index(Page(Leaf("1.0.0", listed: false), Leaf("1.1.0", listed: true), Leaf("2.0.0", listed: true)));

        await BuildService(Router(registrationIndex: _ => Ok(index))).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(Unlisted, (await ReadCacheRowAsync(seeded.Rows["1.0.0"])).Deprecated);
        var listed = await ReadCacheRowAsync(seeded.Rows["1.1.0"]);
        Assert.Null(listed.Deprecated);
        Assert.Equal(Now, listed.DeprecationCheckedAt);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
        Assert.False(await IsBlockedUnderBlockAllAsync(seeded, "1.1.0"));
    }

    [Fact]
    public async Task UnlistedAtFirstFetch_RelistedUpstream_IsUnmarked_AndServable()
    {
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted));
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
        string index = Index(Page(Leaf("1.0.0", listed: true), Leaf("2.0.0", listed: true)));

        await BuildService(Router(registrationIndex: _ => Ok(index))).RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(seeded.Rows["1.0.0"]);
        Assert.Null(row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.False(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
    }

    [Fact]
    public async Task LeafVersion_IsMatchedOnItsNormalizedForm()
    {
        // The registration index carries the publisher's casing and a four-part version; the cached
        // row carries the normalized lowercase form the flatcontainer path writes.
        var seeded = await SeedGroupAsync(("1.0.0-beta", null), ("1.2.0", null));
        string index = Index(Page(Leaf("1.0.0-Beta", listed: false), Leaf("1.2.0.0", listed: false), Leaf("2.0.0", listed: true)));

        await BuildService(Router(registrationIndex: _ => Ok(index))).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(Unlisted, (await ReadCacheRowAsync(seeded.Rows["1.0.0-beta"])).Deprecated);
        Assert.Equal(Unlisted, (await ReadCacheRowAsync(seeded.Rows["1.2.0"])).Deprecated);
    }

    [Fact]
    public async Task RegistrationIndex_IsFetchedOncePerPackage_NotPerVersion()
    {
        await SeedGroupAsync(("1.0.0", null), ("1.1.0", null), ("1.2.0", null));
        string index = Index(Page(Leaf("1.0.0", listed: false), Leaf("1.1.0", listed: true), Leaf("1.2.0", listed: true)));
        var handler = Router(registrationIndex: _ => Ok(index));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Single(handler.Requests, u => u.EndsWith($"/registration5-gz-semver2/{Id}/index.json", StringComparison.Ordinal));
    }

    // ── No registration answer: nothing recorded for any version ───────────────

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task EveryRegistrationSourceFails_RecordsNoListingVerdict_AndKeepsTheUnlistedMark(HttpStatusCode status)
    {
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted), ("1.1.0", null));
        var handler = Router(registrationIndex: _ => Status(status));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        // Both configured sources were asked for the index before the pass gave up on it.
        Assert.Equal(2, handler.Requests.Count(u => u.EndsWith("/index.json", StringComparison.Ordinal) && u.Contains("/registration5-gz-semver2/", StringComparison.Ordinal)));
        var unlisted = await ReadCacheRowAsync(seeded.Rows["1.0.0"]);
        Assert.Equal(Unlisted, unlisted.Deprecated);
        Assert.Equal(StaleStamp, unlisted.DeprecationCheckedAt);
        Assert.Equal(StaleStamp, (await ReadCacheRowAsync(seeded.Rows["1.1.0"])).DeprecationCheckedAt);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));

        // The flatcontainer answer the resolver did get is still recorded.
        Assert.Equal("2.0.0", await ReadLatestAsync(seeded.PackageId));
        Assert.Equal(1, unlisted.VersionsBehind);
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task EverySourceFails_RecordsNothing_AndKeepsTheUnlistedMark(HttpStatusCode status)
    {
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted));

        await BuildService(new RoutingHandler(_ => Status(status))).RunRefreshPassAsync(CancellationToken.None);

        var row = await ReadCacheRowAsync(seeded.Rows["1.0.0"]);
        Assert.Equal(Unlisted, row.Deprecated);
        Assert.Equal(StaleStamp, row.DeprecationCheckedAt);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
    }

    // ── Mixed sources ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task PrimaryIndexFails_MirrorAnswers_TheMirrorVerdictIsRecorded(HttpStatusCode status)
    {
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted), ("1.1.0", null));
        string mirrorIndex = Index(Page(Leaf("1.0.0", listed: true), Leaf("1.1.0", listed: false)));
        var handler = Router(registrationIndex: url => url.StartsWith(PrimaryUrl, StringComparison.Ordinal)
            ? Status(status)
            : Ok(mirrorIndex));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Null((await ReadCacheRowAsync(seeded.Rows["1.0.0"])).Deprecated);
        Assert.Equal(Unlisted, (await ReadCacheRowAsync(seeded.Rows["1.1.0"])).Deprecated);
    }

    [Fact]
    public async Task PrimaryIndexAnswers_TheMirrorIsNotAsked()
    {
        var seeded = await SeedGroupAsync(("1.0.0", null));
        string primaryIndex = Index(Page(Leaf("1.0.0", listed: false)));
        var handler = Router(registrationIndex: url => url.StartsWith(PrimaryUrl, StringComparison.Ordinal)
            ? Ok(primaryIndex)
            : Ok(Index(Page(Leaf("1.0.0", listed: true)))));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(Unlisted, (await ReadCacheRowAsync(seeded.Rows["1.0.0"])).Deprecated);
        Assert.DoesNotContain(handler.Requests, u => u.StartsWith(MirrorUrl, StringComparison.Ordinal) && u.Contains("/registration5-gz-semver2/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PrimaryAnswers200WithoutAnIndex_IsNoAnswer_TheMirrorVerdictIsRecorded()
    {
        // A 2xx error document is not a registration index: the mirror is asked, and its answer
        // relists the version the primary never described.
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted));
        var handler = Router(registrationIndex: url => url.StartsWith(PrimaryUrl, StringComparison.Ordinal)
            ? Ok("""{"error":"x"}""")
            : Ok(Index(Page(Leaf("1.0.0", listed: true)))));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains(handler.Requests, u => u.StartsWith(MirrorUrl, StringComparison.Ordinal) && u.EndsWith($"/registration5-gz-semver2/{Id}/index.json", StringComparison.Ordinal));
        var row = await ReadCacheRowAsync(seeded.Rows["1.0.0"]);
        Assert.Null(row.Deprecated);
        Assert.Equal(Now, row.DeprecationCheckedAt);
        Assert.False(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
    }

    // ── Externalized pages ─────────────────────────────────────────────────────

    // An index of pageCount externalized pages on the primary host; page i holds one listed leaf
    // for version 0.i.0, and the last page holds 1.0.0 (listed).
    private static (string Index, RoutingHandler Handler) ManyExternalPages(int pageCount)
    {
        string PageUrl(int i) => $"{PrimaryUrl}/registration5-gz-semver2/{Id}/page/{i}.json";
        string VersionOn(int i) => i == pageCount ? "1.0.0" : $"0.{i}.0";
        string index = Index(Enumerable.Range(1, pageCount).Select(i => ExternalPage(PageUrl(i))).ToArray());
        var handler = Router(
            registrationIndex: _ => Ok(index),
            page: url =>
            {
                int i = Enumerable.Range(1, pageCount).FirstOrDefault(n => PageUrl(n) == url);
                return i == 0 ? Status(HttpStatusCode.NotFound) : Ok(Page(Leaf(VersionOn(i), listed: true)).ToJsonString());
            });
        return (index, handler);
    }

    [Fact]
    public async Task Fetcher_PagesPastTheCap_AreNotFetched_AndTheirVersionsAreAbsent()
    {
        int cap = NuGetRegistrationHandler.MaxExternalizedPagesPerIndex;
        var (_, handler) = ManyExternalPages(cap + 1);
        var (upstream, _, _) = BuildUpstream(handler);

        var listing = await NuGetUpstreamListingFetcher.FetchAsync(
            upstream, [new UpstreamSource(PrimaryUrl, null)], Id, NullLogger.Instance, CancellationToken.None);

        Assert.NotNull(listing);
        Assert.Equal(cap, listing.Count);
        Assert.True(listing.ContainsKey($"0.{cap}.0"));
        Assert.False(listing.ContainsKey("1.0.0"));
        Assert.Equal(cap, handler.Requests.Count(u => u.Contains("/page/", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task VersionOnAPagePastTheCap_GetsNoVerdict_AndKeepsItsMark()
    {
        int cap = NuGetRegistrationHandler.MaxExternalizedPagesPerIndex;
        var seeded = await SeedGroupAsync(($"0.{cap}.0", Unlisted), ("1.0.0", Unlisted));
        var (_, handler) = ManyExternalPages(cap + 1);

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        // The last page inside the cap is read and relists its version; the page past it is not.
        Assert.Null((await ReadCacheRowAsync(seeded.Rows[$"0.{cap}.0"])).Deprecated);
        var pastCap = await ReadCacheRowAsync(seeded.Rows["1.0.0"]);
        Assert.Equal(Unlisted, pastCap.Deprecated);
        Assert.Equal(StaleStamp, pastCap.DeprecationCheckedAt);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
    }

    [Fact]
    public async Task ExternalizedPage_IsFetched_AndItsLeavesAreRecorded()
    {
        var seeded = await SeedGroupAsync(("1.0.0", null), ("3.0.0", Unlisted));
        string pageUrl = $"{PrimaryUrl}/registration5-gz-semver2/{Id}/page/1.0.0/2.0.0.json";
        string index = Index(ExternalPage(pageUrl), Page(Leaf("3.0.0", listed: true)));
        string page = Page(Leaf("1.0.0", listed: false), Leaf("2.0.0", listed: true)).ToJsonString();
        var handler = Router(registrationIndex: _ => Ok(index), page: url => url == pageUrl ? Ok(page) : Status(HttpStatusCode.NotFound));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(Unlisted, (await ReadCacheRowAsync(seeded.Rows["1.0.0"])).Deprecated);
        Assert.Null((await ReadCacheRowAsync(seeded.Rows["3.0.0"])).Deprecated);
    }

    [Fact]
    public async Task ExternalizedPageThatFails_GivesItsVersionsNoVerdict_WhileInlineLeavesAreRecorded()
    {
        // Mixed partial failure inside one answer: the inline page is read, the externalized page
        // answers 503. The version on the failed page keeps its recorded mark and stamp.
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted), ("3.0.0", Unlisted));
        string pageUrl = $"{PrimaryUrl}/registration5-gz-semver2/{Id}/page/1.0.0/2.0.0.json";
        string index = Index(ExternalPage(pageUrl), Page(Leaf("3.0.0", listed: true)));
        var handler = Router(registrationIndex: _ => Ok(index), page: _ => Status(HttpStatusCode.ServiceUnavailable));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        var unread = await ReadCacheRowAsync(seeded.Rows["1.0.0"]);
        Assert.Equal(Unlisted, unread.Deprecated);
        Assert.Equal(StaleStamp, unread.DeprecationCheckedAt);
        Assert.True(await IsBlockedUnderBlockAllAsync(seeded, "1.0.0"));
        Assert.Null((await ReadCacheRowAsync(seeded.Rows["3.0.0"])).Deprecated);
    }

    [Fact]
    public async Task ExternalizedPageOnAnotherHost_IsNotFetched_AndItsVersionsGetNoVerdict()
    {
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted));
        const string foreignPage = "http://elsewhere.test/page.json";
        var handler = Router(
            registrationIndex: _ => Ok(Index(ExternalPage(foreignPage))),
            page: _ => Ok(Page(Leaf("1.0.0", listed: true)).ToJsonString()));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.DoesNotContain(handler.Requests, u => u.StartsWith("http://elsewhere.test", StringComparison.Ordinal));
        Assert.Equal(Unlisted, (await ReadCacheRowAsync(seeded.Rows["1.0.0"])).Deprecated);
    }

    [Theory]
    // Same host, other scheme: the source's credential must not follow the page there.
    [InlineData("https://primary.test/v3/page.json")]
    // Same host, explicit other port: a different service.
    [InlineData("http://primary.test:8080/v3/page.json")]
    public async Task ExternalizedPageOnTheSourceHostButAnotherSchemeOrPort_IsNotFetched(string foreignPage)
    {
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted));
        var handler = Router(
            registrationIndex: _ => Ok(Index(ExternalPage(foreignPage))),
            page: _ => Ok(Page(Leaf("1.0.0", listed: true)).ToJsonString()));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.DoesNotContain(handler.Requests, u => u.EndsWith("/v3/page.json", StringComparison.Ordinal));
        Assert.Equal(Unlisted, (await ReadCacheRowAsync(seeded.Rows["1.0.0"])).Deprecated);
    }

    [Fact]
    public async Task ExternalizedPageSpellingOutTheSourcesDefaultPort_IsFetched()
    {
        var seeded = await SeedGroupAsync(("1.0.0", Unlisted));
        const string pageUrl = "http://primary.test:80/v3/page.json";
        var handler = Router(
            registrationIndex: _ => Ok(Index(ExternalPage(pageUrl))),
            page: _ => Ok(Page(Leaf("1.0.0", listed: true)).ToJsonString()));

        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Null((await ReadCacheRowAsync(seeded.Rows["1.0.0"])).Deprecated);
    }

    // ── The parser is the first-fetch parser ───────────────────────────────────

    [Fact]
    public void ParseListing_ReadsEachLeafWithTheFirstFetchParser()
    {
        string json = Index(Page(
            Leaf("1.0.0", listed: false),
            Leaf("1.1.0", listed: true),
            Leaf("1.2.0", listed: null),
            new System.Text.Json.Nodes.JsonObject { ["catalogEntry"] = "http://primary.test/catalog/1.3.0.json" }));

        var listing = NuGetUpstreamListingFetcher.ParseListing(json);

        Assert.NotNull(listing);
        Assert.Equal(Unlisted, listing["1.0.0"]);
        Assert.Null(listing["1.1.0"]);
        Assert.Null(listing["1.2.0"]);
        Assert.False(listing.ContainsKey("1.3.0"));
        foreach (var leaf in System.Text.Json.Nodes.JsonNode.Parse(json)!["items"]![0]!["items"]!.AsArray().Take(3))
        {
            string version = leaf!["catalogEntry"]!["version"]!.GetValue<string>();
            Assert.Equal(NuGetNupkgProxyHelper.ParseUnlistedDeprecation(leaf), listing[version]);
        }
    }

    [Fact]
    public void ParseListing_NotAnIndex_IsNoAnswer()
    {
        Assert.Null(NuGetUpstreamListingFetcher.ParseListing("[]"));
        Assert.Null(NuGetUpstreamListingFetcher.ParseListing("not json"));
        Assert.Null(NuGetUpstreamListingFetcher.ParseListing("""{"error":"x"}"""));
        Assert.Null(NuGetUpstreamListingFetcher.ParseListing("""{"items":{}}"""));
        Assert.Empty(NuGetUpstreamListingFetcher.ParseListing("""{"items":[]}""")!);
    }

    // ── Documents ──────────────────────────────────────────────────────────────

    private static System.Text.Json.Nodes.JsonObject Leaf(string version, bool? listed)
    {
        var entry = new System.Text.Json.Nodes.JsonObject
        {
            ["@id"] = $"{PrimaryUrl}/catalog0/data/{Id}.{version}.json",
            ["id"] = "Example.Widget",
            ["version"] = version,
            // nuget.org stamps an unlisted version's published date as 1900-01-01.
            ["published"] = listed == false ? "1900-01-01T00:00:00+00:00" : "2024-01-01T00:00:00+00:00",
        };
        if (listed is { } l)
        {
            entry["listed"] = l;
        }

        return new System.Text.Json.Nodes.JsonObject
        {
            ["@id"] = $"{PrimaryUrl}/registration5-gz-semver2/{Id}/{version}.json",
            ["catalogEntry"] = entry,
            ["packageContent"] = $"{PrimaryUrl}/flatcontainer/{Id}/{version}/{Id}.{version}.nupkg",
        };
    }

    private static System.Text.Json.Nodes.JsonObject Page(params System.Text.Json.Nodes.JsonObject[] leaves) => new()
    {
        ["@id"] = $"{PrimaryUrl}/registration5-gz-semver2/{Id}/index.json#page",
        ["count"] = leaves.Length,
        ["items"] = new System.Text.Json.Nodes.JsonArray(leaves.Select(l => (System.Text.Json.Nodes.JsonNode)l).ToArray()),
    };

    private static System.Text.Json.Nodes.JsonObject ExternalPage(string url) => new()
    {
        ["@id"] = url,
        ["count"] = 2,
        ["lower"] = "1.0.0",
        ["upper"] = "2.0.0",
    };

    private static string Index(params System.Text.Json.Nodes.JsonObject[] pages) => new System.Text.Json.Nodes.JsonObject
    {
        ["count"] = pages.Length,
        ["items"] = new System.Text.Json.Nodes.JsonArray(pages.Select(p => (System.Text.Json.Nodes.JsonNode)p).ToArray()),
    }.ToJsonString();

    // Every source's flatcontainer index lists 1.0.0 and 2.0.0 (so the resolver answers with
    // latest 2.0.0); the registration index and any page answer as the test routes them; every
    // other URL (the resolver's best-effort leaf read) answers 404.
    private static RoutingHandler Router(
        Func<string, HttpResponseMessage> registrationIndex, Func<string, HttpResponseMessage>? page = null)
    {
        return new RoutingHandler(url =>
            url.EndsWith($"/flatcontainer/{Id}/index.json", StringComparison.Ordinal)
                ? Ok("""{"versions":["1.0.0","2.0.0"]}""")
                : url.EndsWith($"/registration5-gz-semver2/{Id}/index.json", StringComparison.Ordinal)
                    ? registrationIndex(url)
                    : url.Contains("/page", StringComparison.Ordinal) && page is not null
                        ? page(url)
                        : Status(HttpStatusCode.NotFound));
    }

    private static HttpResponseMessage Status(HttpStatusCode status) => new(status) { Content = new StringContent("") };

    private static HttpResponseMessage Ok(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    // ── Seeding and reading ────────────────────────────────────────────────────

    private sealed record SeededGroup(string OrgId, string PackageId, IReadOnlyDictionary<string, string> Rows);

    private sealed record CacheRow(string? Deprecated, string? DeprecationCheckedAt, int? VersionsBehind);

    // One org with a packages row, the given cached versions (each with its recorded deprecation),
    // and two configured nuget sources (primary first, mirror second). Every stamp is 30 days stale.
    private async Task<SeededGroup> SeedGroupAsync(params (string Version, string? Deprecated)[] versions)
    {
        await using var conn = await _db.OpenAsync();
        string orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)", new { id = orgId, slug = $"org-{orgId[..8]}" });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });

        string packageId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, upstream_latest_version, upstream_latest_checked_at)
            VALUES (@id, @orgId, 'nuget', @name, @name, 1, '9.9.9', @stale)
            """,
            new { id = packageId, orgId, name = Id, stale = StaleStamp });

        var rows = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (version, deprecated) in versions)
        {
            string caId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, purl,
                     deprecated, deprecation_checked_at, versions_behind)
                VALUES (@id, 'nuget', @name, @version, @filename, @blobKey, 'h', @purl,
                        @deprecated, @stale, 7)
                """,
                new
                {
                    id = caId,
                    name = Id,
                    version,
                    filename = $"{Id}.{version}.nupkg",
                    blobKey = $"proxy/{caId}/{Id}.{version}.nupkg",
                    purl = $"pkg:nuget/{Id}@{version}",
                    deprecated,
                    stale = StaleStamp,
                });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, refresh_checked_at) VALUES (@orgId, @caId, @stale)",
                new { orgId, caId, stale = StaleStamp });
            rows[version] = caId;
        }

        var registries = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        await registries.AddAsync(orgId, new NewUpstreamRegistry("nuget", PrimaryUrl));
        await registries.AddAsync(orgId, new NewUpstreamRegistry("nuget", MirrorUrl));

        return new SeededGroup(orgId, packageId, rows);
    }

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

    // The stored-state block check the listing and index renderers apply to a cached version,
    // under block_deprecated=block_all.
    private async Task<bool> IsBlockedUnderBlockAllAsync(SeededGroup seeded, string version)
    {
        var entries = await new CacheArtifactRepository(_db).ListServeFactsForNameAsync(seeded.OrgId, "nuget", Id);
        var entry = Assert.Single(entries, e => e.Version == version);
        return BlockGateService.IsHardBlockedByCacheEntry(
            entry, new OrgSettings { BlockDeprecated = "block_all" }, signals: null, _clock.GetUtcNow());
    }

    private DeprecationRefreshService BuildService(HttpMessageHandler handler)
    {
        var (upstream, config, airGap) = BuildUpstream(handler);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        return new DeprecationRefreshService(
            new PackageRepository(_db, time: _clock), new CacheArtifactRepository(_db), new AuditRepository(_db), upstream,
            new UpstreamLatestVersionResolver(upstream, registries, _reserved), registries, airGap, config,
            NullLogger<DeprecationRefreshService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            _reserved, new Dependably.Infrastructure.Hex.HexReleaseRepository(_db));
    }

    private (UpstreamClient Upstream, IConfiguration Config, StubAirGap AirGap) BuildUpstream(HttpMessageHandler handler)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-refresh-nuget-{Guid.NewGuid():N}"),
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
        return (upstream, config, airGap);
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
