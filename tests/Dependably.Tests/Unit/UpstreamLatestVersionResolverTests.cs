using System.Net;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the per-ecosystem upstream latest-version resolver: NuGet flatcontainer stable-version
/// selection (with prerelease fallback), Maven metadata release/latest preference, npm dist-tags
/// pass-through, the no-upstream-configured null path, and per-ecosystem publish-timestamp
/// extraction (npm packument time[], PyPI top-level urls[], Maven lastUpdated, NuGet registration
/// leaf). Uses an in-memory SQLite store and a fake HTTP handler returning a controlled upstream
/// document (or, for NuGet's two-fetch path, a per-URL routed document).
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamLatestVersionResolverTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task NuGet_PicksHighestStable_IgnoringPrerelease()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "nuget", "http://nuget.test/v3");
        var resolver = BuildResolver("""{"versions":["1.0.0","2.0.0","2.1.0-rc.1","1.9.0"]}""");

        var latest = await resolver.ResolveAsync("nuget", orgId, "newtonsoft.json", CancellationToken.None);

        Assert.Equal("2.0.0", latest.Version);
    }

    [Fact]
    public async Task NuGet_AllPrerelease_FallsBackToHighestPrerelease()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "nuget", "http://nuget.test/v3");
        var resolver = BuildResolver("""{"versions":["1.0.0-alpha","1.0.0-beta.2","1.0.0-beta.1"]}""");

        var latest = await resolver.ResolveAsync("nuget", orgId, "preview-pkg", CancellationToken.None);

        Assert.Equal("1.0.0-beta.2", latest.Version);
    }

    [Fact]
    public async Task NuGet_StableVersionsDescending_ExcludesPrereleaseAndOrdersDescending()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "nuget", "http://nuget.test/v3");
        var resolver = BuildResolver("""{"versions":["1.0.0","2.0.0","2.1.0-rc.1","1.9.0"]}""");

        var latest = await resolver.ResolveAsync("nuget", orgId, "newtonsoft.json", CancellationToken.None);

        Assert.Equal(new[] { "2.0.0", "1.9.0", "1.0.0" }, latest.StableVersionsDescending);
    }

    [Fact]
    public async Task NuGet_NoUpstreamConfigured_ReturnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var resolver = BuildResolver("""{"versions":["1.0.0"]}""");

        var latest = await resolver.ResolveAsync("nuget", orgId, "x", CancellationToken.None);

        Assert.Null(latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    [Fact]
    public async Task NuGet_FetchesPublishedAtFromRegistrationLeaf()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "nuget", "http://nuget.test/v3");
        // The flatcontainer index carries no timestamp; the resolver's second fetch (the
        // registration leaf for the picked version) is routed by URL suffix.
        var resolver = BuildRoutedResolver(new Dictionary<string, string>
        {
            ["/flatcontainer/newtonsoft.json/index.json"] = """{"versions":["1.0.0","2.0.0"]}""",
            ["/registration5-gz-semver2/newtonsoft.json/2.0.0.json"] =
                """{"catalogEntry":{"published":"2024-03-10T08:00:00.000Z"}}""",
        });

        var latest = await resolver.ResolveAsync("nuget", orgId, "newtonsoft.json", CancellationToken.None);

        Assert.Equal("2.0.0", latest.Version);
        Assert.Equal(new DateTimeOffset(2024, 3, 10, 8, 0, 0, TimeSpan.Zero), latest.PublishedAt);
    }

    [Fact]
    public async Task NuGet_RegistrationLeafPublishedIsUnlistedSentinel_ReturnsNullPublishedAt()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "nuget", "http://nuget.test/v3");
        // NuGet stamps 1900-01-01 on the registration leaf for unlisted versions — the resolver
        // must coerce this sentinel to null rather than surfacing it as a real publish date, or
        // an unlisted latest version would render as "abandoned" instead of "unknown".
        var resolver = BuildRoutedResolver(new Dictionary<string, string>
        {
            ["/flatcontainer/newtonsoft.json/index.json"] = """{"versions":["1.0.0","2.0.0"]}""",
            ["/registration5-gz-semver2/newtonsoft.json/2.0.0.json"] =
                """{"published":"1900-01-01T00:00:00+00:00"}""",
        });

        var latest = await resolver.ResolveAsync("nuget", orgId, "newtonsoft.json", CancellationToken.None);

        Assert.Equal("2.0.0", latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    [Fact]
    public async Task NuGet_RegistrationLeafFetchFails_StillReturnsVersionWithNullPublishedAt()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "nuget", "http://nuget.test/v3");
        var resolver = BuildRoutedResolver(new Dictionary<string, string>
        {
            ["/flatcontainer/newtonsoft.json/index.json"] = """{"versions":["1.0.0","2.0.0"]}""",
            // No registration5-gz-semver2 entry — the routed handler 404s that URL.
        });

        var latest = await resolver.ResolveAsync("nuget", orgId, "newtonsoft.json", CancellationToken.None);

        Assert.Equal("2.0.0", latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    [Fact]
    public async Task Maven_PrefersReleaseOverLatest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "maven", "http://maven.test");
        var resolver = BuildResolver(MavenMetadata(latest: "2.1.0-SNAPSHOT", release: "2.0.0"));

        var latest = await resolver.ResolveAsync("maven", orgId, "org.example:widget", CancellationToken.None);

        Assert.Equal("2.0.0", latest.Version);
    }

    [Fact]
    public async Task Maven_NoRelease_FallsBackToLatest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "maven", "http://maven.test");
        var resolver = BuildResolver(MavenMetadata(latest: "0.1.0-SNAPSHOT", release: null));

        var latest = await resolver.ResolveAsync("maven", orgId, "org.example:snapshot-only", CancellationToken.None);

        Assert.Equal("0.1.0-SNAPSHOT", latest.Version);
    }

    [Fact]
    public async Task Maven_ExtractsPublishedAtFromLastUpdated()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "maven", "http://maven.test");
        var resolver = BuildResolver(MavenMetadata(latest: null, release: "2.0.0", lastUpdated: "20240115093000"));

        var latest = await resolver.ResolveAsync("maven", orgId, "org.example:widget", CancellationToken.None);

        Assert.Equal("2.0.0", latest.Version);
        Assert.Equal(new DateTimeOffset(2024, 1, 15, 9, 30, 0, TimeSpan.Zero), latest.PublishedAt);
    }

    [Fact]
    public async Task Maven_NoLastUpdated_PublishedAtIsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "maven", "http://maven.test");
        var resolver = BuildResolver(MavenMetadata(latest: null, release: "2.0.0", lastUpdated: null));

        var latest = await resolver.ResolveAsync("maven", orgId, "org.example:widget", CancellationToken.None);

        Assert.Equal("2.0.0", latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    [Fact]
    public async Task Maven_StableVersionsDescending_ExcludesSnapshotAndOrdersDescending()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "maven", "http://maven.test");
        const string metadata =
            "<metadata><versioning><release>2.0.0</release>" +
            "<versions><version>1.0.0</version><version>1.10.0</version>" +
            "<version>2.0.0-SNAPSHOT</version><version>2.0.0</version></versions>" +
            "</versioning></metadata>";
        var resolver = BuildResolver(metadata);

        var latest = await resolver.ResolveAsync("maven", orgId, "org.example:widget", CancellationToken.None);

        // 1.10.0 sorts numerically above 1.0.0 (not lexically); the -SNAPSHOT entry is excluded.
        Assert.Equal(new[] { "2.0.0", "1.10.0", "1.0.0" }, latest.StableVersionsDescending);
    }

    [Fact]
    public async Task Npm_ReturnsDistTagsLatest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "npm", "http://npm.test");
        var resolver = BuildResolver("""{"dist-tags":{"latest":"3.4.5"},"versions":{}}""");

        var latest = await resolver.ResolveAsync("npm", orgId, "left-pad", CancellationToken.None);

        Assert.Equal("3.4.5", latest.Version);
    }

    [Fact]
    public async Task Npm_ExtractsPublishedAtFromTimeMap()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "npm", "http://npm.test");
        var resolver = BuildResolver(
            """
            {"dist-tags":{"latest":"3.4.5"},"versions":{},
             "time":{"3.4.5":"2023-11-20T14:30:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z"}}
            """);

        var latest = await resolver.ResolveAsync("npm", orgId, "left-pad", CancellationToken.None);

        Assert.Equal("3.4.5", latest.Version);
        Assert.Equal(new DateTimeOffset(2023, 11, 20, 14, 30, 0, TimeSpan.Zero), latest.PublishedAt);
    }

    [Fact]
    public async Task Npm_TimeMapMissingLatestEntry_PublishedAtIsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "npm", "http://npm.test");
        var resolver = BuildResolver(
            """{"dist-tags":{"latest":"3.4.5"},"versions":{},"time":{"1.0.0":"2020-01-01T00:00:00.000Z"}}""");

        var latest = await resolver.ResolveAsync("npm", orgId, "left-pad", CancellationToken.None);

        Assert.Equal("3.4.5", latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    [Fact]
    public async Task Npm_StableVersionsDescending_ExcludesPrereleaseVersions()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "npm", "http://npm.test");
        var resolver = BuildResolver(
            """
            {"dist-tags":{"latest":"2.0.0"},
             "versions":{"1.0.0":{},"2.0.0":{},"2.1.0-beta.1":{}}}
            """);

        var latest = await resolver.ResolveAsync("npm", orgId, "left-pad", CancellationToken.None);

        Assert.Equal(new[] { "2.0.0", "1.0.0" }, latest.StableVersionsDescending);
    }

    [Fact]
    public async Task Npm_NoUpstreamConfigured_ReturnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var resolver = BuildResolver("""{"dist-tags":{"latest":"3.4.5"},"versions":{}}""");

        var latest = await resolver.ResolveAsync("npm", orgId, "left-pad", CancellationToken.None);

        Assert.Null(latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    [Fact]
    public async Task PyPi_ExtractsPublishedAtFromTopLevelUrls()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "pypi", "http://pypi.test");
        var resolver = BuildResolver(
            """
            {"info":{"version":"2.5.0"},
             "urls":[{"filename":"pkg-2.5.0.tar.gz","upload_time_iso_8601":"2022-07-04T18:00:00.000Z"}],
             "releases":{}}
            """);

        var latest = await resolver.ResolveAsync("pypi", orgId, "good-lib", CancellationToken.None);

        Assert.Equal("2.5.0", latest.Version);
        Assert.Equal(new DateTimeOffset(2022, 7, 4, 18, 0, 0, TimeSpan.Zero), latest.PublishedAt);
    }

    [Fact]
    public async Task PyPi_StableVersionsDescending_ExcludesPreAndDevReleases()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "pypi", "http://pypi.test");
        var resolver = BuildResolver(
            """
            {"info":{"version":"2.0.0"},
             "releases":{"1.0.0":[],"2.0.0":[],"2.1.0a1":[],"2.1.0.dev0":[]}}
            """);

        var latest = await resolver.ResolveAsync("pypi", orgId, "good-lib", CancellationToken.None);

        Assert.Equal(new[] { "2.0.0", "1.0.0" }, latest.StableVersionsDescending);
    }

    [Fact]
    public async Task PyPi_NoUrlsArray_PublishedAtIsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "pypi", "http://pypi.test");
        var resolver = BuildResolver("""{"info":{"version":"2.5.0"},"releases":{}}""");

        var latest = await resolver.ResolveAsync("pypi", orgId, "good-lib", CancellationToken.None);

        Assert.Equal("2.5.0", latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    [Fact]
    public async Task PyPi_NoUpstreamConfigured_ReturnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var resolver = BuildResolver("""{"info":{"version":"2.5.0"},"releases":{}}""");

        var latest = await resolver.ResolveAsync("pypi", orgId, "good-lib", CancellationToken.None);

        Assert.Null(latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    private async Task SeedRegistryAsync(string orgId, string ecosystem, string url)
    {
        var repo = new UpstreamRegistryRepository(_db, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());
        await repo.AddAsync(orgId, new NewUpstreamRegistry(ecosystem, url));
    }

    private UpstreamLatestVersionResolver BuildResolver(string responseBody) =>
        BuildResolverWithHandler(new FixedResponseHandler(responseBody));

    // Builds a resolver whose HTTP handler routes by URL suffix — used for NuGet's two-fetch
    // path (flatcontainer index, then the picked version's registration leaf). A URL with no
    // matching suffix 404s, exercising the best-effort "leaf fetch failed" branch.
    private UpstreamLatestVersionResolver BuildRoutedResolver(Dictionary<string, string> responsesBySuffix) =>
        BuildResolverWithHandler(new RoutedResponseHandler(responsesBySuffix));

    private UpstreamLatestVersionResolver BuildResolverWithHandler(HttpMessageHandler handler)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-latest-{Guid.NewGuid():N}"),
            })
            .Build();
        var blobs = new InMemoryBlobStore();
        var upstream = new UpstreamClient(
            new SingleHandlerFactory(handler),
            new TieredBlobStorage(blobs, blobs),
            new AuditRepository(_db),
            new AllowAllValidator(),
            new StubAirGap(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured()));
        return new UpstreamLatestVersionResolver(upstream, registries);
    }

    private static string MavenMetadata(string? latest, string? release, string? lastUpdated = null)
    {
        string latestEl = latest is null ? "" : $"<latest>{latest}</latest>";
        string releaseEl = release is null ? "" : $"<release>{release}</release>";
        string lastUpdatedEl = lastUpdated is null ? "" : $"<lastUpdated>{lastUpdated}</lastUpdated>";
        return $"<metadata><versioning>{latestEl}{releaseEl}{lastUpdatedEl}</versioning></metadata>";
    }

    private sealed class FixedResponseHandler : HttpMessageHandler
    {
        private readonly string _body;
        public FixedResponseHandler(string body) => _body = body;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            });
    }

    // Routes each request by matching the request URL's path suffix against the map; an
    // unmatched URL 404s, so a resolver's best-effort second fetch can be exercised as a failure.
    private sealed class RoutedResponseHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, string> _responsesBySuffix;
        public RoutedResponseHandler(Dictionary<string, string> responsesBySuffix) => _responsesBySuffix = responsesBySuffix;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string path = request.RequestUri!.AbsolutePath;
            var match = _responsesBySuffix.FirstOrDefault(kv => path.EndsWith(kv.Key, StringComparison.Ordinal));
            return Task.FromResult(match.Value is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(match.Value, Encoding.UTF8, "application/json")
                });
        }
    }

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(HttpMessageHandler handler) => _client = new HttpClient(handler);
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
