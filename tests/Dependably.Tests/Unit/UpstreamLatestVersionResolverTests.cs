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
/// pass-through, and the no-upstream-configured null path. Uses an in-memory SQLite store and a
/// fake HTTP handler returning a controlled upstream document.
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

        string? latest = await resolver.ResolveAsync("nuget", orgId, "newtonsoft.json", CancellationToken.None);

        Assert.Equal("2.0.0", latest);
    }

    [Fact]
    public async Task NuGet_AllPrerelease_FallsBackToHighestPrerelease()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "nuget", "http://nuget.test/v3");
        var resolver = BuildResolver("""{"versions":["1.0.0-alpha","1.0.0-beta.2","1.0.0-beta.1"]}""");

        string? latest = await resolver.ResolveAsync("nuget", orgId, "preview-pkg", CancellationToken.None);

        Assert.Equal("1.0.0-beta.2", latest);
    }

    [Fact]
    public async Task NuGet_NoUpstreamConfigured_ReturnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var resolver = BuildResolver("""{"versions":["1.0.0"]}""");

        string? latest = await resolver.ResolveAsync("nuget", orgId, "x", CancellationToken.None);

        Assert.Null(latest);
    }

    [Fact]
    public async Task Maven_PrefersReleaseOverLatest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "maven", "http://maven.test");
        var resolver = BuildResolver(MavenMetadata(latest: "2.1.0-SNAPSHOT", release: "2.0.0"));

        string? latest = await resolver.ResolveAsync("maven", orgId, "org.example:widget", CancellationToken.None);

        Assert.Equal("2.0.0", latest);
    }

    [Fact]
    public async Task Maven_NoRelease_FallsBackToLatest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedRegistryAsync(orgId, "maven", "http://maven.test");
        var resolver = BuildResolver(MavenMetadata(latest: "0.1.0-SNAPSHOT", release: null));

        string? latest = await resolver.ResolveAsync("maven", orgId, "org.example:snapshot-only", CancellationToken.None);

        Assert.Equal("0.1.0-SNAPSHOT", latest);
    }

    [Fact]
    public async Task Npm_ReturnsDistTagsLatest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var resolver = BuildResolver("""{"dist-tags":{"latest":"3.4.5"},"versions":{}}""");

        string? latest = await resolver.ResolveAsync("npm", orgId, "left-pad", CancellationToken.None);

        Assert.Equal("3.4.5", latest);
    }

    private async Task SeedRegistryAsync(string orgId, string ecosystem, string url)
    {
        var repo = new UpstreamRegistryRepository(_db, TimeProvider.System);
        await repo.AddAsync(orgId, ecosystem, url, name: null);
    }

    private UpstreamLatestVersionResolver BuildResolver(string responseBody)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-latest-{Guid.NewGuid():N}"),
                ["Npm:Upstream"] = "http://npm.test",
                ["PyPI:Upstream"] = "http://pypi.test",
            })
            .Build();
        var blobs = new InMemoryBlobStore();
        var upstream = new UpstreamClient(
            new SingleHandlerFactory(new FixedResponseHandler(responseBody)),
            new TieredBlobStorage(blobs, blobs),
            new AuditRepository(_db),
            new AllowAllValidator(),
            new StubAirGap(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, TimeProvider.System));
        return new UpstreamLatestVersionResolver(upstream, registries, config);
    }

    private static string MavenMetadata(string? latest, string? release)
    {
        string latestEl = latest is null ? "" : $"<latest>{latest}</latest>";
        string releaseEl = release is null ? "" : $"<release>{release}</release>";
        return $"<metadata><versioning>{latestEl}{releaseEl}</versioning></metadata>";
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

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(true);
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
