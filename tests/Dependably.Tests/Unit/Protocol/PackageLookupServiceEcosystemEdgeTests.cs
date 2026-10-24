using System.Net;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The per-ecosystem upstream arms of <see cref="PackageLookupService"/>: for every ecosystem a
/// definitive 404 reads as "no such package", an unhealthy or unreachable source reads as
/// unavailable (never as "not found" and never as a pass), a malformed document makes the source
/// unusable, and a later healthy source still answers when an earlier one failed. Upstream HTTP
/// is a per-request function, so failures are injected rather than timed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageLookupServiceEcosystemEdgeTests : IAsyncLifetime
{
    private readonly List<(string Suffix, Func<HttpResponseMessage> Make)> _routes = new();
    private StubUpstream _stub = null!;
    private string _orgId = null!;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _stub.DisposeAsync();

    private void Route(string suffix, HttpStatusCode status, string body = "")
        => _routes.Add((suffix, () => StubUpstream.Text(body, status)));

    private void Throw(string suffix, Exception ex)
        => _routes.Add((suffix, () => throw ex));

    private void RouteBytes(string suffix, byte[] body)
        => _routes.Add((suffix, () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }));

    // Answers the first request with the document and every later one with a connection fault, so
    // the lookup's own fetch succeeds and the latest-version resolver's fetch of the same URL fails.
    private void RouteThenFault(string suffix, string body)
    {
        int calls = 0;
        _routes.Add((suffix, () => ++calls == 1
            ? StubUpstream.Text(body)
            : throw new HttpRequestException("connection reset")));
    }

    private async Task<PackageLookupService> BuildAsync(string ecosystem, params string[] baseUrls)
        => await BuildKeyedAsync(ecosystem, null, baseUrls);

    private async Task<PackageLookupService> BuildKeyedAsync(string ecosystem, string? publicKeyPem, params string[] baseUrls)
    {
        _stub = await StubUpstream.CreateAsync(req =>
        {
            string url = req.RequestUri!.ToString();
            var (_, make) = _routes.FirstOrDefault(r => url.EndsWith(r.Suffix, StringComparison.Ordinal));
            return make is null ? StubUpstream.Status(HttpStatusCode.NotFound) : make();
        });
        _orgId = await OrgSeeder.InsertAsync(_stub.Db, $"org-{Guid.NewGuid():N}");
        var repo = new UpstreamRegistryRepository(_stub.Db, TimeProvider.System, TestEnvelope.Unconfigured());
        foreach (string url in baseUrls)
        {
            await repo.AddAsync(_orgId, new NewUpstreamRegistry(ecosystem, url, PublicKeyPem: publicKeyPem));
        }

        var resolver = new UpstreamRegistryResolver(repo);
        var reserved = new ReservedNamespaceService(_stub.Db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var latest = new UpstreamLatestVersionResolver(_stub.Client, resolver, reserved);
        return new PackageLookupService(
            new OrgRepository(_stub.Db), resolver, _stub.Client, latest, new CleanOsv(),
            new VulnerabilityRepository(_stub.Db, TimeProvider.System),
            new LicenseRepository(_stub.Db, TimeProvider.System, TestNormalizers.License(_stub.Db)),
            new NoAirGap(), TimeProvider.System, new PackageLookupCache(TimeProvider.System), reserved);
    }

    private static PackageLookupRequest Req(string orgId, string ecosystem, string name, string? version)
        => new(orgId, ecosystem, name, version);

    // ── No upstream configured ──────────────────────────────────────────────────

    [Theory]
    [InlineData("npm", "express")]
    [InlineData("pypi", "requests")]
    [InlineData("nuget", "Serilog")]
    [InlineData("maven", "org.apache.commons:commons-lang3")]
    [InlineData("cargo", "serde")]
    [InlineData("golang", "github.com/gin-gonic/gin")]
    [InlineData("hex", "phoenix")]
    public async Task AnOrgWithNoUpstreamForTheEcosystem_IsNotConfigured_NotUnavailable(string ecosystem, string name)
    {
        var svc = await BuildAsync(ecosystem);

        var outcome = await svc.LookupAsync(Req(_orgId, ecosystem, name, null));

        Assert.Equal(PackageLookupStatus.UpstreamNotConfigured, outcome.Status);
        Assert.Empty(_stub.Requests.Urls);
    }

    // ── npm ─────────────────────────────────────────────────────────────────────

    private const string NpmPackument =
        """{"dist-tags":{"latest":"4.19.2"},"versions":{"4.19.2":{"license":"MIT"},"4.18.0":{}},"time":{"4.19.2":"2024-03-25T00:00:00Z","4.18.0":12}}""";

    [Fact]
    public async Task Npm_ADefinitive404_IsNotFound()
    {
        Route("/express", HttpStatusCode.NotFound);
        var svc = await BuildAsync("npm", "http://npm.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", "4.19.2"));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
    }

    [Fact]
    public async Task Npm_AnUnhealthySource_WithNoVersion_IsUnavailable_NotNotFound()
    {
        Route("/express", HttpStatusCode.BadGateway, "bad gateway");
        var svc = await BuildAsync("npm", "http://npm.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", null));

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable, outcome.Status);
    }

    [Fact]
    public async Task Npm_AnUnreachableSource_WithAnExplicitVersion_DegradesWithTheMetadataChecksUnavailable()
    {
        Throw("/express", new HttpRequestException("connection refused"));
        var svc = await BuildAsync("npm", "http://npm.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", "4.19.2"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Contains("release_age", outcome.Result!.UnavailableChecks);
        Assert.Contains("deprecated", outcome.Result.UnavailableChecks);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
    }

    [Theory]
    [InlineData("not json {")]
    [InlineData("[1,2,3]")]
    public async Task Npm_AnUnusableDocument_MakesTheSourceUnavailable(string body)
    {
        Route("/express", HttpStatusCode.OK, body);
        var svc = await BuildAsync("npm", "http://npm.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", null));

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable, outcome.Status);
    }

    [Fact]
    public async Task Npm_AMissEarlierInPriorityOrder_StaysNotFound_WhenALaterSourceIsUnhealthy()
    {
        Route("http://npm-a.test/express", HttpStatusCode.NotFound);
        Route("http://npm-b.test/express", HttpStatusCode.InternalServerError, "boom");
        var svc = await BuildAsync("npm", "http://npm-a.test", "http://npm-b.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", "4.19.2"));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
    }

    [Fact]
    public async Task Npm_AFailedFirstSource_IsSkipped_AndTheSecondAnswers()
    {
        Route("http://npm-a.test/express", HttpStatusCode.InternalServerError, "boom");
        Route("http://npm-b.test/express", HttpStatusCode.OK, NpmPackument);
        var svc = await BuildAsync("npm", "http://npm-a.test", "http://npm-b.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", "4.19.2"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("4.19.2", outcome.Result!.Version);
        Assert.Equal(["MIT"], outcome.Result.License.Spdx);
    }

    [Fact]
    public async Task Npm_AVersionTheDocumentDoesNotList_IsNotFound()
    {
        Route("/express", HttpStatusCode.OK, NpmPackument);
        var svc = await BuildAsync("npm", "http://npm.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", "9.9.9"));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
    }

    [Fact]
    public async Task Npm_NoVersionAndNoLatestTag_IsNotFound()
    {
        Route("/express", HttpStatusCode.OK, """{"versions":{"4.18.0":{}}}""");
        var svc = await BuildAsync("npm", "http://npm.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", null));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
    }

    [Fact]
    public async Task Npm_ANonStringPublishTime_LeavesReleaseAgeUnavailable_WithoutFailingTheLookup()
    {
        Route("/express", HttpStatusCode.OK, NpmPackument);
        var svc = await BuildAsync("npm", "http://npm.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", "4.18.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Contains("release_age", outcome.Result!.UnavailableChecks);
    }

    [Fact]
    public async Task Npm_ResolvingLatestWhileTheSourceIsReachableOnlyOnce_ReportsUnavailable_NotAGuess()
    {
        // The packument fetch succeeds, then the resolver's own fetch of the same URL fails.
        int calls = 0;
        _routes.Add(("/express", () => ++calls == 1
            ? StubUpstream.Text(NpmPackument)
            : throw new HttpRequestException("reset")));
        var svc = await BuildAsync("npm", "http://npm.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "npm", "express", null));

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable, outcome.Status);
    }

    // ── PyPI ────────────────────────────────────────────────────────────────────

    private const string PyPiDocument =
        """
        {"info":{"version":"2.32.3","license":"Apache-2.0"},
         "releases":{"2.32.3":[{"upload_time_iso_8601":"2024-05-29T15:37:47.000000Z"}],"2.31.0":[{"upload_time_iso_8601":"2023-05-22T00:00:00Z"}],"2.0.0":[]}}
        """;

    [Fact]
    public async Task PyPi_ADefinitive404_IsNotFound()
    {
        Route("/pypi/requests/json", HttpStatusCode.NotFound);
        var svc = await BuildAsync("pypi", "http://pypi.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "pypi", "requests", "2.32.3"))).Status);
    }

    [Fact]
    public async Task PyPi_AnUnhealthySource_WithNoVersion_IsUnavailable()
    {
        Route("/pypi/requests/json", HttpStatusCode.ServiceUnavailable);
        var svc = await BuildAsync("pypi", "http://pypi.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "pypi", "requests", null))).Status);
    }

    [Fact]
    public async Task PyPi_AMalformedDocument_MakesTheSourceUnavailable()
    {
        Route("/pypi/requests/json", HttpStatusCode.OK, "<html>not json</html>");
        var svc = await BuildAsync("pypi", "http://pypi.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "pypi", "requests", null))).Status);
    }

    [Fact]
    public async Task PyPi_LatestReadsTheInfoLicence_ButAnOlderVersionDoesNot()
    {
        Route("/pypi/requests/json", HttpStatusCode.OK, PyPiDocument);
        var svc = await BuildAsync("pypi", "http://pypi.test");

        var latest = await svc.LookupAsync(Req(_orgId, "pypi", "requests", null));
        var older = await svc.LookupAsync(Req(_orgId, "pypi", "requests", "2.31.0"));

        Assert.Equal("2.32.3", latest.Result!.Version);
        Assert.True(latest.Result.VersionInferred);
        Assert.Equal(["Apache-2.0"], latest.Result.License.Spdx);
        Assert.Empty(older.Result!.License.Spdx);
        Assert.Contains("license", older.Result.UnavailableChecks);
    }

    [Theory]
    [InlineData("2.0.0")]
    [InlineData("1.1.1")]
    public async Task PyPi_AVersionWithNoFilesOrNoEntry_IsNotFound(string version)
    {
        Route("/pypi/requests/json", HttpStatusCode.OK, PyPiDocument);
        var svc = await BuildAsync("pypi", "http://pypi.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "pypi", "requests", version))).Status);
    }

    [Fact]
    public async Task PyPi_NoReleasesObject_IsNotFound()
    {
        Route("/pypi/requests/json", HttpStatusCode.OK, """{"info":{"version":"2.32.3"}}""");
        var svc = await BuildAsync("pypi", "http://pypi.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "pypi", "requests", "2.32.3"))).Status);
    }

    [Fact]
    public async Task PyPi_NoVersionAnywhere_IsNotFound()
    {
        Route("/pypi/requests/json", HttpStatusCode.OK, """{"releases":{}}""");
        var svc = await BuildAsync("pypi", "http://pypi.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "pypi", "requests", null))).Status);
    }

    // ── NuGet ───────────────────────────────────────────────────────────────────

    private const string NuGetIndex = """{"versions":["13.0.1","13.0.3","14.0.0-beta1"]}""";

    private const string Nuspec =
        """<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>Newtonsoft.Json</id><license type="expression">MIT</license></metadata></package>""";

    [Fact]
    public async Task NuGet_ADefinitive404_IsNotFound()
    {
        Route("/flatcontainer/serilog/index.json", HttpStatusCode.NotFound);
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "nuget", "Serilog", "4.0.0"))).Status);
    }

    [Fact]
    public async Task NuGet_AnUnhealthySource_WithNoVersion_IsUnavailable()
    {
        Route("/flatcontainer/serilog/index.json", HttpStatusCode.InternalServerError);
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "nuget", "Serilog", null))).Status);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"versions":"13.0.3"}""")]
    [InlineData("""{"items":[]}""")]
    public async Task NuGet_AnUnusableIndex_MakesTheSourceUnavailable(string body)
    {
        Route("/flatcontainer/serilog/index.json", HttpStatusCode.OK, body);
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "nuget", "Serilog", null))).Status);
    }

    [Fact]
    public async Task NuGet_AVersionNotInTheIndex_IsNotFound()
    {
        Route("/flatcontainer/serilog/index.json", HttpStatusCode.OK, NuGetIndex);
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "nuget", "Serilog", "9.9.9"))).Status);
    }

    [Fact]
    public async Task NuGet_AnEquivalentSpellingOfAListedVersion_IsFound_AndTheNuspecLicenceIsRead()
    {
        Route("/flatcontainer/newtonsoft.json/index.json", HttpStatusCode.OK, """{"versions":["13.0.3","", "  "]}""");
        Route("/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec", HttpStatusCode.OK, Nuspec);
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        var outcome = await svc.LookupAsync(Req(_orgId, "nuget", "Newtonsoft.Json", "13.0.3.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal(["MIT"], outcome.Result!.License.Spdx);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task NuGet_AFailingNuspecFetch_DegradesToNoLicence_NotToAFailedLookup(HttpStatusCode status)
    {
        Route("/flatcontainer/newtonsoft.json/index.json", HttpStatusCode.OK, NuGetIndex);
        Route("/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec", status);
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        var outcome = await svc.LookupAsync(Req(_orgId, "nuget", "Newtonsoft.Json", "13.0.3"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Empty(outcome.Result!.License.Spdx);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
    }

    [Fact]
    public async Task NuGet_AThrowingNuspecFetch_DegradesToNoLicence()
    {
        Route("/flatcontainer/newtonsoft.json/index.json", HttpStatusCode.OK, NuGetIndex);
        Throw("/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec", new HttpRequestException("reset"));
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        var outcome = await svc.LookupAsync(Req(_orgId, "nuget", "Newtonsoft.Json", "13.0.3"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Empty(outcome.Result!.License.Spdx);
    }

    [Fact]
    public async Task NuGet_NoVersion_ResolvesTheHighestStable()
    {
        Route("/flatcontainer/newtonsoft.json/index.json", HttpStatusCode.OK, NuGetIndex);
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        var outcome = await svc.LookupAsync(Req(_orgId, "nuget", "Newtonsoft.Json", null));

        Assert.Equal("13.0.3", outcome.Result!.Version);
        Assert.True(outcome.Result.VersionInferred);
    }

    [Fact]
    public async Task NuGet_NoVersionAndNoParseableVersions_IsNotFound()
    {
        Route("/flatcontainer/newtonsoft.json/index.json", HttpStatusCode.OK, """{"versions":["junk"]}""");
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "nuget", "Newtonsoft.Json", null))).Status);
    }

    // ── Maven ───────────────────────────────────────────────────────────────────

    private const string MavenCoordinate = "org.apache.commons:commons-lang3";
    private const string MavenPath = "/org/apache/commons/commons-lang3/maven-metadata.xml";

    [Fact]
    public async Task Maven_ADefinitive404_IsNotFound()
    {
        Route(MavenPath, HttpStatusCode.NotFound);
        var svc = await BuildAsync("maven", "http://maven.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "maven", MavenCoordinate, "3.14.0"))).Status);
    }

    [Fact]
    public async Task Maven_AnUnhealthySource_WithNoVersion_IsUnavailable()
    {
        Route(MavenPath, HttpStatusCode.BadGateway);
        var svc = await BuildAsync("maven", "http://maven.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "maven", MavenCoordinate, null))).Status);
    }

    [Fact]
    public async Task Maven_MalformedXml_MakesTheSourceUnavailable()
    {
        Route(MavenPath, HttpStatusCode.OK, "<metadata><versioning>");
        var svc = await BuildAsync("maven", "http://maven.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "maven", MavenCoordinate, null))).Status);
    }

    [Fact]
    public async Task Maven_AVersionTheMetadataDoesNotList_IsNotFound()
    {
        Route(MavenPath, HttpStatusCode.OK,
            "<metadata><versioning><release>3.14.0</release><versions><version>3.14.0</version></versions></versioning></metadata>");
        var svc = await BuildAsync("maven", "http://maven.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "maven", MavenCoordinate, "9.9.9"))).Status);
    }

    [Fact]
    public async Task Maven_MetadataWithNoVersioningElement_ListsNothing_SoAnyVersionIsNotFound()
    {
        Route(MavenPath, HttpStatusCode.OK, "<metadata/>");
        var svc = await BuildAsync("maven", "http://maven.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "maven", MavenCoordinate, "3.14.0"))).Status);
    }

    [Fact]
    public async Task Maven_NoVersion_ResolvesTheReleaseAndFindsItInTheList()
    {
        Route(MavenPath, HttpStatusCode.OK,
            "<metadata><versioning><release>3.14.0</release><versions><version>3.13.0</version><version>3.14.0</version></versions></versioning></metadata>");
        var svc = await BuildAsync("maven", "http://maven.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "maven", MavenCoordinate, null));

        Assert.Equal("3.14.0", outcome.Result!.Version);
        Assert.True(outcome.Result.VersionInferred);
    }

    [Fact]
    public async Task Maven_NoVersionAndNoReleaseOrLatest_IsNotFound()
    {
        Route(MavenPath, HttpStatusCode.OK, "<metadata><versioning><versions><version>3.14.0</version></versions></versioning></metadata>");
        var svc = await BuildAsync("maven", "http://maven.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "maven", MavenCoordinate, null))).Status);
    }

    // ── Cargo ───────────────────────────────────────────────────────────────────

    private static string CargoIndex(params (string Version, bool Yanked)[] versions)
        => string.Join('\n', versions.Select(v =>
            $$"""{"name":"serde","vers":"{{v.Version}}","cksum":"aa","yanked":{{(v.Yanked ? "true" : "false")}}}"""));

    [Fact]
    public async Task Cargo_ADefinitive404_IsNotFound()
    {
        Route("/se/rd/serde", HttpStatusCode.NotFound);
        var svc = await BuildAsync("cargo", "http://cargo.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "cargo", "serde", "1.0.0"))).Status);
    }

    [Fact]
    public async Task Cargo_AnUnhealthySource_WithNoVersion_IsUnavailable()
    {
        Route("/se/rd/serde", HttpStatusCode.InternalServerError);
        var svc = await BuildAsync("cargo", "http://cargo.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "cargo", "serde", null))).Status);
    }

    [Fact]
    public async Task Cargo_AnIndexWithNoEntries_IsADefinitiveMiss()
    {
        Route("/se/rd/serde", HttpStatusCode.OK, "this is not an index line");
        var svc = await BuildAsync("cargo", "http://cargo.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "cargo", "serde", "1.0.0"))).Status);
    }

    [Fact]
    public async Task Cargo_AVersionTheIndexDoesNotList_IsNotFound()
    {
        Route("/se/rd/serde", HttpStatusCode.OK, CargoIndex(("1.0.0", false)));
        var svc = await BuildAsync("cargo", "http://cargo.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "cargo", "serde", "9.9.9"))).Status);
    }

    [Fact]
    public async Task Cargo_AYankedVersion_IsADeprecation_ThatBlocksUnderBlockDeprecated()
    {
        Route("/se/rd/serde", HttpStatusCode.OK, CargoIndex(("1.0.0", false), ("1.0.1", true)));
        var svc = await BuildAsync("cargo", "http://cargo.test");
        await using (var conn = await _stub.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET block_deprecated = 'block_all' WHERE org_id = @orgId", new { orgId = _orgId });
        }

        var yanked = await svc.LookupAsync(Req(_orgId, "cargo", "serde", "1.0.1"));
        var intact = await svc.LookupAsync(Req(_orgId, "cargo", "serde", "1.0.0"));

        Assert.Equal("blocked", yanked.Result!.Verdict);
        Assert.Equal("deprecated", yanked.Result.BlockedReason);
        Assert.Equal("allowed", intact.Result!.Verdict);
    }

    [Fact]
    public async Task Cargo_NoVersion_ResolvesTheNewestNonYankedRelease()
    {
        Route("/se/rd/serde", HttpStatusCode.OK, CargoIndex(("1.0.0", false), ("1.0.2", true), ("1.0.1", false)));
        var svc = await BuildAsync("cargo", "http://cargo.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "cargo", "serde", null));

        Assert.Equal("1.0.1", outcome.Result!.Version);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task Cargo_ACratesIoApiFailure_NeverAbandonsAHealthyIndex(HttpStatusCode apiStatus)
    {
        Route("/se/rd/serde", HttpStatusCode.OK, CargoIndex(("1.0.0", false)));
        Route("/api/v1/crates/serde", apiStatus);
        var svc = await BuildAsync("cargo", "https://index.crates.io");

        var outcome = await svc.LookupAsync(Req(_orgId, "cargo", "serde", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Empty(outcome.Result!.License.Spdx);
        Assert.Contains(_stub.Requests.Urls, u => u.Contains("/api/v1/crates/serde", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cargo_AThrowingCratesIoApi_NeverAbandonsAHealthyIndex()
    {
        Route("/se/rd/serde", HttpStatusCode.OK, CargoIndex(("1.0.0", false)));
        Throw("/api/v1/crates/serde", new HttpRequestException("reset"));
        var svc = await BuildAsync("cargo", "https://index.crates.io");

        Assert.Equal(PackageLookupStatus.Ok, (await svc.LookupAsync(Req(_orgId, "cargo", "serde", "1.0.0"))).Status);
    }

    [Fact]
    public async Task Cargo_APrivateMirror_NeverTriggersAnEgressCallToCratesIo()
    {
        Route("/se/rd/serde", HttpStatusCode.OK, CargoIndex(("1.0.0", false)));
        var svc = await BuildAsync("cargo", "http://cargo-mirror.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "cargo", "serde", "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.DoesNotContain(_stub.Requests.Urls, u => u.Contains("/api/v1/crates/", StringComparison.Ordinal));
    }

    // ── Go ──────────────────────────────────────────────────────────────────────

    private const string GoModule = "github.com/gin-gonic/gin";

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Gone)]
    public async Task Go_404Or410_IsNotFound(HttpStatusCode status)
    {
        Route($"/{GoModule}/@v/v1.10.0.info", status);
        var svc = await BuildAsync("golang", "http://goproxy.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "golang", GoModule, "v1.10.0"))).Status);
    }

    [Fact]
    public async Task Go_AnUnhealthySource_WithNoVersion_IsUnavailable()
    {
        Route($"/{GoModule}/@latest", HttpStatusCode.InternalServerError);
        var svc = await BuildAsync("golang", "http://goproxy.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "golang", GoModule, null))).Status);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""["v1.10.0"]""")]
    [InlineData("""{"Time":"2024-05-19T13:50:41Z"}""")]
    [InlineData("""{"Version":"   "}""")]
    public async Task Go_AnUnusableLatestDocument_MakesTheSourceUnavailable(string body)
    {
        Route($"/{GoModule}/@latest", HttpStatusCode.OK, body);
        var svc = await BuildAsync("golang", "http://goproxy.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "golang", GoModule, null))).Status);
    }

    [Fact]
    public async Task Go_AnExplicitVersion_ReadsItsInfoDocument_AndAnUnparseableTimeLeavesReleaseAgeUnavailable()
    {
        Route($"/{GoModule}/@v/v1.10.0.info", HttpStatusCode.OK, """{"Version":"v1.10.0","Time":"yesterday"}""");
        var svc = await BuildAsync("golang", "http://goproxy.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "golang", GoModule, "v1.10.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("v1.10.0", outcome.Result!.Version);
        Assert.Contains("release_age", outcome.Result.UnavailableChecks);
    }

    // ── an unreachable source is skipped, never read as a miss ──────────────────

    [Theory]
    [InlineData("npm", "express", "/express", "http://npm.test")]
    [InlineData("pypi", "requests", "/pypi/requests/json", "http://pypi.test")]
    [InlineData("nuget", "Serilog", "/flatcontainer/serilog/index.json", "http://nuget.test/v3")]
    [InlineData("maven", "org.apache.commons:commons-lang3", "/org/apache/commons/commons-lang3/maven-metadata.xml", "http://maven.test")]
    [InlineData("cargo", "serde", "/se/rd/serde", "http://cargo.test")]
    [InlineData("golang", "github.com/gin-gonic/gin", "/github.com/gin-gonic/gin/@latest", "http://goproxy.test")]
    public async Task AnUnreachableSource_IsUnavailable_ForEveryEcosystem_WhenNoVersionWasGiven(
        string ecosystem, string name, string suffix, string baseUrl)
    {
        Throw(suffix, new HttpRequestException("connection refused"));
        var svc = await BuildAsync(ecosystem, baseUrl);

        var outcome = await svc.LookupAsync(Req(_orgId, ecosystem, name, null));

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable, outcome.Status);
    }

    [Theory]
    [InlineData("pypi", "requests", "/pypi/requests/json", "http://pypi.test", "2.32.3")]
    [InlineData("nuget", "Serilog", "/flatcontainer/serilog/index.json", "http://nuget.test/v3", "4.0.0")]
    [InlineData("maven", "org.apache.commons:commons-lang3", "/org/apache/commons/commons-lang3/maven-metadata.xml", "http://maven.test", "3.14.0")]
    [InlineData("cargo", "serde", "/se/rd/serde", "http://cargo.test", "1.0.0")]
    [InlineData("golang", "github.com/gin-gonic/gin", "/github.com/gin-gonic/gin/@v/v1.10.0.info", "http://goproxy.test", "v1.10.0")]
    public async Task AnUnreachableSource_WithAnExplicitVersion_StillGivesAnAdvisoryVerdict_WithTheMetadataChecksUnavailable(
        string ecosystem, string name, string suffix, string baseUrl, string version)
    {
        Throw(suffix, new HttpRequestException("connection refused"));
        var svc = await BuildAsync(ecosystem, baseUrl);

        var outcome = await svc.LookupAsync(Req(_orgId, ecosystem, name, version));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Contains("release_age", outcome.Result!.UnavailableChecks);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
        Assert.NotEqual("blocked", outcome.Result.Verdict);
    }

    [Fact]
    public async Task Cargo_EveryVersionYanked_AndNoVersionGiven_HasNoLatestToCheck()
    {
        Route("/se/rd/serde", HttpStatusCode.OK, CargoIndex(("1.0.0", true), ("1.0.1", true)));
        var svc = await BuildAsync("cargo", "http://cargo.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "cargo", "serde", null))).Status);
    }

    // ── Hex ─────────────────────────────────────────────────────────────────────

    private static string HexKeyPem()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        return rsa.ExportSubjectPublicKeyInfoPem();
    }

    [Fact]
    public async Task Hex_AnUpstreamWithNoKnownKey_IsNeverConsulted()
    {
        Route("/packages/phoenix", HttpStatusCode.OK, "payload");
        var svc = await BuildAsync("hex", "http://hex.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "hex", "phoenix", null));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
        Assert.Empty(_stub.Requests.Urls);
    }

    [Fact]
    public async Task Hex_AKeyedSourceThatErrors_IsUnavailable_NotNotFound()
    {
        Route("/packages/phoenix", HttpStatusCode.InternalServerError);
        var svc = await BuildKeyedAsync("hex", HexKeyPem(), "http://hex.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "hex", "phoenix", null))).Status);
    }

    [Fact]
    public async Task Hex_AKeyedSourceAnswering404_IsNotFound()
    {
        Route("/packages/phoenix", HttpStatusCode.NotFound);
        var svc = await BuildKeyedAsync("hex", HexKeyPem(), "http://hex.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "hex", "phoenix", null))).Status);
    }

    [Fact]
    public async Task Hex_AResourceThatDoesNotVerifyUnderTheKey_IsUnavailable_NeverTrusted()
    {
        Route("/packages/phoenix", HttpStatusCode.OK, "not a signed registry resource");
        var svc = await BuildKeyedAsync("hex", HexKeyPem(), "http://hex.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "hex", "phoenix", null))).Status);
    }

    // ── the latest-version resolver failing after the source answered ───────────

    [Fact]
    public async Task PyPi_ResolverFaultAfterTheDocumentArrived_IsUnavailable_NotAGuess()
    {
        RouteThenFault("/pypi/requests/json", PyPiDocument);
        var svc = await BuildAsync("pypi", "http://pypi.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "pypi", "requests", null))).Status);
    }

    [Fact]
    public async Task NuGet_ResolverFaultAfterTheIndexArrived_IsUnavailable_NotAGuess()
    {
        RouteThenFault("/flatcontainer/newtonsoft.json/index.json", NuGetIndex);
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "nuget", "Newtonsoft.Json", null))).Status);
    }

    [Fact]
    public async Task Maven_ResolverFaultAfterTheMetadataArrived_IsUnavailable_NotAGuess()
    {
        RouteThenFault(MavenPath,
            "<metadata><versioning><release>3.14.0</release><versions><version>3.14.0</version></versions></versioning></metadata>");
        var svc = await BuildAsync("maven", "http://maven.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "maven", MavenCoordinate, null))).Status);
    }

    [Fact]
    public async Task Cargo_ResolverFaultAfterTheIndexArrived_IsUnavailable_NotAGuess()
    {
        RouteThenFault("/se/rd/serde", CargoIndex(("1.0.0", false)));
        var svc = await BuildAsync("cargo", "http://cargo.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "cargo", "serde", null))).Status);
    }

    // ── cancellation is never swallowed into a verdict ──────────────────────────

    [Theory]
    [InlineData("npm", "express", "/express", "http://npm.test")]
    [InlineData("pypi", "requests", "/pypi/requests/json", "http://pypi.test")]
    [InlineData("nuget", "Serilog", "/flatcontainer/serilog/index.json", "http://nuget.test/v3")]
    [InlineData("maven", "org.apache.commons:commons-lang3", "/org/apache/commons/commons-lang3/maven-metadata.xml", "http://maven.test")]
    [InlineData("cargo", "serde", "/se/rd/serde", "http://cargo.test")]
    [InlineData("golang", "github.com/gin-gonic/gin", "/github.com/gin-gonic/gin/@v/v1.10.0.info", "http://goproxy.test")]
    public async Task ACancelledFetch_PropagatesAsCancellation_ForEveryEcosystem(
        string ecosystem, string name, string suffix, string baseUrl)
    {
        Throw(suffix, new OperationCanceledException("caller went away"));
        var svc = await BuildAsync(ecosystem, baseUrl);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            svc.LookupAsync(Req(_orgId, ecosystem, name, ecosystem == "golang" ? "v1.10.0" : "1.0.0")));
    }

    [Fact]
    public async Task NuGet_ACancelledNuspecFetch_PropagatesAsCancellation()
    {
        Route("/flatcontainer/newtonsoft.json/index.json", HttpStatusCode.OK, NuGetIndex);
        Throw("/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec", new OperationCanceledException());
        var svc = await BuildAsync("nuget", "http://nuget.test/v3");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            svc.LookupAsync(Req(_orgId, "nuget", "Newtonsoft.Json", "13.0.3")));
    }

    [Fact]
    public async Task Cargo_ACancelledCratesIoApiFetch_PropagatesAsCancellation()
    {
        Route("/se/rd/serde", HttpStatusCode.OK, CargoIndex(("1.0.0", false)));
        Throw("/api/v1/crates/serde", new OperationCanceledException());
        var svc = await BuildAsync("cargo", "https://index.crates.io");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            svc.LookupAsync(Req(_orgId, "cargo", "serde", "1.0.0")));
    }

    // ── Hex: a verified resource ────────────────────────────────────────────────

    private static byte[] HexResourceFor(string name, RSA key, bool prereleasesOnly = false)
    {
        static HexRelease Release(string version, int day, HexRetirementStatus? retired = null) =>
            new(version, new byte[32], Array.Empty<HexDependency>(), retired, new byte[32], null,
                HexTimestamp.FromDateTimeOffset(new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero).AddDays(day)));
        var releases = prereleasesOnly
            ? new[] { Release("2.0.0-rc.1", 3) }
            : new[]
            {
                Release("1.0.0", 1),
                Release("1.1.0", 2, new HexRetirementStatus(HexRetirementReason.Security, "CVE-2026-9")),
                Release("1.2.0", 4),
            };
        var package = new HexPackage(name, "upstream-repo", releases, Array.Empty<HexSecurityAdvisory>());
        return HexRegistrySigner.BuildResource(HexRegistryCodec.EncodePackage(package), key);
    }

    [Fact]
    public async Task Hex_NoVersion_ResolvesTheNewestStableUnretiredRelease_WithItsPublishTime()
    {
        using var key = RSA.Create(2048);
        RouteBytes("/packages/phoenix", HexResourceFor("phoenix", key));
        var svc = await BuildKeyedAsync("hex", HexRegistrySigner.ExportPublicKeyPem(key), "http://hex.test");

        var outcome = await svc.LookupAsync(Req(_orgId, "hex", "phoenix", null));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("1.2.0", outcome.Result!.Version);
        Assert.True(outcome.Result.VersionInferred);
        Assert.DoesNotContain("release_age", outcome.Result.UnavailableChecks);
    }

    [Fact]
    public async Task Hex_ARetiredRelease_IsADeprecation_ThatBlocksUnderBlockDeprecated()
    {
        using var key = RSA.Create(2048);
        RouteBytes("/packages/phoenix", HexResourceFor("phoenix", key));
        var svc = await BuildKeyedAsync("hex", HexRegistrySigner.ExportPublicKeyPem(key), "http://hex.test");
        await using (var conn = await _stub.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET block_deprecated = 'block_all' WHERE org_id = @orgId", new { orgId = _orgId });
        }

        var retired = await svc.LookupAsync(Req(_orgId, "hex", "phoenix", "1.1.0"));
        var current = await svc.LookupAsync(Req(_orgId, "hex", "phoenix", "1.2.0"));

        Assert.Equal("blocked", retired.Result!.Verdict);
        Assert.Equal("deprecated", retired.Result.BlockedReason);
        Assert.Equal("allowed", current.Result!.Verdict);
    }

    [Fact]
    public async Task Hex_AVersionTheResourceDoesNotList_IsNotFound()
    {
        using var key = RSA.Create(2048);
        RouteBytes("/packages/phoenix", HexResourceFor("phoenix", key));
        var svc = await BuildKeyedAsync("hex", HexRegistrySigner.ExportPublicKeyPem(key), "http://hex.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "hex", "phoenix", "9.9.9"))).Status);
    }

    [Fact]
    public async Task Hex_AResourceWithNoStableRelease_HasNoLatest_SoNoVersionIsNotFound()
    {
        using var key = RSA.Create(2048);
        RouteBytes("/packages/phoenix", HexResourceFor("phoenix", key, prereleasesOnly: true));
        var svc = await BuildKeyedAsync("hex", HexRegistrySigner.ExportPublicKeyPem(key), "http://hex.test");

        Assert.Equal(PackageLookupStatus.UpstreamNotFound,
            (await svc.LookupAsync(Req(_orgId, "hex", "phoenix", null))).Status);
    }

    [Fact]
    public async Task Hex_AResourceSignedByAnotherKey_IsNeverTrusted()
    {
        using var attacker = RSA.Create(2048);
        using var pinned = RSA.Create(2048);
        RouteBytes("/packages/phoenix", HexResourceFor("phoenix", attacker));
        var svc = await BuildKeyedAsync("hex", HexRegistrySigner.ExportPublicKeyPem(pinned), "http://hex.test");

        Assert.Equal(PackageLookupStatus.UpstreamUnavailable,
            (await svc.LookupAsync(Req(_orgId, "hex", "phoenix", null))).Status);
    }

    private sealed class CleanOsv : IOsvSource
    {
        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
            => Task.FromResult(new List<OsvAdvisory>());

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default)
            => Task.FromResult(purls.Select(_ => new List<OsvAdvisory>()).ToList());

        public Task<OsvQueryResult> TryQueryAsync(string purl, CancellationToken ct = default)
            => Task.FromResult(new OsvQueryResult(new List<OsvAdvisory>(), true));

        public Task<OsvScopedQueryResult> TryQueryDistroPackageAsync(
            DistroScope scope, string name, string version, CancellationToken ct = default)
            => Task.FromResult(new OsvScopedQueryResult([], Reached: true, Covered: false));
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;

        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();

        public bool IsJobDisabled(string jobName) => false;
    }
}
