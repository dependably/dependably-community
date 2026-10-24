using System.Net;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The refusal and malformed-document arms of the upstream latest-version resolver: a source
/// that errors, answers with a document of the wrong shape, or names no usable version must
/// yield "no latest" (or fall through to the next configured source), never a guessed version.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamLatestVersionResolverEdgeTests : IAsyncLifetime
{
    private StubUpstream _stub = null!;
    private Dictionary<string, (HttpStatusCode Status, string Body)> _routes = new();
    private string _orgId = null!;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _stub.DisposeAsync();

    private async Task<UpstreamLatestVersionResolver> BuildAsync(
        string ecosystem, string[] baseUrls, Dictionary<string, (HttpStatusCode, string)> routes,
        string? publicKeyPem = null, Dictionary<string, byte[]>? binary = null)
    {
        _routes = routes;
        _stub = await StubUpstream.CreateAsync(req =>
        {
            string url = req.RequestUri!.ToString();
            var bytes = binary?.FirstOrDefault(kv => url.EndsWith(kv.Key, StringComparison.Ordinal));
            if (bytes is { Key: not null })
            {
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes.Value.Value) };
            }

            var hit = _routes.FirstOrDefault(kv => url.EndsWith(kv.Key, StringComparison.Ordinal));
            return hit.Key is null
                ? StubUpstream.Status(HttpStatusCode.NotFound)
                : StubUpstream.Text(hit.Value.Body, hit.Value.Status);
        });
        _orgId = await OrgSeeder.InsertAsync(_stub.Db, $"org-{Guid.NewGuid():N}");
        var repo = new UpstreamRegistryRepository(_stub.Db, TimeProvider.System, TestEnvelope.Unconfigured());
        foreach (string url in baseUrls)
        {
            await repo.AddAsync(_orgId, new NewUpstreamRegistry(ecosystem, url, PublicKeyPem: publicKeyPem));
        }

        return new UpstreamLatestVersionResolver(
            _stub.Client,
            new UpstreamRegistryResolver(repo),
            new ReservedNamespaceService(_stub.Db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System));
    }

    private static Dictionary<string, (HttpStatusCode, string)> Ok(string suffix, string body)
        => new() { [suffix] = (HttpStatusCode.OK, body) };

    [Fact]
    public async Task AnEcosystemWithNoLatestResolver_YieldsNone_WithoutAnUpstreamRequest()
    {
        var resolver = await BuildAsync("rpm", ["http://rpm.test"], new());

        var latest = await resolver.ResolveAsync("rpm", _orgId, "openssl", default);

        Assert.Equal(UpstreamLatestVersion.None, latest);
        Assert.Empty(_stub.Requests.Urls);
    }

    // ── Cargo ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Cargo_YankedVersionsAreNeverLatest()
    {
        string index = """
            {"name":"serde","vers":"1.0.200","cksum":"a","yanked":false,"deps":[],"features":{}}
            {"name":"serde","vers":"1.0.210","cksum":"b","yanked":true,"deps":[],"features":{}}
            {"name":"serde","vers":"1.0.204","cksum":"c","yanked":false,"deps":[],"features":{}}
            """;
        var resolver = await BuildAsync("cargo", ["http://cargo.test"], Ok("/se/rd/serde", index));

        var latest = await resolver.ResolveAsync("cargo", _orgId, "serde", default);

        Assert.Equal("1.0.204", latest.Version);
        Assert.Null(latest.PublishedAt);
        Assert.Equal(["1.0.204", "1.0.200"], latest.StableVersionsDescending);
    }

    [Fact]
    public async Task Cargo_EveryVersionYankedOrPrerelease_YieldsNone()
    {
        string index = """
            {"name":"tokio","vers":"1.0.0","cksum":"a","yanked":true,"deps":[],"features":{}}
            {"name":"tokio","vers":"2.0.0-alpha.1","cksum":"b","yanked":false,"deps":[],"features":{}}
            """;
        var resolver = await BuildAsync("cargo", ["http://cargo.test"], Ok("/to/ki/tokio", index));

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("cargo", _orgId, "tokio", default));
    }

    [Fact]
    public async Task Cargo_AFailingFirstSource_FallsThroughToTheNextSource()
    {
        var routes = new Dictionary<string, (HttpStatusCode, string)>
        {
            ["http://cargo-a.test/se/rd/serde"] = (HttpStatusCode.InternalServerError, "boom"),
            ["http://cargo-b.test/se/rd/serde"] = (HttpStatusCode.OK,
                """{"name":"serde","vers":"1.0.1","cksum":"a","yanked":false,"deps":[],"features":{}}"""),
        };
        var resolver = await BuildAsync("cargo", ["http://cargo-a.test", "http://cargo-b.test"], routes);

        var latest = await resolver.ResolveAsync("cargo", _orgId, "serde", default);

        Assert.Equal("1.0.1", latest.Version);
    }

    // ── Go ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Go_LatestWithATime_ReturnsBothAndNoVersionList()
    {
        var resolver = await BuildAsync("golang", ["http://goproxy.test"],
            Ok("/github.com/gin-gonic/gin/@latest", """{"Version":"v1.10.0","Time":"2024-05-19T13:50:41Z"}"""));

        var latest = await resolver.ResolveAsync("golang", _orgId, "github.com/gin-gonic/gin", default);

        Assert.Equal("v1.10.0", latest.Version);
        Assert.Equal(DateTimeOffset.Parse("2024-05-19T13:50:41Z"), latest.PublishedAt);
        Assert.Null(latest.StableVersionsDescending);
    }

    [Theory]
    [InlineData("""{"Version":"v1.10.0","Time":"not-a-time"}""", "v1.10.0")]
    [InlineData("""{"Version":"v1.10.0"}""", "v1.10.0")]
    [InlineData("""{"Version":"   "}""", null)]
    [InlineData("""{"Version":42}""", null)]
    [InlineData("""{}""", null)]
    [InlineData("""["v1.0.0"]""", null)]
    public async Task Go_MalformedLatestDocument_NeverInventsAVersionOrTime(string body, string? expected)
    {
        var resolver = await BuildAsync("golang", ["http://goproxy.test"], Ok("/github.com/gin-gonic/gin/@latest", body));

        var latest = await resolver.ResolveAsync("golang", _orgId, "github.com/gin-gonic/gin", default);

        Assert.Equal(expected, latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    [Fact]
    public async Task Go_UpperCaseModulePath_IsBangEncodedInTheRequest()
    {
        var resolver = await BuildAsync("golang", ["http://goproxy.test"],
            Ok("/github.com/!burnt!sushi/toml/@latest", """{"Version":"v1.4.0"}"""));

        var latest = await resolver.ResolveAsync("golang", _orgId, "github.com/BurntSushi/toml", default);

        Assert.Equal("v1.4.0", latest.Version);
    }

    // ── npm ─────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("""{"name":"express","versions":{"4.0.0":{}}}""")]
    [InlineData("""{"dist-tags":{"next":"5.0.0-beta.1"}}""")]
    [InlineData("""{"dist-tags":{"latest":7}}""")]
    [InlineData("""{"dist-tags":{"latest":"  "}}""")]
    public async Task Npm_PackumentWithoutALatestTag_YieldsNone(string body)
    {
        var resolver = await BuildAsync("npm", ["http://npm.test"], Ok("/express", body));

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("npm", _orgId, "express", default));
    }

    [Fact]
    public async Task Npm_AnUnparseablePublishTime_LeavesPublishedAtNull_ButKeepsTheVersion()
    {
        var resolver = await BuildAsync("npm", ["http://npm.test"], Ok("/express",
            """{"dist-tags":{"latest":"4.19.2"},"time":{"4.19.2":"yesterday-ish"},"versions":{"4.19.2":{}}}"""));

        var latest = await resolver.ResolveAsync("npm", _orgId, "express", default);

        Assert.Equal("4.19.2", latest.Version);
        Assert.Null(latest.PublishedAt);
        Assert.Equal(["4.19.2"], latest.StableVersionsDescending);
    }

    [Fact]
    public async Task Npm_ANonSuccessFirstSource_FallsThroughToTheSecond()
    {
        var routes = new Dictionary<string, (HttpStatusCode, string)>
        {
            ["http://npm-a.test/express"] = (HttpStatusCode.NotFound, ""),
            ["http://npm-b.test/express"] = (HttpStatusCode.OK, """{"dist-tags":{"latest":"4.19.2"}}"""),
        };
        var resolver = await BuildAsync("npm", ["http://npm-a.test", "http://npm-b.test"], routes);

        var latest = await resolver.ResolveAsync("npm", _orgId, "express", default);

        Assert.Equal("4.19.2", latest.Version);
        Assert.Null(latest.StableVersionsDescending);
    }

    // ── PyPI ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("""{"releases":{}}""")]
    [InlineData("""{"info":{}}""")]
    [InlineData("""{"info":{"version":null}}""")]
    [InlineData("""{"info":{"version":""}}""")]
    public async Task PyPi_DocumentWithoutAVersion_YieldsNone(string body)
    {
        var resolver = await BuildAsync("pypi", ["http://pypi.test"], Ok("/pypi/requests/json", body));

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("pypi", _orgId, "requests", default));
    }

    [Fact]
    public async Task PyPi_SkipsUrlsEntriesWithoutAUsableUploadTime_AndTakesTheFirstThatHasOne()
    {
        var resolver = await BuildAsync("pypi", ["http://pypi.test"], Ok("/pypi/requests/json",
            """
            {"info":{"version":"2.32.3"},
             "urls":[{"filename":"a"},{"upload_time_iso_8601":5},{"upload_time_iso_8601":"bad"},
                     {"upload_time_iso_8601":"2024-05-29T15:37:47.000000Z"}],
             "releases":{"2.32.3":[]}}
            """));

        var latest = await resolver.ResolveAsync("pypi", _orgId, "requests", default);

        Assert.Equal("2.32.3", latest.Version);
        Assert.Equal(DateTimeOffset.Parse("2024-05-29T15:37:47Z"), latest.PublishedAt);
    }

    [Fact]
    public async Task PyPi_ANonSuccessSource_YieldsNone()
    {
        var resolver = await BuildAsync("pypi", ["http://pypi.test"], new()
        {
            ["/pypi/requests/json"] = (HttpStatusCode.NotFound, "{}"),
        });

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("pypi", _orgId, "requests", default));
    }

    // ── NuGet ───────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("../evil")]
    [InlineData("a/b")]
    public async Task NuGet_PathShapedIdIsRefusedBeforeAnyRequest(string id)
    {
        var resolver = await BuildAsync("nuget", ["http://nuget.test/v3"], new());

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("nuget", _orgId, id, default));
        Assert.Empty(_stub.Requests.Urls);
    }

    [Theory]
    [InlineData("""{"versions":[]}""")]
    [InlineData("""{"versions":["", "   ", "not-a-version"]}""")]
    [InlineData("""{"other":[]}""")]
    [InlineData("""{"versions":"1.0.0"}""")]
    public async Task NuGet_IndexWithNoParseableVersion_YieldsNone(string body)
    {
        var resolver = await BuildAsync("nuget", ["http://nuget.test/v3"],
            Ok("/flatcontainer/serilog/index.json", body));

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("nuget", _orgId, "Serilog", default));
    }

    [Fact]
    public async Task NuGet_PublishedAtIsReadFromCatalogEntry_WhenTheLeafRootHasNone()
    {
        var routes = new Dictionary<string, (HttpStatusCode, string)>
        {
            ["/flatcontainer/serilog/index.json"] = (HttpStatusCode.OK, """{"versions":["3.0.0","4.0.0"]}"""),
            ["/registration5-gz-semver2/serilog/4.0.0.json"] = (HttpStatusCode.OK,
                """{"catalogEntry":{"published":"2024-06-01T00:00:00Z"}}"""),
        };
        var resolver = await BuildAsync("nuget", ["http://nuget.test/v3"], routes);

        var latest = await resolver.ResolveAsync("nuget", _orgId, "Serilog", default);

        Assert.Equal("4.0.0", latest.Version);
        Assert.Equal(DateTimeOffset.Parse("2024-06-01T00:00:00Z"), latest.PublishedAt);
        Assert.Equal(["4.0.0", "3.0.0"], latest.StableVersionsDescending);
    }

    [Fact]
    public async Task NuGet_AMalformedRegistrationLeaf_LeavesPublishedAtNull_AndKeepsTheVersion()
    {
        var routes = new Dictionary<string, (HttpStatusCode, string)>
        {
            ["/flatcontainer/serilog/index.json"] = (HttpStatusCode.OK, """{"versions":["4.0.0"]}"""),
            ["/registration5-gz-semver2/serilog/4.0.0.json"] = (HttpStatusCode.OK, "{ not json"),
        };
        var resolver = await BuildAsync("nuget", ["http://nuget.test/v3"], routes);

        var latest = await resolver.ResolveAsync("nuget", _orgId, "Serilog", default);

        Assert.Equal("4.0.0", latest.Version);
        Assert.Null(latest.PublishedAt);
    }

    // ── Maven ───────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("nocolon")]
    [InlineData(":artifact")]
    [InlineData("group:")]
    [InlineData("org..evil:artifact")]
    [InlineData("org.apache:a/b")]
    public async Task Maven_MalformedCoordinate_IsRefusedBeforeAnyRequest(string coordinate)
    {
        var resolver = await BuildAsync("maven", ["http://maven.test"], new());

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("maven", _orgId, coordinate, default));
        Assert.Empty(_stub.Requests.Urls);
    }

    [Theory]
    [InlineData("<metadata></metadata>")]
    [InlineData("<metadata><versioning></versioning></metadata>")]
    [InlineData("<metadata><versioning><release>  </release><latest></latest></versioning></metadata>")]
    public async Task Maven_MetadataNamingNoReleaseOrLatest_YieldsNone(string xml)
    {
        var resolver = await BuildAsync("maven", ["http://maven.test"],
            Ok("/org/apache/commons/commons-lang3/maven-metadata.xml", xml));

        Assert.Equal(UpstreamLatestVersion.None,
            await resolver.ResolveAsync("maven", _orgId, "org.apache.commons:commons-lang3", default));
    }

    [Fact]
    public async Task Maven_AnInvalidLastUpdated_LeavesPublishedAtNull()
    {
        var resolver = await BuildAsync("maven", ["http://maven.test"],
            Ok("/org/apache/commons/commons-lang3/maven-metadata.xml",
                "<metadata><versioning><release>3.14.0</release><lastUpdated>2024-01-01</lastUpdated></versioning></metadata>"));

        var latest = await resolver.ResolveAsync("maven", _orgId, "org.apache.commons:commons-lang3", default);

        Assert.Equal("3.14.0", latest.Version);
        Assert.Null(latest.PublishedAt);
        Assert.Empty(latest.StableVersionsDescending!);
    }

    [Fact]
    public async Task Maven_ANonSuccessFirstSource_FallsThroughToTheSecond()
    {
        var routes = new Dictionary<string, (HttpStatusCode, string)>
        {
            ["http://maven-a.test/org/apache/commons/commons-lang3/maven-metadata.xml"] = (HttpStatusCode.NotFound, ""),
            ["http://maven-b.test/org/apache/commons/commons-lang3/maven-metadata.xml"] = (HttpStatusCode.OK,
                "<metadata><versioning><release>3.14.0</release></versioning></metadata>"),
        };
        var resolver = await BuildAsync("maven", ["http://maven-a.test", "http://maven-b.test"], routes);

        var latest = await resolver.ResolveAsync("maven", _orgId, "org.apache.commons:commons-lang3", default);

        Assert.Equal("3.14.0", latest.Version);
    }

    // ── Hex ─────────────────────────────────────────────────────────────────────

    private static byte[] HexResource(string name, RSA key, params (string Version, bool Retired)[] releases)
    {
        var list = releases.Select((r, i) => new HexRelease(
            r.Version, new byte[32], Array.Empty<HexDependency>(),
            r.Retired ? new HexRetirementStatus(HexRetirementReason.Security, "CVE-2026-9") : null,
            new byte[32], null,
            HexTimestamp.FromDateTimeOffset(new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero).AddDays(i + 1))))
            .ToArray();
        return HexRegistrySigner.BuildResource(
            HexRegistryCodec.EncodePackage(new HexPackage(name, "upstream-repo", list, Array.Empty<HexSecurityAdvisory>())), key);
    }

    [Fact]
    public async Task Hex_LatestIsTheNewestStableUnretiredRelease_WithItsRecordedPublishTime()
    {
        using var key = RSA.Create(2048);
        var resolver = await BuildAsync("hex", ["http://hex.test"], new(), HexRegistrySigner.ExportPublicKeyPem(key),
            new() { ["/packages/phoenix"] = HexResource("phoenix", key, ("1.0.0", false), ("1.1.0", true), ("1.0.5", false), ("2.0.0-rc.1", false)) });

        var latest = await resolver.ResolveAsync("hex", _orgId, "phoenix", default);

        Assert.Equal("1.0.5", latest.Version);
        Assert.Equal(new DateTimeOffset(2025, 6, 4, 0, 0, 0, TimeSpan.Zero), latest.PublishedAt);
        Assert.Equal(["1.0.5", "1.0.0"], latest.StableVersionsDescending);
    }

    [Fact]
    public async Task Hex_AResourceWithNoStableUnretiredRelease_HasNoLatest()
    {
        using var key = RSA.Create(2048);
        var resolver = await BuildAsync("hex", ["http://hex.test"], new(), HexRegistrySigner.ExportPublicKeyPem(key),
            new() { ["/packages/phoenix"] = HexResource("phoenix", key, ("1.0.0", true), ("2.0.0-rc.1", false)) });

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("hex", _orgId, "phoenix", default));
    }

    [Fact]
    public async Task Hex_AnUpstreamWithNoKey_OrWithAResourceSignedByAnotherKey_HasNoLatest()
    {
        using var attacker = RSA.Create(2048);
        using var pinned = RSA.Create(2048);
        var signedByAttacker = new Dictionary<string, byte[]>
        {
            ["/packages/phoenix"] = HexResource("phoenix", attacker, ("1.0.0", false)),
        };
        var resolver = await BuildAsync(
            "hex", ["http://hex.test"], new(), HexRegistrySigner.ExportPublicKeyPem(pinned), signedByAttacker);

        Assert.Equal(UpstreamLatestVersion.None, await resolver.ResolveAsync("hex", _orgId, "phoenix", default));
        await _stub.DisposeAsync();

        var unkeyed = await BuildAsync("hex", ["http://hex.test"], new(), null, signedByAttacker);
        Assert.Equal(UpstreamLatestVersion.None, await unkeyed.ResolveAsync("hex", _orgId, "phoenix", default));
        Assert.Empty(_stub.Requests.Urls);
    }
}
