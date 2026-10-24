using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// <c>GET /api/v1/packages/oci/{name}/{digest}/scan</c> through HTTP in single-tenant mode: the
/// default org reads its own hosted and proxied images' stored detail, and a second org seeded in
/// the same database stays invisible to it, including on a proxied manifest both orgs pulled.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciScanDetailApiTests : IAsyncLifetime
{
    private const string Repo = "team/app";
    private const string Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string OtherDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string LastError = "LAST-ERROR-SENTINEL token=hunter2";

    private readonly DependablyFactory _factory = new()
    {
        FrozenClock = TestTime.Frozen(),
        ExtraSettings = new Dictionary<string, string?> { ["OCI_SCAN_ENABLED"] = "true" },
    };

    // Resolved per use: reaching into the host's services marks the access as the test harness.
    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();
    private string _org = null!;

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        await using var conn = await Db.OpenAsync();
        _org = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'")
            ?? throw new InvalidOperationException("default org missing");
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task AHostedImage_ReturnsCoverageComponentsAndFindings_UnderAnEncodedRepositoryName()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, _org, Repo, Digest));
        await OciScanSeeder.ResultAsync(Db, _org, owner, "linux/amd64", ["rpm packages: no OSV ecosystem for rhel 9"],
        [
            new SeedComponent("libssl3", 0, [new SeedFinding("DSA-7001-1", "reachable")], SourceName: "openssl",
                LayerInstruction: "RUN apt-get install -y libssl3"),
            new SeedComponent("zlib", 0, []),
        ]);
        await OciScanSeeder.ResultAsync(Db, _org, owner, "linux/arm64", [], [new SeedComponent("arm", 0, [])]);

        // The repository's '/' travels as %2F, exactly as the web client sends it.
        using var response = await GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await JsonAsync(response);

        Assert.Equal("scanned", body.GetProperty("state").GetString());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("job").ValueKind);
        var platforms = body.GetProperty("platforms").EnumerateArray().ToList();
        Assert.Equal(["linux/amd64", "linux/arm64"], platforms.Select(p => p.GetProperty("platform").GetString()));
        Assert.Equal("rpm packages: no OSV ecosystem for rhel 9",
            Assert.Single(platforms[0].GetProperty("gaps").EnumerateArray().ToList()).GetString());
        Assert.Equal(2, platforms[0].GetProperty("componentCount").GetInt32());
        Assert.Equal(1, platforms[0].GetProperty("affectedComponentCount").GetInt32());

        var components = body.GetProperty("components");
        Assert.Equal("linux/amd64", components.GetProperty("platform").GetString());
        Assert.Equal(1, components.GetProperty("total").GetInt32());
        var item = Assert.Single(components.GetProperty("items").EnumerateArray().ToList());
        Assert.Equal("libssl3", item.GetProperty("name").GetString());
        Assert.Equal("openssl", item.GetProperty("sourceName").GetString());
        Assert.Equal(0, item.GetProperty("layerIndex").GetInt32());
        Assert.Equal("RUN apt-get install -y libssl3", item.GetProperty("layerInstruction").GetString());
        var finding = Assert.Single(item.GetProperty("findings").EnumerateArray().ToList());
        Assert.Equal("DSA-7001-1", finding.GetProperty("osvId").GetString());
        Assert.Equal("reachable", finding.GetProperty("reachability").GetString());
        // Advisory details are keyed by OSV id, verbatim.
        Assert.Equal("HIGH", body.GetProperty("advisories").GetProperty("DSA-7001-1").GetProperty("severity").GetString());
    }

    [Fact]
    public async Task AProxiedImage_TheOrgPulled_ReturnsItsOwnResult()
    {
        var proxied = OciScanOwner.Proxied(await OciScanSeeder.ProxiedManifestAsync(Db, "library/nginx", Digest));
        await OciScanSeeder.GrantAsync(Db, _org, proxied.Id);
        await OciScanSeeder.ResultAsync(Db, _org, proxied, "linux/amd64", [], [new SeedComponent("nginx", 2, [new SeedFinding("DSA-7002-1")])]);

        using var response = await GetAsync($"/api/v1/packages/oci/library%2Fnginx/{Digest}/scan");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await JsonAsync(response);
        Assert.Equal("nginx", body.GetProperty("components").GetProperty("items")[0].GetProperty("name").GetString());
    }

    [Fact]
    public async Task FindingsAreCappedPerComponent_WithTheFullCount()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, _org, Repo, Digest));
        var findings = Enumerable.Range(0, 60).Select(i => new SeedFinding($"DSA-{i:D4}-9")).ToList();
        await OciScanSeeder.ResultAsync(Db, _org, owner, "linux/amd64", [], [new SeedComponent("busy", 0, findings)]);

        var item = (await JsonAsync(await GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan")))
            .GetProperty("components").GetProperty("items")[0];
        Assert.Equal(60, item.GetProperty("findingCount").GetInt32());
        Assert.Equal(50, item.GetProperty("findings").GetArrayLength());
    }

    [Fact]
    public async Task AHostedImageWithoutAResult_ReadsUnscanned_LikeItsBadge_ThoughItsProxiedTwinHasOne()
    {
        await ScannerLiveAsync();
        var hosted = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, _org, Repo, Digest));
        var proxied = OciScanOwner.Proxied(await OciScanSeeder.ProxiedManifestAsync(Db, Repo, Digest));
        await OciScanSeeder.GrantAsync(Db, _org, proxied.Id);
        await OciScanSeeder.ResultAsync(Db, _org, proxied, "linux/amd64", [], [new SeedComponent("p", 0, [new SeedFinding("DSA-7003-1")])]);

        var body = await JsonAsync(await GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan"));
        Assert.Equal("unscanned", body.GetProperty("state").GetString());
        Assert.Equal(0, body.GetProperty("platforms").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("components").ValueKind);

        // The badge on the version row agrees.
        using var page = await GetAsync("/api/v1/packages/oci/team%2Fapp");
        var row = (await JsonAsync(page)).GetProperty("versions").EnumerateArray()
            .Single(v => v.GetProperty("version").GetString() == Digest);
        Assert.Equal("unscanned", row.GetProperty("ociScan").GetProperty("state").GetString());

        // The lookup still answers from the proxied result.
        var lookup = await _factory.Services.GetRequiredService<OciScanRepository>().FindLookupScanAsync(_org, Repo, Digest);
        Assert.NotNull(lookup);
        Assert.Equal(hosted, await _factory.Services.GetRequiredService<OciScanRepository>().ResolveImageOwnerAsync(_org, Repo, Digest));
    }

    [Fact]
    public async Task AnUnscannedImage_ShowsItsJob_AndNeverTheJobsError()
    {
        await ScannerLiveAsync();
        await OciScanSeeder.HostedImageAsync(Db, _org, Repo, Digest);
        var pending = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, _org, Repo, OtherDigest));
        string failedDigest = "sha256:" + new string('c', 64);
        var failed = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, _org, Repo, failedDigest));
        await OciScanSeeder.JobAsync(Db, _org, pending, Repo, OtherDigest, "pending", 2, LastError);
        await OciScanSeeder.JobAsync(Db, _org, failed, Repo, failedDigest, "failed", 5, LastError);

        string noneBody = await (await GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan")).Content.ReadAsStringAsync();
        string pendingBody = await (await GetAsync($"/api/v1/packages/oci/team%2Fapp/{OtherDigest}/scan")).Content.ReadAsStringAsync();
        string failedBody = await (await GetAsync($"/api/v1/packages/oci/team%2Fapp/{failedDigest}/scan")).Content.ReadAsStringAsync();

        // Checked first, so a leak fails on the leak rather than on a state it happens to garble.
        foreach (string body in new[] { noneBody, pendingBody, failedBody })
        {
            Assert.DoesNotContain("LAST-ERROR-SENTINEL", body);
            Assert.DoesNotContain("hunter2", body);
        }

        Assert.Equal("none", JsonDocument.Parse(noneBody).RootElement.GetProperty("job").GetProperty("state").GetString());
        var p = JsonDocument.Parse(pendingBody).RootElement.GetProperty("job");
        Assert.Equal(("pending", 2), (p.GetProperty("state").GetString(), p.GetProperty("attempts").GetInt32()));
        var f = JsonDocument.Parse(failedBody).RootElement.GetProperty("job");
        Assert.Equal(("failed", 5), (f.GetProperty("state").GetString(), f.GetProperty("attempts").GetInt32()));
    }

    // End to end: a malformed digest answers 404 like any image the org cannot see. The database
    // lookup would 404 these too, so this does not pin the digest check itself;
    // OciScanDetailReaderTests.TheDigestCheck_RejectsATrailingNewline_ThatADollarAnchorWouldAdmit does.
    [Theory]
    [InlineData("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("sha256:aaaa")]
    [InlineData("sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%0A")]
    [InlineData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%20")]
    public async Task AMalformedDigest_AnswersNotFound_EndToEnd(string digest)
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, _org, Repo, Digest));
        await OciScanSeeder.ResultAsync(Db, _org, owner, "linux/amd64", [], [new SeedComponent("x", 0, [])]);

        // Positive control: the well-formed digest of the same image reads.
        using (var ok = await GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan"))
        {
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        using var response = await GetAsync($"/api/v1/packages/oci/team%2Fapp/{digest}/scan");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task AnUnknownRepositoryOrDigest_IsNotFound_AndAnUnknownPlatformIsRefused()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, _org, Repo, Digest));
        await OciScanSeeder.ResultAsync(Db, _org, owner, "linux/amd64", [], [new SeedComponent("x", 0, [])]);

        using (var unknownRepo = await GetAsync($"/api/v1/packages/oci/team%2Fnope/{Digest}/scan"))
        {
            Assert.Equal(HttpStatusCode.NotFound, unknownRepo.StatusCode);
        }

        using (var unknownDigest = await GetAsync($"/api/v1/packages/oci/team%2Fapp/{OtherDigest}/scan"))
        {
            Assert.Equal(HttpStatusCode.NotFound, unknownDigest.StatusCode);
        }

        using var platform = await GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan?platform=linux%2Fs390x");
        Assert.Equal(HttpStatusCode.UnprocessableEntity, platform.StatusCode);
    }

    [Fact]
    public async Task AnotherOrgsImages_AreNotFound_AndOnASharedManifestEachOrgSeesItsOwnResult()
    {
        string other = await OrgSeeder.InsertAsync(Db, "other-" + Guid.NewGuid().ToString("N")[..8]);
        var theirs = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, other, Repo, Digest));
        await OciScanSeeder.ResultAsync(Db, other, theirs, "linux/amd64", [], [new SeedComponent("theirs", 0, [new SeedFinding("DSA-OTHER-1")])]);

        // Another org's hosted image.
        using (var hosted = await GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan"))
        {
            Assert.Equal(HttpStatusCode.NotFound, hosted.StatusCode);
        }

        // A proxied manifest the other org pulled and scanned, but this org never pulled.
        var shared = OciScanOwner.Proxied(await OciScanSeeder.ProxiedManifestAsync(Db, "library/shared", OtherDigest));
        await OciScanSeeder.GrantAsync(Db, other, shared.Id);
        await OciScanSeeder.ResultAsync(Db, other, shared, "linux/amd64", ["their-gap"], [new SeedComponent("their-comp", 0, [new SeedFinding("DSA-OTHER-2")])]);
        using (var notPulled = await GetAsync($"/api/v1/packages/oci/library%2Fshared/{OtherDigest}/scan"))
        {
            Assert.Equal(HttpStatusCode.NotFound, notPulled.StatusCode);
        }

        // Twin: this org pulls the same manifest and has its own result.
        await OciScanSeeder.GrantAsync(Db, _org, shared.Id);
        await OciScanSeeder.ResultAsync(Db, _org, shared, "linux/amd64", [], [new SeedComponent("our-comp", 0, [new SeedFinding("DSA-OURS-1")])]);
        string body = await (await GetAsync($"/api/v1/packages/oci/library%2Fshared/{OtherDigest}/scan?affectedOnly=false"))
            .Content.ReadAsStringAsync();
        var root = JsonDocument.Parse(body).RootElement;
        Assert.Equal(["our-comp"], root.GetProperty("components").GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("name").GetString()));
        Assert.Empty(Assert.Single(root.GetProperty("platforms").EnumerateArray().ToList()).GetProperty("gaps").EnumerateArray());
        Assert.DoesNotContain("their-", body);
        Assert.DoesNotContain("DSA-OTHER", body);
    }

    [Fact]
    public async Task AReadPackagesToken_Reads_AndATokenWithoutIt_IsForbidden()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(Db, _org, Repo, Digest));
        await OciScanSeeder.ResultAsync(Db, _org, owner, "linux/amd64", [], [new SeedComponent("x", 0, [])]);
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var (reader, _) = await tokens.CreateServiceTokenAsync(_org, "scan-reader", """["read:packages"]""", expiresAt: null);
        var (scanner, _) = await tokens.CreateServiceTokenAsync(_org, "scan-only", """["scan:oci"]""", expiresAt: null);

        using var readerClient = _factory.CreateClientWithBearer(reader);
        using (var ok = await readerClient.GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan"))
        {
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        using var scannerClient = _factory.CreateClientWithBearer(scanner);
        using var denied = await scannerClient.GetAsync($"/api/v1/packages/oci/team%2Fapp/{Digest}/scan");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    private async Task ScannerLiveAsync()
        => await OciScanSeeder.ScannerSeenAsync(Db, _org, _factory.FrozenClock!.GetUtcNow());

    private async Task<HttpResponseMessage> GetAsync(string path)
    {
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        return await admin.GetAsync(path);
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        using (response)
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return doc.RootElement.Clone();
        }
    }
}

/// <summary>With the image scanner switched off, a visible image's detail reads no feed; an unknown one is still 404.</summary>
[Trait("Category", "Integration")]
public sealed class OciScanDetailDisabledTests : IAsyncLifetime
{
    private const string Digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    private readonly DependablyFactory _factory = new() { FrozenClock = TestTime.Frozen() };

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task AVisibleImage_ReadsNoFeed_AndAnUnknownOneIsNotFound()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        string org;
        await using (var conn = await db.OpenAsync())
        {
            org = (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'"))!;
        }

        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(db, org, "team/off", Digest));
        // A stored result from when scanning was on is not read while it is off, as on the version row.
        await OciScanSeeder.ResultAsync(db, org, owner, "linux/amd64", [], [new SeedComponent("x", 0, [new SeedFinding("DSA-7009-1")])]);

        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var response = await admin.GetAsync($"/api/v1/packages/oci/team%2Foff/{Digest}/scan");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("no_feed", body.RootElement.GetProperty("state").GetString());
        Assert.Equal(0, body.RootElement.GetProperty("platforms").GetArrayLength());

        using var unknown = await admin.GetAsync($"/api/v1/packages/oci/team%2Foff/sha256:{new string('e', 64)}/scan");
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }
}
