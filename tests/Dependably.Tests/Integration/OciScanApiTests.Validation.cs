using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The scan API's refusals through HTTP: out-of-range claims, scanning switched off, a token
/// without <c>scan:oci</c>, malformed reasons and digests, jobs that do not exist, and result and
/// match bodies that break the contract. Each refusal is paired with a check that no job moved
/// state and nothing was stored.
/// </summary>
public sealed partial class OciScanApiTests
{
    private static readonly (string Method, string Path)[] EveryJobRoute =
    [
        ("POST", "/api/v1/oci-scan/claim"),
        ("GET", "/api/v1/oci-scan/job-1/inventory?attempt=1"),
        ("POST", "/api/v1/oci-scan/job-1/matches?attempt=1"),
        ("POST", "/api/v1/oci-scan/job-1/reextract?attempt=1"),
        ("GET", "/api/v1/oci-scan/job-1/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000"),
        ("GET", "/api/v1/oci-scan/job-1/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000"),
        ("POST", "/api/v1/oci-scan/job-1/heartbeat?attempt=1"),
        ("POST", "/api/v1/oci-scan/job-1/result?attempt=1"),
        ("POST", "/api/v1/oci-scan/job-1/fail?attempt=1"),
    ];

    private static HttpRequestMessage JsonRequest(string method, string path, string json = "{}") =>
        new(new HttpMethod(method), path) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    [Theory]
    [InlineData(0)]
    [InlineData(-3)]
    [InlineData(17)]
    public async Task Claim_WithMaxOutsideTheRange_Is422AndLeasesNothing(int max)
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, $"team/claimrange{Math.Abs(max)}", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        using var claim = await scanner.PostAsJsonAsync("/api/v1/oci-scan/claim", new { max });

        await ProblemBody.AssertValidationAsync(claim, "max");
        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest AND attempts > 0", new { digest = image.ManifestDigest }));
        // The adversarial twin: the same scanner with a legal max leases the job.
        Assert.NotEmpty(await ClaimAllAsync(scanner));
    }

    [Fact]
    public async Task Claim_WithAnEmptyBody_DefaultsToOneJob()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        await PushImageAsync(push, "team/emptybody-a", "1.0");
        await PushImageAsync(push, "team/emptybody-b", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/oci-scan/claim")
        {
            Content = new StringContent("", Encoding.UTF8, "application/json"),
        };

        using var claim = await scanner.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        var jobs = (await ProblemBody.ReadAsync(claim)).GetProperty("jobs");
        Assert.Equal(1, jobs.GetArrayLength());
    }

    [Fact]
    public async Task AScannerReport_IsAcceptedOnEveryRoute_AndAnOversizedOsvStateIsDropped()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        await PushImageAsync(push, "team/report", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        using (var claim = await scanner.PostAsJsonAsync("/api/v1/oci-scan/claim", new
        {
            max = 1,
            scanner = new { version = new string('v', 300), osvSource = "remote", osvState = new { reachable = true } },
        }))
        {
            Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
            var job = (await ProblemBody.ReadAsync(claim)).GetProperty("jobs")[0];
            _attempts[job.GetProperty("id").GetString()!] = job.GetProperty("attempt").GetInt32();
        }

        string version = await ScalarAsync<string>("SELECT scanner_version FROM oci_scanners", new { });
        Assert.Equal(128, version.Length);

        string big = new('x', OciScanLimits.MaxTextLength + 1);
        using var second = await scanner.PostAsJsonAsync("/api/v1/oci-scan/claim", new
        {
            max = 1,
            scanner = new { version = "0.9.0", osvState = new { note = big } },
        });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal("0.9.0", await ScalarAsync<string>("SELECT scanner_version FROM oci_scanners", new { }));
        // The oversized state is not stored; the scanner's previous, in-bounds state stands.
        string? state = await ScalarAsyncOrNull<string>("SELECT osv_state_json FROM oci_scanners", new { });
        Assert.NotNull(state);
        Assert.DoesNotContain(big, state);
        Assert.Equal("""{"reachable":true}""", state);
    }

    private async Task<T?> ScalarAsyncOrNull<T>(string sql, object args) where T : class
    {
        var db = _factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await Dapper.SqlMapper.ExecuteScalarAsync<T?>(conn, sql, args);
    }

    [Fact]
    public async Task EveryRoute_RefusesATokenWithoutScanOci_AndMovesNoJob()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/forbidden", "1.0");

        foreach (var (method, path) in EveryJobRoute)
        {
            using var request = JsonRequest(method, path);
            using var resp = await push.SendAsync(request);
            Assert.True(resp.StatusCode == HttpStatusCode.Forbidden, $"{method} {path} answered {(int)resp.StatusCode}");
        }

        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest AND attempts > 0", new { digest = image.ManifestDigest }));
    }

    [Fact]
    public async Task WithScanningOff_EveryRouteIsAbsent()
    {
        await using var off = new DependablyFactory();
        await off.InitializeAsync();
        using var scanner = off.CreateClientWithBearer(await off.CreateToken("scanner"));

        foreach (var (method, path) in EveryJobRoute)
        {
            using var request = JsonRequest(method, path);
            using var resp = await scanner.SendAsync(request);
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("TOO_LONG")]
    public async Task Fail_WithABlankOrOverlongReason_Is422AndTheJobStaysLeased(string reason)
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, $"team/failreason{reason.Length}", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        string jobId = await ClaimAsync(scanner, image.ManifestDigest);
        string sent = reason == "TOO_LONG" ? new string('r', OciScanLimits.MaxReasonLength + 1) : reason;

        using var fail = await scanner.PostAsJsonAsync(WriteRoute(jobId, "fail"), new { reason = sent, retryable = false });

        await ProblemBody.AssertValidationAsync(fail, "reason");
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE id = @jobId AND lease_expires_at IS NOT NULL", new { jobId }));
    }

    [Fact]
    public async Task WriteRoutes_ForAJobThatDoesNotExist_AreConflicts_NeverAnError()
    {
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        string missing = Guid.NewGuid().ToString("N");

        using (var beat = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/{missing}/heartbeat?attempt=1", new { }))
        {
            Assert.Equal(HttpStatusCode.Conflict, beat.StatusCode);
        }

        using (var fail = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{missing}/fail?attempt=1", new { reason = "gone", retryable = true }))
        {
            Assert.Equal(HttpStatusCode.Conflict, fail.StatusCode);
        }

        using var result = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{missing}/result?attempt=1", ResultBody(withFinding: false, gaps: []));
        Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
    }

    [Theory]
    [InlineData("not-a-digest")]
    [InlineData("sha256:short")]
    [InlineData("md5:d41d8cd98f00b204e9800998ecf8427e")]
    public async Task ImageReads_WithAMalformedDigest_Are404_AndNeverTouchTheBlobStore(string digest)
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/baddigest", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        string jobId = await ClaimAsync(scanner, image.ManifestDigest);
        int reads = _blobs.Reads;

        using (var manifest = await scanner.GetAsync($"/api/v1/oci-scan/{jobId}/manifests/{Uri.EscapeDataString(digest)}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, manifest.StatusCode);
        }

        using (var blob = await scanner.GetAsync($"/api/v1/oci-scan/{jobId}/blobs/{Uri.EscapeDataString(digest)}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, blob.StatusCode);
        }

        Assert.Equal(reads, _blobs.Reads);
        // The twin: the image's real manifest still reads under the same lease.
        Assert.Equal(image.Manifest, await ReadAsync(scanner, $"{jobId}/manifests/{image.ManifestDigest}"));
    }

    [Fact]
    public async Task ImageReads_ForAnUnknownJob_Are404()
    {
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        string digest = "sha256:" + new string('a', 64);

        using var manifest = await scanner.GetAsync($"/api/v1/oci-scan/{Guid.NewGuid():N}/manifests/{digest}");
        using var blob = await scanner.GetAsync($"/api/v1/oci-scan/{Guid.NewGuid():N}/blobs/{digest}");

        Assert.Equal(HttpStatusCode.NotFound, manifest.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, blob.StatusCode);
    }

    [Fact]
    public async Task ABlobTheImageNamesButTheStoreLost_IsAnUnavailable503_NotA404()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/lostblob", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        string jobId = await ClaimAsync(scanner, image.ManifestDigest);
        string layerKey = await ScalarAsync<string>(
            "SELECT blob_key FROM oci_blobs WHERE digest = @digest", new { digest = image.LayerDigest });
        await _blobs.DeleteAsync(layerKey);

        using var layer = await scanner.GetAsync($"/api/v1/oci-scan/{jobId}/blobs/{image.LayerDigest}");

        // A hosted image has no upstream to re-fetch from, so the lost bytes are "unavailable now".
        Assert.Equal(HttpStatusCode.ServiceUnavailable, layer.StatusCode);
        // The config and manifest, still stored, read as before.
        Assert.Equal(image.Config, await ReadAsync(scanner, $"{jobId}/blobs/{image.ConfigDigest}"));
    }

    // ── Result bodies that break the contract ────────────────────────────────────

    private static JsonNode ResultNode(bool withFinding = false) =>
        JsonSerializer.SerializeToNode(ResultBody(withFinding, gaps: []), WebJson)!;

    [Theory]
    [InlineData("no-platforms", "platforms")]
    [InlineData("duplicate-platform", "platforms")]
    [InlineData("blank-scanner-version", "platforms")]
    [InlineData("too-many-platforms", "platforms")]
    [InlineData("components-missing", "components")]
    [InlineData("blank-purl", "components")]
    [InlineData("unknown-advisory", "vulns")]
    [InlineData("bad-reachability", "vulns")]
    [InlineData("bad-advisory-record", "advisories")]
    [InlineData("gap-not-in-gaps", "contentGaps")]
    [InlineData("bad-verdict", "verdict")]
    public async Task Result_BreakingTheContract_Is422NamingTheField_AndStoresNothing(string defect, string field)
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, $"team/badresult-{defect}", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        string jobId = await ClaimAsync(scanner, image.ManifestDigest);
        var node = ResultNode(withFinding: defect == "bad-reachability");
        var platform = node["platforms"]![0]!;
        var component = platform["components"]![0]!;
        switch (defect)
        {
            case "no-platforms":
                node["platforms"] = new JsonArray();
                break;
            case "duplicate-platform":
                node["platforms"] = new JsonArray(platform.DeepClone(), platform.DeepClone());
                break;
            case "blank-scanner-version":
                platform["scannerVersion"] = " ";
                break;
            case "too-many-platforms":
                var many = new JsonArray();
                for (int i = 0; i <= OciScanLimits.MaxPlatforms; i++)
                {
                    var copy = platform.DeepClone();
                    copy["platform"] = $"linux/arch{i}";
                    many.Add(copy);
                }

                node["platforms"] = many;
                break;
            case "components-missing":
                platform["components"] = null;
                break;
            case "blank-purl":
                component["purl"] = "";
                break;
            case "unknown-advisory":
                component["vulns"] = new JsonArray(JsonNode.Parse("""{"id":"DSA-0000-0","reachability":"reachable"}"""));
                break;
            case "bad-reachability":
                component["vulns"]![0]!["reachability"] = "maybe";
                break;
            case "bad-advisory-record":
                node["advisories"] = new JsonArray(JsonNode.Parse("""{"summary":"no id"}"""));
                break;
            case "gap-not-in-gaps":
                platform["contentGaps"] = new JsonArray("missing-layer");
                break;
            case "bad-verdict":
                component["verdict"] = JsonNode.Parse("""{"status":"definitely"}""");
                break;
        }

        using var content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/json");
        using var resp = await scanner.PostAsync(WriteRoute(jobId, "result"), content);

        await ProblemBody.AssertValidationAsync(resp, field);
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_image_components", new { }));
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
        Assert.Equal("unscanned", await StatusAsync($"team/badresult-{defect}", image.ManifestDigest));
    }

    // ── Rematch routes: bodies and reasons ───────────────────────────────────────

    private async Task<(HttpClient Scanner, ClaimedJob Rematch, string CoverageId, string ComponentId)> OpenRematchAsync(
        string repository)
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        await PushImageAsync(push, repository, "1.0");
        var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        var first = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        await PostOkAsync(scanner, $"{first.Id}/result?attempt={first.Attempt}", ScanBody(["DSA-5555-1"]));
        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));
        Assert.Equal(1, await SweepAsync());
        var rematch = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        Assert.Equal("rematch", rematch.Kind);
        using var inventory = await InventoryAsync(scanner, rematch);
        var platform = inventory.RootElement.GetProperty("platforms")[0];
        return (scanner, rematch, platform.GetProperty("coverageId").GetString()!,
            platform.GetProperty("components")[0].GetProperty("id").GetString()!);
    }

    [Fact]
    public async Task Reextract_WithABlankOrOverlongReason_Is422_AndTheRematchStaysLeased()
    {
        var (scanner, rematch, _, _) = await OpenRematchAsync("team/reextract-reason");
        using var scannerLease = scanner;

        foreach (string reason in new[] { "", "  ", new string('r', OciScanLimits.MaxReasonLength + 1) })
        {
            using var resp = await scanner.PostAsJsonAsync(
                $"/api/v1/oci-scan/{rematch.Id}/reextract?attempt={rematch.Attempt}", new { reason });
            await ProblemBody.AssertValidationAsync(resp, "reason");
        }

        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = rematch.Id }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM audit_log WHERE action = 'oci_scan_reextract'", new { }));
    }

    [Fact]
    public async Task Matches_BreakingTheContract_Is422_AndKeepsTheStoredFindings()
    {
        var (scanner, rematch, coverageId, componentId) = await OpenRematchAsync("team/badmatches");
        using var scannerLease = scanner;
        string route = $"/api/v1/oci-scan/{rematch.Id}/matches?attempt={rematch.Attempt}";

        // No platforms at all.
        using (var empty = await scanner.PostAsJsonAsync(route, new { platforms = Array.Empty<object>() }))
        {
            await ProblemBody.AssertValidationAsync(empty, "platforms");
        }

        // A finding for a component the stored inventory does not hold.
        using (var unknown = await scanner.PostAsJsonAsync(route, MatchBody(coverageId, "no-such-component", ["DSA-6666-1"])))
        {
            await ProblemBody.AssertValidationAsync(unknown, "findings");
        }

        // A platform the stored inventory does not have: the result must name every stored one.
        var wrongPlatform = JsonSerializer.SerializeToNode(MatchBody(coverageId, componentId, ["DSA-6666-1"]), WebJson)!;
        wrongPlatform["platforms"]![0]!["platform"] = "linux/riscv64";
        using (var content = new StringContent(wrongPlatform.ToJsonString(), Encoding.UTF8, "application/json"))
        using (var mismatched = await scanner.PostAsync(route, content))
        {
            Assert.Equal(HttpStatusCode.Conflict, mismatched.StatusCode);
        }

        // Nothing moved: the first scan's finding is still the image's finding, and the job is open.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_component_vulns", new { }));
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = rematch.Id }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM audit_log WHERE action = 'oci_scan_rematch_result'", new { }));
    }

    [Fact]
    public async Task Matches_NamingAnAdvisoryTheSourceCannotVerify_Is503_AndTheRematchIsDeferred()
    {
        var (scanner, rematch, coverageId, componentId) = await OpenRematchAsync("team/matchesosvdown");
        using var scannerLease = scanner;
        _osv.Reachable = false;

        using var resp = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{rematch.Id}/matches?attempt={rematch.Attempt}",
            MatchBody(coverageId, componentId, ["DSA-6666-1"]));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE id = @id AND state = 'pending' AND lease_expires_at IS NULL", new { id = rematch.Id }));
        Assert.Equal(["DSA-5555-1"], await ImageLinksAsync(await ScalarAsync<string>(
            "SELECT digest FROM oci_scan_jobs WHERE id = @id", new { id = rematch.Id })));
        _osv.Reachable = true;
    }

    [Fact]
    public async Task Inventory_WithSeveralPlatforms_WritesEachInOrder_IncludingTheOnesWithNoComponentsOrNoGaps()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        await PushImageAsync(push, "team/multiarch", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        var first = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        var node = JsonSerializer.SerializeToNode(ScanBody([]), WebJson)!;
        var amd64 = node["platforms"]![0]!;
        amd64["gaps"] = new JsonArray("layer-0-unreadable");
        amd64["contentGaps"] = new JsonArray("layer-0-unreadable");
        var arm64 = amd64.DeepClone();
        arm64["platform"] = "linux/arm64";
        arm64["gaps"] = new JsonArray();
        arm64["contentGaps"] = new JsonArray();
        var s390x = amd64.DeepClone();
        s390x["platform"] = "linux/s390x";
        s390x["gaps"] = new JsonArray();
        s390x["contentGaps"] = new JsonArray();
        s390x["components"] = new JsonArray();
        node["platforms"] = new JsonArray(amd64.DeepClone(), arm64, s390x);
        using (var content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/json"))
        using (var posted = await scanner.PostAsync($"/api/v1/oci-scan/{first.Id}/result?attempt={first.Attempt}", content))
        {
            Assert.Equal(HttpStatusCode.NoContent, posted.StatusCode);
        }

        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));
        Assert.Equal(1, await SweepAsync());
        var rematch = await ClaimJobAsync(scanner, kinds: "scan,rematch");

        using var inventory = await InventoryAsync(scanner, rematch);

        var platforms = inventory.RootElement.GetProperty("platforms").EnumerateArray().ToList();
        Assert.Equal(new[] { "linux/amd64", "linux/arm64", "linux/s390x" }, platforms.Select(p => p.GetProperty("platform").GetString()).ToArray());
        Assert.Equal(new[] { "layer-0-unreadable" },
            platforms[0].GetProperty("contentGaps").EnumerateArray().Select(g => g.GetString()).ToArray());
        Assert.Equal(1, platforms[0].GetProperty("components").GetArrayLength());
        Assert.Equal(1, platforms[1].GetProperty("components").GetArrayLength());
        Assert.Equal(0, platforms[2].GetProperty("components").GetArrayLength());
    }

    [Fact]
    public async Task AUserOfAnotherOrg_CannotDriveThisOrgsScanner()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/crossorg-scan", "1.0");
        var orgs = _factory.Services.GetRequiredService<Dependably.Infrastructure.OrgRepository>();
        var other = await orgs.CreateOrgAsync($"sc-{Guid.NewGuid():N}"[..14]);
        string userId = await Dependably.Tests.Infrastructure.Seeding.UserSeeder.InsertAsync(
            _factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>(),
            other.Id, $"scan-intruder-{Guid.NewGuid():N}@example.com", "owner");
        using var intruder = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(userId, "owner"));

        using var claim = await intruder.PostAsJsonAsync("/api/v1/oci-scan/claim", new { max = 16 });

        Assert.True(claim.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized,
            $"claim answered {(int)claim.StatusCode}");
        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest AND attempts > 0", new { digest = image.ManifestDigest }));
        // The adversarial twin: the org's own scanner is served.
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        Assert.Contains(image.ManifestDigest, (await ClaimAllAsync(scanner)).Keys);
    }

    [Fact]
    public async Task Inventory_OfALargeImage_StreamsEveryComponentInTheStoredOrder()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        await PushImageAsync(push, "team/bigimage", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        var first = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        var node = JsonSerializer.SerializeToNode(ScanBody([]), WebJson)!;
        var template = node["platforms"]![0]!["components"]![0]!;
        var components = new JsonArray();
        const int Count = 400;
        for (int i = 0; i < Count; i++)
        {
            var copy = template.DeepClone();
            copy["purl"] = $"pkg:deb/debian/library-with-a-long-name-{i:D4}@1.0.{i}?distro=debian-12";
            copy["name"] = $"library-with-a-long-name-{i:D4}";
            copy["version"] = $"1.0.{i}";
            copy["sourceName"] = $"library-with-a-long-name-{i:D4}";
            components.Add(copy);
        }

        node["platforms"]![0]!["components"] = components;
        using (var content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/json"))
        using (var posted = await scanner.PostAsync($"/api/v1/oci-scan/{first.Id}/result?attempt={first.Attempt}", content))
        {
            Assert.Equal(HttpStatusCode.NoContent, posted.StatusCode);
        }

        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));
        Assert.Equal(1, await SweepAsync());
        var rematch = await ClaimJobAsync(scanner, kinds: "scan,rematch");

        using var inventory = await InventoryAsync(scanner, rematch);

        var listed = inventory.RootElement.GetProperty("platforms")[0].GetProperty("components").EnumerateArray().ToList();
        Assert.Equal(Count, listed.Count);
        Assert.Equal(Count, listed.Select(c => c.GetProperty("id").GetString()).Distinct().Count());
    }
}
