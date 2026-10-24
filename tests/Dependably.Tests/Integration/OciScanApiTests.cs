using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Tests.Integration;

/// <summary>
/// The OCI scan API end to end, through HTTP: a pushed image is queued, a scanner holding only
/// <c>scan:oci</c> claims it, reads exactly that image's bytes, and posts a result that becomes the
/// image's version status. The status rules are the point: an image is clean only when it was
/// scanned without gaps and nothing matched, partial when part of it could not be read, and
/// no_feed when nobody is scanning.
/// </summary>
[Trait("Category", "Integration")]
public sealed partial class OciScanApiTests : IAsyncLifetime
{
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private const string DsaRecord = """
        {
          "id": "DSA-5555-1",
          "aliases": ["CVE-2026-5555"],
          "summary": "openssl issue",
          "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" }],
          "affected": [{ "package": { "ecosystem": "Debian:12", "name": "openssl" }, "versions": ["3.0.11-1~deb12u1"] }]
        }
        """;

    private readonly DependablyFactory _factory;

    // Every blob the host reads goes through this, so a test can show a rematch reads none.
    private readonly CountingBlobStore _blobs = new(new Dependably.Storage.InMemoryBlobStore());

    // Job id -> the attempt its claim returned, which every write route requires back.
    private readonly Dictionary<string, int> _attempts = new(StringComparer.Ordinal);

    // The registry's advisory source: it knows the advisories the tests' scanner reports.
    private readonly SwitchableOsvSource _osv = new(DsaRecord, NewRecord);

    public OciScanApiTests()
    {
        _factory = new DependablyFactory
        {
            FrozenClock = TestTime.Frozen(),
            OsvSource = _osv,
            ExtraSettings = new Dictionary<string, string?>
            {
                ["OCI_SCAN_ENABLED"] = "true",
                // The tests drive the sweep themselves; on its schedule it would fire whenever a
                // test advances the frozen clock past :17 and queue jobs behind the test's back.
                // February 31st never comes; an unparseable value would fail the host instead.
                ["OCI_SCAN_SWEEP_SCHEDULE"] = "0 0 31 2 *",
            },
            ServiceOverrides = services =>
            {
                services.RemoveAll<Dependably.Storage.IBlobStore>();
                services.AddSingleton<Dependably.Storage.IBlobStore>(_blobs);
            },
        };
    }

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task Push_QueuesTheImageOnce()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/once", "1.0");

        // A second tag on the same manifest stores no new version, so it queues nothing new.
        using (var put = await PutManifestAsync(push, "team/once", "latest", image.Manifest))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest", new { digest = image.ManifestDigest }));
    }

    [Fact]
    public async Task Scanner_ClaimsReadsOnlyItsImage_AndAResultMakesItVulnerable()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/vuln", "1.0");
        var other = await PushImageAsync(push, "team/other", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        string jobId = await ClaimAsync(scanner, image.ManifestDigest);

        Assert.Equal(image.Manifest, await ReadAsync(scanner, $"{jobId}/manifests/{image.ManifestDigest}"));
        Assert.Equal(image.Config, await ReadAsync(scanner, $"{jobId}/blobs/{image.ConfigDigest}"));
        Assert.Equal(image.Layer, await ReadAsync(scanner, $"{jobId}/blobs/{image.LayerDigest}"));
        // Another image's layer, held by the same org, is outside this job's image.
        using (var outside = await scanner.GetAsync($"/api/v1/oci-scan/{jobId}/blobs/{other.LayerDigest}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, outside.StatusCode);
        }

        // Scanner reads are not tenant downloads. One ordinary pull of the same layer writes one
        // download row; activity rows drain through an ordered background writer, so once that row
        // lands any row the three scanner reads above had queued would have landed first.
        using (var pull = _factory.CreateClientWithBearer(await _factory.CreateToken("pull")))
        using (var pulled = await pull.GetAsync($"/v2/team/vuln/blobs/{image.LayerDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, pulled.StatusCode);
        }

        Assert.Equal(1, await DownloadRowsOnceDrainedAsync("pkg:oci/vuln@%"));

        using (var result = await scanner.PostAsJsonAsync(WriteRoute(jobId, "result"), ResultBody(withFinding: true, gaps: [])))
        {
            Assert.Equal(HttpStatusCode.NoContent, result.StatusCode);
        }

        Assert.Equal("vulnerable", await StatusAsync("team/vuln", image.ManifestDigest));
        // A hosted image's advisories also reach the version itself, so alerts and gates see them.
        Assert.Equal(1, await CountAsync(
            """
            SELECT COUNT(*) FROM package_version_vulns pvv
            JOIN package_versions pv ON pv.id = pvv.package_version_id
            WHERE pv.version = @digest
            """, new { digest = image.ManifestDigest }));
        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM package_versions WHERE version = @digest AND vuln_checked_at IS NOT NULL",
            new { digest = image.ManifestDigest }));
        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM oci_image_components WHERE source_name = 'openssl'", new { }));
        Assert.Equal("done", await ScalarAsync<string>(
            "SELECT state FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));

        // The job is finished: a second result is refused rather than racing the first.
        using var again = await scanner.PostAsJsonAsync(WriteRoute(jobId, "result"), ResultBody(withFinding: true, gaps: []));
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }

    [Fact]
    public async Task AScanAboveTheScoreTolerance_ReadsVulnerable_BecauseThePullIsNotRefused()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/overtolerance", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        string jobId = await ClaimAsync(scanner, image.ManifestDigest);
        await PostResultAsync(scanner, jobId, withFinding: true, gaps: []);

        // The finding scores 6.5; the org tolerates at most 5.0.
        string orgId = await ScalarAsync<string>("SELECT org_id FROM oci_scan_jobs WHERE id = @jobId", new { jobId });
        await ExecAsync(
            """
            INSERT INTO org_settings (org_id, max_osv_score_tolerance) VALUES (@orgId, 5.0)
            ON CONFLICT(org_id) DO UPDATE SET max_osv_score_tolerance = 5.0
            """,
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);

        var v = await VersionAsync("team/overtolerance", image.ManifestDigest);
        Assert.Equal(6.5, v.GetProperty("maxOsvScore").GetDouble());
        Assert.Equal("vulnerable", v.GetProperty("status").GetString());

        // The status must not claim a refusal: the same image still pulls.
        using var pull = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        using var pulled = await pull.GetAsync($"/v2/team/overtolerance/manifests/{image.ManifestDigest}");
        Assert.Equal(HttpStatusCode.OK, pulled.StatusCode);

        // Nor may the pre-adoption lookup: it reads the same scan, and the advisory warns.
        var verdict = await LookupAsync($"ecosystem=oci&name=team/overtolerance&version={Uri.EscapeDataString(image.ManifestDigest)}");
        Assert.Equal(6.5, verdict.GetProperty("vulnerabilities").GetProperty("maxCvss").GetDouble());
        Assert.Equal("warn", verdict.GetProperty("verdict").GetString());
        Assert.Equal(JsonValueKind.Null, verdict.GetProperty("blockedReason").ValueKind);
    }

    [Fact]
    public async Task AScanAboveTheScoreTolerance_ReadsBlocked_WhenTheOrgEnforcesOciScansAtBlock()
    {
        // The twin of the test above: under oci_scan_enforcement = block the pull gate refuses the
        // image on its score, so the status, the pull and the lookup all say so.
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/enforced", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        string jobId = await ClaimAsync(scanner, image.ManifestDigest);
        await PostResultAsync(scanner, jobId, withFinding: true, gaps: []);

        string orgId = await ScalarAsync<string>("SELECT org_id FROM oci_scan_jobs WHERE id = @jobId", new { jobId });
        await ExecAsync(
            """
            INSERT INTO org_settings (org_id, max_osv_score_tolerance, oci_scan_enforcement) VALUES (@orgId, 5.0, 'block')
            ON CONFLICT(org_id) DO UPDATE SET max_osv_score_tolerance = 5.0, oci_scan_enforcement = 'block'
            """,
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);

        var v = await VersionAsync("team/enforced", image.ManifestDigest);
        Assert.Equal("blocked", v.GetProperty("status").GetString());

        using var pull = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        using var pulled = await pull.GetAsync($"/v2/team/enforced/manifests/{image.ManifestDigest}");
        Assert.Equal(HttpStatusCode.Forbidden, pulled.StatusCode);

        var verdict = await LookupAsync($"ecosystem=oci&name=team/enforced&version={Uri.EscapeDataString(image.ManifestDigest)}");
        Assert.Equal("blocked", verdict.GetProperty("verdict").GetString());
    }

    [Fact]
    public async Task ANonOciLookupAboveTheScoreTolerance_IsStillBlocked()
    {
        // The twin of the OCI lookup above: an ecosystem whose serve path enforces the score
        // tolerance keeps the blocked verdict. Air-gapped, so no registry metadata is fetched.
        string orgId = await ScalarAsync<string>("SELECT id FROM orgs LIMIT 1", new { });
        await ExecAsync(
            """
            INSERT INTO org_settings (org_id, max_osv_score_tolerance, air_gapped) VALUES (@orgId, 5.0, 1)
            ON CONFLICT(org_id) DO UPDATE SET max_osv_score_tolerance = 5.0, air_gapped = 1
            """,
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        _osv.PurlAdvisories = [Dependably.Protocol.OsvRecordParser.TryParse(JsonDocument.Parse(DsaRecord).RootElement)!];

        var verdict = await LookupAsync("ecosystem=npm&name=left-pad&version=1.3.0");
        Assert.Equal(6.5, verdict.GetProperty("vulnerabilities").GetProperty("maxCvss").GetDouble());
        Assert.Equal("blocked", verdict.GetProperty("verdict").GetString());
    }

    private async Task<JsonElement> LookupAsync(string query)
    {
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var response = await admin.GetAsync($"/api/v1/lookup?{query}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.Clone();
    }

    [Fact]
    public async Task AResult_WhoseNewAdvisoryCannotBeVerified_Is503_AndTheJobIsRequeued()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/osvdown", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        string jobId = await ClaimAsync(scanner, image.ManifestDigest);

        _osv.Reachable = false;
        using (var result = await scanner.PostAsJsonAsync(WriteRoute(jobId, "result"), ResultBody(withFinding: true, gaps: [])))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, result.StatusCode);
        }

        // Nothing stored, and the scanner's record was not the fallback.
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = 'DSA-5555-1'", new { }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_image_components", new { }));
        // The attempt ended as a retryable failure: back in the queue, leased to no one.
        Assert.Equal(1, await CountAsync(
            """
            SELECT COUNT(*) FROM oci_scan_jobs
            WHERE id = @jobId AND state = 'pending' AND lease_expires_at IS NULL AND next_attempt_at IS NOT NULL
            """, new { jobId }));
        Assert.Equal("unscanned", await StatusAsync("team/osvdown", image.ManifestDigest));

        // Once the source answers, the retried scan is stored with the source's record.
        _osv.Reachable = true;
        _factory.FrozenClock!.Advance(TimeSpan.FromHours(2));
        string retry = await ClaimAsync(scanner, image.ManifestDigest);
        await PostResultAsync(scanner, retry, withFinding: true, gaps: []);
        Assert.Equal("vulnerable", await StatusAsync("team/osvdown", image.ManifestDigest));
    }

    [Fact]
    public async Task AnOutageLongerThanEveryAttempt_NeverParksTheJob_AndItCompletesWhenTheSourceReturns()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/longoutage", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        // Seven deferrals, two more than OCI_SCAN_MAX_ATTEMPTS: none of them spends the budget.
        _osv.Reachable = false;
        string jobId = "";
        for (int i = 0; i < 7; i++)
        {
            jobId = await ClaimAsync(scanner, image.ManifestDigest);
            using var result = await scanner.PostAsJsonAsync(WriteRoute(jobId, "result"), ResultBody(withFinding: true, gaps: []));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, result.StatusCode);
            Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
            _factory.FrozenClock!.Advance(TimeSpan.FromMinutes(16));
        }

        Assert.Equal(7, await ScalarAsync<int>("SELECT deferrals FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));

        _osv.Reachable = true;
        string last = await ClaimAsync(scanner, image.ManifestDigest);
        Assert.Equal(jobId, last);
        await PostResultAsync(scanner, last, withFinding: true, gaps: []);
        Assert.Equal("done", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
        Assert.Equal("vulnerable", await StatusAsync("team/longoutage", image.ManifestDigest));
    }

    [Fact]
    public async Task AnAdvisoryTheSourceDoesNotKnow_IsDropped_AndTheRestOfTheResultIsStored()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/fabricated", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        string jobId = await ClaimAsync(scanner, image.ManifestDigest);

        // A known finding and a fabricated one, the latter claiming the known one's CVE.
        var body = JsonSerializer.Deserialize<OciScanResultRequest>(
            JsonSerializer.Serialize(ResultBody(withFinding: true, gaps: []), WebJson), WebJson)!;
        var platform = body.Platforms![0];
        var component = platform.Components![0];
        body = body with
        {
            Platforms = [platform with
            {
                Components = [component with
                {
                    Vulns = [.. component.Vulns!, component.Vulns![0] with { Id = "GHSA-zz99-fake-0001" }],
                }],
            }],
            Advisories = [.. body.Advisories!, JsonDocument.Parse(
                """{"id":"GHSA-zz99-fake-0001","aliases":["CVE-2026-5555"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}""").RootElement],
        };

        using (var result = await scanner.PostAsJsonAsync(WriteRoute(jobId, "result"), body, WebJson))
        {
            Assert.Equal(HttpStatusCode.NoContent, result.StatusCode);
        }

        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = 'GHSA-zz99-fake-0001'", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_component_vulns", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = 'DSA-5555-1'", new { }));
        Assert.Equal("vulnerable", await StatusAsync("team/fabricated", image.ManifestDigest));
    }

    [Fact]
    public async Task AResultWithGapsAndNoAdvisories_IsPartial_NeverClean()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var gapped = await PushImageAsync(push, "team/gapped", "1.0");
        var clean = await PushImageAsync(push, "team/clean", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        // One claim leases every due job, both of these included.
        var jobs = await ClaimAllAsync(scanner);
        string gappedJob = jobs[gapped.ManifestDigest];
        string cleanJob = jobs[clean.ManifestDigest];
        (await scanner.PostAsJsonAsync(WriteRoute(gappedJob, "result"),
            ResultBody(withFinding: false, gaps: ["rpm packages: no OSV ecosystem for rhel 9"]))).EnsureSuccessStatusCode();
        (await scanner.PostAsJsonAsync(WriteRoute(cleanJob, "result"),
            ResultBody(withFinding: false, gaps: []))).EnsureSuccessStatusCode();

        Assert.Equal("partial", await StatusAsync("team/gapped", gapped.ManifestDigest));
        Assert.Equal("clean", await StatusAsync("team/clean", clean.ManifestDigest));
    }

    [Fact]
    public async Task WithoutALiveScanner_AnUnscannedImageHasNoFeed_AndAScannedOneKeepsItsStatus()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var waiting = await PushImageAsync(push, "team/waiting", "1.0");
        var scanned = await PushImageAsync(push, "team/scanned", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        string jobId = await ClaimAsync(scanner, scanned.ManifestDigest);
        (await scanner.PostAsJsonAsync(WriteRoute(jobId, "result"), ResultBody(withFinding: false, gaps: [])))
            .EnsureSuccessStatusCode();
        Assert.Equal("unscanned", await StatusAsync("team/waiting", waiting.ManifestDigest));

        // The scanner goes quiet for longer than the heartbeat window.
        _factory.FrozenClock!.Advance(TimeSpan.FromMinutes(11));

        Assert.Equal("no_feed", await StatusAsync("team/waiting", waiting.ManifestDigest));
        Assert.Equal("clean", await StatusAsync("team/scanned", scanned.ManifestDigest));
    }

    [Fact]
    public async Task TheVersionProjection_ReportsScanState_NeverInferredFromStatus()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var vuln = await PushImageAsync(push, "team/pvuln", "1.0");
        var gapped = await PushImageAsync(push, "team/pgapped", "1.0");
        var clean = await PushImageAsync(push, "team/pclean", "1.0");
        var waiting = await PushImageAsync(push, "team/pwaiting", "1.0");
        var maskedVuln = await PushImageAsync(push, "team/pmasked", "1.0");
        var maskedGap = await PushImageAsync(push, "team/pmaskedgap", "1.0");
        var maskedWait = await PushImageAsync(push, "team/pmaskedwait", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        var jobs = await ClaimAllAsync(scanner);
        await PostResultAsync(scanner, jobs[vuln.ManifestDigest], withFinding: true, gaps: []);
        await PostResultAsync(scanner, jobs[gapped.ManifestDigest], withFinding: false, gaps: ["rpm packages: no OSV ecosystem for rhel 9"]);
        await PostResultAsync(scanner, jobs[clean.ManifestDigest], withFinding: false, gaps: []);
        await PostResultAsync(scanner, jobs[maskedVuln.ManifestDigest], withFinding: true, gaps: ["rpm packages: no OSV ecosystem for rhel 9"]);
        await PostResultAsync(scanner, jobs[maskedGap.ManifestDigest], withFinding: false, gaps: ["rpm packages: no OSV ecosystem for rhel 9"]);
        // The page must not depend on the hosted-image advisory links.
        await ExecAsync("DELETE FROM package_version_vulns", new { });
        // waiting and maskedWait were claimed but never resolved: no stored result.

        var v = await VersionAsync("team/pvuln", vuln.ManifestDigest);
        Assert.Equal("vulnerable", v.GetProperty("status").GetString());
        var scan = v.GetProperty("ociScan");
        Assert.Equal("scanned", scan.GetProperty("state").GetString());
        Assert.Equal(1, scan.GetProperty("findingCount").GetInt32());
        Assert.Equal(0, scan.GetProperty("gapCount").GetInt32());
        Assert.Equal(JsonValueKind.Number, scan.GetProperty("maxScore").ValueKind);

        scan = (await VersionAsync("team/pgapped", gapped.ManifestDigest)).GetProperty("ociScan");
        Assert.Equal("scanned", scan.GetProperty("state").GetString());
        Assert.Equal(1, scan.GetProperty("gapCount").GetInt32());
        Assert.Equal(0, scan.GetProperty("findingCount").GetInt32());

        // Twin: scanned, nothing matched, no gaps.
        scan = (await VersionAsync("team/pclean", clean.ManifestDigest)).GetProperty("ociScan");
        Assert.Equal("scanned", scan.GetProperty("state").GetString());
        Assert.Equal(0, scan.GetProperty("gapCount").GetInt32());
        Assert.Equal(0, scan.GetProperty("findingCount").GetInt32());

        scan = (await VersionAsync("team/pwaiting", waiting.ManifestDigest)).GetProperty("ociScan");
        Assert.Equal("unscanned", scan.GetProperty("state").GetString());

        // A blocked / allowed / deprecated row still carries the scan facts.
        await ExecAsync("UPDATE package_versions SET manual_block_state = 'blocked' WHERE version = @d", new { d = maskedVuln.ManifestDigest });
        await ExecAsync("UPDATE package_versions SET manual_block_state = 'allowed' WHERE version = @d", new { d = maskedGap.ManifestDigest });
        await ExecAsync("UPDATE package_versions SET deprecated = 'old' WHERE version = @d", new { d = maskedWait.ManifestDigest });

        v = await VersionAsync("team/pmasked", maskedVuln.ManifestDigest);
        Assert.Equal("blocked", v.GetProperty("status").GetString());
        scan = v.GetProperty("ociScan");
        Assert.Equal("scanned", scan.GetProperty("state").GetString());
        Assert.Equal(1, scan.GetProperty("findingCount").GetInt32());
        Assert.Equal(1, scan.GetProperty("gapCount").GetInt32());

        v = await VersionAsync("team/pmaskedgap", maskedGap.ManifestDigest);
        // A manual allow only changes the status of a version above the block tolerance.
        Assert.Equal("partial", v.GetProperty("status").GetString());
        scan = v.GetProperty("ociScan");
        Assert.Equal("scanned", scan.GetProperty("state").GetString());
        Assert.Equal(1, scan.GetProperty("gapCount").GetInt32());

        v = await VersionAsync("team/pmaskedwait", maskedWait.ManifestDigest);
        Assert.Equal("deprecated", v.GetProperty("status").GetString());
        Assert.Equal("unscanned", v.GetProperty("ociScan").GetProperty("state").GetString());

        // The scanner goes quiet: an image with no stored result has no feed; a stored one stays scanned.
        _factory.FrozenClock!.Advance(TimeSpan.FromMinutes(11));
        Assert.Equal("no_feed", (await VersionAsync("team/pwaiting", waiting.ManifestDigest)).GetProperty("ociScan").GetProperty("state").GetString());
        v = await VersionAsync("team/pmaskedwait", maskedWait.ManifestDigest);
        Assert.Equal("deprecated", v.GetProperty("status").GetString());
        Assert.Equal("no_feed", v.GetProperty("ociScan").GetProperty("state").GetString());
        Assert.Equal("scanned", (await VersionAsync("team/pclean", clean.ManifestDigest)).GetProperty("ociScan").GetProperty("state").GetString());
    }

    [Fact]
    public async Task ThePackageList_ReportsEachOciPackagesScanState_NeverCleanWithoutAResult()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var vuln = await PushImageAsync(push, "team/lvuln", "1.0");
        var clean = await PushImageAsync(push, "team/lclean", "1.0");
        var waiting = await PushImageAsync(push, "team/lwaiting", "1.0");
        var gapped = await PushImageAsync(push, "team/lgapped", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        var jobs = await ClaimAllAsync(scanner);
        await PostResultAsync(scanner, jobs[vuln.ManifestDigest], withFinding: true, gaps: []);
        await PostResultAsync(scanner, jobs[clean.ManifestDigest], withFinding: false, gaps: []);
        await PostResultAsync(scanner, jobs[gapped.ManifestDigest], withFinding: false, gaps: ["rpm packages: no OSV ecosystem for rhel 9"]);
        // The list must not depend on the hosted-image advisory links.
        await ExecAsync("DELETE FROM package_version_vulns", new { });

        // Proxied images: shared cache rows with this org's access, and only the org's own scan tables.
        string orgId = await ScalarAsync<string>("SELECT id FROM orgs", new { });
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await SeedProxiedPackageAsync(db, orgId, "library/pvuln", 9.8);
        await SeedProxiedPackageAsync(db, orgId, "library/pclean");
        await SeedProxiedPackageAsync(db, orgId, "library/pwaiting", scanned: false);
        await SeedProxiedPackageAsync(db, orgId, "library/pmixed", 7.5);
        await OciScanSeeder.InsertScanAsync(db, orgId,
            await OciScanSeeder.InsertProxiedManifestAsync(db, orgId, "library/pmixed", "sha256:" + new string('b', 64)),
            proxied: true);

        var list = await OciPackagesAsync();

        AssertScan(list["team/lvuln"], "scanned", findings: 1);
        AssertScan(list["team/lclean"], "scanned", findings: 0, gaps: 0);
        AssertScan(list["team/lgapped"], "scanned", findings: 0, gaps: 1);
        AssertScan(list["team/lwaiting"], "unscanned");
        AssertScan(list["library/pvuln"], "scanned", findings: 1);
        AssertScan(list["library/pclean"], "scanned", findings: 0, gaps: 0);
        AssertScan(list["library/pwaiting"], "unscanned");
        AssertScan(list["library/pmixed"], "scanned", findings: 1);
        // The aggregate counts that drove the false clean are still empty for every one of them.
        Assert.All(list.Values, p => Assert.Equal(0, p.GetProperty("criticalCount").GetInt32() + p.GetProperty("highCount").GetInt32()));

        _factory.FrozenClock!.Advance(TimeSpan.FromMinutes(11));
        list = await OciPackagesAsync();
        AssertScan(list["team/lwaiting"], "no_feed");
        AssertScan(list["library/pwaiting"], "no_feed");
        AssertScan(list["library/pvuln"], "scanned", findings: 1);
    }

    private static async Task<string> SeedProxiedPackageAsync(
        IMetadataStore db, string orgId, string repository, double? score = null, bool scanned = true)
    {
        await PackageSeeder.InsertAsync(db, orgId, "oci", repository, isProxy: true);
        string digest = "sha256:" + new string('a', 64);
        string id = await OciScanSeeder.InsertProxiedManifestAsync(db, orgId, repository, digest);
        if (scanned)
        {
            await OciScanSeeder.InsertScanAsync(db, orgId, id, proxied: true, 0, score is null ? [] : [score.Value]);
        }

        return id;
    }

    private static void AssertScan(JsonElement item, string state, int? findings = null, int? gaps = null)
    {
        var scan = item.GetProperty("ociScan");
        Assert.Equal(state, scan.GetProperty("state").GetString());
        if (findings is not null)
        {
            Assert.Equal(findings, scan.GetProperty("findingCount").GetInt32());
        }

        if (gaps is not null)
        {
            Assert.Equal(gaps, scan.GetProperty("gapCount").GetInt32());
        }
    }

    private async Task<Dictionary<string, JsonElement>> OciPackagesAsync()
    {
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var response = await admin.GetAsync("/api/v1/packages?ecosystem=oci&limit=100");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("items").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.Clone());
    }

    private async Task PostResultAsync(HttpClient scanner, string jobId, bool withFinding, IReadOnlyList<string> gaps)
        => (await scanner.PostAsJsonAsync(WriteRoute(jobId, "result"), ResultBody(withFinding, gaps))).EnsureSuccessStatusCode();

    private async Task ExecAsync(string sql, object args)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(sql, args);
    }

    private async Task<JsonElement> VersionAsync(string repository, string digest)
    {
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var response = await admin.GetAsync($"/api/v1/packages/oci/{Uri.EscapeDataString(repository)}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("versions").EnumerateArray()
            .Single(v => v.GetProperty("version").GetString() == digest).Clone();
    }

    [Fact]
    public async Task Failures_RetryWithBackoff_OrPark_AndALostLeaseIsAConflict()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var retried = await PushImageAsync(push, "team/retried", "1.0");
        var parked = await PushImageAsync(push, "team/parked", "1.0");
        var slow = await PushImageAsync(push, "team/slow", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        var jobs = await ClaimAllAsync(scanner);
        string retryJob = jobs[retried.ManifestDigest];
        using (var fail = await scanner.PostAsJsonAsync(WriteRoute(retryJob, "fail"),
            new { reason = "OSV unreachable", retryable = true }))
        {
            using var body = JsonDocument.Parse(await fail.Content.ReadAsStringAsync());
            Assert.Equal("pending", body.RootElement.GetProperty("state").GetString());
        }

        string parkJob = jobs[parked.ManifestDigest];
        (await scanner.PostAsJsonAsync(WriteRoute(parkJob, "fail"),
            new { reason = "layer path escapes the image root", retryable = false })).EnsureSuccessStatusCode();
        Assert.Equal("failed", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @parkJob", new { parkJob }));

        // Nothing stamped: a failed image stays unscanned.
        Assert.Equal("unscanned", await StatusAsync("team/parked", parked.ManifestDigest));

        string slowJob = jobs[slow.ManifestDigest];
        _factory.FrozenClock!.Advance(TimeSpan.FromMinutes(16));
        using var late = await scanner.PostAsJsonAsync(WriteRoute(slowJob, "result"), ResultBody(withFinding: false, gaps: []));
        Assert.Equal(HttpStatusCode.Conflict, late.StatusCode);
    }

    [Fact]
    public async Task AReclaimedJob_RejectsTheFormerHoldersHeartbeatFailAndResult()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/fenced", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        var (jobId, staleAttempt) = await ClaimWithAttemptAsync(scanner);
        _factory.FrozenClock!.Advance(TimeSpan.FromMinutes(16));
        var (sameJob, liveAttempt) = await ClaimWithAttemptAsync(scanner);
        Assert.Equal(jobId, sameJob);
        Assert.NotEqual(staleAttempt, liveAttempt);

        string leaseBefore = await ScalarAsync<string>(
            "SELECT lease_expires_at FROM oci_scan_jobs WHERE id = @jobId", new { jobId });

        using (var beat = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/{jobId}/heartbeat?attempt={staleAttempt}", new { }))
        {
            Assert.Equal(HttpStatusCode.Conflict, beat.StatusCode);
        }

        using (var fail = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/{jobId}/fail?attempt={staleAttempt}",
            new { reason = "stale holder", retryable = false }))
        {
            Assert.Equal(HttpStatusCode.Conflict, fail.StatusCode);
        }

        using (var result = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{jobId}/result?attempt={staleAttempt}", ResultBody(withFinding: true, gaps: [])))
        {
            Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
        }

        // The live holder's job is untouched: still pending, same lease, nothing stored.
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
        Assert.Equal(leaseBefore, await ScalarAsync<string>(
            "SELECT lease_expires_at FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_image_components", new { }));

        using (var beat = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/{jobId}/heartbeat?attempt={liveAttempt}", new { }))
        {
            Assert.Equal(HttpStatusCode.OK, beat.StatusCode);
        }

        using (var result = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{jobId}/result?attempt={liveAttempt}", ResultBody(withFinding: true, gaps: [])))
        {
            Assert.Equal(HttpStatusCode.NoContent, result.StatusCode);
        }

        Assert.Equal("vulnerable", await StatusAsync("team/fenced", image.ManifestDigest));
    }

    [Theory]
    [InlineData("")]
    [InlineData("?attempt=-1")]
    [InlineData("?attempt=0")]
    public async Task HeartbeatResultAndFail_WithoutAValidAttempt_Are422_AndWriteNothing(string query)
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/unfenced", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        var (jobId, attempt) = await ClaimWithAttemptAsync(scanner);
        string leaseBefore = await ScalarAsync<string>(
            "SELECT lease_expires_at FROM oci_scan_jobs WHERE id = @jobId", new { jobId });
        _factory.FrozenClock!.Advance(TimeSpan.FromMinutes(1));

        using (var beat = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/{jobId}/heartbeat{query}", new { }))
        {
            Assert.Equal(HttpStatusCode.UnprocessableEntity, beat.StatusCode);
            Assert.Contains("attempt", await beat.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        using (var result = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{jobId}/result{query}", ResultBody(withFinding: true, gaps: [])))
        {
            Assert.Equal(HttpStatusCode.UnprocessableEntity, result.StatusCode);
        }

        using (var fail = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{jobId}/fail{query}", new { reason = "no attempt", retryable = false }))
        {
            Assert.Equal(HttpStatusCode.UnprocessableEntity, fail.StatusCode);
        }

        // The lease was not extended, the job not closed or failed, and nothing stored.
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
        Assert.Equal(leaseBefore, await ScalarAsync<string>(
            "SELECT lease_expires_at FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_image_components", new { }));

        // The holder that names its attempt is served as usual.
        using (var ok = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{jobId}/result?attempt={attempt}", ResultBody(withFinding: true, gaps: [])))
        {
            Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);
        }

        Assert.Equal("vulnerable", await StatusAsync("team/unfenced", image.ManifestDigest));
    }

    [Fact]
    public async Task AResultReadUnderASupersededClaim_IsNotStored_WhenTheJobIsReclaimedBeforeTheWrite()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/raced", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        // A result passes the lease and attempt check, and the job is re-claimed before its
        // result is written: the write itself must still refuse the old attempt.
        var (jobId, staleAttempt) = await ClaimWithAttemptAsync(scanner);
        string orgId = await ScalarAsync<string>("SELECT org_id FROM oci_scan_jobs WHERE id = @jobId", new { jobId });
        var jobs = _factory.Services.GetRequiredService<OciScanRepository>();
        var stale = await jobs.GetLeasedAsync(
            orgId, jobId, _factory.FrozenClock!.GetUtcNow().ToUtcIsoMillis(), staleAttempt);
        Assert.NotNull(stale);
        Assert.Equal(staleAttempt, stale.Attempts);

        _factory.FrozenClock.Advance(TimeSpan.FromMinutes(16));
        var (_, liveAttempt) = await ClaimWithAttemptAsync(scanner);
        Assert.NotEqual(staleAttempt, liveAttempt);

        var body = JsonSerializer.Deserialize<OciScanResultRequest>(
            JsonSerializer.Serialize(ResultBody(withFinding: true, gaps: []), WebJson), WebJson)!;
        var status = await _factory.Services.GetRequiredService<OciScanResultWriter>().WriteAsync(stale, body);

        Assert.Equal(OciScanResultOutcome.LeaseLost, status.Outcome);
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @jobId", new { jobId }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_image_components", new { }));
        Assert.NotEqual("vulnerable", await StatusAsync("team/raced", image.ManifestDigest));
    }

    [Fact]
    public async Task ATokenWithoutScanOci_IsForbidden()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        using var claim = await push.PostAsJsonAsync("/api/v1/oci-scan/claim", new { max = 1 });
        Assert.Equal(HttpStatusCode.Forbidden, claim.StatusCode);
    }

    [Fact]
    public async Task WithScanningOff_TheApiIsAbsent_AndNothingIsQueued()
    {
        await using var off = new DependablyFactory();
        await off.InitializeAsync();
        using var push = off.CreateClientWithBearer(await off.CreateToken("push"));
        await PushImageAsync(push, "team/off", "1.0");

        using var scanner = off.CreateClientWithBearer(await off.CreateToken("scanner"));
        using var claim = await scanner.PostAsJsonAsync("/api/v1/oci-scan/claim", new { max = 1 });
        Assert.Equal(HttpStatusCode.NotFound, claim.StatusCode);

        var db = off.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM oci_scan_jobs"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private sealed record PushedImage(
        string ManifestDigest, byte[] Manifest, string ConfigDigest, byte[] Config, string LayerDigest, byte[] Layer);

    private static object ResultBody(bool withFinding, IReadOnlyList<string> gaps) => new
    {
        platforms = new[]
        {
            new
            {
                platform = "linux/amd64",
                scannerVersion = "0.3.0",
                extractionVersion = "1",
                osvSource = "remote",
                gaps,
                entrypointKind = "native",
                closureBounded = true,
                components = new[]
                {
                    new
                    {
                        purl = "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?distro=debian-12&upstream=openssl",
                        ecosystem = "deb",
                        name = "libssl3",
                        version = "3.0.11-1~deb12u1",
                        sourceName = "openssl",
                        sourceVersion = "3.0.11-1~deb12u1",
                        layerIndex = 0,
                        vulns = withFinding
                            ? new[] { new { id = "DSA-5555-1", reachability = "reachable" } }
                            : [],
                    },
                },
            },
        },
        advisories = withFinding ? new[] { JsonDocument.Parse(DsaRecord).RootElement } : [],
    };

    private async Task<string> ClaimAsync(HttpClient scanner, string digest)
        => (await ClaimAllAsync(scanner))[digest];

    // Leases every due job in one claim (the maximum batch), keyed by image digest.
    private async Task<Dictionary<string, string>> ClaimAllAsync(HttpClient scanner)
    {
        using var claim = await scanner.PostAsJsonAsync("/api/v1/oci-scan/claim", new { max = 16 });
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        using var body = JsonDocument.Parse(await claim.Content.ReadAsStringAsync());
        var jobs = body.RootElement.GetProperty("jobs").EnumerateArray().ToList();
        foreach (var job in jobs)
        {
            _attempts[job.GetProperty("id").GetString()!] = job.GetProperty("attempt").GetInt32();
        }

        return jobs.ToDictionary(j => j.GetProperty("digest").GetString()!, j => j.GetProperty("id").GetString()!);
    }

    // A write route of a job ClaimAllAsync leased, fenced with the attempt its claim returned.
    private string WriteRoute(string jobId, string route) =>
        $"/api/v1/oci-scan/{jobId}/{route}?attempt={_attempts[jobId]}";

    private static async Task<(string JobId, int Attempt)> ClaimWithAttemptAsync(HttpClient scanner)
    {
        using var claim = await scanner.PostAsJsonAsync("/api/v1/oci-scan/claim", new { max = 1 });
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        using var body = JsonDocument.Parse(await claim.Content.ReadAsStringAsync());
        var job = Assert.Single(body.RootElement.GetProperty("jobs").EnumerateArray().ToList());
        return (job.GetProperty("id").GetString()!, job.GetProperty("attempt").GetInt32());
    }

    private static async Task<byte[]> ReadAsync(HttpClient scanner, string path)
    {
        using var response = await scanner.GetAsync($"/api/v1/oci-scan/{path}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsByteArrayAsync();
    }

    private async Task<string> StatusAsync(string repository, string digest)
    {
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var response = await admin.GetAsync($"/api/v1/packages/oci/{Uri.EscapeDataString(repository)}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("versions").EnumerateArray()
            .Single(v => v.GetProperty("version").GetString() == digest)
            .GetProperty("status").GetString()!;
    }

    private async Task<int> CountAsync(string sql, object args) => await ScalarAsync<int>(sql, args);

    private async Task<int> DownloadRowsOnceDrainedAsync(string purlPattern)
    {
        const string sql = "SELECT COUNT(*) FROM activity WHERE event_type = 'download' AND purl LIKE @purlPattern";
        // now-ok: polls for a row the background activity writer inserts on its own thread; the
        // deadline bounds a genuine asynchronous completion, not a timed behaviour under test.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        int rows;
        while ((rows = await CountAsync(sql, new { purlPattern })) == 0 && DateTime.UtcNow < deadline)
        {
            // now-ok: the same poll's interval.
            await Task.Delay(50);
        }

        return rows;
    }

    private async Task<T> ScalarAsync<T>(string sql, object args)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return (await conn.ExecuteScalarAsync<T>(sql, args))!;
    }

    private static async Task<PushedImage> PushImageAsync(HttpClient client, string repository, string tag)
    {
        byte[] config = Encoding.UTF8.GetBytes($$"""{"architecture":"amd64","os":"linux","variant":"{{Guid.NewGuid():N}}"}""");
        byte[] layer = RandomNumberGenerator.GetBytes(2048);
        string configDigest = Digest(config);
        string layerDigest = Digest(layer);
        await PushBlobAsync(client, repository, config, configDigest);
        await PushBlobAsync(client, repository, layer, layerDigest);

        byte[] manifest = Encoding.UTF8.GetBytes($$"""
            {
              "schemaVersion": 2,
              "mediaType": "{{ManifestMediaType}}",
              "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "{{configDigest}}", "size": {{config.Length}} },
              "layers": [ { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "{{layerDigest}}", "size": {{layer.Length}} } ]
            }
            """);
        using var put = await PutManifestAsync(client, repository, tag, manifest);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        return new PushedImage(Digest(manifest), manifest, configDigest, config, layerDigest, layer);
    }

    private static async Task PushBlobAsync(HttpClient client, string repository, byte[] bytes, string digest)
    {
        using var post = await client.PostAsync($"/v2/{repository}/blobs/uploads/?digest={digest}", new ByteArrayContent(bytes));
        Assert.Equal(HttpStatusCode.Created, post.StatusCode);
    }

    private static async Task<HttpResponseMessage> PutManifestAsync(HttpClient client, string repository, string reference, byte[] manifest)
    {
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(ManifestMediaType);
        return await client.PutAsync($"/v2/{repository}/manifests/{reference}", content);
    }

    private static string Digest(byte[] bytes) => "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    /// <summary>
    /// The host's advisory source: answers every PURL query with <see cref="PurlAdvisories"/>, and
    /// answers <c>GET /vulns/{id}</c> for the records it was given, or as unreachable while
    /// <see cref="Reachable"/> is false.
    /// </summary>
    private sealed class SwitchableOsvSource : Dependably.Protocol.IOsvSource
    {
        private readonly Dictionary<string, Dependably.Protocol.OsvAdvisory> _records;
        private volatile bool _reachable = true;

        public SwitchableOsvSource(params string[] records) =>
            _records = records
                .Select(r => Dependably.Protocol.OsvRecordParser.TryParse(JsonDocument.Parse(r).RootElement)!)
                .ToDictionary(a => a.Id, StringComparer.Ordinal);

        public bool Reachable
        {
            get => _reachable;
            set => _reachable = value;
        }

        public List<Dependably.Protocol.OsvAdvisory> PurlAdvisories { get; set; } = [];

        public Task<List<Dependably.Protocol.OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default) =>
            Task.FromResult(PurlAdvisories.ToList());

        public Task<List<List<Dependably.Protocol.OsvAdvisory>>> QueryBatchAsync(
            IReadOnlyList<string> purls, CancellationToken ct = default) =>
            Task.FromResult(purls.Select(_ => PurlAdvisories.ToList()).ToList());

        public Task<Dependably.Protocol.OsvIdLookupResult> TryGetAdvisoryAsync(string id, CancellationToken ct = default) =>
            Task.FromResult(Reachable
                ? new Dependably.Protocol.OsvIdLookupResult(_records.GetValueOrDefault(id), Reached: true)
                : new Dependably.Protocol.OsvIdLookupResult(null, Reached: false));
    }
}

/// <summary>With the image scanner switched off, an OCI version reports no feed rather than unscanned.</summary>
[Trait("Category", "Integration")]
public sealed class OciScanDisabledVersionProjectionTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new() { FrozenClock = TestTime.Frozen() };

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task AnImage_ReportsNoFeed_WhenTheScannerIsOff()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        byte[] config = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        string configDigest = "sha256:" + Convert.ToHexString(SHA256.HashData(config)).ToLowerInvariant();
        using (var blob = await push.PostAsync($"/v2/team/off/blobs/uploads/?digest={configDigest}", new ByteArrayContent(config)))
        {
            Assert.Equal(HttpStatusCode.Created, blob.StatusCode);
        }
        byte[] manifest = Encoding.UTF8.GetBytes($$"""
            {
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "{{configDigest}}", "size": {{config.Length}} },
              "layers": []
            }
            """);
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json");
        using (var put = await push.PutAsync("/v2/team/off/manifests/1.0", content))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var response = await admin.GetAsync("/api/v1/packages/oci/team%2Foff");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var version = Assert.Single(body.RootElement.GetProperty("versions").EnumerateArray().ToList());
        Assert.Equal("no_feed", version.GetProperty("status").GetString());
        Assert.Equal("no_feed", version.GetProperty("ociScan").GetProperty("state").GetString());
    }
}
