using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The OCI pull gate over the org's own image scan results, end to end over <c>/v2/</c> against a
/// hermetic upstream: every manifest-returning serve site with the posture <c>off</c> (served as
/// before), and at <c>block</c> (an advisory finding and a missing scan both refused, the same way
/// on every site); each advisory arm with its <c>off</c> twin; the first-pull and HEAD-first flows
/// that must enqueue the scan their own refusal is waiting on; partial results; arm-scoped
/// approval; a fact-read failure; and a platform manifest inheriting its index's verdict.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciScanPullGateTests : IAsyncLifetime
{
    private const string Repo = "library/gated-app";

    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private const string OtherRepo = "library/other-app";

    private readonly FakeOciRegistry _upstream = new(Repo);
    private readonly FakeOciRegistry _other = new(OtherRepo);
    private DependablyFactory _factory = null!;

    public async Task InitializeAsync()
    {
        _factory = new DependablyFactory
        {
            FrozenClock = _clock,
            OciUpstreamHandler = req =>
                req.RequestUri!.AbsolutePath.StartsWith($"/v2/{OtherRepo}/", StringComparison.Ordinal)
                    ? _other.Respond(req)
                    : _upstream.Respond(req),
            ExtraSettings = new Dictionary<string, string?>
            {
                ["OCI_SCAN_ENABLED"] = "true",
                // The tests drive any sweep themselves (see OciScanApiTests for the schedule).
                ["OCI_SCAN_SWEEP_SCHEDULE"] = "0 0 31 2 *",
            },
        };
        await _factory.InitializeAsync();
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── Serve-site matrix ───────────────────────────────────────────────────────

    public static TheoryData<string> Sites => new()
    {
        "local-get", "local-head", "upstream-get", "upstream-head", "stale-tag", "blob-local", "blob-upstream",
        // Docker distribution labels a manifest read through the blob route application/octet-stream.
        "blob-upstream-octet", "blob-local-octet",
        // Nothing stops an upstream labelling a manifest as a layer; the label is not trusted.
        "blob-upstream-layerlabel", "blob-local-layerlabel",
    };

    /// <summary>
    /// With the posture off, an image carrying a KEV finding the org's other ecosystems would
    /// block on is served exactly as before on every site: 200, the manifest's bytes, no refusal
    /// header, and no refusal recorded.
    /// </summary>
    [Theory]
    [MemberData(nameof(Sites))]
    public async Task OffPosture_ServesEverySite_AsBefore(string site)
    {
        await SetPolicyAsync(new { ociScanEnforcement = "off", blockKev = "block" });
        var image = _upstream.AddImage($"off-{site}");
        _upstream.Tag("v1", image.Digest);
        await SeedKevResultAsync(image.Digest);

        using var response = await HitSiteAsync(site, image);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("X-Dependably-Block-Reason"));
        if (response.RequestMessage!.Method == HttpMethod.Get)
        {
            Assert.Equal(image.Manifest, await response.Content.ReadAsByteArrayAsync());
        }

        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM activity WHERE event_type LIKE 'blocked_%' AND org_id = @orgId", new { orgId = await OrgIdAsync() }));
    }

    /// <summary>
    /// The same KEV finding, the posture at block: refused as <c>kev</c> on every site, so a cache
    /// hit, an upstream miss, a stale serve, a HEAD and a blob-route read cannot disagree.
    /// </summary>
    [Theory]
    [MemberData(nameof(Sites))]
    public async Task BlockPosture_RefusesAKevFinding_OnEverySite(string site)
    {
        await SetPolicyAsync(new { ociScanEnforcement = "off", blockKev = "block" });
        var image = _upstream.AddImage($"kev-{site}");
        _upstream.Tag("v1", image.Digest);
        await SeedKevResultAsync(image.Digest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });

        using var response = await HitSiteAsync(site, image, primeUnderOff: true);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("kev", response.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    /// <summary>An image the org holds no result for is refused as unscanned on every site.</summary>
    [Theory]
    [MemberData(nameof(Sites))]
    public async Task BlockPosture_RefusesAnUnscannedImage_OnEverySite(string site)
    {
        var image = _upstream.AddImage($"unscanned-{site}");
        _upstream.Tag("v1", image.Digest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });

        using var response = await HitSiteAsync(site, image, primeUnderOff: true);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("unscanned", response.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    /// <summary>
    /// The adversarial twin of the octet-stream blob sites: under block, an image's config and
    /// layer blobs, labelled application/octet-stream as Docker distribution labels them, are still
    /// served. Only bytes that are a manifest are gated.
    /// </summary>
    [Fact]
    public async Task BlockPosture_StillServesLayersAndConfigs_LabelledOctetStream()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        var image = _upstream.AddImage("layers-octet");
        _upstream.ServeManifestsAsBlobs = true;
        _upstream.BlobRouteManifestType = "application/octet-stream";
        using var client = await PullClientAsync();

        foreach (string digest in new[] { image.ConfigDigest, image.LayerDigest })
        {
            using (var miss = await client.GetAsync($"/v2/{Repo}/blobs/{digest}"))
            {
                Assert.Equal(HttpStatusCode.OK, miss.StatusCode);
            }

            using var hit = await client.GetAsync($"/v2/{Repo}/blobs/{digest}");
            Assert.Equal(HttpStatusCode.OK, hit.StatusCode);
        }

        // And the image's manifest on the same route is refused, its stored type corrected.
        using (var manifest = await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, manifest.StatusCode);
        }

        Assert.Equal(FakeOciRegistry.ImageManifestType, await ScalarAsync<string>(
            "SELECT media_type FROM oci_blobs WHERE digest = @digest", new { digest = image.Digest }));
    }

    /// <summary>
    /// An index fetched through the blob route under a generic type is refused too, and so is its
    /// platform manifest once the index is held: a child of an index the org holds is a manifest.
    /// </summary>
    [Fact]
    public async Task BlockPosture_RefusesAnIndexAndItsChild_ReadAsOctetStreamBlobs()
    {
        var amd64 = _upstream.AddImage("octet-idx-amd64");
        var arm64 = _upstream.AddImage("octet-idx-arm64");
        var (indexDigest, _) = _upstream.AddIndex(amd64, arm64);
        _upstream.Tag("multi", indexDigest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        _upstream.ServeManifestsAsBlobs = true;
        _upstream.BlobRouteManifestType = "application/octet-stream";
        using var client = await PullClientAsync();

        using (var index = await client.GetAsync($"/v2/{Repo}/blobs/{indexDigest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, index.StatusCode);
        }

        using (var byTag = await client.GetAsync($"/v2/{Repo}/manifests/multi"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, byTag.StatusCode);
        }

        using var child = await client.GetAsync($"/v2/{Repo}/blobs/{arm64.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, child.StatusCode);
    }

    // ── Each arm, with its posture-off twin ─────────────────────────────────────

    public static TheoryData<string, string, string, string> Arms => new()
    {
        // arm token, advisory id, the advisory's column update, the org policy that enforces it
        { "malicious", "MAL-2026-0001", "UPDATE vulnerabilities SET is_kev = 0 WHERE osv_id = @osvId", """{"blockMalicious":"block"}""" },
        { "kev", "DSA-KEV-1", "UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = @osvId", """{"blockKev":"block"}""" },
        { "kev_ransomware", "DSA-RW-1", "UPDATE vulnerabilities SET is_kev = 1, kev_known_ransomware = 1 WHERE osv_id = @osvId", """{"blockKevRansomware":"block","blockKev":"off"}""" },
        { "ssvc_exploitation", "DSA-SSVC-1", "UPDATE vulnerabilities SET ssvc_exploitation = 'active', ssvc_checked_at = '2026-06-15T12:00:00Z' WHERE osv_id = @osvId", """{"blockSsvcExploitation":"block"}""" },
        { "epss", "DSA-EPSS-1", "UPDATE vulnerabilities SET epss_score = 0.9 WHERE osv_id = @osvId", """{"maxEpssTolerance":0.5}""" },
        { "epss_percentile", "DSA-PCT-1", "UPDATE vulnerabilities SET epss_percentile = 0.99 WHERE osv_id = @osvId", """{"maxEpssPercentileTolerance":0.5}""" },
        { "vuln_score", "DSA-CVSS-1", "UPDATE vulnerabilities SET cvss_score = 9.8 WHERE osv_id = @osvId", """{"maxOsvScoreTolerance":7.0}""" },
        // The NVD fallback: no OSV score at all, an NVD score over the ceiling.
        { "vuln_score", "DSA-NVD-1", "UPDATE vulnerabilities SET cvss_score = NULL, nvd_score = 9.8, nvd_checked_at = '2026-06-15T12:00:00Z' WHERE osv_id = @osvId", """{"maxOsvScoreTolerance":7.0}""" },
    };

    [Theory]
    [MemberData(nameof(Arms))]
    public async Task EachArm_RefusesUnderBlock_AndItsOffTwinServes(string arm, string osvId, string update, string policyJson)
    {
        var image = _upstream.AddImage($"arm-{arm}-{osvId}");
        _upstream.Tag("v1", image.Digest);
        using (var prime = await PullClientAsync())
        {
            await SetPolicyAsync(new { ociScanEnforcement = "off" });
            using var first = await prime.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        string owner = await CatalogueAsync(image.Digest);
        await OciScanSeeder.ResultAsync(Store(), await OrgIdAsync(), OciScanOwner.Proxied(owner), "linux/amd64", [],
            [new SeedComponent("libfoo", 0, [new SeedFinding(osvId, CvssScore: null)])]);
        await ExecAsync(update, new { osvId });
        await PutPolicyJsonAsync(policyJson);

        using var client = await PullClientAsync();

        // Twin first: the arm's own mode is set, but the OCI posture is off — served.
        await SetPolicyAsync(new { ociScanEnforcement = "off" });
        using (var off = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, off.StatusCode);
        }

        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var blocked = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Equal(arm, blocked.Headers.GetValues("X-Dependably-Block-Reason").Single());
        Assert.True(await ActivityLandsAsync("blocked_" + arm), $"no blocked_{arm} activity row");
    }

    // ── First pull and HEAD-first ───────────────────────────────────────────────

    [Fact]
    public async Task AFirstPull_IsRefusedAsUnscanned_ButCataloguedAndQueued_AndARetryAfterTheScanIsServed()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        var image = _upstream.AddImage("first-pull");
        _upstream.Tag("v1", image.Digest);
        using var client = await PullClientAsync();

        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
            Assert.Equal("unscanned", first.Headers.GetValues("X-Dependably-Block-Reason").Single());
            // A token-holding caller is told the image is queued for scanning.
            Assert.Contains("queued for scanning", await first.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest", new { digest = image.Digest }));

        await ScanCleanAsync(image.Digest);

        using var retry = await client.GetAsync($"/v2/{Repo}/manifests/v1");
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(image.Manifest, await retry.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task AHeadFirstClient_IsQueuedByTheHeadItself_AndServedOnceTheScanLands()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        var image = _upstream.AddImage("head-first");
        _upstream.Tag("v1", image.Digest);
        using var client = await PullClientAsync();

        using (var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/v1")))
        {
            Assert.Equal(HttpStatusCode.Forbidden, head.StatusCode);
            Assert.Equal("unscanned", head.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        // The HEAD itself queued the image: no GET has been issued.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest", new { digest = image.Digest }));

        await ScanCleanAsync(image.Digest);

        using (var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/v1")))
        {
            Assert.Equal(HttpStatusCode.OK, head.StatusCode);
            Assert.Equal(image.Digest, head.Headers.GetValues("Docker-Content-Digest").Single());
        }

        using var byDigest = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");
        Assert.Equal(HttpStatusCode.OK, byDigest.StatusCode);
        Assert.Equal(image.Manifest, await byDigest.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task AHeadMiss_UnderOff_StaysHeadersOnly()
    {
        // Twin of the HEAD-first enqueue: with the posture off a HEAD acquires and queues nothing.
        await SetPolicyAsync(new { ociScanEnforcement = "off" });
        var image = _upstream.AddImage("head-off");
        _upstream.Tag("v1", image.Digest);
        using var client = await PullClientAsync();

        using var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/v1"));

        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest", new { digest = image.Digest }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest", new { digest = image.Digest }));
    }

    // ── Partial results and arm-scoped approval ─────────────────────────────────

    [Fact]
    public async Task APartialResult_IsRefusedAsUnscanned_AnApprovalServesIt_AndALaterKevRefusesAndReopens()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block", blockKev = "block" });
        var image = _upstream.AddImage("partial");
        _upstream.Tag("v1", image.Digest);
        using var client = await PullClientAsync();
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
        }

        string orgId = await OrgIdAsync();
        string owner = await CatalogueAsync(image.Digest);
        await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Proxied(owner), "linux/amd64",
            ["rpm packages: no OSV ecosystem for rhel 9"], [new SeedComponent("bash", 0, [])]);

        using (var partial = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, partial.StatusCode);
            Assert.Equal("unscanned", partial.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        Assert.True(await ActivityLandsAsync("blocked_unscanned", "\"sub_reason\":\"partial\""));

        // Approve past the missing scan through the review queue.
        string rowId = await ScalarAsync<string>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND gate = 'unscanned' AND state = 'pending'", new { orgId });
        using (var admin = await AdminClientAsync())
        using (var decide = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowId}/decide", new { decision = "approved" }))
        {
            Assert.Equal(HttpStatusCode.OK, decide.StatusCode);
        }

        // The approval sets no manual allow: that override would waive every later finding.
        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = @orgId AND manual_block_state IS NOT NULL", new { orgId }));

        using (var approved = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        }

        // A KEV finding then lands on the same digest.
        await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Proxied(owner), "linux/arm64", [],
            [new SeedComponent("openssl", 0, [new SeedFinding("DSA-LATE-KEV")])]);
        await ExecAsync("UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = 'DSA-LATE-KEV'", new { });

        using (var kev = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, kev.StatusCode);
            Assert.Equal("kev", kev.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        var (gate, state) = await QuerySingleAsync<(string Gate, string State)>(
            "SELECT gate AS Gate, state AS State FROM quarantine WHERE id = @rowId", new { rowId });
        Assert.Equal("kev", gate);
        Assert.Equal("pending", state);
    }

    [Fact]
    public async Task ApprovingAnAdvisoryRefusal_SetsTheManualAllow_UnlikeAnUnscannedApproval()
    {
        // Twin of the unscanned approval: an approval past any other arm is the ordinary review
        // decision, which sets the manual allow override on the org's own catalogue row.
        await SetPolicyAsync(new { ociScanEnforcement = "block", blockKev = "block" });
        var image = _upstream.AddImage("approve-kev");
        _upstream.Tag("v1", image.Digest);
        await SeedKevResultAsync(image.Digest);
        using var client = await PullClientAsync();
        using (var refused = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        }

        string orgId = await OrgIdAsync();
        string rowId = await ScalarAsync<string>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND gate = 'kev' AND state = 'pending'", new { orgId });
        using (var admin = await AdminClientAsync())
        using (var decide = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowId}/decide", new { decision = "approved" }))
        {
            Assert.Equal(HttpStatusCode.OK, decide.StatusCode);
        }

        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = @orgId AND manual_block_state = 'allowed'", new { orgId }));
        using var served = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
    }

    [Fact]
    public async Task AnExplicitManualAllow_StillShortCircuitsEveryArm()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block", blockKev = "block" });
        var image = _upstream.AddImage("manual-allow");
        _upstream.Tag("v1", image.Digest);
        await SeedKevResultAsync(image.Digest);
        await ExecAsync(
            "UPDATE tenant_artifact_access SET manual_block_state = 'allowed' WHERE org_id = @orgId",
            new { orgId = await OrgIdAsync() });
        using var client = await PullClientAsync();

        using var response = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ── Warn posture ───────────────────────────────────────────────────────────

    [Fact]
    public async Task WarnPosture_ServesAnUnscannedImage_AndRecordsTheArmBlockWouldHaveUsed()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "warn" });
        var image = _upstream.AddImage("warn");
        _upstream.Tag("v1", image.Digest);
        using var client = await PullClientAsync();

        using var response = await client.GetAsync($"/v2/{Repo}/manifests/v1");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await ActivityLandsAsync("gate_warned", "\"arm\":\"unscanned\""));
    }

    [Fact]
    public async Task WarnPosture_PartialScanWithAKev_NamesUnscanned_AndKeepsTheKevInWarnedArms()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "warn", blockKev = "warn" });
        var image = _upstream.AddImage("warn-partial-kev");
        _upstream.Tag("v1", image.Digest);
        string orgId = await OrgIdAsync();
        string owner = await CatalogueAsync(image.Digest);
        await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Proxied(owner), "linux/amd64",
            ["rpm packages: no OSV ecosystem for rhel 9"],
            [new SeedComponent("openssl", 0, [new SeedFinding("DSA-WARN-KEV")])]);
        await ExecAsync("UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = 'DSA-WARN-KEV'", new { });
        using var client = await PullClientAsync();

        using var response = await client.GetAsync($"/v2/{Repo}/manifests/v1");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await ActivityLandsAsync("gate_warned", "\"arm\":\"unscanned\""));
        Assert.True(await ActivityLandsAsync("gate_warned", "\"sub_reason\":\"partial\""));
        Assert.True(await ActivityLandsAsync("gate_warned", "\"warned_arms\":[\"kev\"]"));
    }

    // ── Deny then approve an unscanned refusal ──────────────────────────────────

    [Fact]
    public async Task ApprovingAnUnscannedRefusal_AfterADeny_LiftsTheManualBlock_WithoutSettingAnAllow()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        var image = _upstream.AddImage("deny-then-approve");
        _upstream.Tag("v1", image.Digest);
        using var client = await PullClientAsync();
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
        }

        string orgId = await OrgIdAsync();
        string rowId = await ScalarAsync<string>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND gate = 'unscanned' AND state = 'pending'", new { orgId });
        using var admin = await AdminClientAsync();
        using (var deny = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowId}/decide", new { decision = "denied" }))
        {
            Assert.Equal(HttpStatusCode.OK, deny.StatusCode);
        }

        using (var denied = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            Assert.Equal("manual", denied.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        using (var approve = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowId}/decide", new { decision = "approved" }))
        {
            Assert.Equal(HttpStatusCode.OK, approve.StatusCode);
        }

        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = @orgId AND manual_block_state IS NOT NULL", new { orgId }));
        using var served = await client.GetAsync($"/v2/{Repo}/manifests/v1");
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
    }

    // ── Hosted images ───────────────────────────────────────────────────────────

    [Fact]
    public async Task AHostedImage_RefusedOnAKev_IsApprovedThroughQuarantine_AndAnotherImageStaysRefused()
    {
        const string HostedRepo = "team/hosted-gated";
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        string digestA = await PushImageAsync(client, HostedRepo, "a");
        string digestB = await PushImageAsync(client, HostedRepo, "b");
        string orgId = await OrgIdAsync();
        foreach (string digest in new[] { digestA, digestB })
        {
            string versionId = await HostedVersionIdAsync(orgId, HostedRepo, digest);
            string osvId = "DSA-HOSTED-" + digest[7..15];
            await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Hosted(versionId), "linux/amd64", [],
                [new SeedComponent("openssl", 0, [new SeedFinding(osvId)])]);
            await ExecAsync("UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = @osvId", new { osvId });
        }

        await SetPolicyAsync(new { ociScanEnforcement = "block", blockKev = "block" });
        foreach (string digest in new[] { digestA, digestB })
        {
            using var refused = await client.GetAsync($"/v2/{HostedRepo}/manifests/{digest}");
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("kev", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        string versionA = await HostedVersionIdAsync(orgId, HostedRepo, digestA);
        string rowA = await ScalarAsync<string>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND gate = 'kev' AND package_version_id = @versionA AND state = 'pending'",
            new { orgId, versionA });
        using (var admin = await AdminClientAsync())
        using (var decide = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowA}/decide", new { decision = "approved" }))
        {
            Assert.Equal(HttpStatusCode.OK, decide.StatusCode);
        }

        using (var served = await client.GetAsync($"/v2/{HostedRepo}/manifests/{digestA}"))
        {
            Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        }

        using var stillRefused = await client.GetAsync($"/v2/{HostedRepo}/manifests/{digestB}");
        Assert.Equal(HttpStatusCode.Forbidden, stillRefused.StatusCode);
        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM package_versions WHERE manual_block_state = 'allowed'", new { }));
    }

    private async Task<string> HostedVersionIdAsync(string orgId, string repository, string digest) =>
        await ScalarAsync<string>(
            """
            SELECT pv.id FROM package_versions pv JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'oci' AND p.purl_name = @repository AND pv.version = @digest
            """,
            new { orgId, repository, digest });

    // ── Review-queue and approval scope ─────────────────────────────────────────

    /// <summary>
    /// An owner catalogued while the posture was off has no queue row. When the posture later
    /// blocks, the refusal queues every owner that lacks an approval, so each can be approved and
    /// the approval-must-cover-every-owner rule is satisfiable.
    /// </summary>
    [Fact]
    public async Task ARefusal_QueuesEveryOwnerLackingAnApproval_SoAllOwnersCanBeApproved()
    {
        var shared = _upstream.AddImage("q-shared");
        var armA = _upstream.AddImage("q-arm-a");
        var armB = _upstream.AddImage("q-arm-b");
        var (indexA, _) = _upstream.AddIndex(shared, armA);
        var (indexB, _) = _upstream.AddIndex(shared, armB);
        _upstream.Tag("a", indexA);
        _upstream.Tag("b", indexB);
        await SetPolicyAsync(new { ociScanEnforcement = "off" });
        using var client = await PullClientAsync();
        foreach (string tag in new[] { "a", "b" })
        {
            using var pulled = await client.GetAsync($"/v2/{Repo}/manifests/{tag}");
            Assert.Equal(HttpStatusCode.OK, pulled.StatusCode);
        }

        string orgId = await OrgIdAsync();
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM quarantine WHERE org_id = @orgId", new { orgId }));

        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using (var refused = await client.GetAsync($"/v2/{Repo}/manifests/{shared.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("unscanned", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        foreach (string index in new[] { indexA, indexB })
        {
            Assert.Equal(1, await CountAsync(
                "SELECT COUNT(*) FROM quarantine WHERE org_id = @orgId AND gate = 'unscanned' AND state = 'pending' AND purl LIKE @pattern",
                new { orgId, pattern = "%" + index.Replace(":", "%3A") + "%" }));
        }

        await ApproveUnscannedAsync(indexA);
        await ApproveUnscannedAsync(indexB);
        using var served = await client.GetAsync($"/v2/{Repo}/manifests/{shared.Digest}");
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
    }

    /// <summary>
    /// An unscanned approval waives only the unscanned arm: an advisory arm in warn mode that
    /// fired on the partial result is still reported under block, as it is under warn.
    /// </summary>
    [Fact]
    public async Task BlockPosture_AnApprovedPartialScan_StillWarnsOnAnAdvisoryArmInWarnMode()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block", blockKev = "warn" });
        var image = _upstream.AddImage("block-approved-kev-warn");
        _upstream.Tag("v1", image.Digest);
        using var client = await PullClientAsync();
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
        }

        string orgId = await OrgIdAsync();
        string owner = await CatalogueAsync(image.Digest);
        await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Proxied(owner), "linux/amd64",
            ["rpm packages: no OSV ecosystem for rhel 9"],
            [new SeedComponent("openssl", 0, [new SeedFinding("DSA-BLOCK-WARN-KEV")])]);
        await ExecAsync("UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = 'DSA-BLOCK-WARN-KEV'", new { });
        using (var partial = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, partial.StatusCode);
            Assert.Equal("unscanned", partial.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        await ApproveUnscannedAsync(image.Digest);

        using var served = await client.GetAsync($"/v2/{Repo}/manifests/v1");
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.True(await ActivityLandsAsync("gate_warned", "\"arm\":\"kev\""));
    }

    /// <summary>
    /// Approving an unscanned refusal lifts the manual block only when that deny set it. A block an
    /// operator placed through the version block endpoint after the deny persists.
    /// </summary>
    [Fact]
    public async Task ApprovingAnUnscannedRefusal_KeepsAManualBlockTheDenyDidNotSet()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        var image = _upstream.AddImage("c1-after-deny");
        _upstream.Tag("v1", image.Digest);
        using var client = await PullClientAsync();
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
        }

        string orgId = await OrgIdAsync();
        string rowId = await ScalarAsync<string>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND gate = 'unscanned' AND state = 'pending'", new { orgId });
        using var admin = await AdminClientAsync();
        using (var deny = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowId}/decide", new { decision = "denied" }))
        {
            Assert.Equal(HttpStatusCode.OK, deny.StatusCode);
        }

        using (var block = await admin.PostAsync(
            $"/api/v1/packages/oci/{Uri.EscapeDataString(Repo)}/{Uri.EscapeDataString(image.Digest)}/block", null))
        {
            Assert.Equal(HttpStatusCode.OK, block.StatusCode);
        }

        using (var approve = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowId}/decide", new { decision = "approved" }))
        {
            Assert.Equal(HttpStatusCode.OK, approve.StatusCode);
        }

        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = @orgId AND manual_block_state = 'blocked'", new { orgId }));
        using var stillBlocked = await client.GetAsync($"/v2/{Repo}/manifests/v1");
        Assert.Equal(HttpStatusCode.Forbidden, stillBlocked.StatusCode);
        Assert.Equal("manual", stillBlocked.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    // The block endpoint resolves the pending row itself (hosted rows match by version id), so a
    // later approval of that row must not lift the operator's block.
    [Fact]
    public async Task ApprovingAnUnscannedRefusal_KeepsAHostedBlockTheBlockEndpointSet()
    {
        const string HostedRepo = "team/hosted-c1";
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        string digest = await PushImageAsync(client, HostedRepo, "c1");
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using (var refused = await client.GetAsync($"/v2/{HostedRepo}/manifests/{digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        }

        string orgId = await OrgIdAsync();
        string rowId = await ScalarAsync<string>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND gate = 'unscanned' AND state = 'pending'", new { orgId });
        using var admin = await AdminClientAsync();
        using (var block = await admin.PostAsync(
            $"/api/v1/packages/oci/{Uri.EscapeDataString(HostedRepo)}/{Uri.EscapeDataString(digest)}/block", null))
        {
            Assert.Equal(HttpStatusCode.OK, block.StatusCode);
        }

        Assert.Equal("denied", await ScalarAsync<string>("SELECT state FROM quarantine WHERE id = @rowId", new { rowId }));
        using (var approve = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowId}/decide", new { decision = "approved" }))
        {
            Assert.Equal(HttpStatusCode.OK, approve.StatusCode);
        }

        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM package_versions WHERE manual_block_state = 'blocked'", new { }));
    }

    // Pushes a one-layer image (the suffix makes its layer, and so its manifest digest, unique)
    // and returns the manifest digest.
    private static async Task<string> PushImageAsync(HttpClient client, string repository, string suffix)
    {
        static string Sha(byte[] b) => "sha256:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(b)).ToLowerInvariant();
        async Task PushBlobAsync(byte[] bytes)
        {
            using var resp = await client.PostAsync(
                $"/v2/{repository}/blobs/uploads/?digest={Sha(bytes)}", new ByteArrayContent(bytes));
            Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        }

        byte[] config = System.Text.Encoding.UTF8.GetBytes($$"""{"architecture":"amd64","os":"linux","x":"{{suffix}}"}""");
        byte[] layer = System.Text.Encoding.UTF8.GetBytes("layer-" + suffix + new string('x', 256));
        await PushBlobAsync(config);
        await PushBlobAsync(layer);
        const string MediaType = "application/vnd.oci.image.manifest.v1+json";
        byte[] manifest = System.Text.Encoding.UTF8.GetBytes($$"""
            {"schemaVersion":2,"mediaType":"{{MediaType}}",
             "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{{Sha(config)}}","size":{{config.Length}}},
             "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{{Sha(layer)}}","size":{{layer.Length}}}]}
            """);
        using var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(MediaType);
        using var put = await client.PutAsync($"/v2/{repository}/manifests/{suffix}", content);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        return Sha(manifest);
    }

    // ── Posture header ─────────────────────────────────────────────────────────

    public static TheoryData<string, string> PostureHeaderCases()
    {
        var data = new TheoryData<string, string>();
        foreach (string site in new[] { "local-get", "local-head", "upstream-get", "upstream-head" })
        {
            foreach (string posture in new[] { "warn", "block", "off" })
            {
                data.Add(posture, site);
            }
        }

        return data;
    }

    /// <summary>
    /// A master states the org's posture on every manifest response, off included: an edge learns
    /// from it whether it may answer from its own cache, and reads a response without it as saying
    /// nothing about the org.
    /// </summary>
    [Theory]
    [MemberData(nameof(PostureHeaderCases))]
    public async Task ManifestResponse_StatesThePosture_AtEveryPosture(string posture, string site)
    {
        await SetPolicyAsync(new { ociScanEnforcement = "off" });
        var image = _upstream.AddImage($"hdr-{posture}-{site}");
        _upstream.Tag("v1", image.Digest);
        await SetPolicyAsync(new { ociScanEnforcement = posture });

        using var response = await HitSiteAsync(site, image, primeUnderOff: true);

        bool present = response.Headers.TryGetValues(
            Dependably.Infrastructure.Edge.EdgeOciScanPostureStore.Header, out var values);
        Assert.True(present, $"{site} at {posture} carried no posture header (status {(int)response.StatusCode}).");
        Assert.Equal(posture, values!.Single());
    }

    /// <summary>
    /// The posture is stated to an anonymous caller too: an edge whose master token stops resolving
    /// while anonymous pull is on is answered anonymously, and must still learn that a gated org is
    /// gated rather than read the silence as off.
    /// </summary>
    [Theory]
    [InlineData("block")]
    [InlineData("warn")]
    [InlineData("off")]
    public async Task ManifestResponse_StatesThePosture_ToAnAnonymousCaller(string posture)
    {
        await SetPolicyAsync(new { ociScanEnforcement = "off" });
        var image = _upstream.AddImage($"anon-hdr-{posture}");
        using (var prime = await PullClientAsync())
        {
            using var primed = await prime.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");
            Assert.Equal(HttpStatusCode.OK, primed.StatusCode);
        }

        using (var admin = await AdminClientAsync())
        {
            (await admin.PutAsJsonAsync("/api/v1/settings", new { anonymousPull = true })).EnsureSuccessStatusCode();
        }

        await SetPolicyAsync(new { ociScanEnforcement = posture });
        using var anonymous = _factory.CreateClient();

        foreach (var method in new[] { HttpMethod.Get, HttpMethod.Head })
        {
            using var response = await anonymous.SendAsync(new HttpRequestMessage(method, $"/v2/{Repo}/manifests/{image.Digest}"));

            Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.True(
                response.Headers.TryGetValues(Dependably.Infrastructure.Edge.EdgeOciScanPostureStore.Header, out var values),
                $"anonymous {method} at {posture} carried no posture header (status {(int)response.StatusCode}).");
            Assert.Equal(posture, values!.Single());
        }
    }

    // ── Fact-read failure ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("block", HttpStatusCode.Forbidden)]
    [InlineData("warn", HttpStatusCode.OK)]
    public async Task AFactReadFailure_RefusesUnderBlock_AndServesUnderWarn(string posture, HttpStatusCode expected)
    {
        var image = _upstream.AddImage($"read-failure-{posture}");
        _upstream.Tag("v1", image.Digest);
        await SeedKevResultAsync(image.Digest);
        await SetPolicyAsync(new { ociScanEnforcement = posture });

        // Take the org's scan coverage table away, so the facts read throws.
        await ExecAsync("ALTER TABLE oci_scan_coverage RENAME TO oci_scan_coverage_gone", new { });
        try
        {
            using var client = await PullClientAsync();
            using var response = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");
            Assert.Equal(expected, response.StatusCode);
        }
        finally
        {
            await ExecAsync("ALTER TABLE oci_scan_coverage_gone RENAME TO oci_scan_coverage", new { });
        }
    }

    // ── Platform manifests through the reference graph ──────────────────────────

    [Fact]
    public async Task APlatformManifest_GetsItsIndexsVerdict_BeforeAndAfterTheScan()
    {
        var amd64 = _upstream.AddImage("idx-amd64");
        var arm64 = _upstream.AddImage("idx-arm64");
        var (indexDigest, _) = _upstream.AddIndex(amd64, arm64);
        _upstream.Tag("multi", indexDigest);
        await SetPolicyAsync(new { ociScanEnforcement = "block", blockKev = "block" });
        using var client = await PullClientAsync();

        // The index pull is refused (unscanned) but catalogues it and records its children.
        using (var index = await client.GetAsync($"/v2/{Repo}/manifests/multi"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, index.StatusCode);
        }

        // Before any scan, the child resolves to the index and is refused the same way; it is not
        // catalogued as an image of its own.
        using (var child = await client.GetAsync($"/v2/{Repo}/manifests/{amd64.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, child.StatusCode);
            Assert.Equal("unscanned", child.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci' AND version = @digest", new { digest = amd64.Digest }));

        string owner = await CatalogueAsync(indexDigest);
        await OciScanSeeder.ResultAsync(Store(), await OrgIdAsync(), OciScanOwner.Proxied(owner), "linux/amd64", [],
            [new SeedComponent("zlib", 0, [])]);

        using (var child = await client.GetAsync($"/v2/{Repo}/manifests/{amd64.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, child.StatusCode);
        }

        // A KEV on the index refuses its platforms too.
        await OciScanSeeder.ResultAsync(Store(), await OrgIdAsync(), OciScanOwner.Proxied(owner), "linux/arm64", [],
            [new SeedComponent("openssl", 0, [new SeedFinding("DSA-IDX-KEV")])]);
        await ExecAsync("UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = 'DSA-IDX-KEV'", new { });

        using var refused = await client.GetAsync($"/v2/{Repo}/manifests/{arm64.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal("kev", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    /// <summary>
    /// The result writer records which manifest each scanned platform is, from the stored index,
    /// so a platform the scanner skipped reads as unscanned while the scanned one is served.
    /// </summary>
    [Fact]
    public async Task APlatformTheScannerSkipped_IsUnscanned_WhileTheScannedOneIsServed()
    {
        var amd64 = _upstream.AddImage("skip-amd64");
        var arm64 = _upstream.AddImage("skip-arm64");
        var (indexDigest, _) = _upstream.AddIndex(amd64, arm64);
        _upstream.Tag("multi", indexDigest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var client = await PullClientAsync();
        using (var index = await client.GetAsync($"/v2/{Repo}/manifests/multi"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, index.StatusCode);
        }

        // The scanner covers linux/amd64 only.
        await ScanCleanAsync(indexDigest);
        Assert.Equal(amd64.Digest, await ScalarAsync<string?>(
            "SELECT manifest_digest FROM oci_scan_coverage WHERE platform = 'linux/amd64'", new { }));

        using (var scanned = await client.GetAsync($"/v2/{Repo}/manifests/{amd64.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, scanned.StatusCode);
        }

        using var skipped = await client.GetAsync($"/v2/{Repo}/manifests/{arm64.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, skipped.StatusCode);
        Assert.Equal("unscanned", skipped.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    /// <summary>
    /// Coverage rows written before the platform's manifest was recorded leave membership to the
    /// reference graph, so an already-scanned multi-arch image keeps serving its platforms; the
    /// sweep's backfill then records the manifests and the skipped platform reads as unscanned.
    /// </summary>
    [Fact]
    public async Task UnfilledCoverageRows_LeaveMembershipToTheReferenceGraph_UntilTheBackfillFillsThem()
    {
        var amd64 = _upstream.AddImage("legacy-amd64");
        var arm64 = _upstream.AddImage("legacy-arm64");
        var (indexDigest, _) = _upstream.AddIndex(amd64, arm64);
        _upstream.Tag("multi", indexDigest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var client = await PullClientAsync();
        using (var index = await client.GetAsync($"/v2/{Repo}/manifests/multi"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, index.StatusCode);
        }

        await ScanCleanAsync(indexDigest);
        // As a row written before the column existed.
        await ExecAsync("UPDATE oci_scan_coverage SET manifest_digest = NULL", new { });

        using (var legacy = await client.GetAsync($"/v2/{Repo}/manifests/{arm64.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, legacy.StatusCode);
        }

        TestHarnessDbScope.Enter();
        await _factory.Services.GetRequiredService<OciScanSweepService>().RunPassAsync(default);
        Assert.Equal(amd64.Digest, await ScalarAsync<string?>(
            "SELECT manifest_digest FROM oci_scan_coverage WHERE platform = 'linux/amd64'", new { }));

        // The same pull now reads the filled coverage: arm64 was never scanned.
        using var filled = await client.GetAsync($"/v2/{Repo}/manifests/{arm64.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, filled.StatusCode);
        Assert.Equal("unscanned", filled.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    /// <summary>
    /// A platform manifest pulled by digest in a repository that does not hold its index is not
    /// reachable through the reference graph from there, so it is catalogued and queued as an image
    /// of its own; once its scan lands a retry is answered from it rather than staying unscanned.
    /// </summary>
    [Fact]
    public async Task AChildWhoseIndexIsHeldInAnotherRepository_IsQueuedAndScanned_ThenServed()
    {
        var amd64 = _upstream.AddImage("c2-amd64");
        var arm64 = _upstream.AddImage("c2-arm64");
        _other.AddImage("c2-amd64");
        var (indexDigest, _) = _upstream.AddIndex(amd64, arm64);
        _upstream.Tag("multi", indexDigest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var client = await PullClientAsync();

        using (var index = await client.GetAsync($"/v2/{Repo}/manifests/multi"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, index.StatusCode);
        }

        // The org's reference graph knows the edge, but the index lives in a different repository.
        using (var first = await client.GetAsync($"/v2/{OtherRepo}/manifests/{amd64.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
            Assert.Equal("unscanned", first.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'oci' AND name = @repo AND version = @digest",
            new { repo = OtherRepo, digest = amd64.Digest }));

        // The scan lands (the claim names the queued job), and a retry is answered from it.
        await ScanCleanAsync(amd64.Digest);
        using var retry = await client.GetAsync($"/v2/{OtherRepo}/manifests/{amd64.Digest}");
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
    }

    /// <summary>
    /// A platform manifest listed by two indexes the org holds is owned by both. An approval past
    /// the missing scan covers it only once every owner carries one.
    /// </summary>
    [Fact]
    public async Task AnUnscannedApproval_MustCoverEveryOwnerOfAPlatformManifest()
    {
        var shared = _upstream.AddImage("s6-shared");
        var armA = _upstream.AddImage("s6-arm-a");
        var armB = _upstream.AddImage("s6-arm-b");
        var (indexA, _) = _upstream.AddIndex(shared, armA);
        var (indexB, _) = _upstream.AddIndex(shared, armB);
        _upstream.Tag("a", indexA);
        _upstream.Tag("b", indexB);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var client = await PullClientAsync();
        foreach (string tag in new[] { "a", "b" })
        {
            using var pulled = await client.GetAsync($"/v2/{Repo}/manifests/{tag}");
            Assert.Equal(HttpStatusCode.Forbidden, pulled.StatusCode);
        }

        // The platform resolves through both indexes; the first owner is the lower digest.
        string first = string.CompareOrdinal(indexA, indexB) < 0 ? indexA : indexB;
        string second = first == indexA ? indexB : indexA;
        await ApproveUnscannedAsync(first);

        using (var one = await client.GetAsync($"/v2/{Repo}/manifests/{shared.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, one.StatusCode);
            Assert.Equal("unscanned", one.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        await ApproveUnscannedAsync(second);
        using var both = await client.GetAsync($"/v2/{Repo}/manifests/{shared.Digest}");
        Assert.Equal(HttpStatusCode.OK, both.StatusCode);
    }

    /// <summary>
    /// A platform manifest owned by a proxied index and by a hosted image: a deny on the hosted
    /// owner's queue row must set that version's manual override whichever owner sorts first, so
    /// the child stays refused after a clean scan lands.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ADenyOnAHostedOwner_RefusesTheSharedChild_WhicheverOwnerSortsFirst(bool hostedSortsFirst)
    {
        var shared = _upstream.AddImage("ho-shared");
        var arm = _upstream.AddImage("ho-arm");
        var (proxiedIndex, _) = _upstream.AddIndex(shared, arm);
        _upstream.Tag("p", proxiedIndex);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var client = await PullClientAsync();
        using (var pulled = await client.GetAsync($"/v2/{Repo}/manifests/p"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, pulled.StatusCode);
        }

        string orgId = await OrgIdAsync();
        using var pusher = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        string hostedDigest = "";
        for (int attempt = 0; attempt < 64; attempt++)
        {
            hostedDigest = await PushImageAsync(pusher, Repo, "ho-" + attempt);
            if ((string.CompareOrdinal(hostedDigest, proxiedIndex) < 0) == hostedSortsFirst)
            {
                break;
            }
        }

        Assert.Equal(hostedSortsFirst, string.CompareOrdinal(hostedDigest, proxiedIndex) < 0);
        await ExecAsync(
            "INSERT INTO oci_manifest_blobs (org_id, manifest_digest, blob_digest) VALUES (@orgId, @hostedDigest, @child)",
            new { orgId, hostedDigest, child = shared.Digest });

        using (var refused = await client.GetAsync($"/v2/{Repo}/manifests/{shared.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("unscanned", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        string hostedVersionId = await HostedVersionIdAsync(orgId, Repo, hostedDigest);
        string hostedRow = await ScalarAsync<string>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND gate = 'unscanned' AND state = 'pending' AND package_version_id = @hostedVersionId",
            new { orgId, hostedVersionId });
        using (var admin = await AdminClientAsync())
        using (var deny = await admin.PostAsJsonAsync($"/api/v1/quarantine/{hostedRow}/decide", new { decision = "denied" }))
        {
            Assert.Equal(HttpStatusCode.OK, deny.StatusCode);
        }

        Assert.Equal("blocked", await ScalarAsync<string>(
            "SELECT manual_block_state FROM package_versions WHERE id = @hostedVersionId", new { hostedVersionId }));
        await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Hosted(hostedVersionId), "linux/amd64", [], []);
        await OciScanSeeder.ResultAsync(
            Store(), orgId, OciScanOwner.Proxied(await CatalogueAsync(proxiedIndex)), "linux/amd64", [], []);

        using var stillRefused = await client.GetAsync($"/v2/{Repo}/manifests/{shared.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, stillRefused.StatusCode);
        Assert.Equal("manual", stillRefused.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    private async Task ApproveUnscannedAsync(string digest)
    {
        string orgId = await OrgIdAsync();
        string rowId = await ScalarAsync<string>(
            "SELECT id FROM quarantine WHERE org_id = @orgId AND gate = 'unscanned' AND state = 'pending' AND purl LIKE @pattern",
            new { orgId, pattern = "%" + digest.Replace(":", "%3A") + "%" });
        using var admin = await AdminClientAsync();
        using var decide = await admin.PostAsJsonAsync($"/api/v1/quarantine/{rowId}/decide", new { decision = "approved" });
        Assert.Equal(HttpStatusCode.OK, decide.StatusCode);
    }

    /// <summary>
    /// A coverage row the backfill can never attribute to a manifest (the index does not list its
    /// platform) is recorded as unlisted instead of staying NULL, because a NULL row reads as
    /// covering every platform of the image. Rows behind it are still reached on the next pass.
    /// </summary>
    [Fact]
    public async Task TheBackfill_RecordsAnUnlistedPlatform_AndPagesPastImagesItCannotFill()
    {
        var amd64 = _upstream.AddImage("bf-amd64");
        var arm64 = _upstream.AddImage("bf-arm64");
        var (indexDigest, _) = _upstream.AddIndex(amd64, arm64);
        _upstream.Tag("multi", indexDigest);
        var solo = _upstream.AddImage("bf-solo");
        _upstream.Tag("solo", solo.Digest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var client = await PullClientAsync();
        foreach (string tag in new[] { "multi", "solo" })
        {
            using var pulled = await client.GetAsync($"/v2/{Repo}/manifests/{tag}");
            Assert.Equal(HttpStatusCode.Forbidden, pulled.StatusCode);
        }

        // The index is scanned for a platform it does not list, and the solo image has coverage.
        string orgId = await OrgIdAsync();
        string indexOwner = await CatalogueAsync(indexDigest);
        string soloOwner = await CatalogueAsync(solo.Digest);
        await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Proxied(indexOwner), "linux/s390x", [],
            [new SeedComponent("zlib", 0, [])]);
        await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Proxied(soloOwner), "linux/amd64", [],
            [new SeedComponent("zlib", 0, [])]);
        await ExecAsync("UPDATE oci_scan_coverage SET manifest_digest = NULL", new { });
        await OciScanSeeder.ScannerSeenAsync(Store(), orgId, _clock.GetUtcNow());

        TestHarnessDbScope.Enter();
        var sweep = _factory.Services.GetRequiredService<OciScanSweepService>();
        for (int pass = 0; pass < 3; pass++)
        {
            await sweep.RunPassAsync(default);
        }

        Assert.Equal(OciScanRepository.UnlistedPlatformDigest, await ScalarAsync<string?>(
            "SELECT manifest_digest FROM oci_scan_coverage WHERE platform = 'linux/s390x'", new { }));
        Assert.Equal(solo.Digest, await ScalarAsync<string?>(
            "SELECT manifest_digest FROM oci_scan_coverage WHERE platform = 'linux/amd64' AND manifest_digest IS NOT NULL", new { }));

        // And the unlisted row no longer covers the platforms the index lists.
        using var skipped = await client.GetAsync($"/v2/{Repo}/manifests/{amd64.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, skipped.StatusCode);
    }

    // ── Moving tags ─────────────────────────────────────────────────────────────

    /// <summary>
    /// A tag repointed upstream to an image this org has not scanned keeps serving its last
    /// gate-passing digest. The new digest is fetched, catalogued and queued without repointing
    /// the tag; the hold shows on the image's version page; and once its scan passes, the next
    /// revalidation promotes it. A later advisory on the promoted digest refuses the tag rather
    /// than falling back to an older digest.
    /// </summary>
    [Fact]
    public async Task ARepointedTag_HoldsItsLastPassingDigest_UntilTheNewDigestsScanPasses()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block", blockKev = "block" });
        var first = _upstream.AddImage("tag-gen-1");
        var second = _upstream.AddImage("tag-gen-2");
        _upstream.Tag("latest", first.Digest);
        using var client = await PullClientAsync();

        using (var refused = await client.GetAsync($"/v2/{Repo}/manifests/latest"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        }

        await ScanCleanAsync(first.Digest);
        await AssertTagServesAsync(client, first);

        // Upstream rebuilds the tag; the TTL expires.
        _upstream.Tag("latest", second.Digest);
        _clock.Advance(TimeSpan.FromHours(2));

        await AssertTagServesAsync(client, first);
        var (digest, pending) = await QuerySingleAsync<(string Digest, string? Pending)>(
            "SELECT digest AS Digest, pending_digest AS Pending FROM oci_tags WHERE repository = @repo AND tag = 'latest'",
            new { repo = Repo });
        Assert.Equal(first.Digest, digest);
        Assert.Equal(second.Digest, pending);

        // The held digest was acquired: cached, catalogued and queued for its scan.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest", new { digest = second.Digest }));

        using (var admin = await AdminClientAsync())
        using (var page = await admin.GetAsync($"/api/v1/packages/oci/{Uri.EscapeDataString(Repo)}/{second.Digest}/scan"))
        {
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            using var doc = JsonDocument.Parse(await page.Content.ReadAsStringAsync());
            var hold = Assert.Single(doc.RootElement.GetProperty("pendingHolds").EnumerateArray().ToList());
            Assert.Equal("latest", hold.GetProperty("tag").GetString());
            Assert.Equal(first.Digest, hold.GetProperty("servingDigest").GetString());
        }

        // Still unscanned at the next revalidation: still held.
        _clock.Advance(TimeSpan.FromHours(2));
        await AssertTagServesAsync(client, first);

        // The scan passes; the next revalidation promotes.
        await ScanCleanAsync(second.Digest);
        _clock.Advance(TimeSpan.FromHours(2));
        await AssertTagServesAsync(client, second);
        Assert.Null(await ScalarAsync<string?>(
            "SELECT pending_digest FROM oci_tags WHERE repository = @repo AND tag = 'latest'", new { repo = Repo }));

        // No fallback: an advisory landing on the accepted digest refuses the tag.
        string owner = await CatalogueAsync(second.Digest);
        await OciScanSeeder.ResultAsync(Store(), await OrgIdAsync(), OciScanOwner.Proxied(owner), "linux/arm64", [],
            [new SeedComponent("openssl", 0, [new SeedFinding("DSA-TAG-KEV")])]);
        await ExecAsync("UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = 'DSA-TAG-KEV'", new { });
        using var kev = await client.GetAsync($"/v2/{Repo}/manifests/latest");
        Assert.Equal(HttpStatusCode.Forbidden, kev.StatusCode);
        Assert.Equal("kev", kev.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    [Fact]
    public async Task ARepointedTag_UnderOff_PromotesOnTheFirstRevalidation()
    {
        // Twin: with the posture off the scan is no part of promotion.
        await SetPolicyAsync(new { ociScanEnforcement = "off" });
        var first = _upstream.AddImage("off-tag-1");
        var second = _upstream.AddImage("off-tag-2");
        _upstream.Tag("latest", first.Digest);
        using var client = await PullClientAsync();
        await AssertTagServesAsync(client, first);

        _upstream.Tag("latest", second.Digest);
        _clock.Advance(TimeSpan.FromHours(2));

        await AssertTagServesAsync(client, second);
    }

    private static async Task AssertTagServesAsync(HttpClient client, FakeOciRegistry.Image expected)
    {
        using var response = await client.GetAsync($"/v2/{Repo}/manifests/latest");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(expected.Digest, response.Headers.GetValues("Docker-Content-Digest").Single());
        Assert.Equal(expected.Manifest, await response.Content.ReadAsByteArrayAsync());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    // Primes the image under the current posture where the site needs it held locally, then
    // issues the site's request. primeUnderOff primes with the posture temporarily off, so the
    // prime itself is never refused.
    private async Task<HttpResponseMessage> HitSiteAsync(string site, FakeOciRegistry.Image image, bool primeUnderOff = false)
    {
        using var client = await PullClientAsync();
        string? posture = primeUnderOff ? await PostureAsync() : null;

        async Task PrimeAsync(string path)
        {
            if (posture is not null)
            {
                await SetPolicyAsync(new { ociScanEnforcement = "off" });
            }

            using var prime = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, prime.StatusCode);
            if (posture is not null)
            {
                await SetPolicyAsync(new { ociScanEnforcement = posture });
            }
        }

        switch (site)
        {
            case "local-get":
                await PrimeAsync($"/v2/{Repo}/manifests/{image.Digest}");
                return await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");
            case "local-head":
                await PrimeAsync($"/v2/{Repo}/manifests/{image.Digest}");
                return await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/{image.Digest}"));
            case "upstream-get":
                return await client.GetAsync($"/v2/{Repo}/manifests/v1");
            case "upstream-head":
                return await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/v1"));
            case "stale-tag":
                await PrimeAsync($"/v2/{Repo}/manifests/v1");
                _clock.Advance(TimeSpan.FromHours(2));
                _upstream.Down = true;
                try
                {
                    var stale = await client.GetAsync($"/v2/{Repo}/manifests/v1");
                    if (stale.StatusCode == HttpStatusCode.OK)
                    {
                        Assert.Equal("STALE", stale.Headers.GetValues("X-Cache").Single());
                    }

                    return stale;
                }
                finally
                {
                    _upstream.Down = false;
                }

            case "blob-local":
                await PrimeAsync($"/v2/{Repo}/manifests/{image.Digest}");
                return await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}");
            case "blob-upstream":
                _upstream.ServeManifestsAsBlobs = true;
                return await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}");
            case "blob-upstream-octet":
                _upstream.ServeManifestsAsBlobs = true;
                _upstream.BlobRouteManifestType = "application/octet-stream";
                return await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}");
            case "blob-local-octet":
                _upstream.ServeManifestsAsBlobs = true;
                _upstream.BlobRouteManifestType = "application/octet-stream";
                // Primed through the blob route itself, so the stored row carries the generic type.
                await PrimeAsync($"/v2/{Repo}/blobs/{image.Digest}");
                return await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}");
            case "blob-upstream-layerlabel":
                _upstream.ServeManifestsAsBlobs = true;
                _upstream.BlobRouteManifestType = "application/vnd.oci.image.layer.v1.tar+gzip";
                return await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}");
            case "blob-local-layerlabel":
                _upstream.ServeManifestsAsBlobs = true;
                _upstream.BlobRouteManifestType = "application/vnd.oci.image.layer.v1.tar+gzip";
                await PrimeAsync($"/v2/{Repo}/blobs/{image.Digest}");
                return await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}");
            default:
                throw new ArgumentOutOfRangeException(nameof(site), site, null);
        }
    }

    // Seeds the org's result for the image with one KEV finding, cataloguing the image first as
    // a proxied manifest the org pulled (so a site whose first request is the upstream miss
    // already has its owner row).
    private async Task SeedKevResultAsync(string digest)
    {
        string orgId = await OrgIdAsync();
        string owner = await CatalogueAsync(digest);
        string osvId = "DSA-KEV-" + digest[7..19];
        await OciScanSeeder.ResultAsync(Store(), orgId, OciScanOwner.Proxied(owner), "linux/amd64", [],
            [new SeedComponent("openssl", 0, [new SeedFinding(osvId)])]);
        await ExecAsync("UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = @osvId", new { osvId });
    }

    // The org's proxied catalogue row for the digest, creating the shared row and the org's
    // access to it when the image has not been pulled yet.
    private async Task<string> CatalogueAsync(string digest)
    {
        string orgId = await OrgIdAsync();
        string? existing = await ScalarAsync<string?>(
            """
            SELECT ca.id FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.ecosystem = 'oci' AND ca.filename = 'manifest' AND ca.name = @repo AND ca.version = @digest
            """,
            new { orgId, repo = Repo, digest });
        if (existing is not null)
        {
            return existing;
        }

        string id = await OciScanSeeder.ProxiedManifestAsync(Store(), Repo, digest);
        await OciScanSeeder.GrantAsync(Store(), orgId, id);
        return id;
    }

    // Claims the image's scan job as the org's scanner and posts a clean, gap-free result.
    private async Task ScanCleanAsync(string digest)
    {
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        using var claim = await scanner.PostAsJsonAsync("/api/v1/oci-scan/claim", new { max = 16 });
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        using var body = JsonDocument.Parse(await claim.Content.ReadAsStringAsync());
        var job = body.RootElement.GetProperty("jobs").EnumerateArray()
            .Single(j => j.GetProperty("digest").GetString() == digest);
        string jobId = job.GetProperty("id").GetString()!;
        int attempt = job.GetProperty("attempt").GetInt32();
        using var result = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/{jobId}/result?attempt={attempt}", new
        {
            platforms = new[]
            {
                new
                {
                    platform = "linux/amd64", scannerVersion = "0.3.0", extractionVersion = "1", osvSource = "remote",
                    gaps = Array.Empty<string>(), entrypointKind = "native", closureBounded = true,
                    components = new[]
                    {
                        new
                        {
                            purl = "pkg:deb/debian/zlib1g@1.2.13", ecosystem = "deb", name = "zlib1g", version = "1.2.13",
                            sourceName = "zlib", sourceVersion = "1.2.13", layerIndex = 0, vulns = Array.Empty<object>(),
                        },
                    },
                },
            },
            advisories = Array.Empty<object>(),
        });
        Assert.Equal(HttpStatusCode.NoContent, result.StatusCode);
    }

    // ── Blob-route manifests: answered under their own type, sized like the manifest route ──

    [Fact]
    public async Task AManifestReadAsABlob_IsAnsweredUnderItsManifestType_OnTheMissAndTheLocalHit()
    {
        _upstream.ServeManifestsAsBlobs = true;
        _upstream.BlobRouteManifestType = "application/octet-stream";
        var miss = _upstream.AddImage("typed-miss");
        var hit = _upstream.AddImage("typed-hit");
        using var client = await PullClientAsync();

        // Primed while enforcement is off, so the row keeps the upstream's generic label.
        using (var prime = await client.GetAsync($"/v2/{Repo}/blobs/{hit.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, prime.StatusCode);
        }

        Assert.Equal("application/octet-stream", await ScalarAsync<string>(
            "SELECT media_type FROM oci_blobs WHERE digest = @digest", new { digest = hit.Digest }));

        await SetPolicyAsync(new { ociScanEnforcement = "warn" });

        using (var missResponse = await client.GetAsync($"/v2/{Repo}/blobs/{miss.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, missResponse.StatusCode);
            Assert.Equal(FakeOciRegistry.ImageManifestType, missResponse.Content.Headers.ContentType!.MediaType);
        }

        using var hitResponse = await client.GetAsync($"/v2/{Repo}/blobs/{hit.Digest}");
        Assert.Equal(HttpStatusCode.OK, hitResponse.StatusCode);
        Assert.Equal(FakeOciRegistry.ImageManifestType, hitResponse.Content.Headers.ContentType!.MediaType);

        // The twin: a layer on the same route keeps its own label.
        using var layer = await client.GetAsync($"/v2/{Repo}/blobs/{hit.LayerDigest}");
        Assert.Equal("application/octet-stream", layer.Content.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task BlockPosture_HoldsAnOversizedBlobLabelledAsAManifest_ButStreamsAnOversizedLayer()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        byte[] big = new byte[(int)Dependably.Protocol.OciManifestParser.ManifestSniffMaxBytes + 1024];
        string asManifest = _upstream.AddBlob((byte[])big.Clone(), FakeOciRegistry.ImageManifestType);
        big[0] = 1;
        string asLayer = _upstream.AddBlob(big, "application/vnd.oci.image.layer.v1.tar+gzip");
        using var client = await PullClientAsync();

        using (var held = await client.GetAsync($"/v2/{Repo}/blobs/{asManifest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, held.StatusCode);
            Assert.Equal("unscanned", held.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        using var layer = await client.GetAsync($"/v2/{Repo}/blobs/{asLayer}");
        Assert.Equal(HttpStatusCode.OK, layer.StatusCode);
        Assert.Equal(big.Length, (await layer.Content.ReadAsByteArrayAsync()).Length);
    }

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task AnUpstreamManifestLargerThanAManifestMayBe_IsRefusedOnTheManifestRoute_UnderEnforcement(string posture)
    {
        await SetPolicyAsync(new { ociScanEnforcement = posture });
        int cap = (int)Dependably.Protocol.OciManifestParser.ManifestSniffMaxBytes;
        string within = _upstream.AddPaddedImage("padded-within-" + posture, cap / 2);
        string beyond = _upstream.AddPaddedImage("padded-beyond-" + posture, cap + 1024);
        using var client = await PullClientAsync();

        using (var inside = await client.GetAsync($"/v2/{Repo}/manifests/{within}"))
        {
            Assert.NotEqual(HttpStatusCode.BadGateway, inside.StatusCode);
        }

        using var refused = await client.GetAsync($"/v2/{Repo}/manifests/{beyond}");
        Assert.Equal(HttpStatusCode.BadGateway, refused.StatusCode);
        string body = await refused.Content.ReadAsStringAsync();
        Assert.Contains("UNAVAILABLE", body, StringComparison.Ordinal);
        Assert.Contains("manifest_too_large", body, StringComparison.Ordinal);
        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @beyond", new { beyond }));
    }

    /// <summary>With the posture off the 4 MiB manifest cap does not apply: a larger upstream manifest is served as before.</summary>
    [Fact]
    public async Task AnUpstreamManifestLargerThanAManifestMayBe_IsServed_AtOffPosture()
    {
        int cap = (int)Dependably.Protocol.OciManifestParser.ManifestSniffMaxBytes;
        string beyond = _upstream.AddPaddedImage("padded-beyond-off", cap + 1024);
        using var client = await PullClientAsync();

        using var served = await client.GetAsync($"/v2/{Repo}/manifests/{beyond}");
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
    }

    /// <summary>
    /// A known manifest larger than a manifest may now be, stored under a generic type (cached
    /// when the cap was larger), is still gated on the blob route: its size is no proof it is not one.
    /// </summary>
    [Fact]
    public async Task AKnownManifestLargerThanTheCap_StoredUnderAGenericType_IsGatedOnTheBlobRoute()
    {
        int cap = (int)Dependably.Protocol.OciManifestParser.ManifestSniffMaxBytes;
        string beyond = _upstream.AddPaddedImage("legacy-big", cap + 1024);
        using var client = await PullClientAsync();
        using (var prime = await client.GetAsync($"/v2/{Repo}/manifests/{beyond}"))
        {
            Assert.Equal(HttpStatusCode.OK, prime.StatusCode);
        }

        await CatalogueAsync(beyond);
        await ExecAsync(
            "UPDATE oci_blobs SET media_type = 'application/octet-stream' WHERE digest = @beyond", new { beyond });
        Assert.True(await ScalarAsync<long>("SELECT size_bytes FROM oci_blobs WHERE digest = @beyond", new { beyond }) > cap);

        using (var served = await client.GetAsync($"/v2/{Repo}/blobs/{beyond}"))
        {
            Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        }

        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var refused = await client.GetAsync($"/v2/{Repo}/blobs/{beyond}");
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
    }

    /// <summary>
    /// A manifest the org already knows, larger than the cap and labelled octet-stream by the
    /// upstream, is held on a blob-route miss rather than streamed, so the gate refuses it.
    /// </summary>
    [Fact]
    public async Task AKnownManifestLargerThanTheCap_ReadThroughTheBlobRouteOnAMiss_IsHeldAndGated()
    {
        int cap = (int)Dependably.Protocol.OciManifestParser.ManifestSniffMaxBytes;
        string beyond = _upstream.AddPaddedImage("miss-big", cap + 1024);
        await CatalogueAsync(beyond);
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_blobs WHERE digest = @beyond", new { beyond }));
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        _upstream.ServeManifestsAsBlobs = true;
        _upstream.BlobRouteManifestType = "application/octet-stream";
        using var client = await PullClientAsync();

        using var refused = await client.GetAsync($"/v2/{Repo}/blobs/{beyond}");

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
    }

    /// <summary>A HEAD for a manifest over the cap is refused under enforcement exactly as the GET is.</summary>
    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task AnUpstreamManifestLargerThanTheCap_IsRefusedOnHead_AsOnGet(string posture)
    {
        await SetPolicyAsync(new { ociScanEnforcement = posture });
        int cap = (int)Dependably.Protocol.OciManifestParser.ManifestSniffMaxBytes;
        string beyond = _upstream.AddPaddedImage("head-big-" + posture, cap + 1024);
        using var client = await PullClientAsync();

        using var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/{beyond}"));
        using var get = await client.GetAsync($"/v2/{Repo}/manifests/{beyond}");

        Assert.Equal(HttpStatusCode.BadGateway, head.StatusCode);
        Assert.Equal(get.StatusCode, head.StatusCode);
    }

    /// <summary>A manifest led by a UTF-8 byte-order mark and labelled octet-stream is still recognised and refused on the blob route.</summary>
    [Fact]
    public async Task ABomPrefixedManifest_ReadAsAnOctetStreamBlob_IsRefusedUnderBlock()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        var image = _upstream.AddImage("bom");
        string digest = _upstream.AddBlob([0xEF, 0xBB, 0xBF, .. image.Manifest], "application/octet-stream");
        using var client = await PullClientAsync();

        using var refused = await client.GetAsync($"/v2/{Repo}/blobs/{digest}");
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
    }

    // A digest the bytes proved not to be a manifest is not read again: the stored bytes are
    // swapped for a manifest's (impossible under a real content-addressed store), and the twin
    // that was never read still sniffs them.
    [Fact]
    public async Task ABlobProvenNotAManifest_IsNotReadAgain()
    {
        var image = _upstream.AddImage("memo");
        var control = _upstream.AddImage("memo-control");
        using var client = await PullClientAsync();

        // The control is primed while enforcement is off, so nothing reads its bytes.
        using (var prime = await client.GetAsync($"/v2/{Repo}/blobs/{control.LayerDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, prime.StatusCode);
        }

        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using (var proven = await client.GetAsync($"/v2/{Repo}/blobs/{image.LayerDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, proven.StatusCode);
        }

        foreach (string layer in new[] { image.LayerDigest, control.LayerDigest })
        {
            string[] parts = layer.Split(':');
            await _factory.BlobStore.PutAsync(
                Dependably.Storage.BlobKeys.OciBlob(parts[0], parts[1]), new MemoryStream(image.Manifest));
        }

        using var remembered = await client.GetAsync($"/v2/{Repo}/blobs/{image.LayerDigest}");
        Assert.Equal(HttpStatusCode.OK, remembered.StatusCode);

        using var sniffed = await client.GetAsync($"/v2/{Repo}/blobs/{control.LayerDigest}");
        Assert.Equal(HttpStatusCode.Forbidden, sniffed.StatusCode);
    }

    private async Task<HttpClient> PullClientAsync() => _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));

    private async Task<HttpClient> AdminClientAsync()
    {
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        return c;
    }

    private async Task SetPolicyAsync(object body)
    {
        await OciScanSeeder.StaleScannerAsync(Store(), await OrgIdAsync(), _clock.GetUtcNow());
        using var admin = await AdminClientAsync();
        using var put = await admin.PutAsJsonAsync("/api/v1/proxy-settings", body);
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);
    }

    private async Task PutPolicyJsonAsync(string json)
    {
        await OciScanSeeder.StaleScannerAsync(Store(), await OrgIdAsync(), _clock.GetUtcNow());
        using var admin = await AdminClientAsync();
        using var put = await admin.PutAsync("/api/v1/proxy-settings",
            new StringContent(json, System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);
    }

    private async Task<string> PostureAsync()
    {
        using var admin = await AdminClientAsync();
        using var get = await admin.GetAsync("/api/v1/proxy-settings");
        using var doc = JsonDocument.Parse(await get.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("oci_scan_enforcement").GetString()!;
    }

    private async Task<string> OrgIdAsync() =>
        await ScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'", new { });

    // Reaching into the host's services as the test harness, so seeding runs as the owner under
    // row-level security rather than as an undeclared background tenant.
    private IMetadataStore Store()
    {
        TestHarnessDbScope.Enter();
        return _factory.Services.GetRequiredService<IMetadataStore>();
    }

    private async Task ExecAsync(string sql, object args)
    {
        await using var conn = await Store().OpenAsync();
        await conn.ExecuteAsync(sql, args);
    }

    private async Task<T> ScalarAsync<T>(string sql, object args)
    {
        await using var conn = await Store().OpenAsync();
        return (await conn.ExecuteScalarAsync<T>(sql, args))!;
    }

    private async Task<T> QuerySingleAsync<T>(string sql, object args)
    {
        await using var conn = await Store().OpenAsync();
        return await conn.QuerySingleAsync<T>(sql, args);
    }

    private async Task<int> CountAsync(string sql, object args) => await ScalarAsync<int>(sql, args);

    // Activity rows drain through an ordered background writer, so a refusal's row is polled for.
    private async Task<bool> ActivityLandsAsync(string eventType, string? detailContains = null)
    {
        // now-ok: polls for a row the background activity writer inserts on its own thread; the
        // deadline bounds a genuine asynchronous completion, not a timed behaviour under test.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (true)
        {
            var details = (await QueryAsync<string?>(
                "SELECT detail FROM activity WHERE event_type = @eventType", new { eventType })).ToList();
            if (details.Count > 0 && (detailContains is null || details.Any(d => d?.Contains(detailContains, StringComparison.Ordinal) == true)))
            {
                return true;
            }

            // now-ok: the same poll's deadline check.
            if (DateTime.UtcNow >= deadline)
            {
                return false;
            }

            // now-ok: the same poll's interval.
            await Task.Delay(50);
        }
    }

    private async Task<IEnumerable<T>> QueryAsync<T>(string sql, object args)
    {
        await using var conn = await Store().OpenAsync();
        return (await conn.QueryAsync<T>(sql, args)).AsList();
    }
}
