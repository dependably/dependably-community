using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Webhooks;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Tests.Integration;

/// <summary>
/// The OCI pull gate's answers at the edges of image ownership and request shape: a hosted
/// manifest pushed by digest only, a platform manifest catalogued as its own image before its
/// index, a blob-route HEAD that misses the cache, and the HEAD a publish-only pusher issues
/// before it writes.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciScanPullGateProbeAndOwnerTests : IAsyncLifetime
{
    private const string Repo = "library/probe-app";

    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private readonly FakeOciRegistry _upstream = new(Repo);
    private readonly RecordingEventSink _events = new();
    private DependablyFactory _factory = null!;

    public async Task InitializeAsync()
    {
        _factory = new DependablyFactory
        {
            FrozenClock = _clock,
            OciUpstreamHandler = _upstream.Respond,
            ExtraSettings = new Dictionary<string, string?>
            {
                ["OCI_SCAN_ENABLED"] = "true",
                ["OCI_SCAN_SWEEP_SCHEDULE"] = "0 0 31 2 *",
            },
            ServiceOverrides = services =>
            {
                services.RemoveAll<IPackageEventSink>();
                services.AddSingleton<IPackageEventSink>(_events);
            },
        };
        await _factory.InitializeAsync();
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── A hosted manifest pushed by digest only ─────────────────────────────────

    /// <summary>
    /// A manifest pushed by digest has no tag to catalogue it under at push time. Its first gated
    /// pull catalogues and queues it, so the refusal's "queued for scanning" is true and a retry
    /// after the scan is served.
    /// </summary>
    [Fact]
    public async Task ADigestOnlyHostedPush_IsCataloguedAndQueuedByItsFirstGatedPull_AndServedAfterTheScan()
    {
        const string HostedRepo = "team/digest-only";
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var pushed = await PushImageAsync(client, HostedRepo, "digest-only", byDigest: true);
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest", new { digest = pushed.Digest }));
        await SetPolicyAsync(new { ociScanEnforcement = "block" });

        using (var refused = await client.GetAsync($"/v2/{HostedRepo}/manifests/{pushed.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("unscanned", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
            Assert.Contains("queued for scanning", await refused.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @digest", new { digest = pushed.Digest }));
        Assert.Equal(1, await CountAsync(
            """
            SELECT COUNT(*) FROM package_versions pv JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = 'oci' AND p.purl_name = @repo AND pv.version = @digest AND pv.origin = 'uploaded'
            """,
            new { repo = HostedRepo, digest = pushed.Digest }));

        await ScanCleanAsync(pushed.Digest);
        using var served = await client.GetAsync($"/v2/{HostedRepo}/manifests/{pushed.Digest}");
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal(pushed.Manifest, await served.Content.ReadAsByteArrayAsync());
    }

    /// <summary>
    /// The twin: a platform manifest pushed by digest and listed by an index pushed by tag is not an
    /// image of its own. Its pull resolves to the index and catalogues nothing for the platform.
    /// </summary>
    [Fact]
    public async Task ADigestOnlyPlatformOfAHostedIndex_IsNotCataloguedAsItsOwnImage()
    {
        const string HostedRepo = "team/digest-index";
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var amd64 = await PushImageAsync(client, HostedRepo, "idx-amd64", byDigest: true);
        var arm64 = await PushImageAsync(client, HostedRepo, "idx-arm64", byDigest: true);
        string index = await PushIndexAsync(client, HostedRepo, "multi", amd64, arm64);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });

        using (var child = await client.GetAsync($"/v2/{HostedRepo}/manifests/{amd64.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, child.StatusCode);
            Assert.Equal("unscanned", child.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM package_versions WHERE version = @digest", new { digest = amd64.Digest }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE digest = @index", new { index }));
    }

    /// <summary>
    /// A pushed digest is reachable under any repository name of the org, because the bytes are
    /// held by digest. A pull under a name it was never pushed to catalogues and queues nothing:
    /// the image stays refused as unscanned there, so a manual block on the repository it was
    /// pushed to cannot be sidestepped by a clean scan of a second catalogue row.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task APushedDigestPulledUnderAnotherName_IsNotCatalogued_AndStaysRefused(bool byDigest)
    {
        const string RealRepo = "team/real";
        const string OtherRepo = "team/other";
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var pushed = await PushImageAsync(client, RealRepo, "real-x", byDigest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        if (byDigest)
        {
            // The pull under the pushed name catalogues it, so it has a row to block.
            using var own = await client.GetAsync($"/v2/{RealRepo}/manifests/{pushed.Digest}");
            Assert.Equal(HttpStatusCode.Forbidden, own.StatusCode);
        }

        using (var admin = await AdminClientAsync())
        using (var block = await admin.PostAsync(
            $"/api/v1/packages/oci/{Uri.EscapeDataString(RealRepo)}/{Uri.EscapeDataString(pushed.Digest)}/block", null))
        {
            Assert.Equal(HttpStatusCode.OK, block.StatusCode);
        }

        using (var first = await client.GetAsync($"/v2/{OtherRepo}/manifests/{pushed.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
        }

        await ScanEveryClaimableJobCleanAsync();

        using var retry = await client.GetAsync($"/v2/{OtherRepo}/manifests/{pushed.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, retry.StatusCode);
        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM packages WHERE ecosystem = 'oci' AND purl_name = @repo", new { repo = OtherRepo }));
        Assert.Equal(0, await CountAsync(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE repository = @repo", new { repo = OtherRepo }));
    }

    // ── A platform catalogued as its own image before its index ─────────────────

    /// <summary>
    /// A platform manifest pulled by digest before its index is catalogued as an image of its own,
    /// and so has a direct owner. A manual block an administrator later places on the index still
    /// refuses it: the strictest manual state across the direct owner and every parent wins.
    /// </summary>
    [Fact]
    public async Task AManualBlockOnAnIndex_RefusesAPlatformCataloguedFirstAsItsOwnImage()
    {
        var amd64 = _upstream.AddImage("pre-amd64");
        var arm64 = _upstream.AddImage("pre-arm64");
        var (indexDigest, _) = _upstream.AddIndex(amd64, arm64);
        _upstream.Tag("multi", indexDigest);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        using var client = await PullClientAsync();

        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/{amd64.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
        }

        await ScanCleanAsync(amd64.Digest);
        using (var index = await client.GetAsync($"/v2/{Repo}/manifests/multi"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, index.StatusCode);
        }

        // Its own clean scan serves it while the index carries no manual state.
        using (var served = await client.GetAsync($"/v2/{Repo}/manifests/{amd64.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        }

        using (var admin = await AdminClientAsync())
        using (var block = await admin.PostAsync(
            $"/api/v1/packages/oci/{Uri.EscapeDataString(Repo)}/{Uri.EscapeDataString(indexDigest)}/block", null))
        {
            Assert.Equal(HttpStatusCode.OK, block.StatusCode);
        }

        using var refused = await client.GetAsync($"/v2/{Repo}/manifests/{amd64.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal("manual", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    // ── Blob-route HEAD on a cache miss ─────────────────────────────────────────

    /// <summary>
    /// Under enforcement a blob-route HEAD for a manifest digest answers the same status whether
    /// it misses the cache or hits it, however the upstream labels the bytes.
    /// </summary>
    [Theory]
    [InlineData("application/octet-stream")]
    [InlineData(FakeOciRegistry.ImageManifestType)]
    [InlineData("application/vnd.oci.image.layer.v1.tar+gzip")]
    public async Task ABlobRouteHeadMiss_IsAnsweredAsTheHitIs_UnderEnforcement(string label)
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        _upstream.ServeManifestsAsBlobs = true;
        _upstream.BlobRouteManifestType = label;
        var image = _upstream.AddImage("head-miss-" + label.Length);
        using var client = await PullClientAsync();

        using var miss = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{image.Digest}"));
        using var hit = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{image.Digest}"));

        Assert.Equal(HttpStatusCode.Forbidden, miss.StatusCode);
        Assert.Equal("unscanned", miss.Headers.GetValues("X-Dependably-Block-Reason").Single());
        Assert.Equal(hit.StatusCode, miss.StatusCode);

        // The twin: a layer's HEAD miss under the same posture is still answered.
        using var layer = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{image.LayerDigest}"));
        Assert.Equal(HttpStatusCode.OK, layer.StatusCode);
    }

    /// <summary>With the posture off a blob-route HEAD miss stays a headers-only upstream call.</summary>
    [Fact]
    public async Task ABlobRouteHeadMiss_UnderOff_StaysHeadersOnly()
    {
        _upstream.ServeManifestsAsBlobs = true;
        _upstream.BlobRouteManifestType = "application/octet-stream";
        var image = _upstream.AddImage("head-miss-off");
        using var client = await PullClientAsync();

        using var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{image.Digest}"));

        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest", new { digest = image.Digest }));
    }

    /// <summary>
    /// The blob route streams an unlabelled blob ungated only when it is larger than a manifest may
    /// be, which is exactly the size the manifest route refuses under enforcement; one inside the
    /// cap is read and gated.
    /// </summary>
    [Fact]
    public async Task TheBlobRouteStreamsUngated_OnlyWhatTheManifestRouteRefusesAsTooLarge()
    {
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        int cap = (int)Dependably.Protocol.OciManifestParser.ManifestSniffMaxBytes;
        string beyond = _upstream.AddPaddedImage("cap-beyond", cap + 1024);
        string within = _upstream.AddPaddedImage("cap-within", cap - 4096);
        _upstream.ServeManifestsAsBlobs = true;
        _upstream.BlobRouteManifestType = "application/octet-stream";
        using var client = await PullClientAsync();

        using (var manifestRoute = await client.GetAsync($"/v2/{Repo}/manifests/{beyond}"))
        {
            Assert.Equal(HttpStatusCode.BadGateway, manifestRoute.StatusCode);
        }

        using (var streamed = await client.GetAsync($"/v2/{Repo}/blobs/{beyond}"))
        {
            Assert.Equal(HttpStatusCode.OK, streamed.StatusCode);
        }

        using var gated = await client.GetAsync($"/v2/{Repo}/blobs/{within}");
        Assert.Equal(HttpStatusCode.Forbidden, gated.StatusCode);
    }

    // ── A publish-only pusher's manifest HEAD ───────────────────────────────────

    /// <summary>
    /// A push re-HEADs a manifest it is about to write with a publish-only token. That probe is not
    /// a pull: it is answered as it was before the scan gate, and writes no refusal activity, no
    /// quarantine row and no webhook. The pull twin on the same image keeps every side effect.
    /// </summary>
    [Theory]
    [InlineData("tag")]
    [InlineData("digest")]
    public async Task APushProbeHead_OnAnUnscannedImage_WritesNoRefusalSideEffects(string reference)
    {
        const string HostedRepo = "team/push-probe";
        using var pusher = _factory.CreateClientWithBearer(await _factory.CreateToken("publish-only"));
        var pushed = await PushImageAsync(pusher, HostedRepo, "probe", byDigest: false);
        await SetPolicyAsync(new { ociScanEnforcement = "block" });
        string orgId = await OrgIdAsync();
        string path = $"/v2/{HostedRepo}/manifests/{(reference == "tag" ? "probe" : pushed.Digest)}";

        using (var probe = await pusher.SendAsync(new HttpRequestMessage(HttpMethod.Head, path)))
        {
            Assert.Equal(HttpStatusCode.OK, probe.StatusCode);
            Assert.Equal(pushed.Digest, probe.Headers.GetValues("Docker-Content-Digest").Single());
        }

        Assert.Equal(0, _events.BlockedCount);
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM quarantine WHERE org_id = @orgId", new { orgId }));

        // The pull twin: refused, with every side effect. Its activity row lands behind any the
        // probe would have written, so the count below sees both.
        using var puller = await PullClientAsync();
        using (var pull = await puller.SendAsync(new HttpRequestMessage(HttpMethod.Head, path)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, pull.StatusCode);
        }

        Assert.True(await ActivityLandsAsync("blocked_unscanned"));
        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM activity WHERE event_type = 'blocked_unscanned' AND org_id = @orgId", new { orgId }));
        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM quarantine WHERE org_id = @orgId AND gate = 'unscanned'", new { orgId }));
        Assert.Equal(1, _events.BlockedCount);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private sealed record Pushed(string Digest, byte[] Manifest);

    private static string Sha(byte[] b) =>
        "sha256:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(b)).ToLowerInvariant();

    // Pushes a one-layer image (the suffix makes its digest unique) under its tag, or under its
    // own digest only.
    private static async Task<Pushed> PushImageAsync(HttpClient client, string repository, string suffix, bool byDigest)
    {
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
        byte[] manifest = System.Text.Encoding.UTF8.GetBytes($$"""
            {"schemaVersion":2,"mediaType":"{{FakeOciRegistry.ImageManifestType}}",
             "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{{Sha(config)}}","size":{{config.Length}}},
             "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{{Sha(layer)}}","size":{{layer.Length}}}]}
            """);
        await PutManifestAsync(client, repository, byDigest ? Sha(manifest) : suffix, manifest, FakeOciRegistry.ImageManifestType);
        return new Pushed(Sha(manifest), manifest);
    }

    private static async Task<string> PushIndexAsync(HttpClient client, string repository, string tag, params Pushed[] platforms)
    {
        string entries = string.Join(",", platforms.Select((p, i) =>
            $$$"""{"mediaType":"{{{FakeOciRegistry.ImageManifestType}}}","digest":"{{{p.Digest}}}","size":{{{p.Manifest.Length}}},"platform":{"architecture":"{{{(i == 0 ? "amd64" : "arm64")}}}","os":"linux"}}"""));
        byte[] index = System.Text.Encoding.UTF8.GetBytes(
            $$"""{"schemaVersion":2,"mediaType":"{{FakeOciRegistry.ImageIndexType}}","manifests":[{{entries}}]}""");
        await PutManifestAsync(client, repository, tag, index, FakeOciRegistry.ImageIndexType);
        return Sha(index);
    }

    private static async Task PutManifestAsync(HttpClient client, string repository, string reference, byte[] bytes, string mediaType)
    {
        using var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        using var put = await client.PutAsync($"/v2/{repository}/manifests/{reference}", content);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);
    }

    // Claims every job the scanner can claim and posts a clean, gap-free result for each.
    private async Task ScanEveryClaimableJobCleanAsync()
    {
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        using var claim = await scanner.PostAsJsonAsync("/api/v1/oci-scan/claim", new { max = 16 });
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        using var body = JsonDocument.Parse(await claim.Content.ReadAsStringAsync());
        foreach (var job in body.RootElement.GetProperty("jobs").EnumerateArray())
        {
            await PostCleanResultAsync(scanner, job.GetProperty("id").GetString()!, job.GetProperty("attempt").GetInt32());
        }
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
        await PostCleanResultAsync(scanner, job.GetProperty("id").GetString()!, job.GetProperty("attempt").GetInt32());
    }

    private static async Task PostCleanResultAsync(HttpClient scanner, string jobId, int attempt)
    {
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

    private async Task<string> OrgIdAsync() =>
        await ScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'", new { });

    // Reaching into the host's services as the test harness, so reads run as the owner under
    // row-level security rather than as an undeclared background tenant.
    private IMetadataStore Store()
    {
        TestHarnessDbScope.Enter();
        return _factory.Services.GetRequiredService<IMetadataStore>();
    }

    private async Task<T> ScalarAsync<T>(string sql, object args)
    {
        await using var conn = await Store().OpenAsync();
        return (await conn.ExecuteScalarAsync<T>(sql, args))!;
    }

    private async Task<int> CountAsync(string sql, object args) => await ScalarAsync<int>(sql, args);

    // Activity rows drain through an ordered background writer, so a refusal's row is polled for.
    private async Task<bool> ActivityLandsAsync(string eventType)
    {
        // now-ok: polls for a row the background activity writer inserts on its own thread; the
        // deadline bounds a genuine asynchronous completion, not a timed behaviour under test.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (await CountAsync("SELECT COUNT(*) FROM activity WHERE event_type = @eventType", new { eventType }) == 0)
        {
            // now-ok: the same poll's deadline check.
            if (DateTime.UtcNow >= deadline)
            {
                return false;
            }

            // now-ok: the same poll's interval.
            await Task.Delay(50);
        }

        return true;
    }

    // Records the package events the block gate dispatches, in place of the webhook queue.
    private sealed class RecordingEventSink : IPackageEventSink
    {
        private readonly ConcurrentQueue<PackageEventEnvelope> _events = new();

        public int BlockedCount => _events.Count(e => e.EventType == Dependably.Infrastructure.Audit.Events.PackageEvents.TypeBlocked);

        public void Dispatch(PackageEventEnvelope envelope) => _events.Enqueue(envelope);
    }
}
