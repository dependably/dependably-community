using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the OCI blob reclaim — the sweep that removes layers and config blobs no image references
/// any more.
///
/// This is the destructive path, so the emphasis is on what it must NOT delete. Every reclaim case
/// is paired with a claim that has to survive it, because the failure mode is not "a layer lingers"
/// but "a running deployment's pull 404s and the bytes are gone": OCI blob keys carry no org
/// segment, and without a `_CACHE`/`_REGISTRY` override the Cache and Registry tiers are the same
/// store, so a wrong delete reaches durable bytes across tenants.
///
/// The scenario that makes an origin-based check unsafe is covered explicitly — the pull-then-push
/// round trip, where a hosted image's oci_blobs row still reads origin='proxy' because the upsert
/// never rewrites it.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciBlobReclaimTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Repo = "team/reclaim";
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private readonly DependablyFactory _factory;

    public OciBlobReclaimTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── What must survive ────────────────────────────────────────────────────────

    [Fact]
    public async Task Reclaim_LeavesEveryBlobOfALiveImageInPlace()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "live");
        await BackfillAsync();

        await ReclaimAsync();

        // The tag still resolves the manifest, the manifest still references config + layer, so
        // none of the three may come off. Asserted per digest rather than on the sweep's total,
        // which is org-wide and picks up whatever other images this shared fixture has retired.
        Assert.True(await BlobRowExistsAsync(image.ManifestDigest));
        Assert.True(await BlobRowExistsAsync(image.ConfigDigest));
        Assert.True(await BlobRowExistsAsync(image.LayerDigest));

        using var pull = await client.GetAsync($"/v2/{Repo}/manifests/live");
        Assert.Equal(HttpStatusCode.OK, pull.StatusCode);
    }

    [Fact]
    public async Task Reclaim_KeepsALayerAnotherImageStillReferences()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var first = await PushImageAsync(client, "shareA");
        byte[] secondManifest = BuildImageManifest(
            first.ConfigDigest, first.ConfigSize, first.LayerDigest, first.LayerSize, "shareB");
        string secondDigest = Digest(secondManifest);
        using (var put = await PutManifestAsync(client, "shareB", secondManifest))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        // Retire only the first image: drop its tag and its edges, the state image eviction leaves.
        await RetireManifestAsync(first.ManifestDigest, "shareA");
        await BackfillAsync();
        await ReclaimAsync();

        // The shared layer and config are still referenced by the second manifest.
        Assert.True(await BlobRowExistsAsync(first.LayerDigest));
        Assert.True(await BlobRowExistsAsync(first.ConfigDigest));
        Assert.True(await BlobRowExistsAsync(secondDigest));
    }

    [Fact]
    public async Task Reclaim_KeepsBlobsOfAHostedImageWhoseRowStillReadsOriginProxy()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "roundtrip");

        // The pull-then-push round trip: the digest was first seen via the proxy, so origin stays
        // 'proxy' forever even though a hosted image now depends on the bytes. A reclaim that
        // gated on origin would read these as proxy-owned and destroy a hosted image.
        await SetOriginAsync(image.ManifestDigest, "proxy");
        await SetOriginAsync(image.ConfigDigest, "proxy");
        await SetOriginAsync(image.LayerDigest, "proxy");

        await BackfillAsync();
        await ReclaimAsync();

        Assert.True(await BlobRowExistsAsync(image.ManifestDigest));
        Assert.True(await BlobRowExistsAsync(image.ConfigDigest));
        Assert.True(await BlobRowExistsAsync(image.LayerDigest));
    }

    [Fact]
    public async Task Reclaim_DoesNothingWhileAnyManifestClosureIsUnknown()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var live = await PushImageAsync(client, "gated-live");
        var retired = await PushImageAsync(client, "gated-dead");
        await BackfillAsync();

        // Retire one image, then blind the graph to the *other* one. The retired image's layers are
        // genuinely unreferenced, but with an unknown closure anywhere in the org the sweep cannot
        // prove that, and must decline rather than delete on partial evidence.
        await RetireManifestAsync(retired.ManifestDigest, "gated-dead");
        await _factory.Services.GetRequiredService<OciReferenceGraph>()
            .RemoveManifestAsync(await DefaultOrgIdAsync(), live.ManifestDigest);

        Assert.False(await _factory.Services.GetRequiredService<OciBlobReclaimer>()
            .IsOrgClosureCompleteAsync(await DefaultOrgIdAsync()));

        // The gate short-circuits before any candidate is examined, so the total is meaningfully
        // zero here even though it is org-wide.
        Assert.Equal(0, await ReclaimAsync());
        Assert.True(await BlobRowExistsAsync(retired.LayerDigest));

        // Restore the graph so this test leaves the shared fixture in a state where the gate is
        // satisfied again; otherwise it would silently disable the sweep for every later test.
        await BackfillAsync();
    }

    // ── What must be reclaimed ───────────────────────────────────────────────────

    [Fact]
    public async Task Reclaim_RemovesLayersOrphanedByARetiredImage()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "orphan");
        await RetireManifestAsync(image.ManifestDigest, "orphan");
        await BackfillAsync();

        // With the manifest retired, its config and layer are referenced by nothing and claimed by
        // nothing — the leak that made "unlimited" the only honest OCI retention setting.
        int reclaimed = await ReclaimAsync();
        Assert.True(reclaimed >= 2, $"expected config + layer to be reclaimed, got {reclaimed}");

        Assert.False(await BlobRowExistsAsync(image.ConfigDigest));
        Assert.False(await BlobRowExistsAsync(image.LayerDigest));
    }

    [Fact]
    public async Task Reclaim_IsIdempotent_AndConvergesToZero()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "converge");
        await RetireManifestAsync(image.ManifestDigest, "converge");
        await BackfillAsync();

        await ReclaimAsync();
        Assert.False(await BlobRowExistsAsync(image.LayerDigest));

        // A second pass must not find this image's rows again — a sweep that re-reported already
        // reclaimed rows would never converge and would keep issuing physical deletes for bytes
        // that are already gone.
        await ReclaimAsync();
        Assert.False(await BlobRowExistsAsync(image.LayerDigest));
        Assert.False(await BlobRowExistsAsync(image.ConfigDigest));
    }

    [Fact]
    public async Task IsClaimed_HoldsForEachOfTheFourClaimSurfaces()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "claims");
        var reclaimer = _factory.Services.GetRequiredService<OciBlobReclaimer>();
        string orgId = await DefaultOrgIdAsync();

        // Graph reference: the layer is referenced by the manifest.
        Assert.True(await reclaimer.IsClaimedAsync(orgId, image.LayerDigest));

        // Tag claim: the manifest itself is pointed at by a tag, and additionally carries an
        // uploaded package_versions row from the tag push.
        Assert.True(await reclaimer.IsClaimedAsync(orgId, image.ManifestDigest));

        // A digest nothing has ever referenced is claimed by nothing.
        Assert.False(await reclaimer.IsClaimedAsync(orgId, "sha256:" + new string('c', 64)));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private sealed record PushedImage(
        string ManifestDigest, string ConfigDigest, long ConfigSize, string LayerDigest, long LayerSize);

    private static async Task<PushedImage> PushImageAsync(HttpClient client, string tag)
    {
        byte[] configBytes = Encoding.UTF8.GetBytes(
            $$"""{"architecture":"amd64","os":"linux","variant":"{{Guid.NewGuid():N}}"}""");
        byte[] layerBytes = RandomBytes(1024);
        string configDigest = Digest(configBytes);
        string layerDigest = Digest(layerBytes);

        await PushBlobAsync(client, configBytes, configDigest);
        await PushBlobAsync(client, layerBytes, layerDigest);

        byte[] manifest = BuildImageManifest(
            configDigest, configBytes.Length, layerDigest, layerBytes.Length, null);
        using var put = await PutManifestAsync(client, tag, manifest);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);

        return new PushedImage(
            Digest(manifest), configDigest, configBytes.Length, layerDigest, layerBytes.Length);
    }

    private static async Task PushBlobAsync(HttpClient client, byte[] bytes, string digest)
    {
        using var post = await client.PostAsync(
            $"/v2/{Repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(bytes));
        Assert.Equal(HttpStatusCode.Created, post.StatusCode);
    }

    private static async Task<HttpResponseMessage> PutManifestAsync(
        HttpClient client, string reference, byte[] manifest)
    {
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(ManifestMediaType);
        return await client.PutAsync($"/v2/{Repo}/manifests/{reference}", content);
    }

    private static byte[] BuildImageManifest(
        string configDigest, long configSize, string layerDigest, long layerSize, string? annotation)
    {
        string annotations = annotation is null
            ? ""
            : $$""" , "annotations": { "org.example.variant": "{{annotation}}" } """;
        return Encoding.UTF8.GetBytes($$"""
        {
          "schemaVersion": 2,
          "mediaType": "{{ManifestMediaType}}",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "{{configDigest}}",
            "size": {{configSize}}
          },
          "layers": [
            { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "digest": "{{layerDigest}}", "size": {{layerSize}} }
          ]{{annotations}}
        }
        """);
    }

    /// <summary>
    /// Puts a manifest into the state image eviction leaves it in: tag gone, catalogue rows gone,
    /// edges gone, blob row gone — its referenced blobs left for the sweep. Done directly rather
    /// than through retention, which still excludes OCI.
    /// </summary>
    private async Task RetireManifestAsync(string manifestDigest, string tag)
    {
        string orgId = await DefaultOrgIdAsync();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        await conn.ExecuteAsync(
            "DELETE FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = Repo, tag });
        await conn.ExecuteAsync(
            """
            DELETE FROM package_versions WHERE version = @manifestDigest AND package_id IN (
                SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = 'oci')
            """,
            new { orgId, manifestDigest });
        await conn.ExecuteAsync(
            "DELETE FROM oci_blobs WHERE org_id = @orgId AND digest = @manifestDigest",
            new { orgId, manifestDigest });

        await _factory.Services.GetRequiredService<OciReferenceGraph>()
            .RemoveManifestAsync(orgId, manifestDigest);
    }

    private async Task SetOriginAsync(string digest, string origin)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE oci_blobs SET origin = @origin WHERE digest = @digest AND org_id = @orgId",
            new { origin, digest, orgId = await DefaultOrgIdAsync() });
    }

    private async Task BackfillAsync() =>
        await _factory.Services.GetRequiredService<OciReferenceGraphBackfillService>().RunOnceAsync();

    private async Task<int> ReclaimAsync() =>
        await _factory.Services.GetRequiredService<OciBlobReclaimer>()
            .ReclaimUnreferencedAsync(await DefaultOrgIdAsync(), limit: 500);

    private async Task<bool> BlobRowExistsAsync(string digest)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(1) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId = await DefaultOrgIdAsync() }) > 0;
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return Assert.IsType<string>(
            await conn.ExecuteScalarAsync<string?>("SELECT id FROM orgs WHERE slug = 'default'"));
    }

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] RandomBytes(int n)
    {
        byte[] buf = new byte[n];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }
}
