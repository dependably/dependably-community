using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the manifest → referenced-blob graph that OCI eviction refcounts against.
///
/// The property that matters is not "edges get written" but "a shared layer is never mistaken for
/// an orphan, and an unknown closure is never mistaken for a leaf". Both directions are asserted:
/// what the graph must record, and what it must refuse to record — because every false leaf is a
/// delete of bytes a live image serves from, and the OCI blob namespace has no org segment, so the
/// blast radius crosses tenants.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciReferenceGraphTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Repo = "team/graph";
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
    private const string IndexMediaType = "application/vnd.oci.image.index.v1+json";

    private readonly DependablyFactory _factory;

    public OciReferenceGraphTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Recording on the hosted push path ────────────────────────────────────────

    [Fact]
    public async Task Push_ImageManifest_RecordsConfigAndLayerEdges()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "1.0.0");

        var edges = await EdgesForAsync(image.ManifestDigest);
        Assert.Equal(
            new[] { image.ConfigDigest, image.LayerDigest }.OrderBy(d => d, StringComparer.Ordinal).ToArray(),
            edges);
    }

    [Fact]
    public async Task Push_ImageIndex_RecordsChildManifestEdges()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var amd64 = await PushImageAsync(client, reference: null);
        var arm64 = await PushImageAsync(client, reference: null);

        byte[] index = BuildIndex(amd64.ManifestDigest, arm64.ManifestDigest);
        string indexDigest = Digest(index);
        using (var put = await PutManifestAsync(client, "multi", index, IndexMediaType))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        // An index's closure is its children, not their layers — the walk recurses one level at a
        // time, so recording a child's layers here would double-count them.
        var edges = await EdgesForAsync(indexDigest);
        Assert.Equal(
            new[] { amd64.ManifestDigest, arm64.ManifestDigest }.OrderBy(d => d, StringComparer.Ordinal).ToArray(),
            edges);
    }

    [Fact]
    public async Task Push_SameManifestTwice_DoesNotDuplicateEdges()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "dup-a");

        // A re-push under a second tag repoints the tag but stores the same manifest digest; the
        // edge upsert must absorb that rather than throwing on the PK.
        using (var put = await PutManifestAsync(client, "dup-b", image.ManifestBytes, ManifestMediaType))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        Assert.Equal(2, (await EdgesForAsync(image.ManifestDigest)).Count);
    }

    // ── The refcount property ────────────────────────────────────────────────────

    [Fact]
    public async Task SharedLayer_StaysReferenced_WhenOneOfTwoManifestsIsRemoved()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Two manifests over the same config and layer blobs — the mirror-then-retag shape that
        // makes layer sharing the norm rather than the exception.
        var first = await PushImageAsync(client, "shared-1");
        byte[] second = BuildImageManifest(
            first.ConfigDigest, first.ConfigSize, first.LayerDigest, first.LayerSize, annotation: "second");
        string secondDigest = Digest(second);
        using (var put = await PutManifestAsync(client, "shared-2", second, ManifestMediaType))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        var graph = _factory.Services.GetRequiredService<OciReferenceGraph>();
        string orgId = await DefaultOrgIdAsync();

        Assert.True(await graph.IsReferencedAsync(orgId, first.LayerDigest));

        // Removing the first manifest's edges must NOT orphan the layer — the second still needs it.
        await graph.RemoveManifestAsync(orgId, first.ManifestDigest);
        Assert.True(await graph.IsReferencedAsync(orgId, first.LayerDigest));

        // Only once the last referencing manifest is gone does the layer become reclaimable.
        await graph.RemoveManifestAsync(orgId, secondDigest);
        Assert.False(await graph.IsReferencedAsync(orgId, first.LayerDigest));
    }

    [Fact]
    public async Task IsClosureKnown_IsFalse_ForAManifestWithNoRecordedEdges()
    {
        var graph = _factory.Services.GetRequiredService<OciReferenceGraph>();
        string orgId = await DefaultOrgIdAsync();

        // The distinction the whole design rests on: "references nothing" is not a state a manifest
        // can be in, so no edges means the closure is unknown and the manifest is un-evictable.
        Assert.False(await graph.IsClosureKnownAsync(orgId, "sha256:" + new string('a', 64)));
    }

    [Fact]
    public async Task RecordAsync_WithNoReferences_DoesNotMarkTheClosureKnown()
    {
        var graph = _factory.Services.GetRequiredService<OciReferenceGraph>();
        string orgId = await DefaultOrgIdAsync();
        string digest = "sha256:" + new string('b', 64);

        // A caller that hands over an empty set must not be able to promote a manifest to
        // "known, references nothing" — that is precisely the false leaf that authorizes a delete.
        await graph.RecordAsync(orgId, digest, []);

        Assert.False(await graph.IsClosureKnownAsync(orgId, digest));
    }

    [Fact]
    public async Task Graph_IsOrgScoped_AndDoesNotLeakAcrossTenants()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "scoped");
        var graph = _factory.Services.GetRequiredService<OciReferenceGraph>();

        Assert.True(await graph.IsReferencedAsync(await DefaultOrgIdAsync(), image.LayerDigest));

        // The same digest under a different tenant is a different question; the graph must not
        // answer it from this org's edges, or one tenant's push would pin another tenant's bytes.
        Assert.False(await graph.IsReferencedAsync("org-that-does-not-exist", image.LayerDigest));
        Assert.False(await graph.IsClosureKnownAsync("org-that-does-not-exist", image.ManifestDigest));
    }

    // ── Backfill of pre-upgrade content ──────────────────────────────────────────

    [Fact]
    public async Task Backfill_RecordsClosureForAManifestStoredBeforeTheGraphExisted()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "backfill-1");

        // Drop the edges to reproduce a manifest pushed by a release that had no graph. The bytes
        // and the oci_blobs row survive, which is exactly the pre-upgrade state.
        string orgId = await DefaultOrgIdAsync();
        await _factory.Services.GetRequiredService<OciReferenceGraph>()
            .RemoveManifestAsync(orgId, image.ManifestDigest);
        Assert.Empty(await EdgesForAsync(image.ManifestDigest));

        var summary = await BuildBackfill().RunOnceAsync();

        Assert.True(summary.Recorded >= 1);
        Assert.Equal(
            new[] { image.ConfigDigest, image.LayerDigest }.OrderBy(d => d, StringComparer.Ordinal).ToArray(),
            await EdgesForAsync(image.ManifestDigest));
    }

    [Fact]
    public async Task Backfill_LeavesClosureUnknown_WhenTheManifestBytesAreGone()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var image = await PushImageAsync(client, "backfill-2");
        string orgId = await DefaultOrgIdAsync();

        await _factory.Services.GetRequiredService<OciReferenceGraph>()
            .RemoveManifestAsync(orgId, image.ManifestDigest);

        // Bytes gone, row surviving: the backfill cannot enumerate a closure it cannot read, and
        // must leave the manifest unrecorded rather than recording it as referencing nothing.
        string blobKey = await ManifestBlobKeyAsync(image.ManifestDigest);
        await _factory.Services.GetRequiredService<Dependably.Storage.TieredBlobStorage>()
            .Registry.DeleteAsync(Dependably.Storage.BlobKeys.StoreKey(blobKey));

        await BuildBackfill().RunOnceAsync();

        Assert.Empty(await EdgesForAsync(image.ManifestDigest));
        Assert.False(await _factory.Services.GetRequiredService<OciReferenceGraph>()
            .IsClosureKnownAsync(orgId, image.ManifestDigest));
    }

    [Fact]
    public async Task Backfill_IsIdempotent_AndConvergesToNoRemainingWork()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        await PushImageAsync(client, "converge");

        var svc = BuildBackfill();
        await svc.RunOnceAsync();

        // A second pass must find nothing: layer and config rows are not manifests and must never
        // re-enter the claim query, or the sweep would churn every tick and never look done.
        var second = await svc.RunOnceAsync();
        Assert.Equal(0, second.Recorded);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private sealed record PushedImage(
        string ManifestDigest, byte[] ManifestBytes,
        string ConfigDigest, long ConfigSize,
        string LayerDigest, long LayerSize);

    /// <summary>
    /// Pushes a config blob, a layer blob, and an image manifest referencing both. Passing a null
    /// reference pushes the manifest by digest, which is how an index's children arrive.
    /// </summary>
    private static async Task<PushedImage> PushImageAsync(HttpClient client, string? reference)
    {
        byte[] configBytes = Encoding.UTF8.GetBytes(
            $$"""{"architecture":"amd64","os":"linux","variant":"{{Guid.NewGuid():N}}"}""");
        byte[] layerBytes = RandomBytes(2048);
        string configDigest = Digest(configBytes);
        string layerDigest = Digest(layerBytes);

        await PushBlobAsync(client, configBytes, configDigest);
        await PushBlobAsync(client, layerBytes, layerDigest);

        byte[] manifest = BuildImageManifest(
            configDigest, configBytes.Length, layerDigest, layerBytes.Length, annotation: null);
        string manifestDigest = Digest(manifest);

        using var put = await PutManifestAsync(client, reference ?? manifestDigest, manifest, ManifestMediaType);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);

        return new PushedImage(
            manifestDigest, manifest, configDigest, configBytes.Length, layerDigest, layerBytes.Length);
    }

    private static async Task PushBlobAsync(HttpClient client, byte[] bytes, string digest)
    {
        using var post = await client.PostAsync(
            $"/v2/{Repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(bytes));
        Assert.Equal(HttpStatusCode.Created, post.StatusCode);
    }

    private static async Task<HttpResponseMessage> PutManifestAsync(
        HttpClient client, string reference, byte[] manifest, string mediaType)
    {
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        return await client.PutAsync($"/v2/{Repo}/manifests/{reference}", content);
    }

    private static byte[] BuildImageManifest(
        string configDigest, long configSize, string layerDigest, long layerSize, string? annotation)
    {
        // The annotation varies the manifest bytes (and so its digest) without changing what it
        // references — the shape needed to get two distinct manifests over one shared layer.
        string annotations = annotation is null
            ? ""
            : $$""" , "annotations": { "org.example.variant": "{{annotation}}" } """;
        string json = $$"""
        {
          "schemaVersion": 2,
          "mediaType": "{{ManifestMediaType}}",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "{{configDigest}}",
            "size": {{configSize}}
          },
          "layers": [
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "digest": "{{layerDigest}}",
              "size": {{layerSize}}
            }
          ]{{annotations}}
        }
        """;
        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] BuildIndex(string firstChild, string secondChild)
    {
        string json = $$"""
        {
          "schemaVersion": 2,
          "mediaType": "{{IndexMediaType}}",
          "manifests": [
            {
              "mediaType": "{{ManifestMediaType}}",
              "digest": "{{firstChild}}",
              "size": 100,
              "platform": { "architecture": "amd64", "os": "linux" }
            },
            {
              "mediaType": "{{ManifestMediaType}}",
              "digest": "{{secondChild}}",
              "size": 100,
              "platform": { "architecture": "arm64", "os": "linux" }
            }
          ]
        }
        """;
        return Encoding.UTF8.GetBytes(json);
    }

    /// <summary>
    /// Builds the backfill sweep against the running factory's services. Constructed directly
    /// rather than resolved, because it is registered as a hosted service and its cron schedule is
    /// irrelevant to a test that drives RunOnceAsync itself.
    /// </summary>
    private OciReferenceGraphBackfillService BuildBackfill()
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OCI_REFERENCE_BACKFILL_SCHEDULE"] = "0 0 1 1 0",
            })
            .Build();
        var clock = _factory.Services.GetRequiredService<TimeProvider>();
        return new OciReferenceGraphBackfillService(
            _factory.Services.GetRequiredService<IMetadataStore>(),
            _factory.Services.GetRequiredService<Dependably.Storage.TieredBlobStorage>(),
            _factory.Services.GetRequiredService<IAirGapMode>(),
            cfg,
            NullLogger<OciReferenceGraphBackfillService>.Instance,
            clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(clock));
    }

    private async Task<IReadOnlyList<string>> EdgesForAsync(string manifestDigest)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        var rows = await conn.QueryAsync<string>(
            "SELECT blob_digest FROM oci_manifest_blobs WHERE manifest_digest = @manifestDigest ORDER BY blob_digest",
            new { manifestDigest });
        return rows.AsList();
    }

    private async Task<string> ManifestBlobKeyAsync(string digest)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return Assert.IsType<string>(
            await conn.ExecuteScalarAsync<string?>(
                "SELECT blob_key FROM oci_blobs WHERE digest = @digest", new { digest }));
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
