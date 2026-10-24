using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Edge;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Tests.Integration;

/// <summary>
/// An edge node under its master's OCI pull gate. The edge holds no scan results and no copy of
/// the master's org settings; the master states each org's posture on its manifest responses. For
/// an org the master gates, the edge never answers a manifest from its own warm cache and never
/// stale-serves one through a master outage; for an org at <c>off</c>, or whose posture the master
/// has never stated, it keeps answering from its cache through an outage.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciScanEdgeTests : IAsyncLifetime
{
    private const string Repo = "library/edge-app";

    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private readonly FakeOciRegistry _registry = new(Repo);
    private DependablyFactory _edge = null!;

    // The master's behaviour, as this edge sees it.
    private string _posture = "off";
    private string? _refuseWith;
    private bool _down;
    private int _manifestCalls;

    // Whether this master also states its posture on blob responses it gates, and the blob digests
    // it refuses by policy (a manifest read through the blob route).
    private bool _statePostureOnBlobs;
    private readonly HashSet<string> _refusedBlobs = [];

    // A master that answers without stating a posture: one that predates the header, or one
    // answering this edge anonymously.
    private bool _omitPosture;

    // The posture store the edge's request path reads. Clearing it stands in for an edge restart:
    // the next request builds a fresh store with nothing in memory, reading only what was persisted.
    private EdgeOciScanPostureStore? _postureStore;

    public async Task InitializeAsync()
    {
        _edge = new DependablyFactory
        {
            DeploymentMode = "edge",
            FrozenClock = _clock,
            OciUpstreamHandler = Master,
            ServiceOverrides = services =>
            {
                services.RemoveAll<EdgeOciScanPostureStore>();
                services.AddTransient(sp => _postureStore ??= new EdgeOciScanPostureStore(
                    sp.GetRequiredService<IMetadataStore>(), sp.GetRequiredService<TimeProvider>()));
            },
        };
        await _edge.InitializeAsync();
    }

    private void RestartPostureStore() => _postureStore = null;

    public async Task DisposeAsync() => await _edge.DisposeAsync();

    private HttpResponseMessage Master(HttpRequestMessage req)
    {
        bool manifest = FakeOciRegistry.IsManifestUrl(req.RequestUri!.AbsoluteUri);
        if (manifest)
        {
            Interlocked.Increment(ref _manifestCalls);
        }

        if (_down)
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }

        string path = req.RequestUri!.AbsolutePath;
        var resp = manifest && _refuseWith is { } reason
            ? Refusal(reason)
            : !manifest && _refuseWith is { } blobReason && _refusedBlobs.Contains(path[(path.LastIndexOf('/') + 1)..])
                ? Refusal(blobReason)
                : _registry.Respond(req);
        if ((manifest || _statePostureOnBlobs) && !_omitPosture)
        {
            resp.Headers.TryAddWithoutValidation("X-Dependably-Oci-Scan-Enforcement", _posture);
        }

        return resp;
    }

    private static HttpResponseMessage Refusal(string reason) =>
        new(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("""{"errors":[{"code":"DENIED","message":"blocked"}]}"""),
            Headers = { { "X-Dependably-Block-Reason", reason } },
        };

    [Fact]
    public async Task AnOffOrg_IsAnsweredFromTheWarmCache_AndStaleServedThroughAnOutage()
    {
        var image = _registry.AddImage("off");
        _registry.Tag("v1", image.Digest);
        using var client = _edge.CreateClient();

        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        int calls = Volatile.Read(ref _manifestCalls);
        using (var warm = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
            Assert.Equal("HIT", warm.Headers.GetValues("X-Cache").Single());
        }

        Assert.Equal(calls, Volatile.Read(ref _manifestCalls));

        _down = true;
        _clock.Advance(TimeSpan.FromHours(2));
        using var stale = await client.GetAsync($"/v2/{Repo}/manifests/v1");
        Assert.Equal(HttpStatusCode.OK, stale.StatusCode);
        Assert.Equal("STALE", stale.Headers.GetValues("X-Cache").Single());
    }

    [Fact]
    public async Task AnOffOrg_IsAskedOfTheMasterAgain_OnceItsOffPostureIsStale()
    {
        var image = _registry.AddImage("off-stale");
        _registry.Tag("v1", image.Digest);
        using var client = _edge.CreateClient();
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        int afterFirst = Volatile.Read(ref _manifestCalls);
        _clock.Advance(Dependably.Infrastructure.Edge.EdgeOciScanPostureStore.OffFreshness - TimeSpan.FromSeconds(1));
        using (var within = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, within.StatusCode);
        }

        Assert.Equal(afterFirst, Volatile.Read(ref _manifestCalls));

        _clock.Advance(TimeSpan.FromSeconds(2));
        using (var after = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, after.StatusCode);
        }

        Assert.True(Volatile.Read(ref _manifestCalls) > afterFirst);
    }

    [Fact]
    public async Task ABlockOrg_IsNeverAnsweredFromTheWarmCache_TheMastersRefusalIsServed()
    {
        _posture = "block";
        var image = _registry.AddImage("block");
        _registry.Tag("v1", image.Digest);
        using var client = _edge.CreateClient();

        // The master serves it (its scan passed): the edge caches it and records the posture.
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        Assert.Equal("block", await RecordedPostureAsync());

        // A KEV lands on the master. The edge holds the manifest warm, but asks the master anyway
        // and answers with its verdict.
        _refuseWith = "kev";
        int calls = Volatile.Read(ref _manifestCalls);
        using (var refused = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("kev", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        Assert.Equal(calls + 1, Volatile.Read(ref _manifestCalls));

        // HEAD is answered the same way.
        using var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/{image.Digest}"));
        Assert.Equal(HttpStatusCode.Forbidden, head.StatusCode);
    }

    [Fact]
    public async Task ABlockOrg_IsRefusedThroughAMasterOutage_RatherThanStaleServed()
    {
        _posture = "block";
        var image = _registry.AddImage("outage");
        _registry.Tag("v1", image.Digest);
        using var client = _edge.CreateClient();
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        _down = true;
        _clock.Advance(TimeSpan.FromHours(2));

        using (var byTag = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, byTag.StatusCode);
            Assert.Equal("unscanned", byTag.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        using var byDigest = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");
        Assert.Equal(HttpStatusCode.Forbidden, byDigest.StatusCode);
        Assert.Equal("unscanned", byDigest.Headers.GetValues("X-Dependably-Block-Reason").Single());
        Assert.Contains("scan enforcement is block", await byDigest.Content.ReadAsStringAsync());
    }

    // A multi-arch pull through an outage: the index by tag (stale-served), then the platform
    // manifest by digest, its manifest bytes on the blob route, and its layer. An org at 'off' is
    // answered from the edge cache however long ago the master last confirmed 'off'.
    [Fact]
    public async Task AnOffOrg_ServesCachedDigestsAndBlobsThroughAnOutage_OnceItsOffIsStale()
    {
        var (platform, index) = await PrimeMultiArchAsync("off-digest");
        Assert.Equal("off", await RecordedPostureAsync());

        _down = true;
        _clock.Advance(TimeSpan.FromHours(2));

        await AssertMultiArchPullServedAsync(platform, index);
    }

    [Fact]
    public async Task AnOffOrg_ServesCachedDigestsAndBlobsThroughAnOutage_AfterARestart()
    {
        var (platform, index) = await PrimeMultiArchAsync("off-restart");

        _down = true;
        RestartPostureStore();
        _clock.Advance(TimeSpan.FromHours(2));

        await AssertMultiArchPullServedAsync(platform, index);
    }

    // The 'off' confirmation survives a restart: within the freshness bound the restarted edge
    // still answers from its cache without asking the master.
    [Fact]
    public async Task AFreshOff_IsStillTrustedAfterARestart()
    {
        var image = _registry.AddImage("off-fresh-restart");
        using var client = _edge.CreateClient();
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        RestartPostureStore();
        _clock.Advance(EdgeOciScanPostureStore.OffFreshness - TimeSpan.FromSeconds(30));
        int calls = Volatile.Read(ref _manifestCalls);
        using var warm = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");

        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
        Assert.Equal("HIT", warm.Headers.GetValues("X-Cache").Single());
        Assert.Equal(calls, Volatile.Read(ref _manifestCalls));
    }

    // Never-stated is not a reason to refuse: an edge upgraded under a master that has not stated a
    // posture (or answers it anonymously) keeps serving what it holds through an outage.
    [Fact]
    public async Task AnOrgWhosePostureWasNeverStated_ServesItsCacheDuringAnOutage()
    {
        _omitPosture = true;
        var (platform, index) = await PrimeMultiArchAsync("never-stated");
        Assert.Null(await RecordedPostureAsync());

        _down = true;
        RestartPostureStore();
        _clock.Advance(TimeSpan.FromHours(2));

        await AssertMultiArchPullServedAsync(platform, index);
    }

    // With nothing cached and nothing recorded, an outage is an upstream failure, not a policy
    // refusal naming a scan the org never asked for.
    [Fact]
    public async Task AnOrgWhosePostureWasNeverSeen_GetsAnUpstreamErrorForWhatItDoesNotHold()
    {
        _registry.Tag("v1", _registry.AddImage("unknown").Digest);
        _down = true;
        using var client = _edge.CreateClient();

        using var response = await client.GetAsync($"/v2/{Repo}/manifests/v1");

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.False(response.Headers.Contains("X-Dependably-Block-Reason"));
    }

    // A block org's manifest answered without a stated posture (the master answering anonymously)
    // says nothing about the org: the edge records nothing, and keeps asking the master.
    [Fact]
    public async Task AManifestAnsweredWithoutAPosture_IsNotRecordedAsOff_AndTheMasterIsStillAsked()
    {
        _posture = "block";
        _omitPosture = true;
        var image = _registry.AddImage("anon-master");
        using var client = _edge.CreateClient();
        using (var first = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        Assert.Null(await RecordedPostureAsync());

        _refuseWith = "kev";
        int calls = Volatile.Read(ref _manifestCalls);
        using var refused = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}");

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal("kev", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
        Assert.Equal(calls + 1, Volatile.Read(ref _manifestCalls));
    }

    // The twin of the off-org outage tests: a gated org's held manifest is never answered from the
    // edge cache while the master is down, on either route, whatever the request shape.
    [Theory]
    [InlineData("block")]
    [InlineData("warn")]
    public async Task AGatedOrgsHeldManifest_IsRefusedOnEveryRouteThroughAnOutage(string posture)
    {
        _posture = posture;
        var (platform, _) = await PrimeMultiArchAsync($"gated-outage-{posture}");
        Assert.Equal(posture, await RecordedPostureAsync());

        _down = true;
        RestartPostureStore();
        _clock.Advance(TimeSpan.FromHours(2));

        using var client = _edge.CreateClient();
        var requests = new List<HttpRequestMessage>
        {
            new(HttpMethod.Get, $"/v2/{Repo}/blobs/{platform.Digest}"),
            new(HttpMethod.Head, $"/v2/{Repo}/blobs/{platform.Digest}"),
            new(HttpMethod.Get, $"/v2/{Repo}/blobs/{platform.Digest}") { Headers = { Range = new System.Net.Http.Headers.RangeHeaderValue(0, 9) } },
            new(HttpMethod.Get, $"/v2/{Repo}/manifests/{platform.Digest}"),
            new(HttpMethod.Head, $"/v2/{Repo}/manifests/{platform.Digest}"),
        };
        foreach (var request in requests)
        {
            string label = $"{request.Method} {request.RequestUri} (range: {request.Headers.Range})";
            using var response = await client.SendAsync(request);

            Assert.True(response.StatusCode == HttpStatusCode.Forbidden, $"{label} answered {(int)response.StatusCode}.");
            Assert.Equal("unscanned", response.Headers.GetValues("X-Dependably-Block-Reason").Single());
            if (request.Method == HttpMethod.Get)
            {
                Assert.Contains($"scan enforcement is {posture}", await response.Content.ReadAsStringAsync());
            }
        }
    }

    // A HEAD of a gated org's held manifest on the blob route is the master's to answer too, not
    // the edge's cached metadata: a 200 there would tell a client a refused image is available.
    [Fact]
    public async Task ABlobRouteHeadOfAGatedOrgsHeldManifest_GetsTheMastersVerdict()
    {
        _posture = "block";
        var (platform, _) = await PrimeMultiArchAsync("gated-blob-head");
        _refuseWith = "kev";
        _refusedBlobs.Add(platform.Digest);
        using var client = _edge.CreateClient();

        using var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{platform.Digest}"));

        Assert.Equal(HttpStatusCode.Forbidden, head.StatusCode);
        Assert.Equal("kev", head.Headers.GetValues("X-Dependably-Block-Reason").Single());

        // The twin: a layer HEAD is still answered from the edge cache.
        using var layer = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{platform.LayerDigest}"));
        Assert.Equal(HttpStatusCode.OK, layer.StatusCode);
    }

    private async Task<(FakeOciRegistry.Image Platform, string Index)> PrimeMultiArchAsync(string seed)
    {
        var platform = _registry.AddImage(seed);
        var (index, _) = _registry.AddIndex(platform);
        _registry.Tag("v1", index);
        using var client = _edge.CreateClient();
        foreach (string path in new[]
                 {
                     $"/v2/{Repo}/manifests/v1",
                     $"/v2/{Repo}/manifests/{platform.Digest}",
                     $"/v2/{Repo}/blobs/{platform.ConfigDigest}",
                     $"/v2/{Repo}/blobs/{platform.LayerDigest}",
                 })
        {
            using var prime = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, prime.StatusCode);
        }

        return (platform, index);
    }

    private async Task AssertMultiArchPullServedAsync(FakeOciRegistry.Image platform, string index)
    {
        using var client = _edge.CreateClient();
        using (var byTag = await client.GetAsync($"/v2/{Repo}/manifests/v1"))
        {
            Assert.Equal(HttpStatusCode.OK, byTag.StatusCode);
            Assert.Equal(index, byTag.Headers.GetValues("Docker-Content-Digest").Single());
        }

        using (var byDigest = await client.GetAsync($"/v2/{Repo}/manifests/{platform.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, byDigest.StatusCode);
            Assert.Equal(platform.Manifest, await byDigest.Content.ReadAsByteArrayAsync());
        }

        using (var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/{platform.Digest}")))
        {
            Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        }

        using (var manifestBlob = await client.GetAsync($"/v2/{Repo}/blobs/{platform.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, manifestBlob.StatusCode);
            Assert.Equal(platform.Manifest, await manifestBlob.Content.ReadAsByteArrayAsync());
        }

        using (var manifestBlobHead = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{platform.Digest}")))
        {
            Assert.Equal(HttpStatusCode.OK, manifestBlobHead.StatusCode);
        }

        using var layer = await client.GetAsync($"/v2/{Repo}/blobs/{platform.LayerDigest}");
        Assert.Equal(HttpStatusCode.OK, layer.StatusCode);
    }

    // The edge learns "off" from a manifest response only; a manifest read through the blob route
    // is gated by the master's decision, so it must go there once the org is gated, whatever label
    // the edge stored the bytes under.
    [Fact]
    public async Task AManifestPrimedThroughTheBlobRouteUnderAGenericLabel_GoesToTheMasterOnceTheOrgIsGated()
    {
        _registry.ServeManifestsAsBlobs = true;
        _registry.BlobRouteManifestType = "application/octet-stream";
        _posture = "warn";
        var other = _registry.AddImage("posture-source");
        var image = _registry.AddImage("generic-label");
        using var client = _edge.CreateClient();
        using (var learn = await client.GetAsync($"/v2/{Repo}/manifests/{other.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, learn.StatusCode);
        }

        using (var prime = await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, prime.StatusCode);
        }

        Assert.Equal("application/octet-stream", await StoredMediaTypeAsync(image.Digest));

        _refuseWith = "kev";
        _refusedBlobs.Add(image.Digest);
        using var refused = await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}");

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal("kev", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());

        // The twin: a layer cached under the same generic label is still served from the edge.
        using var layer = await client.GetAsync($"/v2/{Repo}/blobs/{image.LayerDigest}");
        Assert.Equal(HttpStatusCode.OK, layer.StatusCode);
        int calls = _registry.CallCount;
        using var layerAgain = await client.GetAsync($"/v2/{Repo}/blobs/{image.LayerDigest}");
        Assert.Equal(HttpStatusCode.OK, layerAgain.StatusCode);
        Assert.Equal("HIT", layerAgain.Headers.GetValues("X-Cache").Single());
        Assert.Equal(calls, _registry.CallCount);
    }

    // A stale "off" is not trusted on the blob route either: the master is asked again, rather than
    // the last-known posture standing in for it while the master is reachable.
    [Fact]
    public async Task AManifestReadThroughTheBlobRoute_IsNotServedFromCacheOnAStaleOff()
    {
        _registry.ServeManifestsAsBlobs = true;
        var image = _registry.AddImage("stale-off-blob");
        using var client = _edge.CreateClient();
        using (var learn = await client.GetAsync($"/v2/{Repo}/manifests/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, learn.StatusCode);
        }

        using (var warm = await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
        }

        _posture = "block";
        _refuseWith = "kev";
        _refusedBlobs.Add(image.Digest);

        // Within the freshness bound the recorded off still stands.
        using (var within = await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, within.StatusCode);
        }

        _clock.Advance(Dependably.Infrastructure.Edge.EdgeOciScanPostureStore.OffFreshness + TimeSpan.FromSeconds(1));
        using var stale = await client.GetAsync($"/v2/{Repo}/blobs/{image.Digest}");

        Assert.Equal(HttpStatusCode.Forbidden, stale.StatusCode);
        Assert.Equal("kev", stale.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    [Fact]
    public async Task ABlobResponse_RecordsTheMastersStatedPosture()
    {
        _statePostureOnBlobs = true;
        _posture = "block";
        var image = _registry.AddImage("blob-posture");
        using var client = _edge.CreateClient();

        using var layer = await client.GetAsync($"/v2/{Repo}/blobs/{image.LayerDigest}");

        Assert.Equal(HttpStatusCode.OK, layer.StatusCode);
        Assert.Equal("block", await RecordedPostureAsync());
    }

    // Only a manifest response can say "off" by carrying no header; a layer the master does not
    // gate says nothing.
    [Fact]
    public async Task AHeaderlessBlobResponse_IsNotRecordedAsOff()
    {
        var image = _registry.AddImage("headerless-blob");
        using var client = _edge.CreateClient();

        using var layer = await client.GetAsync($"/v2/{Repo}/blobs/{image.LayerDigest}");

        Assert.Equal(HttpStatusCode.OK, layer.StatusCode);
        Assert.Null(await RecordedPostureAsync());
    }

    private async Task<string?> StoredMediaTypeAsync(string digest)
    {
        TestHarnessDbScope.Enter();
        await using var conn = await _edge.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<string?>("SELECT media_type FROM oci_blobs WHERE digest = @digest", new { digest });
    }

    private async Task<string?> RecordedPostureAsync()
    {
        TestHarnessDbScope.Enter();
        await using var conn = await _edge.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<string?>("SELECT posture FROM edge_oci_scan_postures");
    }
}
