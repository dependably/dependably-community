using System.Text;
using Dapper;
using Dependably.Infrastructure.OciScan;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// What a scanner may read of the image it leased, and nothing else: the root manifest and
/// whatever the recorded reference graph reaches from it. A digest outside that closure, or in a
/// manifest whose closure is unknown, is not found; bytes the store no longer holds are refetched
/// from the upstream for a proxied image and reported unavailable for a hosted one; an upstream
/// that cannot answer is unavailable, never an empty success.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanImageReaderTests : IAsyncLifetime
{
    private OciResolverHarness _h = null!;
    private OciScanImageReader _reader = null!;
    private OciReferenceGraph _graph = null!;

    public async Task InitializeAsync() => await BuildAsync();

    public async Task DisposeAsync() => await _h.DisposeAsync();

    private async Task BuildAsync(bool airGapped = false, Func<HttpRequestMessage, HttpResponseMessage?>? intercept = null)
    {
        if (_h is not null)
        {
            await _h.DisposeAsync();
        }

        _h = await OciResolverHarness.CreateAsync(airGapped, intercept);
        _graph = new OciReferenceGraph(_h.Db);
        _reader = new OciScanImageReader(
            _h.Db, _graph, new TieredBlobStorage(_h.Cache, _h.Registry), _h.Resolver,
            NullLogger<OciScanImageReader>.Instance);
    }

    private OciScanJob Job(string digest, bool hosted = false)
        => new("job-1", _h.OrgId, hosted ? OciScanOwner.Hosted("pv-1") : OciScanOwner.Proxied("ca-1"),
            OciResolverHarness.Repository, digest, "scan", 1, "2026-06-15T13:00:00Z");

    private static string Key(string digest)
    {
        string[] parts = digest.Split(':');
        return BlobKeys.OciBlob(parts[0], parts[1]);
    }

    private async Task StoreAsync(
        string digest, byte[] bytes, string mediaType, string origin = "proxy", bool putBytes = true)
    {
        await using (var conn = await _h.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
                VALUES (@digest, @orgId, @mediaType, @size, @key, @origin)
                """,
                new { digest, orgId = _h.OrgId, mediaType, size = bytes.Length, key = Key(digest), origin });
        }

        if (putBytes)
        {
            await (origin == "proxy" ? _h.Cache : _h.Registry).PutAsync(Key(digest), new MemoryStream(bytes));
        }
    }

    private static async Task<byte[]> ReadAllAsync(Stream? s)
    {
        await using (s)
        {
            using var ms = new MemoryStream();
            await s!.CopyToAsync(ms);
            return ms.ToArray();
        }
    }

    // ── the closure ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task TheRootManifest_InTheProxyTier_IsServedWithItsMediaTypeAndSize()
    {
        var image = _h.Upstream.AddImage("root");
        await StoreAsync(image.Digest, image.Manifest, FakeOciRegistry.ImageManifestType);

        var read = await _reader.ReadAsync(Job(image.Digest), image.Digest, manifest: true);

        Assert.Equal(OciScanReadOutcome.Found, read.Outcome);
        Assert.Equal(FakeOciRegistry.ImageManifestType, read.MediaType);
        Assert.Equal(image.Manifest.Length, read.SizeBytes);
        Assert.Equal(image.Manifest, await ReadAllAsync(read.Content));
    }

    [Fact]
    public async Task AnUploadedRootManifest_IsReadFromTheRegistryTier()
    {
        var image = _h.Upstream.AddImage("hosted");
        await StoreAsync(image.Digest, image.Manifest, FakeOciRegistry.ImageManifestType, origin: "uploaded");

        var read = await _reader.ReadAsync(Job(image.Digest, hosted: true), image.Digest, manifest: true);

        Assert.Equal(OciScanReadOutcome.Found, read.Outcome);
        Assert.Equal(image.Manifest, await ReadAllAsync(read.Content));
    }

    [Fact]
    public async Task AStoredRowWithoutAMediaType_IsServedAsOctetStream()
    {
        var image = _h.Upstream.AddImage("typeless");
        await StoreAsync(image.ConfigDigest, Encoding.UTF8.GetBytes("{}"), "");
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, image.LayerDigest]);

        var read = await _reader.ReadAsync(Job(image.Digest), image.ConfigDigest, manifest: false);

        Assert.Equal(OciScanReadOutcome.Found, read.Outcome);
        Assert.Equal("", read.MediaType);
    }

    [Fact]
    public async Task ABlobOfTheImage_ReachableThroughTheGraph_IsServed_AndOneOutsideItIsNotFound()
    {
        var image = _h.Upstream.AddImage("graph");
        var other = _h.Upstream.AddImage("other");
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, image.LayerDigest]);
        await StoreAsync(image.LayerDigest, Encoding.UTF8.GetBytes("layer-bytes-graph"), "application/vnd.oci.image.layer.v1.tar+gzip");
        await StoreAsync(other.LayerDigest, Encoding.UTF8.GetBytes("layer-bytes-other"), "application/vnd.oci.image.layer.v1.tar+gzip");

        var inside = await _reader.ReadAsync(Job(image.Digest), image.LayerDigest, manifest: false);
        var outside = await _reader.ReadAsync(Job(image.Digest), other.LayerDigest, manifest: false);

        Assert.Equal(OciScanReadOutcome.Found, inside.Outcome);
        Assert.Equal(OciScanRead.NotFound, outside);
        Assert.Empty(_h.Requests);
        await inside.Content!.DisposeAsync();
    }

    [Fact]
    public async Task AnImageWhoseClosureIsUnknown_ExposesNothingBeyondItsRoot()
    {
        var image = _h.Upstream.AddImage("legacy");
        await StoreAsync(image.LayerDigest, Encoding.UTF8.GetBytes("layer-bytes-legacy"), "application/octet-stream");

        var read = await _reader.ReadAsync(Job(image.Digest), image.LayerDigest, manifest: false);

        Assert.Equal(OciScanRead.NotFound, read);
    }

    [Fact]
    public async Task AnIndexReachesItsChildrensLayers_OnlyOnceTheChildManifestsClosureIsRecorded()
    {
        var amd64 = _h.Upstream.AddImage("amd64");
        var arm64 = _h.Upstream.AddImage("arm64");
        var (indexDigest, _) = _h.Upstream.AddIndex(amd64, arm64);
        await _graph.RecordAsync(_h.OrgId, indexDigest, [amd64.Digest, arm64.Digest]);

        Assert.True(await _reader.IsInImageAsync(_h.OrgId, indexDigest, indexDigest));
        Assert.True(await _reader.IsInImageAsync(_h.OrgId, indexDigest, amd64.Digest));
        Assert.False(await _reader.IsInImageAsync(_h.OrgId, indexDigest, amd64.LayerDigest));

        await _graph.RecordAsync(_h.OrgId, amd64.Digest, [amd64.ConfigDigest, amd64.LayerDigest]);

        Assert.True(await _reader.IsInImageAsync(_h.OrgId, indexDigest, amd64.LayerDigest));
        Assert.False(await _reader.IsInImageAsync(_h.OrgId, indexDigest, arm64.LayerDigest));
        Assert.False(await _reader.IsInImageAsync("another-org", indexDigest, amd64.LayerDigest));
    }

    [Fact]
    public async Task AGraphThatLoopsBackOnItself_TerminatesAndRefusesAnUnreachableDigest()
    {
        var a = _h.Upstream.AddImage("loop-a");
        var b = _h.Upstream.AddImage("loop-b");
        await _graph.RecordAsync(_h.OrgId, a.Digest, [b.Digest]);
        await _graph.RecordAsync(_h.OrgId, b.Digest, [a.Digest]);

        Assert.False(await _reader.IsInImageAsync(_h.OrgId, a.Digest, a.LayerDigest));
    }

    // ── bytes the store no longer holds ─────────────────────────────────────────

    [Fact]
    public async Task AnEvictedBlob_OfAProxiedImage_IsRefetchedFromTheUpstreamByDigest()
    {
        var image = _h.Upstream.AddImage("evicted");
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, image.LayerDigest]);
        await StoreAsync(image.LayerDigest, Encoding.UTF8.GetBytes("layer-bytes-evicted"), "application/octet-stream", putBytes: false);

        var read = await _reader.ReadAsync(Job(image.Digest), image.LayerDigest, manifest: false);

        Assert.Equal(OciScanReadOutcome.Found, read.Outcome);
        Assert.Equal("layer-bytes-evicted", Encoding.UTF8.GetString(await ReadAllAsync(read.Content)));
        Assert.Contains(_h.Requests, r => r.Contains($"/blobs/{image.LayerDigest}", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ABlobNeverCached_OfAProxiedImage_IsFetchedFromTheUpstream()
    {
        var image = _h.Upstream.AddImage("never-cached");
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, image.LayerDigest]);

        var read = await _reader.ReadAsync(Job(image.Digest), image.ConfigDigest, manifest: false);

        Assert.Equal(OciScanReadOutcome.Found, read.Outcome);
        await read.Content!.DisposeAsync();
    }

    [Fact]
    public async Task AnEvictedRootManifest_IsRefetchedByDigest_WithItsMediaTypeAndSize()
    {
        var image = _h.Upstream.AddImage("manifest-evicted");

        var read = await _reader.ReadAsync(Job(image.Digest), image.Digest, manifest: true);

        Assert.Equal(OciScanReadOutcome.Found, read.Outcome);
        Assert.Equal(FakeOciRegistry.ImageManifestType, read.MediaType);
        Assert.Equal(image.Manifest, await ReadAllAsync(read.Content));
    }

    [Fact]
    public async Task AnEvictedManifestTheUpstreamNoLongerHas_IsUnavailable_NotAnEmptySuccess()
    {
        string gone = FakeOciRegistry.Digest(Encoding.UTF8.GetBytes("a manifest nobody serves"));

        var read = await _reader.ReadAsync(Job(gone), gone, manifest: true);

        Assert.Equal(OciScanRead.Unavailable, read);
    }

    [Fact]
    public async Task AnEvictedBlobTheUpstreamNoLongerHas_IsUnavailable()
    {
        var image = _h.Upstream.AddImage("blob-gone");
        string missing = FakeOciRegistry.Digest(Encoding.UTF8.GetBytes("a layer nobody serves"));
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, missing]);

        var read = await _reader.ReadAsync(Job(image.Digest), missing, manifest: false);

        Assert.Equal(OciScanRead.Unavailable, read);
    }

    [Fact]
    public async Task AHostedImageWhoseBytesAreGone_IsUnavailable_WithoutAnyUpstreamAsk()
    {
        var image = _h.Upstream.AddImage("hosted-gone");
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, image.LayerDigest]);
        await StoreAsync(image.LayerDigest, Encoding.UTF8.GetBytes("layer"), "application/octet-stream", origin: "uploaded", putBytes: false);

        var read = await _reader.ReadAsync(Job(image.Digest, hosted: true), image.LayerDigest, manifest: false);

        Assert.Equal(OciScanRead.Unavailable, read);
        Assert.Empty(_h.Requests);
    }

    [Fact]
    public async Task AnUpstreamOutage_IsUnavailable_AndAThrowingUpstreamIsContained()
    {
        var image = _h.Upstream.AddImage("outage");
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, image.LayerDigest]);
        _h.Upstream.Down = true;

        var down = await _reader.ReadAsync(Job(image.Digest), image.LayerDigest, manifest: false);
        Assert.Equal(OciScanRead.Unavailable, down);

        await BuildAsync(intercept: _ => throw new HttpRequestException("connection reset"));
        var image2 = _h.Upstream.AddImage("outage-2");
        await _graph.RecordAsync(_h.OrgId, image2.Digest, [image2.ConfigDigest, image2.LayerDigest]);

        var thrown = await _reader.ReadAsync(Job(image2.Digest), image2.LayerDigest, manifest: false);
        Assert.Equal(OciScanRead.Unavailable, thrown);
    }

    [Fact]
    public async Task AnAirGappedInstance_ReadsStoredBytes_ButNeverReachesOut()
    {
        await BuildAsync(airGapped: true);
        var image = _h.Upstream.AddImage("airgap");
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, image.LayerDigest]);
        await StoreAsync(image.ConfigDigest, Encoding.UTF8.GetBytes("{}"), "application/vnd.oci.image.config.v1+json");

        var stored = await _reader.ReadAsync(Job(image.Digest), image.ConfigDigest, manifest: false);
        var missing = await _reader.ReadAsync(Job(image.Digest), image.LayerDigest, manifest: false);

        Assert.Equal(OciScanReadOutcome.Found, stored.Outcome);
        Assert.Equal(OciScanRead.Unavailable, missing);
        Assert.Empty(_h.Requests);
        await stored.Content!.DisposeAsync();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task AnOrgWithUpstreamFetchingOff_ReadsStoredBytes_ButNeverReachesOut(bool passthrough, bool airGapped)
    {
        await _h.SetUpstreamPostureAsync(passthrough, airGapped);
        var image = _h.Upstream.AddImage("passthrough-off");
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.ConfigDigest, image.LayerDigest]);
        await StoreAsync(image.ConfigDigest, Encoding.UTF8.GetBytes("{}"), "application/vnd.oci.image.config.v1+json");

        var stored = await _reader.ReadAsync(Job(image.Digest), image.ConfigDigest, manifest: false);
        var missingBlob = await _reader.ReadAsync(Job(image.Digest), image.LayerDigest, manifest: false);
        var missingManifest = await _reader.ReadAsync(Job(image.Digest), image.Digest, manifest: true);

        Assert.Equal(OciScanReadOutcome.Found, stored.Outcome);
        Assert.Equal(OciScanRead.Unavailable, missingBlob);
        Assert.Equal(OciScanRead.Unavailable, missingManifest);
        Assert.Empty(_h.Requests);
        await stored.Content!.DisposeAsync();
    }

    [Fact]
    public async Task Mixed_OneLayerRefetchable_OneNot_EachReadIsIndependent()
    {
        var image = _h.Upstream.AddImage("mixed");
        string missing = FakeOciRegistry.Digest(Encoding.UTF8.GetBytes("second layer, not served"));
        await _graph.RecordAsync(_h.OrgId, image.Digest, [image.LayerDigest, missing]);

        var good = await _reader.ReadAsync(Job(image.Digest), image.LayerDigest, manifest: false);
        var bad = await _reader.ReadAsync(Job(image.Digest), missing, manifest: false);
        var good2 = await _reader.ReadAsync(Job(image.Digest), image.LayerDigest, manifest: false);

        Assert.Equal(OciScanReadOutcome.Found, good.Outcome);
        Assert.Equal(OciScanRead.Unavailable, bad);
        Assert.Equal(OciScanReadOutcome.Found, good2.Outcome);
        await good.Content!.DisposeAsync();
        await good2.Content!.DisposeAsync();
    }

    // ── platform manifest reader ────────────────────────────────────────────────

    private OciPlatformManifestReader PlatformReader(IBlobStore? cache = null, IBlobStore? registry = null)
        => new(_h.Db, new TieredBlobStorage(cache ?? _h.Cache, registry ?? _h.Registry),
            NullLogger<OciPlatformManifestReader>.Instance);

    [Fact]
    public async Task PlatformMap_OfAProxiedIndex_ListsEachPlatform()
    {
        var amd64 = _h.Upstream.AddImage("p-amd64");
        var arm64 = _h.Upstream.AddImage("p-arm64");
        var (indexDigest, indexBytes) = _h.Upstream.AddIndex(amd64, arm64);
        await StoreAsync(indexDigest, indexBytes, FakeOciRegistry.ImageIndexType);

        var map = await PlatformReader().ReadAsync(_h.OrgId, indexDigest);

        Assert.Equal(amd64.Digest, map!.ManifestDigestFor("linux/amd64"));
        Assert.Equal(arm64.Digest, map.ManifestDigestFor("linux/arm64"));
        Assert.Null(map.ManifestDigestFor("linux/s390x"));
    }

    [Fact]
    public async Task PlatformMap_OfAHostedSingleImage_MapsEveryPlatformToItself()
    {
        var image = _h.Upstream.AddImage("p-hosted");
        await StoreAsync(image.Digest, image.Manifest, FakeOciRegistry.ImageManifestType, origin: "uploaded");

        var map = await PlatformReader().ReadAsync(_h.OrgId, image.Digest);

        Assert.Equal(image.Digest, map!.ManifestDigestFor("linux/riscv64"));
    }

    [Fact]
    public async Task PlatformMap_FindsBytesInTheOtherTier_WhenTheOriginTierLacksThem()
    {
        var image = _h.Upstream.AddImage("p-moved");
        await StoreAsync(image.Digest, image.Manifest, FakeOciRegistry.ImageManifestType, origin: "proxy", putBytes: false);
        await _h.Registry.PutAsync(Key(image.Digest), new MemoryStream(image.Manifest));

        var map = await PlatformReader().ReadAsync(_h.OrgId, image.Digest);

        Assert.NotNull(map);
    }

    [Fact]
    public async Task PlatformMap_IsNull_ForAnUnknownDigest_AMissingBlob_AndNonManifestBytes()
    {
        var image = _h.Upstream.AddImage("p-null");
        await StoreAsync(image.Digest, image.Manifest, FakeOciRegistry.ImageManifestType, putBytes: false);
        string junk = FakeOciRegistry.Digest(Encoding.UTF8.GetBytes("plain text, not json"));
        await StoreAsync(junk, Encoding.UTF8.GetBytes("plain text, not json"), "text/plain");
        var reader = PlatformReader();

        Assert.Null(await reader.ReadAsync(_h.OrgId, "sha256:" + new string('0', 64)));
        Assert.Null(await reader.ReadAsync(_h.OrgId, image.Digest));
        Assert.Null(await reader.ReadAsync(_h.OrgId, junk));
        Assert.Null(await reader.ReadAsync("another-org", image.Digest));
    }

    [Fact]
    public async Task PlatformMap_IsNull_WhenTheBlobStoreFailsToRead()
    {
        var image = _h.Upstream.AddImage("p-failing");
        await StoreAsync(image.Digest, image.Manifest, FakeOciRegistry.ImageManifestType);

        var map = await PlatformReader(cache: new ThrowingReadStore()).ReadAsync(_h.OrgId, image.Digest);

        Assert.Null(map);
    }

    private sealed class ThrowingReadStore : IBlobStore
    {
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
            => throw new IOException("backing store unreachable");

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Task.CompletedTask;

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => Task.FromResult(false);

        public Task DeleteAsync(string key, CancellationToken ct = default) => Task.CompletedTask;

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Task.FromResult(0L);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => Task.FromResult<RangedStream?>(null);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => AsyncEnumerable.Empty<BlobInfo>();
    }
}
