using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The real pull sequence a moving tag sees across an upstream rebuild, end to end over HTTP:
/// HEAD the tag, GET the manifest by the returned digest, GET the config and layer blobs — the
/// containerd-snapshotter / BuildKit shape — plus a classic GET-by-tag pull that records the
/// durable <c>oci_tags</c> mapping. Then the upstream repoints the tag, the clock advances past
/// <c>Oci:ManifestTagTtl</c>, and the same sequence must resolve and serve the NEW generation,
/// with the tag row durably repointed.
///
/// The upstream is a hermetic in-test registry served through the factory's
/// <see cref="DependablyFactory.OciUpstreamHandler"/> seam; time is the factory's frozen clock,
/// so TTL expiry is advanced, never slept.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciMovingTagRevalidationTests : IAsyncLifetime
{
    private const string Repo = "library/moving-app";

    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private readonly FakeOciUpstream _upstream = new(Repo);
    private DependablyFactory _factory = null!;

    public async Task InitializeAsync()
    {
        _factory = new DependablyFactory
        {
            FrozenClock = _clock,
            OciUpstreamHandler = _upstream.Respond,
        };
        await _factory.InitializeAsync();
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task MovingTagPullSequence_AcrossUpstreamRebuild_ResolvesNewGenerationAfterTtl()
    {
        var gen1 = FakeOciUpstream.BuildGeneration("gen-1");
        var gen2 = FakeOciUpstream.BuildGeneration("gen-2");
        _upstream.Current = gen1;

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // ── First pull: HEAD tag → GET by digest → GET config + layer blobs ──────
        using (var head = await client.SendAsync(new HttpRequestMessage(
            HttpMethod.Head, $"/v2/{Repo}/manifests/latest")))
        {
            Assert.Equal(HttpStatusCode.OK, head.StatusCode);
            Assert.Equal(gen1.ManifestDigest, head.Headers.GetValues("Docker-Content-Digest").Single());
        }

        using (var manifest = await client.GetAsync($"/v2/{Repo}/manifests/{gen1.ManifestDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, manifest.StatusCode);
            Assert.Equal(gen1.ManifestBytes, await manifest.Content.ReadAsByteArrayAsync());
        }

        using (var config = await client.GetAsync($"/v2/{Repo}/blobs/{gen1.ConfigDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, config.StatusCode);
            Assert.Equal(gen1.ConfigBytes, await config.Content.ReadAsByteArrayAsync());
        }

        using (var layer = await client.GetAsync($"/v2/{Repo}/blobs/{gen1.LayerDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, layer.StatusCode);
            Assert.Equal(gen1.LayerBytes, await layer.Content.ReadAsByteArrayAsync());
        }

        // Classic client shape: GET by tag — this is what records the durable oci_tags mapping.
        using (var byTag = await client.GetAsync($"/v2/{Repo}/manifests/latest"))
        {
            Assert.Equal(HttpStatusCode.OK, byTag.StatusCode);
            Assert.Equal(gen1.ManifestDigest, byTag.Headers.GetValues("Docker-Content-Digest").Single());
        }

        // Within the TTL the tag serves locally — zero upstream dependency.
        int callsBeforeFreshHead = _upstream.CallCount;
        using (var freshHead = await client.SendAsync(new HttpRequestMessage(
            HttpMethod.Head, $"/v2/{Repo}/manifests/latest")))
        {
            Assert.Equal(HttpStatusCode.OK, freshHead.StatusCode);
            Assert.Equal(gen1.ManifestDigest, freshHead.Headers.GetValues("Docker-Content-Digest").Single());
            Assert.Equal("HIT", freshHead.Headers.GetValues("X-Cache").Single());
        }
        Assert.Equal(callsBeforeFreshHead, _upstream.CallCount);

        // ── Upstream rebuilds :latest; the TTL (1h default) expires ──────────────
        _upstream.Current = gen2;
        _clock.Advance(TimeSpan.FromHours(2));

        // Second pull, same sequence: the revalidating HEAD must surface the NEW digest…
        using (var head2 = await client.SendAsync(new HttpRequestMessage(
            HttpMethod.Head, $"/v2/{Repo}/manifests/latest")))
        {
            Assert.Equal(HttpStatusCode.OK, head2.StatusCode);
            Assert.Equal(gen2.ManifestDigest, head2.Headers.GetValues("Docker-Content-Digest").Single());
        }

        // …and the rest of the pull fetches the new generation's content by digest.
        using (var manifest2 = await client.GetAsync($"/v2/{Repo}/manifests/{gen2.ManifestDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, manifest2.StatusCode);
            Assert.Equal(gen2.ManifestBytes, await manifest2.Content.ReadAsByteArrayAsync());
        }

        using (var config2 = await client.GetAsync($"/v2/{Repo}/blobs/{gen2.ConfigDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, config2.StatusCode);
            Assert.Equal(gen2.ConfigBytes, await config2.Content.ReadAsByteArrayAsync());
        }

        using (var layer2 = await client.GetAsync($"/v2/{Repo}/blobs/{gen2.LayerDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, layer2.StatusCode);
            Assert.Equal(gen2.LayerBytes, await layer2.Content.ReadAsByteArrayAsync());
        }

        // GET by tag repoints the durable mapping to the new generation…
        using (var byTag2 = await client.GetAsync($"/v2/{Repo}/manifests/latest"))
        {
            Assert.Equal(HttpStatusCode.OK, byTag2.StatusCode);
            Assert.Equal(gen2.ManifestDigest, byTag2.Headers.GetValues("Docker-Content-Digest").Single());
        }

        // …verified in the database, not just in response headers.
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        var (Digest, PendingDigest) = await conn.QuerySingleAsync<(string Digest, string? PendingDigest)>(
            "SELECT digest AS Digest, pending_digest AS PendingDigest " +
            "FROM oci_tags WHERE repository = @repo AND tag = 'latest'",
            new { repo = Repo });
        Assert.Equal(gen2.ManifestDigest, Digest);
        Assert.Null(PendingDigest);
    }

    /// <summary>
    /// A minimal but protocol-correct OCI upstream: one repository, one moving tag, each
    /// generation a config blob + one layer + a manifest referencing both by digest.
    /// </summary>
    private sealed class FakeOciUpstream
    {
        private readonly string _repo;
        private int _calls;

        public FakeOciUpstream(string repo) => _repo = repo;

        public Generation Current { get; set; } = null!;

        public int CallCount => _calls;

        public sealed record Generation(
            byte[] ManifestBytes, string ManifestDigest,
            byte[] ConfigBytes, string ConfigDigest,
            byte[] LayerBytes, string LayerDigest);

        public static Generation BuildGeneration(string seed)
        {
            byte[] config = Encoding.UTF8.GetBytes(
                """{"architecture":"amd64","os":"linux","config":{"Labels":{"gen":"""
                + $"\"{seed}\"" + "}}}");
            byte[] layer = Encoding.UTF8.GetBytes($"layer-bytes-{seed}");
            string configDigest = Digest(config);
            string layerDigest = Digest(layer);
            byte[] manifest = Encoding.UTF8.GetBytes(
                $$"""
                {"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{{configDigest}}","size":{{config.Length}}},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{{layerDigest}}","size":{{layer.Length}}}]}
                """);
            return new Generation(manifest, Digest(manifest), config, configDigest, layer, layerDigest);
        }

        private static string Digest(byte[] bytes)
            => "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

        public HttpResponseMessage Respond(HttpRequestMessage req)
        {
            Interlocked.Increment(ref _calls);
            string path = req.RequestUri!.AbsolutePath;
            var gen = Current;

            return path switch
            {
                _ when path == $"/v2/{_repo}/manifests/latest"
                    || path == $"/v2/{_repo}/manifests/{gen.ManifestDigest}"
                    => Manifest(req, gen.ManifestBytes, gen.ManifestDigest),
                _ when path == $"/v2/{_repo}/blobs/{gen.ConfigDigest}" => Blob(gen.ConfigBytes),
                _ when path == $"/v2/{_repo}/blobs/{gen.LayerDigest}" => Blob(gen.LayerBytes),
                _ => new HttpResponseMessage(HttpStatusCode.NotFound),
            };
        }

        private static HttpResponseMessage Manifest(HttpRequestMessage req, byte[] bytes, string digest)
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(req.Method == HttpMethod.Head ? [] : bytes),
            };
            resp.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json");
            resp.Content.Headers.ContentLength = bytes.Length;
            resp.Headers.TryAddWithoutValidation("Docker-Content-Digest", digest);
            return resp;
        }

        private static HttpResponseMessage Blob(byte[] bytes)
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(bytes),
            };
            resp.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            return resp;
        }
    }
}
