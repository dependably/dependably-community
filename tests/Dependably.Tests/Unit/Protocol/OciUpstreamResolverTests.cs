using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Unit coverage for <see cref="OciUpstreamResolver"/>.
///
/// Coverage targets:
///  - MatchUpstream: prefix routing, catch-all (""), no match when list empty
///  - FetchManifestAsync: digest ref → cache HIT (DB + blob); tag ref → TTL HIT; tag ref → stale → upstream fetch
///  - FetchManifestAsync: no matching upstream → null
///  - FetchBlobAsync: cache HIT; cache MISS → fetch + SHA-256 verify; digest mismatch → null + evict
///  - FetchBlobAsync: no matching upstream → null
///  - FetchTagsAsync: upstream responds with tag list; 404 → null
///  - Air-gap: all three public methods throw AirGappedException
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamResolverTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _cacheBlobs = new();

    private string _orgId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_db, "oci-resolver-org");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ────────────────────────────────────────────────────────────────

    private OciUpstreamResolver Build(
        IHttpClientFactory? http = null,
        OciOptions? options = null,
        bool airGapped = false)
    {
        var opts = Options.Create(options ?? DefaultOptions());
        var authSvc = new OciUpstreamAuthService(
            http ?? new NeverCallFactory(),
            opts,
            new StubAirGap(false), // auth never needs to be called for cache-hit tests
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        return new OciUpstreamResolver(
            http ?? new NeverCallFactory(),
            authSvc,
            opts,
            blobs,
            _db,
            new StubAirGap(airGapped),
            NullLogger<OciUpstreamResolver>.Instance);
    }

    private static OciOptions DefaultOptions(string? host = "registry-1.docker.io", string prefix = "")
        => new()
        {
            ManifestTagTtl = TimeSpan.FromMinutes(5),
            TokenCacheDuration = TimeSpan.FromMinutes(55),
            Upstreams =
            [
                new OciUpstreamRegistryOptions
                {
                    Name = "dockerhub",
                    Host = host ?? "registry-1.docker.io",
                    AuthType = OciAuthType.Anonymous,
                    Prefixes = [prefix],
                }
            ],
        };

    private static OciOptions OptionsWithNoUpstreams()
        => new() { Upstreams = [] };

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static string Sha256Digest(byte[] data)
        => "sha256:" + Sha256Hex(data);

    private static byte[] RandomBytes(int n = 128)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private async Task<string> SeedManifestAsync(byte[] manifestBytes, string? tag = null)
    {
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);

        await _cacheBlobs.PutAsync(blobKey, new MemoryStream(manifestBytes), default);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size, @blobKey, 'proxy')
            """,
            new { digest, orgId = _orgId, size = (long)manifestBytes.Length, blobKey });

        if (tag is not null)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
                VALUES (@orgId, 'library/ubuntu', @tag, @digest,
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                """,
                new { orgId = _orgId, tag, digest });
        }

        return digest;
    }

    // ── MatchUpstream ──────────────────────────────────────────────────────────

    [Fact]
    public void MatchUpstream_PrefixMatch_ReturnsMatchingEntry()
    {
        var opts = new OciOptions
        {
            Upstreams =
            [
                new() { Name = "ghcr",  Host = "ghcr.io",               Prefixes = ["ghcr/"] },
                new() { Name = "docker", Host = "registry-1.docker.io", Prefixes = ["library/"] },
            ],
        };
        var resolver = Build(options: opts);

        Assert.Equal("ghcr.io", resolver.MatchUpstream("ghcr/myapp")?.Host);
        Assert.Equal("registry-1.docker.io", resolver.MatchUpstream("library/ubuntu")?.Host);
        Assert.Null(resolver.MatchUpstream("private/custom"));
    }

    [Fact]
    public void MatchUpstream_EmptyPrefix_IsCatchAll()
    {
        var opts = new OciOptions
        {
            Upstreams =
            [
                new() { Name = "fallback", Host = "mirror.example.com", Prefixes = [""] },
            ],
        };
        var resolver = Build(options: opts);

        Assert.Equal("mirror.example.com", resolver.MatchUpstream("anything/goes")?.Host);
        Assert.Equal("mirror.example.com", resolver.MatchUpstream("other")?.Host);
    }

    [Fact]
    public void MatchUpstream_EmptyUpstreamList_ReturnsNull()
    {
        var resolver = Build(options: OptionsWithNoUpstreams());
        Assert.Null(resolver.MatchUpstream("library/ubuntu"));
    }

    // ── FetchManifestAsync — cache hits ───────────────────────────────────────

    [Fact]
    public async Task FetchManifestAsync_DigestRef_CacheHit_ReturnsFromCache()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        string digest = await SeedManifestAsync(manifestBytes);

        var resolver = Build(); // NeverCallFactory — no HTTP should be made

        var result = await resolver.FetchManifestAsync(
            _orgId, "library/ubuntu", digest, isDigest: true, default);

        Assert.NotNull(result);
        Assert.Equal(digest, result!.Digest);
    }

    [Fact]
    public async Task FetchManifestAsync_TagRef_WithinTtl_ReturnsFromCache()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        await SeedManifestAsync(manifestBytes, tag: "latest");

        var resolver = Build(); // NeverCallFactory

        var result = await resolver.FetchManifestAsync(
            _orgId, "library/ubuntu", "latest", isDigest: false, default);

        Assert.NotNull(result);
    }

    // ── FetchManifestAsync — stale tag → upstream ─────────────────────────────

    [Fact]
    public async Task FetchManifestAsync_TagRef_Stale_FetchesFromUpstream()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "stale-tag-org");

        // Seed a tag that was revalidated long ago (outside TTL).
        byte[] oldManifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"old\":true}");
        string oldSha256 = Sha256Hex(oldManifestBytes);
        string oldDigest = "sha256:" + oldSha256;
        string oldBlobKey = BlobKeys.OciBlob("sha256", oldSha256);
        await _cacheBlobs.PutAsync(oldBlobKey, new MemoryStream(oldManifestBytes), default);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@d, @o, 'application/vnd.oci.image.manifest.v1+json', @s, @k, 'proxy')
            """,
            new { d = oldDigest, o = orgId, s = (long)oldManifestBytes.Length, k = oldBlobKey });
        // last_revalidated is 2 hours ago — outside the default 5-min TTL.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
            VALUES (@o, 'library/ubuntu', 'latest', @d, '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')
            """,
            new { o = orgId, d = oldDigest });

        // Upstream will return a new manifest.
        byte[] newManifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"new\":true}");
        string newSha256 = Sha256Hex(newManifestBytes);
        string newDigest = "sha256:" + newSha256;

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(newManifestBytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        upstreamResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", newDigest);

        var http = new SingleResponseFactory(upstreamResp);

        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance);

        var result = await resolver.FetchManifestAsync(orgId, "library/ubuntu", "latest", isDigest: false, default);

        Assert.NotNull(result);
        Assert.Equal(newDigest, result!.Digest);
    }

    [Fact]
    public async Task FetchManifestAsync_UpstreamDigestHeaderMismatch_UsesComputedDigest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "digest-mismatch-org");

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"x\":1}");
        string computedDigest = "sha256:" + Sha256Hex(manifestBytes);
        string bogusDigest = "sha256:" + new string('b', 64); // upstream lies / MITM

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(manifestBytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        upstreamResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", bogusDigest);

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance);

        var result = await resolver.FetchManifestAsync(orgId, "library/ubuntu", "latest", isDigest: false, default);

        Assert.NotNull(result);
        // The unverified upstream header must NOT become the stored identity; computed wins so a
        // by-digest fetch returns bytes that hash to the requested digest (OCI spec invariant).
        Assert.Equal(computedDigest, result!.Digest);
        Assert.NotEqual(bogusDigest, result.Digest);

        await using var conn = await _db.OpenAsync();
        string? storedTagDigest = await conn.ExecuteScalarAsync<string>(
            "SELECT digest FROM oci_tags WHERE org_id = @o AND repository = 'library/ubuntu' AND tag = 'latest'",
            new { o = orgId });
        Assert.Equal(computedDigest, storedTagDigest);
    }

    // ── FetchManifestAsync — no upstream ──────────────────────────────────────

    [Fact]
    public async Task FetchManifestAsync_NoMatchingUpstream_ReturnsNull()
    {
        var resolver = Build(options: OptionsWithNoUpstreams());

        var result = await resolver.FetchManifestAsync(
            _orgId, "library/ubuntu", "latest", isDigest: false, default);

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchManifestAsync_UpstreamReturns401_ReturnsNull_DoesNotThrow()
    {
        // Regression test: Docker Hub returns 401 (not 404) for a nonexistent /
        // unauthorized repository, even after the token retry. The resolver must return
        // null — so OciController emits a clean OCI 404 MANIFEST_UNKNOWN — rather than
        // letting an HttpRequestException escape to a 500 with an empty body.
        string orgId = await OrgSeeder.InsertAsync(_db, "oci-401-org");

        var http = new StatusFactory(HttpStatusCode.Unauthorized);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance);

        var result = await resolver.FetchManifestAsync(
            orgId, "library/does-not-exist-xyz", "1.0", isDigest: false, default);

        Assert.Null(result);
    }

    // ── Catalogue surfacing (#: OCI shows up on dashboards / Packages page) ─────

    [Fact]
    public async Task FetchManifestAsync_TagPull_RecordsCataloguePackageAndVersion()
    {
        // A tagged docker pull must land in packages / package_versions — the tables the overview
        // counts and the Packages page read from — not only in oci_blobs/oci_tags. Without this,
        // a successfully-pulled image shows as zero everywhere.
        byte[] manifestBytes = Encoding.UTF8.GetBytes(
            """{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}""");
        string sha256 = Sha256Hex(manifestBytes);
        string digest = "sha256:" + sha256;

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(manifestBytes),
        };
        upstreamResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.docker.distribution.manifest.v2+json");

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance);

        var result = await resolver.FetchManifestAsync(_orgId, "library/ubuntu", "22.04", isDigest: false, default);
        Assert.NotNull(result);

        // Overview stats now count Docker (1 package) and report its real cached footprint.
        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync(_orgId, default);
        Assert.Contains(stats.PackagesByEcosystem, e => e.Ecosystem == "oci" && e.Count == 1);
        Assert.Contains(stats.DiskByEcosystem, d => d.Ecosystem == "oci" && d.TotalBytes == manifestBytes.Length);

        // The version row is the manifest digest, proxy-origin, with the tag captured in the PURL.
        await using var conn = await _db.OpenAsync(default);
        var row = await conn.QuerySingleAsync<(string Version, string Purl, string Origin)>(
            """
            SELECT pv.version, pv.purl, pv.origin
            FROM package_versions pv JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'oci'
            """,
            new { orgId = _orgId });
        Assert.Equal(digest, row.Version);
        Assert.Equal("proxy", row.Origin);
        Assert.StartsWith("pkg:oci/ubuntu@sha256%3A", row.Purl);
        Assert.Contains("tag=22.04", row.Purl);
    }

    // ── FetchBlobAsync — cache hit ─────────────────────────────────────────────

    [Fact]
    public async Task FetchBlobAsync_CacheHit_ReturnsFromBlobStore()
    {
        byte[] blobBytes = RandomBytes(256);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);
        await _cacheBlobs.PutAsync(blobKey, new MemoryStream(blobBytes), default);

        var resolver = Build(); // NeverCallFactory

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", digest, default);

        Assert.NotNull(result);
        using var ms = new MemoryStream();
        await result!.Content.CopyToAsync(ms);
        Assert.Equal(blobBytes, ms.ToArray());
    }

    // ── FetchBlobAsync — cache miss → upstream ────────────────────────────────

    [Fact]
    public async Task FetchBlobAsync_CacheMiss_FetchesFromUpstream_VerifiesDigest()
    {
        byte[] blobBytes = RandomBytes(512);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(blobBytes)),
        };
        upstreamResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance);

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", digest, default);

        Assert.NotNull(result);
        // Blob should now be in cache.
        Assert.True(await _cacheBlobs.ExistsAsync(BlobKeys.OciBlob("sha256", sha256), default));
    }

    [Fact]
    public async Task FetchBlobAsync_DigestMismatch_ReturnsNull()
    {
        // Upstream returns bytes that don't match the requested digest.
        byte[] blobBytes = RandomBytes(64);
        string wrongDigest = "sha256:" + new string('0', 64); // definitely wrong

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(blobBytes)),
        };
        upstreamResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance);

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", wrongDigest, default);

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchBlobAsync_NoMatchingUpstream_ReturnsNull()
    {
        var resolver = Build(options: OptionsWithNoUpstreams());
        string digest = "sha256:" + new string('a', 64);

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", digest, default);

        Assert.Null(result);
    }

    // ── FetchTagsAsync ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FetchTagsAsync_UpstreamReturnsTags_ReturnsList()
    {
        string[] tags = new[] { "latest", "22.04", "22.10" };
        string json = JsonSerializer.Serialize(new { name = "library/ubuntu", tags });
        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance);

        var result = await resolver.FetchTagsAsync("library/ubuntu", default);

        Assert.NotNull(result);
        Assert.Equal(tags.OrderBy(t => t), result!.OrderBy(t => t));
    }

    [Fact]
    public async Task FetchTagsAsync_UpstreamReturns404_ReturnsNull()
    {
        var upstreamResp = new HttpResponseMessage(HttpStatusCode.NotFound);
        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance);

        var result = await resolver.FetchTagsAsync("library/ubuntu", default);

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchTagsAsync_NoMatchingUpstream_ReturnsNull()
    {
        var resolver = Build(options: OptionsWithNoUpstreams());
        var result = await resolver.FetchTagsAsync("library/ubuntu", default);
        Assert.Null(result);
    }

    // ── Air-gap ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task FetchManifestAsync_AirGapped_Throws()
    {
        var resolver = Build(airGapped: true);
        await Assert.ThrowsAsync<AirGappedException>(() =>
            resolver.FetchManifestAsync(_orgId, "library/ubuntu", "latest", isDigest: false, default));
    }

    [Fact]
    public async Task FetchBlobAsync_AirGapped_Throws()
    {
        var resolver = Build(airGapped: true);
        string digest = "sha256:" + new string('a', 64);
        await Assert.ThrowsAsync<AirGappedException>(() =>
            resolver.FetchBlobAsync(_orgId, "library/ubuntu", digest, default));
    }

    [Fact]
    public async Task FetchTagsAsync_AirGapped_Throws()
    {
        var resolver = Build(airGapped: true);
        await Assert.ThrowsAsync<AirGappedException>(() =>
            resolver.FetchTagsAsync("library/ubuntu", default));
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    private sealed class SingleResponseFactory : IHttpClientFactory
    {
        private readonly HttpResponseMessage _response;
        public SingleResponseFactory(HttpResponseMessage response) => _response = response;
        public HttpClient CreateClient(string name) => new(new FixedHandler(_response));

        private sealed class FixedHandler : HttpMessageHandler
        {
            private readonly HttpResponseMessage _resp;
            public FixedHandler(HttpResponseMessage resp) => _resp = resp;
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
                => Task.FromResult(_resp);
        }
    }

    // Returns a FRESH response with the given status on every SendAsync (so retry loops
    // that re-send don't read a disposed shared instance).
    private sealed class StatusFactory : IHttpClientFactory
    {
        private readonly HttpStatusCode _status;
        public StatusFactory(HttpStatusCode status) => _status = status;
        public HttpClient CreateClient(string name) => new(new Handler(_status));

        private sealed class Handler : HttpMessageHandler
        {
            private readonly HttpStatusCode _status;
            public Handler(HttpStatusCode status) => _status = status;
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
                => Task.FromResult(new HttpResponseMessage(_status));
        }
    }

    private sealed class NeverCallFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new NeverCallHandler());

        private sealed class NeverCallHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
                => throw new InvalidOperationException(
                    $"HTTP call must not be made in this test (URL={request.RequestUri})");
        }
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public StubAirGap(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
    }
}
