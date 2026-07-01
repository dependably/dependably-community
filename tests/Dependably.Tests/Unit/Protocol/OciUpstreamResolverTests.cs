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

        // Seed a default catch-all upstream for _orgId so tests that fetch library/ubuntu
        // via the inline resolver have a matching route without seeding per-test.
        await SeedOciUpstreamAsync(_orgId, "registry-1.docker.io", [""], position: 0);
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
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        return new OciUpstreamResolver(
            http ?? new NeverCallFactory(),
            authSvc,
            opts,
            blobs,
            _db,
            new StubAirGap(airGapped),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());
    }

    private static OciOptions DefaultOptions()
        => new()
        {
            ManifestTagTtl = TimeSpan.FromMinutes(5),
            TokenCacheDuration = TimeSpan.FromMinutes(55),
        };

    /// <summary>
    /// Seeds one OCI upstream_registry row for the given org directly into the DB.
    /// Mirrors the shape AddOciAsync writes so MatchUpstreamAsync and BuildOciUpstreamsForOrgAsync
    /// pick it up during tests.
    /// </summary>
    private async Task SeedOciUpstreamAsync(
        string orgId, string host, string[] prefixes,
        OciAuthType authType = OciAuthType.Anonymous,
        string? name = null,
        int position = 0)
    {
        await using var conn = await _db.OpenAsync();
        string prefixJson = System.Text.Json.JsonSerializer.Serialize(prefixes);
        string authTypeStr = authType switch
        {
            OciAuthType.Anonymous => "anonymous",
            OciAuthType.Basic => "basic",
            OciAuthType.DockerHubTokenExchange => "dockerhub_token_exchange",
            _ => "anonymous",
        };
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, name, url, position, auth_type, prefixes)
            VALUES (@id, @orgId, 'oci', @name, @host, @position, @authType, @prefixes)
            ON CONFLICT (org_id, ecosystem, url) DO NOTHING
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, name = name ?? host, host, position, authType = authTypeStr, prefixes = prefixJson });
    }

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

    // ── MatchUpstreamAsync ─────────────────────────────────────────────────────

    [Fact]
    public async Task MatchUpstreamAsync_PrefixMatch_ReturnsMatchingEntry()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "match-prefix-org");
        // Position 0: ghcr.io routes ghcr/ prefix.
        await SeedOciUpstreamAsync(orgId, "ghcr.io", ["ghcr/"], position: 0);
        // Position 1: docker routes library/ prefix.
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", ["library/"], position: 1);

        var resolver = Build();

        Assert.Equal("ghcr.io", (await resolver.MatchUpstreamAsync(orgId, "ghcr/myapp", default))?.Host);
        Assert.Equal("registry-1.docker.io", (await resolver.MatchUpstreamAsync(orgId, "library/ubuntu", default))?.Host);
        Assert.Null(await resolver.MatchUpstreamAsync(orgId, "private/custom", default));
    }

    [Fact]
    public async Task MatchUpstreamAsync_EmptyPrefix_IsCatchAll()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "catchall-prefix-org");
        await SeedOciUpstreamAsync(orgId, "mirror.example.com", [""], position: 0);

        var resolver = Build();

        Assert.Equal("mirror.example.com", (await resolver.MatchUpstreamAsync(orgId, "anything/goes", default))?.Host);
        Assert.Equal("mirror.example.com", (await resolver.MatchUpstreamAsync(orgId, "other", default))?.Host);
    }

    [Fact]
    public async Task MatchUpstreamAsync_EmptyUpstreamList_ReturnsNull()
    {
        // Use an org with no OCI rows in the DB (OrgSeeder does not seed OCI defaults).
        string orgId = await OrgSeeder.InsertAsync(_db, "no-upstream-org");
        var resolver = Build();
        Assert.Null(await resolver.MatchUpstreamAsync(orgId, "library/ubuntu", default));
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
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

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
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestAsync(orgId, "library/ubuntu", "latest", isDigest: false, default);

        Assert.NotNull(result);
        Assert.Equal(newDigest, result!.Digest);
    }

    [Fact]
    public async Task FetchManifestAsync_UpstreamDigestHeaderMismatch_UsesComputedDigest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "digest-mismatch-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

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
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
        // An org with no OCI rows in upstream_registry returns null (OrgSeeder does not seed them).
        string emptyOrg = await OrgSeeder.InsertAsync(_db, "no-manifest-upstream-org");
        var resolver = Build();

        var result = await resolver.FetchManifestAsync(
            emptyOrg, "library/ubuntu", "latest", isDigest: false, default);

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
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        var http = new StatusFactory(HttpStatusCode.Unauthorized);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", wrongDigest, default);

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchBlobAsync_NoMatchingUpstream_ReturnsNull()
    {
        // An org with no OCI rows in upstream_registry returns null.
        string emptyOrg = await OrgSeeder.InsertAsync(_db, "no-blob-upstream-org");
        var resolver = Build();
        string digest = "sha256:" + new string('a', 64);

        var result = await resolver.FetchBlobAsync(emptyOrg, "library/ubuntu", digest, default);

        Assert.Null(result);
    }

    // ── FetchBlobAsync — digest mismatch leaves content-addressed key unwritten ─

    [Fact]
    public async Task FetchBlobAsync_DigestMismatch_ContentAddressedKeyNeverWritten()
    {
        // Upstream bytes hash to the correct SHA-256, but the requested digest is wrong.
        // The content-addressed blobKey must remain absent (verify-then-commit).
        byte[] blobBytes = RandomBytes(64);
        string wrongHex = new('0', 64); // definitely wrong
        string wrongDigest = "sha256:" + wrongHex;
        string contentAddressedKey = BlobKeys.OciBlob("sha256", wrongHex);

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(blobBytes)),
        };
        upstreamResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", wrongDigest, default);

        Assert.Null(result);
        // Content-addressed key must never have been written.
        Assert.False(await cacheBlobs.ExistsAsync(contentAddressedKey, default));
        // Staging key must also be cleaned up — no oci/_staging/* entries persist.
        var allKeys = await cacheBlobs.ListAsync("oci/_staging/", default)
            .ToListAsync();
        Assert.Empty(allKeys);
    }

    // ── FetchManifestAsync — by-digest mismatch rejects and caches nothing ─────

    [Fact]
    public async Task FetchManifestAsync_ByDigest_Mismatch_ReturnsNull_NothingCached()
    {
        // Upstream returns bytes whose true SHA-256 differs from the requested digest.
        string orgId = await OrgSeeder.InsertAsync(_db, "manifest-digest-mismatch-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"mismatch\":true}");
        string computedHex = Sha256Hex(manifestBytes);
        string wrongRequestedDigest = "sha256:" + new string('f', 64); // not the computed one

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(manifestBytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        upstreamResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", wrongRequestedDigest);

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestAsync(orgId, "library/ubuntu", wrongRequestedDigest, isDigest: true, default);

        Assert.Null(result);
        // Nothing written to cache under either the requested or computed digest key.
        Assert.False(await cacheBlobs.ExistsAsync(BlobKeys.OciBlob("sha256", new string('f', 64)), default));
        Assert.False(await cacheBlobs.ExistsAsync(BlobKeys.OciBlob("sha256", computedHex), default));

        // No oci_blobs row written.
        await using var conn = await _db.OpenAsync(default);
        int blobRows = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM oci_blobs WHERE org_id = @orgId", new { orgId });
        Assert.Equal(0, blobRows);
    }

    [Fact]
    public async Task FetchManifestAsync_ByDigest_Match_CachedAndServed()
    {
        // When the computed digest matches the requested digest, the manifest is cached and returned.
        string orgId = await OrgSeeder.InsertAsync(_db, "manifest-digest-match-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"match\":true}");
        string computedDigest = Sha256Digest(manifestBytes);

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(manifestBytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        upstreamResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", computedDigest);

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestAsync(orgId, "library/ubuntu", computedDigest, isDigest: true, default);

        Assert.NotNull(result);
        Assert.Equal(computedDigest, result!.Digest);
        // Blob is cached under the content-addressed key.
        string expectedBlobKey = BlobKeys.OciBlob("sha256", Sha256Hex(manifestBytes));
        Assert.True(await cacheBlobs.ExistsAsync(expectedBlobKey, default));
    }

    [Fact]
    public async Task FetchManifestAsync_ByTag_WithMismatchingDigestHeader_StillCached()
    {
        // Tag references have no expected digest — verify-then-reject must NOT apply.
        // The existing Docker-Content-Digest divergence test covers the log behaviour;
        // this confirms the tag path is still cached even when the header disagrees.
        string orgId = await OrgSeeder.InsertAsync(_db, "manifest-tag-nocmp-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"tag\":true}");
        string computedDigest = Sha256Digest(manifestBytes);
        string bogusHeader = "sha256:" + new string('e', 64);

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(manifestBytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        upstreamResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", bogusHeader);

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestAsync(orgId, "library/ubuntu", "stable", isDigest: false, default);

        Assert.NotNull(result);
        Assert.Equal(computedDigest, result!.Digest);
    }

    // ── Mixed/partial-failure: one valid + one poisoned in the same resolver ───

    [Fact]
    public async Task FetchManifest_PartialFailure_GoodDigestCachedBadDigestRejected()
    {
        // In a single resolver instance: a manifest whose computed digest matches the
        // requested digest is cached and served; a manifest whose computed digest does
        // not match the requested digest is rejected with no cache writes and no DB row.
        // Proves one poisoned response does not corrupt a concurrent legitimate one.
        string orgId = await OrgSeeder.InsertAsync(_db, "manifest-partial-failure-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        // Good manifest — computed digest matches the request.
        byte[] goodBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"good\":true}");
        string goodDigest = Sha256Digest(goodBytes);

        // Bad manifest — upstream returns wrong bytes for the requested digest.
        byte[] badBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"bad\":true}");
        string badRequestedDigest = "sha256:" + new string('d', 64); // not the actual hash of badBytes

        var cacheBlobs = new InMemoryBlobStore();
        var opts = Options.Create(DefaultOptions());

        // ── Good fetch ──
        var goodResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(goodBytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        goodResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", goodDigest);
        var goodHttp = new SingleResponseFactory(goodResp);
        var goodAuthSvc = new OciUpstreamAuthService(goodHttp, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var goodBlobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var goodResolver = new OciUpstreamResolver(goodHttp, goodAuthSvc, opts, goodBlobs, _db,
            new StubAirGap(false), NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var goodResult = await goodResolver.FetchManifestAsync(orgId, "library/ubuntu", goodDigest, isDigest: true, default);

        // ── Bad fetch (same cacheBlobs, same DB) ──
        var badResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(badBytes)
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        badResp.Headers.TryAddWithoutValidation("Docker-Content-Digest", badRequestedDigest);
        var badHttp = new SingleResponseFactory(badResp);
        var badAuthSvc = new OciUpstreamAuthService(badHttp, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var badBlobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var badResolver = new OciUpstreamResolver(badHttp, badAuthSvc, opts, badBlobs, _db,
            new StubAirGap(false), NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var badResult = await badResolver.FetchManifestAsync(orgId, "library/ubuntu", badRequestedDigest, isDigest: true, default);

        // Good: cached and served.
        Assert.NotNull(goodResult);
        Assert.Equal(goodDigest, goodResult!.Digest);
        Assert.True(await cacheBlobs.ExistsAsync(BlobKeys.OciBlob("sha256", Sha256Hex(goodBytes)), default));

        // Bad: rejected, nothing cached under the bad digest key, and no staging leftovers.
        Assert.Null(badResult);
        Assert.False(await cacheBlobs.ExistsAsync(BlobKeys.OciBlob("sha256", new string('d', 64)), default));
        Assert.False(await cacheBlobs.ExistsAsync(BlobKeys.OciBlob("sha256", Sha256Hex(badBytes)), default));
        var stagingKeys = await cacheBlobs.ListAsync("oci/_staging/", default).ToListAsync();
        Assert.Empty(stagingKeys);

        // Good digest has a DB row; bad one has none.
        await using var conn = await _db.OpenAsync(default);
        bool goodRow = await conn.ExecuteScalarAsync<bool>(
            "SELECT COUNT(*) > 0 FROM oci_blobs WHERE org_id = @orgId AND digest = @digest",
            new { orgId, digest = goodDigest });
        bool badRow = await conn.ExecuteScalarAsync<bool>(
            "SELECT COUNT(*) > 0 FROM oci_blobs WHERE org_id = @orgId AND digest = @digest",
            new { orgId, digest = badRequestedDigest });
        Assert.True(goodRow);
        Assert.False(badRow);
    }

    [Fact]
    public async Task FetchBlob_PartialFailure_GoodDigestCachedBadDigestRejectedNoStagingLeftover()
    {
        // In a single resolver instance: a blob whose computed digest matches is cached at
        // the content-addressed key; a blob whose computed digest mismatches is rejected
        // and leaves no entry at the content-addressed key and no staging leftovers.
        string orgId = await OrgSeeder.InsertAsync(_db, "blob-partial-failure-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        byte[] goodBytes = RandomBytes(128);
        string goodHex = Sha256Hex(goodBytes);
        string goodDigest = "sha256:" + goodHex;

        byte[] badBytes = RandomBytes(64);
        string wrongHex = new('1', 64); // not the hash of badBytes
        string wrongDigest = "sha256:" + wrongHex;

        var cacheBlobs = new InMemoryBlobStore();
        var opts = Options.Create(DefaultOptions());

        // ── Good blob ──
        var goodResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(goodBytes)),
        };
        goodResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        var goodHttp = new SingleResponseFactory(goodResp);
        var goodAuthSvc = new OciUpstreamAuthService(goodHttp, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var goodBlobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var goodResolver = new OciUpstreamResolver(goodHttp, goodAuthSvc, opts, goodBlobs, _db,
            new StubAirGap(false), NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var goodResult = await goodResolver.FetchBlobAsync(orgId, "library/ubuntu", goodDigest, default);

        // ── Bad blob (same cacheBlobs) ──
        var badResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(badBytes)),
        };
        badResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        var badHttp = new SingleResponseFactory(badResp);
        var badAuthSvc = new OciUpstreamAuthService(badHttp, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var badBlobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var badResolver = new OciUpstreamResolver(badHttp, badAuthSvc, opts, badBlobs, _db,
            new StubAirGap(false), NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var badResult = await badResolver.FetchBlobAsync(orgId, "library/ubuntu", wrongDigest, default);

        // Good blob: present at content-addressed key.
        Assert.NotNull(goodResult);
        Assert.True(await cacheBlobs.ExistsAsync(BlobKeys.OciBlob("sha256", goodHex), default));

        // Bad blob: rejected; neither the content-addressed key nor any staging key persists.
        Assert.Null(badResult);
        Assert.False(await cacheBlobs.ExistsAsync(BlobKeys.OciBlob("sha256", wrongHex), default));
        var stagingKeys = await cacheBlobs.ListAsync("oci/_staging/", default).ToListAsync();
        Assert.Empty(stagingKeys);
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
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchTagsAsync(_orgId, "library/ubuntu", default);

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
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchTagsAsync(_orgId, "library/ubuntu", default);

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchTagsAsync_NoMatchingUpstream_ReturnsNull()
    {
        // An org with no OCI rows in upstream_registry returns null.
        string emptyOrg = await OrgSeeder.InsertAsync(_db, "no-tags-upstream-org");
        var resolver = Build();
        var result = await resolver.FetchTagsAsync(emptyOrg, "library/ubuntu", default);
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
            resolver.FetchTagsAsync(_orgId, "library/ubuntu", default));
    }

    // ── Verify-then-commit ordering: spy-based pinning tests ──────────────────

    /// <summary>
    /// PutAsync on the content-addressed OciBlob key must never be called when the upstream
    /// blob bytes do not match the requested digest.
    ///
    /// The old write-before-verify ordering wrote the content key first and deleted it on
    /// mismatch, so a spy would record the content key in PutAsync — this assertion would fail
    /// on the old code. The current verify-then-commit path never calls PutAsync for the
    /// content key on a mismatch, so the spy records it only for the staging slot.
    /// </summary>
    [Fact]
    public async Task FetchBlobAsync_DigestMismatch_ContentAddressedKeyNeverPutAsync()
    {
        byte[] blobBytes = RandomBytes(64);
        string wrongHex = new('0', 64); // definitely not the hash of blobBytes
        string wrongDigest = "sha256:" + wrongHex;
        string contentAddressedKey = BlobKeys.OciBlob("sha256", wrongHex);

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(blobBytes)),
        };
        upstreamResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);

        // Spy wraps the real in-memory store; records every key passed to PutAsync.
        var spy = new PutAsyncSpyBlobStore(new InMemoryBlobStore());
        var blobs = new TieredBlobStorage(spy, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", wrongDigest, default);

        Assert.Null(result);

        // The content-addressed key must never have been passed to PutAsync.
        // Old code called PutAsync(blobKey, ...) BEFORE verifying the digest, so this
        // assertion would fail on the pre-fix ordering.
        Assert.DoesNotContain(contentAddressedKey, spy.PutKeys);
    }

    /// <summary>
    /// For a successful (matching-digest) blob fetch the staging key must be passed to
    /// PutAsync strictly before the content-addressed OciBlob key.
    ///
    /// The old write-before-verify ordering never used a staging key — it wrote directly to
    /// the content key. A spy would therefore see no staging key preceding the content key,
    /// and the ordering assertion below would fail on the old code.
    /// </summary>
    [Fact]
    public async Task FetchBlobAsync_MatchingDigest_StagingKeyPutAsyncBeforeContentAddressedKey()
    {
        byte[] blobBytes = RandomBytes(256);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;
        string contentAddressedKey = BlobKeys.OciBlob("sha256", sha256);

        var upstreamResp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(blobBytes)),
        };
        upstreamResp.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var http = new SingleResponseFactory(upstreamResp);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);

        // Spy wraps the real in-memory store; records every key passed to PutAsync in order.
        var spy = new PutAsyncSpyBlobStore(new InMemoryBlobStore());
        var blobs = new TieredBlobStorage(spy, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", digest, default);

        Assert.NotNull(result);

        // The content-addressed key must be present in the PutAsync call log.
        Assert.Contains(contentAddressedKey, spy.PutKeys);

        // A staging key (oci/_staging/...) must appear in the log before the content key.
        // Old code wrote directly to the content key — no staging key would precede it,
        // so this ordering assertion would fail on the pre-fix code.
        int contentKeyIndex = spy.PutKeys.IndexOf(contentAddressedKey);
        int stagingKeyIndex = spy.PutKeys.FindIndex(k => k.StartsWith("oci/_staging/", StringComparison.Ordinal));
        Assert.True(stagingKeyIndex >= 0, "A staging key must have been written before the content-addressed key.");
        Assert.True(stagingKeyIndex < contentKeyIndex,
            $"Staging key (index {stagingKeyIndex}) must precede content key (index {contentKeyIndex}) — " +
            "digest must be verified before bytes are promoted to the content-addressed slot.");
    }

    // ── Auth-retry helper regression: 401 → evict → retry → success ──────────

    /// <summary>
    /// A 401 on the first attempt must trigger token eviction and a single retry.
    /// The retry succeeds (200 with manifest body) and the manifest is cached and returned.
    /// This pins the shared <c>SendUpstreamWithAuthRetryAsync</c> logic for the GET manifest
    /// path — fails on any code that does not retry on 401.
    /// </summary>
    [Fact]
    public async Task FetchManifestAsync_FirstAttempt401ThenSuccess_RetriesAndReturnsManifest()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "manifest-auth-retry-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"authRetry\":true}");
        string digest = Sha256Digest(manifestBytes);

        // First call returns 401; second call returns 200 with manifest body.
        var seq = new SequenceFactory(
            new HttpResponseMessage(HttpStatusCode.Unauthorized),
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(manifestBytes)
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
                },
            });

        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(seq, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(seq, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestAsync(orgId, "library/ubuntu", "latest", isDigest: false, default);

        // Retry succeeded — manifest is returned and cached.
        Assert.NotNull(result);
        Assert.Equal(digest, result!.Digest);
        // Both the 401 and the 200 must have been sent (one attempt for auth, one for retry).
        Assert.Equal(2, seq.CallCount);
    }

    /// <summary>
    /// A 401 on the first attempt for a HEAD manifest request must trigger a retry.
    /// The second attempt succeeds — verifies the HEAD path uses the same auth-retry helper.
    /// Fails on old code that had a separate per-method retry loop removed in this refactor.
    /// </summary>
    [Fact]
    public async Task FetchManifestMetadataAsync_FirstAttempt401ThenSuccess_RetriesAndReturnsMetadata()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "manifest-head-auth-retry-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2}");
        string digest = Sha256Digest(manifestBytes);

        var headSuccess = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([])
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        headSuccess.Headers.TryAddWithoutValidation("Docker-Content-Digest", digest);
        headSuccess.Content.Headers.ContentLength = manifestBytes.Length;

        var seq = new SequenceFactory(
            new HttpResponseMessage(HttpStatusCode.Unauthorized),
            headSuccess);

        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(seq, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(seq, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestMetadataAsync(orgId, "library/ubuntu", "latest", isDigest: false, default);

        Assert.NotNull(result);
        Assert.Equal(digest, result!.Digest);
        Assert.Equal(2, seq.CallCount);
    }

    /// <summary>
    /// A 401 on the first attempt for a HEAD blob request must trigger a retry.
    /// Verifies the blob HEAD path uses the shared auth-retry helper.
    /// </summary>
    [Fact]
    public async Task FetchBlobMetadataAsync_FirstAttempt401ThenSuccess_RetriesAndReturnsMetadata()
    {
        byte[] blobBytes = RandomBytes(64);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;
        // Not in cache — forces upstream round-trip.

        var headSuccess = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([])
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream") },
            },
        };

        var seq = new SequenceFactory(
            new HttpResponseMessage(HttpStatusCode.Unauthorized),
            headSuccess);

        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(seq, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(new InMemoryBlobStore(), new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(seq, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-head-auth-retry-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);
        var result = await resolver.FetchBlobMetadataAsync(orgId, "library/ubuntu", digest, default);

        Assert.NotNull(result);
        Assert.Equal("application/octet-stream", result!.MediaType);
        Assert.Equal(2, seq.CallCount);
    }

    /// <summary>
    /// Mixed partial-failure across the auth-retry helper:
    /// - One manifest HEAD request: 401 → retry → 200 (succeeds)
    /// - One manifest HEAD request: 404 on first attempt (returns null cleanly)
    /// Proves the shared helper handles 401-retry and 404-null correctly in the same process.
    /// </summary>
    [Fact]
    public async Task AuthRetry_MixedPartialFailure_401RetrySucceeds_404ReturnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, "auth-retry-mixed-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"schemaVersion\":2,\"mixed\":true}");
        string digest = Sha256Digest(manifestBytes);

        var headSuccess = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([])
            {
                Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json") },
            },
        };
        headSuccess.Headers.TryAddWithoutValidation("Docker-Content-Digest", digest);
        headSuccess.Content.Headers.ContentLength = manifestBytes.Length;

        // Request 1: 401 → 200 (auth-retry succeeds)
        var seqGood = new SequenceFactory(
            new HttpResponseMessage(HttpStatusCode.Unauthorized),
            headSuccess);

        var optsGood = Options.Create(DefaultOptions());
        var authGood = new OciUpstreamAuthService(seqGood, optsGood, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobsGood = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolverGood = new OciUpstreamResolver(seqGood, authGood, optsGood, blobsGood, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        // Request 2: 404 on first attempt (no retry for 404)
        var seq404 = new SequenceFactory(new HttpResponseMessage(HttpStatusCode.NotFound));
        var opts404 = Options.Create(DefaultOptions());
        var auth404 = new OciUpstreamAuthService(seq404, opts404, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs404 = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver404 = new OciUpstreamResolver(seq404, auth404, opts404, blobs404, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var goodResult = await resolverGood.FetchManifestMetadataAsync(orgId, "library/ubuntu", "latest", isDigest: false, default);
        var nullResult = await resolver404.FetchManifestMetadataAsync(orgId, "library/ubuntu", "missing", isDigest: false, default);

        // 401→retry path: succeeds and returns metadata.
        Assert.NotNull(goodResult);
        Assert.Equal(digest, goodResult!.Digest);
        Assert.Equal(2, seqGood.CallCount); // exactly 2 HTTP calls (401 + 200)

        // 404 path: null, no retry (only 1 HTTP call).
        Assert.Null(nullResult);
        Assert.Equal(1, seq404.CallCount); // exactly 1 HTTP call (404 → no retry)
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    // Returns responses from a fixed sequence in order; tracks the total call count.
    // Each SendAsync call pops the next response; throws if the sequence is exhausted.
    // Test factories are used sequentially so a simple non-atomic counter is sufficient.
    private sealed class SequenceFactory : IHttpClientFactory
    {
        private readonly Queue<HttpResponseMessage> _responses;
        private readonly SequenceCallCounter _counter = new();

        public SequenceFactory(params HttpResponseMessage[] responses)
            => _responses = new Queue<HttpResponseMessage>(responses);

        public int CallCount => _counter.Value;

        public HttpClient CreateClient(string name) => new(new SequenceHandler(this));

        private sealed class SequenceCallCounter
        {
            private int _count;
            public int Value => _count;
            public void Increment() => Interlocked.Increment(ref _count);
        }

        private sealed class SequenceHandler : HttpMessageHandler
        {
            private readonly SequenceFactory _owner;
            public SequenceHandler(SequenceFactory owner) => _owner = owner;

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                _owner._counter.Increment();
                return !_owner._responses.TryDequeue(out var resp)
                    ? throw new InvalidOperationException(
                        $"SequenceFactory exhausted — no more responses queued (URL={request.RequestUri})")
                    : Task.FromResult(resp);
            }
        }
    }



    /// <summary>
    /// Wraps an inner <see cref="IBlobStore"/> and records the key argument of every
    /// <see cref="PutAsync"/> call in insertion order. All other operations delegate to the
    /// inner store unchanged — only the ordering observation matters here.
    /// </summary>
    private sealed class PutAsyncSpyBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;

        public PutAsyncSpyBlobStore(IBlobStore inner) => _inner = inner;

        /// <summary>Ordered list of keys passed to PutAsync, in call order.</summary>
        public List<string> PutKeys { get; } = [];

        public async Task PutAsync(string key, Stream data, CancellationToken ct = default)
        {
            PutKeys.Add(key);
            await _inner.PutAsync(key, data, ct);
        }

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
            => _inner.GetAsync(key, ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, from, to, ct);

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
            => _inner.ExistsAsync(key, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default)
            => _inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
            => _inner.GetTotalSizeAsync(ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }

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

    // ── OCI blob single-flight: concurrent miss collapses to one upstream pull ──

    /// <summary>
    /// Broken code analysis: before this fix, FetchAndCacheBlobAsync returned an OciBlobResult
    /// carrying the single stream opened via _blobs.Cache.GetAsync. All N concurrent waiters
    /// received the SAME Task result and therefore the SAME stream object. The first waiter to
    /// read it exhausted the MemoryStream (Position advanced to end); subsequent waiters read
    /// 0 bytes from the already-read stream, producing empty (not the expected) blobs.
    ///
    /// Fixed behaviour: FetchAndCacheBlobAsync returns only OciBlobFetchMetadata (key + media
    /// type). Each waiter independently calls _blobs.Cache.GetAsync to open its OWN stream.
    /// InMemoryBlobStore returns a fresh MemoryStream per GetAsync call, so every waiter reads
    /// the full expected bytes.
    ///
    /// This test FAILS on the broken version because the 2nd–Nth readers receive 0 bytes;
    /// it PASSES on the fixed version because each reader gets a fresh independent stream.
    /// </summary>
    [Fact]
    public async Task FetchBlobAsync_ConcurrentSameDigestMisses_CollapseToOneUpstreamPull_EachWaiterGetsOwnStream()
    {
        byte[] blobBytes = RandomBytes(512);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;

        // GateFactory parks the HTTP response until Release() is called, giving all concurrent
        // callers time to queue up on the Lazy before any result is published.
        var gate = new GateFactory(blobBytes);

        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(gate, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(gate, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-singleflight-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        const int concurrency = 6;
        // Start all callers before releasing the gate so they all queue behind the Lazy.
        var tasks = Enumerable.Range(0, concurrency)
            .Select(_ => Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digest, default)))
            .ToArray();

        await Task.Delay(100); // allow all tasks to enter FetchBlobAsync and park on the Lazy
        gate.Release();

        var results = await Task.WhenAll(tasks);

        // Exactly one upstream HTTP pull for all concurrent callers.
        Assert.Equal(1, gate.CallCount);

        // Every waiter must have received an independent, fully-readable stream.
        // On the broken version: the 2nd+ waiters receive an exhausted (shared) stream and
        // read 0 bytes, causing the assertion below to fail.
        for (int i = 0; i < concurrency; i++)
        {
            var result = results[i];
            Assert.NotNull(result);

            using var ms = new MemoryStream();
            await result!.Content.CopyToAsync(ms);
            Assert.Equal(blobBytes, ms.ToArray());
        }
    }

    /// <summary>
    /// Distinct digests must each trigger their own independent upstream pull — the single-flight
    /// key is digest-specific and must not collapse pulls for different blobs.
    /// </summary>
    [Fact]
    public async Task FetchBlobAsync_ConcurrentDistinctDigests_EachFetchesIndependently()
    {
        byte[] bytesA = RandomBytes(64);
        byte[] bytesB = RandomBytes(64);
        byte[] bytesC = RandomBytes(64);
        string digestA = "sha256:" + Sha256Hex(bytesA);
        string digestB = "sha256:" + Sha256Hex(bytesB);
        string digestC = "sha256:" + Sha256Hex(bytesC);

        var gateA = new GateFactory(bytesA);
        var gateB = new GateFactory(bytesB);
        var gateC = new GateFactory(bytesC);
        var routing = new RoutingGateFactory(
            (digestA, gateA), (digestB, gateB), (digestC, gateC));

        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(routing, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(routing, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-distinct-singleflight-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        var tasks = new[]
        {
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestA, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestB, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestC, default)),
        };
        await Task.Delay(80);
        gateA.Release(); gateB.Release(); gateC.Release();
        var results = await Task.WhenAll(tasks);

        // Three distinct digests → three independent upstream calls.
        Assert.Equal(1, gateA.CallCount);
        Assert.Equal(1, gateB.CallCount);
        Assert.Equal(1, gateC.CallCount);
        Assert.NotNull(results[0]);
        Assert.NotNull(results[1]);
        Assert.NotNull(results[2]);
    }

    /// <summary>
    /// Mixed scenario (house rule: tests must cover the partial-failure case).
    /// Two callers share the same digest (collapse to 1 fetch); two distinct digests each
    /// fetch independently. All four race simultaneously. Every waiter reads its own stream
    /// to completion and receives the expected bytes.
    /// </summary>
    [Fact]
    public async Task FetchBlobAsync_Mixed_SharedDigestCollapses_DistinctDigestsFetchIndependently_AllStreamReadable()
    {
        byte[] sharedBytes = RandomBytes(128);
        byte[] bytesB = RandomBytes(64);
        byte[] bytesC = RandomBytes(64);
        string sharedDigest = "sha256:" + Sha256Hex(sharedBytes);
        string digestB = "sha256:" + Sha256Hex(bytesB);
        string digestC = "sha256:" + Sha256Hex(bytesC);

        var gateShared = new GateFactory(sharedBytes);
        var gateB = new GateFactory(bytesB);
        var gateC = new GateFactory(bytesC);
        var routing = new RoutingGateFactory(
            (sharedDigest, gateShared), (digestB, gateB), (digestC, gateC));

        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(routing, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(routing, authSvc, opts, blobs, _db, new StubAirGap(false),
            NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-mixed-singleflight-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        // Two callers on the shared digest, one each on B and C.
        var tasks = new[]
        {
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", sharedDigest, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", sharedDigest, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestB, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestC, default)),
        };
        await Task.Delay(100);
        gateShared.Release(); gateB.Release(); gateC.Release();
        var results = await Task.WhenAll(tasks);

        // Shared digest → exactly 1 upstream call (2 callers collapsed).
        Assert.Equal(1, gateShared.CallCount);
        // Distinct digests → 1 call each.
        Assert.Equal(1, gateB.CallCount);
        Assert.Equal(1, gateC.CallCount);

        // Both waiters on the shared digest must read the FULL expected bytes independently.
        // On the broken version: the second waiter shares the first's exhausted stream → reads
        // 0 bytes → this assertion fails.
        for (int i = 0; i < 2; i++)
        {
            Assert.NotNull(results[i]);
            using var ms = new MemoryStream();
            await results[i]!.Content.CopyToAsync(ms);
            Assert.Equal(sharedBytes, ms.ToArray());
        }

        // Distinct-digest callers each get their expected bytes too.
        Assert.NotNull(results[2]);
        Assert.NotNull(results[3]);
        using var msB = new MemoryStream();
        await results[2]!.Content.CopyToAsync(msB);
        Assert.Equal(bytesB, msB.ToArray());

        using var msC = new MemoryStream();
        await results[3]!.Content.CopyToAsync(msC);
        Assert.Equal(bytesC, msC.ToArray());
    }

    // ── Gate factories for single-flight concurrency tests ─────────────────────

    /// <summary>
    /// Returns a single gated HTTP response whose body holds <paramref name="blobBytes"/>.
    /// The response is parked until <see cref="Release"/> is called so all concurrent callers
    /// can queue up before the Lazy resolves.
    /// </summary>
    private sealed class GateFactory : IHttpClientFactory
    {
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly byte[] _body;
        private readonly GateCallCounter _counter = new();

        public GateFactory(byte[] body) => _body = body;

        public int CallCount => _counter.Value;
        public void Release() => _gate.TrySetResult();

        // Called directly by RoutingGateFactory to avoid re-sending the same HttpRequestMessage
        // through another HttpClient (which would raise InvalidOperationException).
        public async Task<HttpResponseMessage> HandleAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            _ = request; // not inspected — gate returns a fixed response body
            _counter.Increment();
            await _gate.Task.WaitAsync(ct);
            var resp = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StreamContent(new MemoryStream(_body)),
            };
            resp.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            return resp;
        }

        public HttpClient CreateClient(string name) => new(new GateHandler(this));

        private sealed class GateCallCounter
        {
            private int _count;
            public int Value => _count;
            public void Increment() => Interlocked.Increment(ref _count);
        }

        private sealed class GateHandler : HttpMessageHandler
        {
            private readonly GateFactory _owner;
            public GateHandler(GateFactory owner) => _owner = owner;

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
                => _owner.HandleAsync(request, cancellationToken);
        }
    }

    /// <summary>
    /// Routes each request to the <see cref="GateFactory"/> whose digest appears in the URL path.
    /// Supports the distinct-digest and mixed-scenario tests.
    /// </summary>
    private sealed class RoutingGateFactory : IHttpClientFactory
    {
        private readonly (string Digest, GateFactory Gate)[] _routes;

        public RoutingGateFactory(params (string Digest, GateFactory Gate)[] routes)
            => _routes = routes;

        public HttpClient CreateClient(string name) => new(new RoutingHandler(this));

        private sealed class RoutingHandler : HttpMessageHandler
        {
            private readonly RoutingGateFactory _owner;
            public RoutingHandler(RoutingGateFactory owner) => _owner = owner;

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                string url = request.RequestUri?.ToString() ?? string.Empty;
                foreach (var (digest, gate) in _owner._routes)
                {
                    // The URL path for a blob is /v2/{repository}/blobs/{digest} where the
                    // digest is url-encoded as "sha256:{hex}" — match on the hex portion.
                    string hex = digest.Length > 7 ? digest[7..] : digest;
                    if (url.Contains(hex, StringComparison.OrdinalIgnoreCase))
                    {
                        // Call HandleAsync directly — reusing the HttpRequestMessage through a
                        // new HttpClient would raise InvalidOperationException ("already sent").
                        return gate.HandleAsync(request, cancellationToken);
                    }
                }
                return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
            }
        }
    }
}
