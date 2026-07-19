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
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly CacheAccessRecorder _cacheRecorder;

    private string _orgId = null!;

    public OciUpstreamResolverTests()
    {
        _cacheArtifacts = new CacheArtifactRepository(_db);
        _cacheRecorder = new CacheAccessRecorder(
            _cacheArtifacts, new TenantArtifactAccessRepository(_db),
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
    }

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());
    }

    // Builds a resolver whose cache and registry tiers are the SAME store, reproducing the
    // default single-store deployment (no _CACHE/_REGISTRY override) in which an uploaded blob
    // written to the registry tier resolves under the identical content-addressed key on the
    // cache tier — the topology the cross-tenant blob-read guard defends.
    private OciUpstreamResolver BuildOverSharedStore(IBlobStore shared, IHttpClientFactory http)
    {
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(shared, shared);
        return new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance,
            TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());
    }

    // License recorder for the resolver constructor. Best-effort by design; these tests do not
    // assert license capture, so a recorder over the shared cache store + metadata store suffices.
    private OciImageLicenseRecorder NewRecorder()
        => new(_db, new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore()),
            TimeProvider.System, NullLogger<OciImageLicenseRecorder>.Instance,
            new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)));

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

    /// <summary>
    /// Deterministically waits until <paramref name="count"/> callers have registered against
    /// the shared in-flight entry for <paramref name="sha256"/>, observed via
    /// <see cref="OciUpstreamResolver.BlobInflightArrivalCount"/> — a test-only internal seam
    /// (InternalsVisibleTo) that exposes the exact production invariant a concurrency test needs
    /// (winner + joiners have registered) rather than a proxy for it. FetchBlobAsync does one
    /// real async DB read (MatchUpstreamAsync) before registering, so — unlike the pure-in-memory
    /// single-flight paths on UpstreamClient — neither a "task started" signal nor a direct
    /// sequential call can observe registration directly; this polls the real counter instead of
    /// guessing how long that DB round-trip takes.
    /// </summary>
    private static async Task WaitForBlobArrivalsAsync(
        OciUpstreamResolver resolver, string sha256, int count, TimeSpan? timeout = null)
    {
        string blobKey = BlobKeys.OciBlob("sha256", sha256);
        // now-ok: polling deadline awaiting a real, observable production invariant (arrival
        // count), not a proxy for it — see the method doc above.
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (resolver.BlobInflightArrivalCount(blobKey) < count && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(5);
        }

        if (resolver.BlobInflightArrivalCount(blobKey) < count)
        {
            throw new TimeoutException(
                $"Expected {count} arrivals on blob key {blobKey}, saw {resolver.BlobInflightArrivalCount(blobKey)} " +
                "within the safety timeout.");
        }
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

    /// <summary>
    /// Seeds one oci_blobs row directly for the given org/digest/origin without touching the
    /// blob store — used by the cross-tenant blob-read tests to place a metadata row (uploaded
    /// or proxy) that the entitlement gate reads.
    /// </summary>
    private async Task SeedOciBlobRowAsync(
        string orgId, string digest, string blobKey, string origin, long sizeBytes,
        string mediaType = "application/octet-stream")
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, @origin)
            """,
            new { digest, orgId, mediaType, sizeBytes, blobKey, origin });
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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestAsync(
            orgId, "library/does-not-exist-xyz", "1.0", isDigest: false, default);

        Assert.Null(result);
    }

    // ── Catalogue surfacing (OCI shows up on dashboards / Packages page) ────────

    [Fact]
    public async Task FetchManifestAsync_TagPull_RecordsCataloguePackageAndCacheArtifact()
    {
        // A tagged docker pull must land in packages (for the Packages page) and on the shared
        // cache_artifact / tenant_artifact_access plane (for the version count and detail list) —
        // not only in oci_blobs/oci_tags. Without this, a successfully-pulled image shows as zero
        // everywhere, or disagrees between the packages list and the package detail page.
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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestAsync(_orgId, "library/ubuntu", "22.04", isDigest: false, default);
        Assert.NotNull(result);

        // Overview stats now count Docker (1 package) and report its real cached footprint.
        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync(_orgId, default);
        Assert.Contains(stats.PackagesByEcosystem, e => e.Ecosystem == "oci" && e.Count == 1);
        Assert.Contains(stats.DiskByEcosystem, d => d.Ecosystem == "oci" && d.TotalBytes == manifestBytes.Length);

        // No package_versions row is written for the proxy pull — the global cache plane is
        // authoritative for proxy metadata, same as every other proxy ecosystem.
        await using var conn = await _db.OpenAsync(default);
        int pvCount = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'oci'
            """,
            new { orgId = _orgId });
        Assert.Equal(0, pvCount);

        // The cache_artifact row carries the manifest digest as its version, the "manifest"
        // filename, and the resolving tag captured in the PURL qualifier; tenant_artifact_access
        // binds it to this org.
        var row = await conn.QuerySingleAsync<(string Version, string Filename, string? Purl)>(
            """
            SELECT ca.version, ca.filename, ca.purl
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.name = 'library/ubuntu'
            """,
            new { orgId = _orgId });
        Assert.Equal(digest, row.Version);
        Assert.Equal("manifest", row.Filename);
        Assert.NotNull(row.Purl);
        Assert.StartsWith("pkg:oci/ubuntu@sha256%3A", row.Purl);
        Assert.Contains("tag=22.04", row.Purl);
    }

    /// <summary>
    /// Pins the reported bug directly: the packages-list version count (sums
    /// <c>package_versions WHERE origin='uploaded'</c> plus the cache-plane join) and the package
    /// detail listing (<c>package_versions</c> plus <see cref="CacheArtifactRepository.ListServeFactsForNameAsync"/>)
    /// must agree for an OCI proxy package. Before the fix, an OCI proxy pull landed only in
    /// <c>package_versions</c> with <c>origin='proxy'</c> — counted by neither arm of the list-count
    /// join (which only sums <c>origin='uploaded'</c> plus <c>cache_artifact</c>) while still being
    /// returned by <see cref="PackageRepository.GetVersionsAsync"/> (no origin filter) on the detail
    /// page — so list showed 0 versions while detail showed 1. Both must now report exactly 1.
    /// </summary>
    [Fact]
    public async Task FetchManifestAsync_TagPull_ListCountAndDetailListing_Agree()
    {
        byte[] manifestBytes = Encoding.UTF8.GetBytes(
            """{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}""");

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchManifestAsync(_orgId, "library/ubuntu", "latest", isDigest: false, default);
        Assert.NotNull(result);

        // "List" source: PackageRepository.ListPaginatedAsync's VersionCount aggregate.
        var packages = new PackageRepository(_db, time: TimeProvider.System);
        var (items, _) = await packages.ListPaginatedAsync(
            new PackageListQuery(_orgId, Limit: 10, Offset: 0, Ecosystem: "oci"));
        var listedPackage = Assert.Single(items, p => p.PurlName == "library/ubuntu");
        Assert.Equal(1, listedPackage.VersionCount);

        // "Detail" source: the same cache-plane query OrgController.LoadCombinedVersionsForOrgAsync
        // uses to combine with the (empty, for this proxy pull) package_versions arm.
        var detailEntries = await _cacheArtifacts.ListServeFactsForNameAsync(_orgId, "oci", "library/ubuntu", default);
        Assert.Single(detailEntries);

        // List and detail agree.
        Assert.Equal(listedPackage.VersionCount, detailEntries.Count);
    }

    /// <summary>
    /// Regression: <c>RecordCatalogVersionAsync</c> is awaited before the manifest is returned to
    /// the client (<see cref="OciUpstreamResolver.FetchManifestAsync"/> → …
    /// <c>CacheAndReturnManifestAsync</c>), so an unhandled exception from cataloguing would 500 a
    /// pull whose bytes are already durably cached (blob store + <c>oci_blobs</c> row, both
    /// written before cataloguing runs). This forces <c>CacheArtifactRepository.UpdateGlobalFactsAsync</c>
    /// to throw a genuine <see cref="Microsoft.Data.Sqlite.SqliteException"/> (dropping the
    /// <c>purl</c> column it writes) after <c>CacheAccessRecorder.RecordAccessAsync</c> has
    /// already created the <c>cache_artifact</c> row, and asserts the pull still succeeds.
    /// </summary>
    [Fact]
    public async Task FetchManifestAsync_TagPull_CataloguingDbFault_PullStillSucceeds()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await TestSchemaViews.DropAsync(conn);
            await conn.ExecuteAsync("DROP INDEX IF EXISTS idx_cache_artifact_purl");
            await conn.ExecuteAsync("ALTER TABLE cache_artifact DROP COLUMN purl");
        }

        byte[] manifestBytes = Encoding.UTF8.GetBytes(
            """{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}""");
        string digest = Sha256Digest(manifestBytes);

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        // Must not throw — the transient cataloguing fault is swallowed, not propagated.
        var result = await resolver.FetchManifestAsync(_orgId, "library/ubuntu", "22.10", isDigest: false, default);

        Assert.NotNull(result);
        Assert.Equal(digest, result!.Digest);
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

        // A bare content-addressed store hit is served across orgs only for proxy-derived bytes
        // to a caller that has a matching upstream. Seed a proxy-origin row owned by a different
        // org (proving upstream provenance); _orgId carries the catch-all upstream seeded in
        // InitializeAsync, so it is entitled to the shared dedup hit.
        string primingOrg = await OrgSeeder.InsertAsync(_db, "cache-hit-priming-org");
        await SeedOciBlobRowAsync(primingOrg, digest, blobKey, "proxy", blobBytes.Length);

        var resolver = Build(); // NeverCallFactory

        var result = await resolver.FetchBlobAsync(_orgId, "library/ubuntu", digest, default);

        Assert.NotNull(result);
        using var ms = new MemoryStream();
        await result!.Content.CopyToAsync(ms);
        Assert.Equal(blobBytes, ms.ToArray());
    }

    // ── BOLA: cross-tenant blob read via the shared content-addressed store ─────

    [Fact]
    public async Task FetchBlobAsync_OtherOrgUploadedBlob_NotCrossServed()
    {
        // Regression: the blob store is content-addressed with no org segment, and in the default
        // single-store deployment cache == registry, so org A's PRIVATE uploaded bytes resolve
        // under the same oci/{algo}/{hex} key any other org would compute. A bare store hit must
        // NOT authorize org B to read them. Before the fix FetchBlobAsync served the store hit
        // unconditionally and back-filled a row for B — leaking A's private blob.
        var shared = new InMemoryBlobStore();

        byte[] privateBytes = RandomBytes(256);
        string sha256 = Sha256Hex(privateBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);
        await shared.PutAsync(blobKey, new MemoryStream(privateBytes), default);

        string orgA = await OrgSeeder.InsertAsync(_db, "private-uploader-org");
        await SeedOciBlobRowAsync(orgA, digest, blobKey, "uploaded", privateBytes.Length);

        // Org B has no upstream configured, so it has no legitimate route to these bytes at all.
        string orgB = await OrgSeeder.InsertAsync(_db, "cross-tenant-reader-org");

        var resolver = BuildOverSharedStore(shared, new NeverCallFactory());

        var result = await resolver.FetchBlobAsync(orgB, "library/private", digest, default);

        // Refused: B owns no row, the only row is A's private upload, and B has no upstream.
        Assert.Null(result);

        // B must not have been granted a piggybacked oci_blobs row either.
        await using var conn = await _db.OpenAsync(default);
        int bRows = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM oci_blobs WHERE org_id = @orgB", new { orgB });
        Assert.Equal(0, bRows);
    }

    [Fact]
    public async Task FetchBlobMetadataAsync_OtherOrgUploadedBlob_NotReportedAsHit()
    {
        // HEAD counterpart: a bare store ExistsAsync hit must not report another tenant's private
        // uploaded blob as present. Before the fix FetchBlobMetadataAsync answered HIT on the raw
        // store existence check with no org-scoped entitlement.
        var shared = new InMemoryBlobStore();

        byte[] privateBytes = RandomBytes(128);
        string sha256 = Sha256Hex(privateBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);
        await shared.PutAsync(blobKey, new MemoryStream(privateBytes), default);

        string orgA = await OrgSeeder.InsertAsync(_db, "private-uploader-head-org");
        await SeedOciBlobRowAsync(orgA, digest, blobKey, "uploaded", privateBytes.Length);

        string orgB = await OrgSeeder.InsertAsync(_db, "cross-tenant-head-reader-org");

        var resolver = BuildOverSharedStore(shared, new NeverCallFactory());

        var result = await resolver.FetchBlobMetadataAsync(orgB, "library/private", digest, default);

        Assert.Null(result);
    }

    [Fact]
    public async Task FetchBlob_Mixed_UploadedCrossOrgRefused_ProxyDedupServed()
    {
        // House rule (mixed partial-failure): in ONE resolver over ONE shared content-addressed
        // store, the caller is REFUSED another org's private uploaded blob but is SERVED a
        // proxy-origin blob it is entitled to (a matching upstream proves the bytes are
        // upstream-derived public content). One request is denied, the other succeeds, in the
        // same process — proving the gate distinguishes private uploads from public proxy cache.
        var shared = new InMemoryBlobStore();

        // Private upload owned by another org — must never cross-serve.
        byte[] privateBytes = RandomBytes(200);
        string privateSha = Sha256Hex(privateBytes);
        string privateDigest = "sha256:" + privateSha;
        string privateKey = BlobKeys.OciBlob("sha256", privateSha);
        await shared.PutAsync(privateKey, new MemoryStream(privateBytes), default);
        string orgA = await OrgSeeder.InsertAsync(_db, "mixed-private-uploader-org");
        await SeedOciBlobRowAsync(orgA, privateDigest, privateKey, "uploaded", privateBytes.Length);

        // Proxy-cached public blob owned by yet another org — dedup-servable to an org with a
        // matching upstream.
        byte[] publicBytes = RandomBytes(200);
        string publicSha = Sha256Hex(publicBytes);
        string publicDigest = "sha256:" + publicSha;
        string publicKey = BlobKeys.OciBlob("sha256", publicSha);
        await shared.PutAsync(publicKey, new MemoryStream(publicBytes), default);
        string orgC = await OrgSeeder.InsertAsync(_db, "mixed-proxy-cacher-org");
        await SeedOciBlobRowAsync(orgC, publicDigest, publicKey, "proxy", publicBytes.Length);

        // Caller B has a catch-all upstream. Any upstream fetch it is forced into returns 404, so
        // the refused private-blob request resolves to a clean miss and never leaks A's bytes.
        string orgB = await OrgSeeder.InsertAsync(_db, "mixed-reader-org");
        await SeedOciUpstreamAsync(orgB, "registry-1.docker.io", [""], position: 0);

        var resolver = BuildOverSharedStore(shared, new StatusFactory(HttpStatusCode.NotFound));

        var refused = await resolver.FetchBlobAsync(orgB, "library/private", privateDigest, default);
        var served = await resolver.FetchBlobAsync(orgB, "library/public", publicDigest, default);

        // Private upload: refused the shared hit, resolves to upstream 404 → null. A's bytes
        // never reach B.
        Assert.Null(refused);

        // Proxy dedup: served straight from the shared store with the full bytes, no upstream
        // round-trip needed.
        Assert.NotNull(served);
        using var ms = new MemoryStream();
        await served!.Content.CopyToAsync(ms);
        Assert.Equal(publicBytes, ms.ToArray());
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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            new StubAirGap(false), NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            new StubAirGap(false), NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            new StubAirGap(false), NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            new StubAirGap(false), NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-head-auth-retry-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);
        var result = await resolver.FetchBlobMetadataAsync(orgId, "library/ubuntu", digest, default);

        Assert.NotNull(result);
        Assert.Equal("application/octet-stream", result!.MediaType);
        Assert.Equal(2, seq.CallCount);
    }

    /// <summary>
    /// Cross-tenant existence oracle regression: a blob's bytes sit in the shared,
    /// content-addressed cache store (primed by ANOTHER org) but the probing org owns no
    /// <c>oci_blobs</c> row for the digest. A bare global <c>Cache.ExistsAsync</c> short-circuit
    /// would answer the HEAD with a 200 (metadata), leaking that the digest exists somewhere on the
    /// instance. The org-scoped path must ignore the foreign bytes and fall through to the probing
    /// org's own upstream — which here 404s → null.
    ///
    /// FAILS on the pre-fix code (foreign cache hit → non-null); PASSES on the fix (null).
    /// </summary>
    [Fact]
    public async Task FetchBlobMetadataAsync_ForeignCachedBlob_NoOrgRow_DoesNotLeakExistence()
    {
        byte[] blobBytes = RandomBytes(96);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);

        // Foreign org's bytes are present in the shared cache store; the probing org owns no row.
        var sharedCache = new InMemoryBlobStore();
        await sharedCache.PutAsync(blobKey, new MemoryStream(blobBytes), default);

        string probingOrg = await OrgSeeder.InsertAsync(_db, "oci-head-oracle-probing-org");
        // Matching upstream so a genuine miss does a real, org-scoped upstream HEAD.
        await SeedOciUpstreamAsync(probingOrg, "registry-1.docker.io", [""], position: 0);

        // Upstream reports the blob does not exist for THIS org.
        var http = new StatusFactory(HttpStatusCode.NotFound);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(sharedCache, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var result = await resolver.FetchBlobMetadataAsync(probingOrg, "library/ubuntu", digest, default);

        // No org-scoped row → the foreign cache hit must NOT satisfy the HEAD.
        Assert.Null(result);
    }

    /// <summary>
    /// Mixed partial-failure (house rule): two digests probed by the SAME org against the SAME
    /// shared cache store.
    ///  - "own": the org holds an <c>oci_blobs</c> row and the bytes are present → HEAD returns
    ///    metadata (media type from the org's own row, not a hardcoded default).
    ///  - "foreign": the bytes are present in the shared store (another org primed them) but the
    ///    probing org owns no row → must NOT be reported as a hit; falls through to upstream 404.
    /// Proves the fix distinguishes entitled content from merely-globally-present content in one
    /// process.
    /// </summary>
    [Fact]
    public async Task FetchBlobMetadata_MixedEntitlement_OwnBlobReturnsMetadata_ForeignBlobFallsThrough()
    {
        byte[] ownBytes = RandomBytes(80);
        string ownSha = Sha256Hex(ownBytes);
        string ownDigest = "sha256:" + ownSha;
        string ownKey = BlobKeys.OciBlob("sha256", ownSha);

        byte[] foreignBytes = RandomBytes(112);
        string foreignSha = Sha256Hex(foreignBytes);
        string foreignDigest = "sha256:" + foreignSha;
        string foreignKey = BlobKeys.OciBlob("sha256", foreignSha);

        var sharedCache = new InMemoryBlobStore();
        await sharedCache.PutAsync(ownKey, new MemoryStream(ownBytes), default);
        await sharedCache.PutAsync(foreignKey, new MemoryStream(foreignBytes), default);

        string probingOrg = await OrgSeeder.InsertAsync(_db, "oci-head-mixed-org");
        await SeedOciUpstreamAsync(probingOrg, "registry-1.docker.io", [""], position: 0);

        // The probing org owns a row ONLY for the "own" digest.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
                VALUES (@digest, @orgId, 'application/vnd.oci.image.layer.v1.tar+gzip', @size, @blobKey, 'proxy')
                """,
                new { digest = ownDigest, orgId = probingOrg, size = (long)ownBytes.Length, blobKey = ownKey });
        }

        // On a genuine miss the foreign digest hits upstream — which 404s for this org.
        var http = new StatusFactory(HttpStatusCode.NotFound);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(http, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs = new TieredBlobStorage(sharedCache, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(http, authSvc, opts, blobs, _db, new StubAirGap(false),
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        var ownResult = await resolver.FetchBlobMetadataAsync(probingOrg, "library/ubuntu", ownDigest, default);
        var foreignResult = await resolver.FetchBlobMetadataAsync(probingOrg, "library/ubuntu", foreignDigest, default);

        // Own: entitled → metadata carrying the media type from the org's own row.
        Assert.NotNull(ownResult);
        Assert.Equal("application/vnd.oci.image.layer.v1.tar+gzip", ownResult!.MediaType);

        // Foreign: not entitled → no leak.
        Assert.Null(foreignResult);
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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        // Request 2: 404 on first attempt (no retry for 404)
        var seq404 = new SequenceFactory(new HttpResponseMessage(HttpStatusCode.NotFound));
        var opts404 = Options.Create(DefaultOptions());
        var auth404 = new OciUpstreamAuthService(seq404, opts404, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var blobs404 = new TieredBlobStorage(_cacheBlobs, new InMemoryBlobStore());
        var resolver404 = new OciUpstreamResolver(seq404, auth404, opts404, blobs404, _db, new StubAirGap(false),
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-singleflight-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        const int concurrency = 6;
        // Start all callers before releasing the gate so they all queue behind the Lazy, then
        // wait for the real production invariant — all 6 have registered against the shared
        // in-flight entry — via the BlobInflightArrivalCount test seam. See
        // WaitForBlobArrivalsAsync's doc for why this observes the invariant directly instead of
        // guessing at it.
        var tasks = Enumerable.Range(0, concurrency)
            .Select(_ => Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digest, default)))
            .ToArray();

        await WaitForBlobArrivalsAsync(resolver, sha256, concurrency);
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
    /// A caller cancelling its own <c>WaitAsync(ct)</c> while the shared upstream pull is still
    /// running must not evict the in-flight entry — a second, uncancelled caller for the SAME
    /// digest must join the SAME shared fetch rather than triggering a brand-new upstream pull.
    /// </summary>
    [Fact]
    public async Task FetchBlobAsync_FirstWaiterCancels_SecondJoinerDoesNotTriggerSecondFetch()
    {
        byte[] blobBytes = RandomBytes(256);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;

        var gate = new GateFactory(blobBytes);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(gate, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(gate, authSvc, opts, blobs, _db, new StubAirGap(false),
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-cancel-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        using var cts = new CancellationTokenSource();
        var firstTask = resolver.FetchBlobAsync(orgId, "library/ubuntu", digest, cts.Token);

        // Wait until the first caller has actually registered and parked the shared Lazy on the
        // gate before cancelling it — a deterministic replacement for a fixed delay.
        await gate.WaitForCallCountAsync(1);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstTask);

        // Wait for the real production invariant — the second caller has registered as a joiner
        // on the still-live in-flight entry (arrival count reaches 2: the cancelled first caller
        // already registered arrival 1) — before releasing the gate. Releasing before that
        // registration lands would let the second caller find the entry already gone and mint a
        // second fetch.
        var secondTask = Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digest, default));
        await WaitForBlobArrivalsAsync(resolver, sha256, 2);
        gate.Release();
        var result = await secondTask;

        Assert.Equal(1, gate.CallCount);
        Assert.NotNull(result);
        using var ms = new MemoryStream();
        await result!.Content.CopyToAsync(ms);
        Assert.Equal(blobBytes, ms.ToArray());
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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-distinct-singleflight-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        // Distinct digests never collapse, so there is no registration race to wait out here —
        // each gate simply unblocks its own caller whenever that caller reaches it.
        var tasks = new[]
        {
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestA, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestB, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestC, default)),
        };
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
        string sha256Shared = Sha256Hex(sharedBytes);
        string sha256B = Sha256Hex(bytesB);
        string sha256C = Sha256Hex(bytesC);
        string sharedDigest = "sha256:" + sha256Shared;
        string digestB = "sha256:" + sha256B;
        string digestC = "sha256:" + sha256C;

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
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        string orgId = await OrgSeeder.InsertAsync(_db, "blob-mixed-singleflight-org");
        await SeedOciUpstreamAsync(orgId, "registry-1.docker.io", [""], position: 0);

        // Two callers on the shared digest, one each on B and C. Wait for the real production
        // invariant — every caller has registered against its in-flight entry — via the
        // BlobInflightArrivalCount test seam, so the shared-digest collapse is exercised under
        // genuine concurrency without guessing at the registration window.
        var tasks = new[]
        {
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", sharedDigest, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", sharedDigest, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestB, default)),
            Task.Run(() => resolver.FetchBlobAsync(orgId, "library/ubuntu", digestC, default)),
        };
        await Task.WhenAll(
            WaitForBlobArrivalsAsync(resolver, sha256Shared, 2),
            WaitForBlobArrivalsAsync(resolver, sha256B, 1),
            WaitForBlobArrivalsAsync(resolver, sha256C, 1));
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

    /// <summary>
    /// Regression: the blob single-flight entry is keyed by the content-addressed blob key only,
    /// but the shared work item (<c>FetchAndCacheBlobAsync</c>) captures the WINNER's org — it
    /// writes the <c>oci_blobs</c> row (and fires the config-blob arrival hook on first insert)
    /// for that org alone. A joiner from a DIFFERENT org shares the cached bytes but, before the
    /// fix, returned the stream with NO per-org DB row of its own: its dashboards, license
    /// projection, and quota accounting never saw the blob.
    ///
    /// Two orgs miss on the same digest concurrently and collapse to one upstream pull. Whichever
    /// org loses the single-flight race is the joiner. This test FAILS on the broken version —
    /// the joiner org has zero <c>oci_blobs</c> rows — and PASSES on the fix, where each waiter
    /// ensures its own org's row (with the real media type and size) after the shared fetch.
    /// </summary>
    [Fact]
    public async Task FetchBlobAsync_SecondOrgJoinsSingleFlight_GetsOwnBlobRow()
    {
        byte[] blobBytes = RandomBytes(384);
        string sha256 = Sha256Hex(blobBytes);
        string digest = "sha256:" + sha256;

        var gate = new GateFactory(blobBytes);
        var opts = Options.Create(DefaultOptions());
        var authSvc = new OciUpstreamAuthService(gate, opts, new StubAirGap(false),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
        var cacheBlobs = new InMemoryBlobStore();
        var blobs = new TieredBlobStorage(cacheBlobs, new InMemoryBlobStore());
        var resolver = new OciUpstreamResolver(gate, authSvc, opts, blobs, _db, new StubAirGap(false),
            NewRecorder(), _cacheRecorder, _cacheArtifacts, NullLogger<OciUpstreamResolver>.Instance, TimeProvider.System, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());

        // Two independent orgs, each with a catch-all upstream, both entitled to a real fetch.
        string orgA = await OrgSeeder.InsertAsync(_db, "join-singleflight-org-a");
        string orgB = await OrgSeeder.InsertAsync(_db, "join-singleflight-org-b");
        await SeedOciUpstreamAsync(orgA, "registry-1.docker.io", [""], position: 0);
        await SeedOciUpstreamAsync(orgB, "registry-1.docker.io", [""], position: 0);

        // Start both callers before releasing the gate so they both queue behind the shared Lazy
        // (one wins the fetch, the other joins as a waiter), then release once both have arrived.
        var taskA = Task.Run(() => resolver.FetchBlobAsync(orgA, "library/ubuntu", digest, default));
        var taskB = Task.Run(() => resolver.FetchBlobAsync(orgB, "library/ubuntu", digest, default));
        await WaitForBlobArrivalsAsync(resolver, sha256, 2);
        gate.Release();

        var resultA = await taskA;
        var resultB = await taskB;

        // Exactly one upstream pull served both orgs.
        Assert.Equal(1, gate.CallCount);
        Assert.NotNull(resultA);
        Assert.NotNull(resultB);

        // Each org — winner AND joiner — must own its per-org oci_blobs row with the real size,
        // not just the single-flight winner. On the broken version the joiner org has zero rows.
        await using var conn = await _db.OpenAsync(default);
        var (countA, sizeA) = await conn.QuerySingleAsync<(int Count, long Size)>(
            "SELECT COUNT(*) AS Count, COALESCE(MAX(size_bytes), 0) AS Size FROM oci_blobs WHERE org_id = @orgA AND digest = @digest",
            new { orgA, digest });
        var (countB, sizeB) = await conn.QuerySingleAsync<(int Count, long Size)>(
            "SELECT COUNT(*) AS Count, COALESCE(MAX(size_bytes), 0) AS Size FROM oci_blobs WHERE org_id = @orgB AND digest = @digest",
            new { orgB, digest });

        Assert.Equal(1, countA);
        Assert.Equal(1, countB);
        Assert.Equal(blobBytes.Length, sizeA);
        Assert.Equal(blobBytes.Length, sizeB);
    }

    // ── Gate factories for single-flight concurrency tests ─────────────────────

    /// <summary>
    /// Returns a single gated HTTP response whose body holds <paramref name="blobBytes"/>.
    /// The response is parked until <see cref="Release"/> is called so all concurrent callers
    /// can queue up before the Lazy resolves.
    /// </summary>
    private sealed class GateFactory : IHttpClientFactory
    {
        private readonly object _arrivalLock = new();
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly byte[] _body;
        private readonly GateCallCounter _counter = new();
        private TaskCompletionSource? _arrival;
        private int _arrivalTarget;

        public GateFactory(byte[] body) => _body = body;

        public int CallCount => _counter.Value;
        public void Release() => _gate.TrySetResult();

        /// <summary>
        /// Completes once the gate has been hit by at least <paramref name="count"/> requests —
        /// a deterministic replacement for guessing how long a caller takes to reach the HTTP
        /// layer with a fixed <see cref="Task.Delay(int)"/>, which flakes under load.
        /// </summary>
        public Task WaitForCallCountAsync(int count, CancellationToken ct = default)
        {
            lock (_arrivalLock)
            {
                if (_counter.Value >= count)
                {
                    return Task.CompletedTask;
                }

                _arrivalTarget = count;
                _arrival = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                return _arrival.Task.WaitAsync(ct);
            }
        }

        // Called directly by RoutingGateFactory to avoid re-sending the same HttpRequestMessage
        // through another HttpClient (which would raise InvalidOperationException).
        public async Task<HttpResponseMessage> HandleAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            _ = request; // not inspected — gate returns a fixed response body
            int count = _counter.Increment();
            lock (_arrivalLock)
            {
                if (_arrival is not null && count >= _arrivalTarget)
                {
                    _arrival.TrySetResult();
                }
            }

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
            public int Increment() => Interlocked.Increment(ref _count);
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
