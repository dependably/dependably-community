using System.Diagnostics.Metrics;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

// Attaches a MeterListener filtered only by DependablyMeter.MeterName + instrument name and
// asserts exact counts — must run alone against the process-wide static meter.
// See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public class CacheEvictionServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IConfiguration Config(IDictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static string ShaSentinelFor(string version)
    {
        byte[] bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(version));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private async Task SeedAsync(string version, DateTimeOffset accessed, long size = 100)
    {
        // Insert blob first so eviction's blob-delete step has something to remove.
        // BlobKeys.Proxy requires 64-char lowercase hex (hardened to reject non-hex input); derive a
        // deterministic-but-valid sentinel from the version.
        string blobKey = BlobKeys.Proxy(ShaSentinelFor(version));
        await _blobs.PutAsync(blobKey, new MemoryStream(new byte[size]));

        var repo = new CacheArtifactRepository(_db);
        await repo.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "lodash",
            Version = version,
            Filename = $"lodash-{version}.tgz",
            BlobKey = blobKey,
            ContentHash = "sha256:x",
            SizeBytes = size,
            FirstCachedAt = accessed,
            LastAccessedAt = accessed
        });
    }

    /// <summary>
    /// Seeds a cache_artifact row whose blob_key is derived from <paramref name="contentLabel"/>
    /// rather than the coordinate — letting two distinct coordinates (different name and/or
    /// version) share one content-addressed blob key, the shared-key refcount scenario the
    /// "SharedBlobKey" tests below exercise. Only puts the blob into the store when it isn't
    /// already there, so seeding two rows with the same contentLabel doesn't re-write it.
    /// </summary>
    private async Task SeedSharedContentAsync(
        string name, string version, string contentLabel, DateTimeOffset accessed, long size = 100)
    {
        string blobKey = BlobKeys.Proxy(ShaSentinelFor(contentLabel));
        if (!await _blobs.ExistsAsync(blobKey))
        {
            await _blobs.PutAsync(blobKey, new MemoryStream(new byte[size]));
        }

        var repo = new CacheArtifactRepository(_db);
        await repo.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = name,
            Version = version,
            Filename = $"{name}-{version}.tgz",
            BlobKey = blobKey,
            ContentHash = "sha256:x",
            SizeBytes = size,
            FirstCachedAt = accessed,
            LastAccessedAt = accessed
        });
    }

    // OCI manifests carry a fixed "manifest" filename and a digest as their version. Seeds the
    // full shape a proxy manifest pull leaves behind — the shared cache_artifact row plus one
    // oci_blobs row and one tenant_artifact_access claim per holding org — so eviction exercises
    // the per-holder claim release rather than a bare row delete. Returns the cache_artifact id.
    private async Task<string> SeedOciAsync(
        string digestHex, DateTimeOffset accessed, long size = 100, params string[] holderOrgs)
    {
        string blobKey = BlobKeys.OciBlob("sha256", digestHex);
        await _blobs.PutAsync(blobKey, new MemoryStream(new byte[size]));

        string id = Guid.NewGuid().ToString("D");
        var repo = new CacheArtifactRepository(_db);
        await repo.InsertAsync(new CacheArtifact
        {
            Id = id,
            Ecosystem = "oci",
            Name = "library/ubuntu",
            Version = "sha256:" + digestHex,
            Filename = "manifest",
            BlobKey = blobKey,
            ContentHash = digestHex,
            SizeBytes = size,
            FirstCachedAt = accessed,
            LastAccessedAt = accessed
        });

        string[] orgs = holderOrgs.Length > 0 ? holderOrgs : ["o1"];
        await using var conn = await _db.OpenAsync();
        foreach (string orgId in orgs)
        {
            await conn.ExecuteAsync(
                "INSERT OR IGNORE INTO orgs (id, slug) VALUES (@id, @id)", new { id = orgId });
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, last_accessed_at, last_used)
                VALUES (@orgId, @caId, @at, @at)
                """,
                new { orgId, caId = id, at = accessed.ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
                VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', @size, @blobKey, 'proxy')
                """,
                new { digest = "sha256:" + digestHex, orgId, size, blobKey });
        }

        return id;
    }

    private async Task<long> OciBlobRowCountAsync(string digestHex)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @d", new { d = "sha256:" + digestHex });
    }

    private CacheEvictionService Build(IDictionary<string, string?> cfg)
    {
        // Tier-shared bootstrap: in unit tests the cache and registry tiers point to the
        // same in-memory store. The eviction service only ever calls Cache.DeleteAsync.
        return Build(cfg, _blobs);
    }

    private CacheEvictionService Build(IDictionary<string, string?> cfg, IBlobStore cacheTier)
    {
        var repo = new CacheArtifactRepository(_db);
        var tiered = new TieredBlobStorage(cacheTier, _blobs);
        var orphanBlobs = new CacheOrphanBlobDeleter(repo, new CacheBlobKeyLock());
        var deps = new CacheEvictionService.Dependencies(
            repo,
            tiered,
            orphanBlobs,
            new TenantArtifactAccessRepository(_db),
            new PackageRepository(_db, time: _clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, tiered, new Dependably.Protocol.OciBlobKeyLock()));
        return new CacheEvictionService(deps, Config(cfg), NullLogger<CacheEvictionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));
    }

    [Fact]
    public async Task NoCapsConfigured_AppliesDefaultAgeCap()
    {
        var t = _clock.GetUtcNow();
        await SeedAsync("old", t.AddDays(-100));
        await SeedAsync("recent", t.AddDays(-1));

        var svc = Build(new Dictionary<string, string?>());
        var result = await svc.RunOnceAsync();

        Assert.Equal(1, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "old", "lodash-old.tgz"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "recent", "lodash-recent.tgz"));
    }

    [Fact]
    public async Task ExplicitCap_OverridesDefault()
    {
        var t = _clock.GetUtcNow();
        await SeedAsync("stale", t.AddDays(-15));
        await SeedAsync("fresh", t.AddDays(-3));

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(1, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "stale", "lodash-stale.tgz"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "fresh", "lodash-fresh.tgz"));
    }

    [Fact]
    public async Task Eviction_EmitsCacheEvictionsMetric()
    {
        var t = _clock.GetUtcNow();
        await SeedAsync("evict-me", t.AddDays(-100));

        long evictions = 0;
        long evictedBytes = 0;
        using var listener = EvictionMeterListener(
            onEvictions: delta => evictions += delta,
            onBytes: delta => evictedBytes += delta);

        var svc = Build(new Dictionary<string, string?>());
        var result = await svc.RunOnceAsync();

        Assert.Equal(1, result.ArtifactsEvicted);
        Assert.Equal(1, evictions);
        Assert.Equal(100, evictedBytes);
    }

    [Fact]
    public async Task AgeCap_EvictsArtifactsOlderThanLimit()
    {
        var t = _clock.GetUtcNow();
        await SeedAsync("old", t.AddDays(-30));
        await SeedAsync("recent", t.AddDays(-1));

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(1, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "old", "lodash-old.tgz"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "recent", "lodash-recent.tgz"));
    }

    [Fact]
    public async Task SizeCap_EvictsOldestFirstUntilUnderCap()
    {
        var t = _clock.GetUtcNow();
        await SeedAsync("v1", t.AddDays(-3), size: 100);
        await SeedAsync("v2", t.AddDays(-2), size: 100);
        await SeedAsync("v3", t.AddDays(-1), size: 100);

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_SIZE_BYTES"] = "150" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(2, result.ArtifactsEvicted);
        Assert.Equal(200, result.BytesFreed);

        var repo = new CacheArtifactRepository(_db);
        // v3 (newest) should remain
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "v3", "lodash-v3.tgz"));
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "v1", "lodash-v1.tgz"));
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "v2", "lodash-v2.tgz"));
    }

    [Fact]
    public async Task CountCap_EvictsOldestFirstUntilUnderCap()
    {
        // CACHE_MAX_ARTIFACTS set with NO CACHE_MAX_SIZE_BYTES and NO CACHE_MAX_AGE_DAYS — the
        // exact operator configuration that previously left the count cap unenforced (maxSizeBytes
        // null meant the size cap defaulted to long.MaxValue and the pass evicted nothing).
        var t = _clock.GetUtcNow();
        await SeedAsync("v1", t.AddDays(-3), size: 100);
        await SeedAsync("v2", t.AddDays(-2), size: 100);
        await SeedAsync("v3", t.AddDays(-1), size: 100);

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_ARTIFACTS"] = "1" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(2, result.ArtifactsEvicted);
        Assert.Equal(200, result.BytesFreed);

        var repo = new CacheArtifactRepository(_db);
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "v3", "lodash-v3.tgz"));
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "v1", "lodash-v1.tgz"));
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "v2", "lodash-v2.tgz"));
        Assert.Equal(1, await repo.GetTotalCountAsync());
    }

    [Fact]
    public async Task CountCap_EnforcedEvenWhenSizeCapAlreadySatisfied()
    {
        // Mixed-cap scenario: the size cap alone is nowhere near tripped, but the count cap is —
        // eviction must still run to satisfy the count cap independently of the size cap.
        var t = _clock.GetUtcNow();
        await SeedAsync("v1", t.AddDays(-3), size: 10);
        await SeedAsync("v2", t.AddDays(-2), size: 10);
        await SeedAsync("v3", t.AddDays(-1), size: 10);

        var svc = Build(new Dictionary<string, string?>
        {
            ["CACHE_MAX_SIZE_BYTES"] = "1000",
            ["CACHE_MAX_ARTIFACTS"] = "2",
        });
        var result = await svc.RunOnceAsync();

        Assert.Equal(1, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "v1", "lodash-v1.tgz"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "v2", "lodash-v2.tgz"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "v3", "lodash-v3.tgz"));
        Assert.Equal(2, await repo.GetTotalCountAsync());
    }

    [Fact]
    public async Task CountCap_CountsOciAndEvictsItWhenOverBudget()
    {
        // OCI rows count toward the artifact cap and are evictable like any other row. Two rows
        // against a cap of 1 must leave exactly one behind.
        var t = _clock.GetUtcNow();
        string digest = new('d', 64);
        await SeedOciAsync(digest, t.AddDays(-2));
        await SeedAsync("small-npm", t.AddDays(-1));

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_ARTIFACTS"] = "1" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(1, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        // The OCI row is the least-recently-accessed, so it is the one that goes.
        Assert.Null(await repo.GetByCoordinateAsync(
            "oci", "library/ubuntu", "sha256:" + digest, "manifest"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "small-npm", "lodash-small-npm.tgz"));
        // Its holder's claim came off with it.
        Assert.Equal(0, await OciBlobRowCountAsync(digest));
    }

    [Fact]
    public async Task OciEviction_TwoOrgsHoldOneManifest_SecondOrgCanStillPull()
    {
        // The acceptance case. cache_artifact is shared and oci_blobs is keyed (digest, org_id),
        // so evicting the shared row must release BOTH holders' claims — and must not delete the
        // manifest bytes while either still points at them. Releasing only the sweep's "own" org
        // (it has none) or deleting the blob through the cache-plane guard would corrupt org two.
        var t = _clock.GetUtcNow();
        string digest = new('e', 64);
        await SeedOciAsync(digest, t.AddDays(-100), size: 100, holderOrgs: ["o1", "o2"]);

        Assert.Equal(2, await OciBlobRowCountAsync(digest));

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(1, result.ArtifactsEvicted);

        // Both claims released — one oci_blobs row per holder, both gone.
        Assert.Equal(0, await OciBlobRowCountAsync(digest));

        // The catalogue row is gone, and so is every tenant_artifact_access claim on it.
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync(
            "oci", "library/ubuntu", "sha256:" + digest, "manifest"));
        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id IN " +
            "(SELECT id FROM cache_artifact WHERE ecosystem = 'oci')"));
    }

    [Fact]
    public async Task OciEviction_NeverDeletesBytesThroughTheCachePlaneGuard()
    {
        // The cache-plane blob delete is guarded only against sibling cache_artifact rows and
        // cannot see an oci_blobs row, so the OCI arm must not call it at all. Physical reclaim is
        // OciBlobReclaimer's job, on a later pass, once all four claims are gone. Here a second org
        // still holds the digest via a hosted push, so the bytes must survive this sweep.
        var t = _clock.GetUtcNow();
        string digest = new('f', 64);
        string blobKey = BlobKeys.OciBlob("sha256", digest);
        await SeedOciAsync(digest, t.AddDays(-100), size: 100, holderOrgs: ["o1"]);

        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o3', 'o3')");
            await seed.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
                VALUES (@digest, 'o3', 'application/vnd.oci.image.manifest.v1+json', 100, @blobKey, 'uploaded')
                """,
                new { digest = "sha256:" + digest, blobKey });
        }

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        await svc.RunOnceAsync();

        // o3's row survives (it was never a cache-plane holder), and so must the bytes.
        Assert.Equal(1, await OciBlobRowCountAsync(digest));
        Assert.True(await _blobs.ExistsAsync(blobKey),
            "manifest bytes were deleted while another org's oci_blobs row still referenced them");
    }

    // ── Shared content-addressed blob_key across distinct coordinates ────────
    // Proxy blob keys (BlobKeys.Proxy) are content-addressed and shared by any coordinate with
    // byte-identical upstream bytes. Evicting one coordinate's row must never physically delete
    // a blob a sibling coordinate's own (surviving) row still references.

    [Fact]
    public async Task AgeCap_SharedBlobKeyAcrossDistinctCoordinates_SurvivesUntilLastSharerEvicted()
    {
        var t = _clock.GetUtcNow();
        // Two unrelated coordinates share byte-identical content; "kept" is recent so only "old"
        // is past the age cap this pass.
        await SeedSharedContentAsync("pkg-old", "1.0.0", "shared-bytes", t.AddDays(-100));
        await SeedSharedContentAsync("pkg-kept", "1.0.0", "shared-bytes", t.AddDays(-1));
        string blobKey = BlobKeys.Proxy(ShaSentinelFor("shared-bytes"));

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(1, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "pkg-old", "1.0.0", "pkg-old-1.0.0.tgz"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "pkg-kept", "1.0.0", "pkg-kept-1.0.0.tgz"));

        // The surviving sibling's own row still references this key — the blob must not vanish
        // out from under it.
        Assert.True(await _blobs.ExistsAsync(blobKey),
            "a blob shared by a surviving sibling coordinate must not be deleted");
    }

    [Fact]
    public async Task AgeCap_SharedBlobKey_ReclaimedOnceLastSharerEvicted()
    {
        var t = _clock.GetUtcNow();
        // Both sharers are past the cap and evicted in the same pass — the blob must only be
        // reclaimed once neither row references it any more, not leaked forever.
        await SeedSharedContentAsync("pkg-a", "1.0.0", "shared-last", t.AddDays(-100));
        await SeedSharedContentAsync("pkg-b", "1.0.0", "shared-last", t.AddDays(-100));
        string blobKey = BlobKeys.Proxy(ShaSentinelFor("shared-last"));

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(2, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "pkg-a", "1.0.0", "pkg-a-1.0.0.tgz"));
        Assert.Null(await repo.GetByCoordinateAsync("npm", "pkg-b", "1.0.0", "pkg-b-1.0.0.tgz"));
        Assert.False(await _blobs.ExistsAsync(blobKey),
            "once both sharers are gone the blob must finally be reclaimed, not leaked");
    }

    // Mixed batch, ONE pass: "mixed-shared" is referenced by an old row (evicted this pass) and
    // a recent row (kept) — its blob must survive. "mixed-solo" is referenced by only one old
    // row — its blob must be reclaimed. Both old rows are evicted together in the same
    // RunOnceAsync call.
    [Fact]
    public async Task AgeCap_MixedSharedAndSoloBlobKeysInOnePass_OnlySoloBlobReclaimed()
    {
        var t = _clock.GetUtcNow();
        await SeedSharedContentAsync("pkg-mixed-old", "1.0.0", "mixed-shared", t.AddDays(-100));
        await SeedSharedContentAsync("pkg-mixed-kept", "1.0.0", "mixed-shared", t.AddDays(-1));
        await SeedSharedContentAsync("pkg-mixed-solo", "1.0.0", "mixed-solo", t.AddDays(-100));
        string sharedKey = BlobKeys.Proxy(ShaSentinelFor("mixed-shared"));
        string soloKey = BlobKeys.Proxy(ShaSentinelFor("mixed-solo"));

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        var result = await svc.RunOnceAsync();

        // Both "old" rows (pkg-mixed-old and pkg-mixed-solo) are past the cap and evicted this
        // pass; "pkg-mixed-kept" is recent and survives.
        Assert.Equal(2, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "pkg-mixed-old", "1.0.0", "pkg-mixed-old-1.0.0.tgz"));
        Assert.Null(await repo.GetByCoordinateAsync("npm", "pkg-mixed-solo", "1.0.0", "pkg-mixed-solo-1.0.0.tgz"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "pkg-mixed-kept", "1.0.0", "pkg-mixed-kept-1.0.0.tgz"));

        Assert.True(await _blobs.ExistsAsync(sharedKey),
            "a blob key still referenced by the surviving sibling must not be deleted");
        Assert.False(await _blobs.ExistsAsync(soloKey),
            "a blob key referenced by no remaining row must be reclaimed, not leaked");
    }

    [Fact]
    public async Task Eviction_CascadesTenantArtifactAccess()
    {
        var t = _clock.GetUtcNow();
        await SeedAsync("v1", t.AddDays(-30));
        var repo = new CacheArtifactRepository(_db);
        var a = await repo.GetByCoordinateAsync("npm", "lodash", "v1", "lodash-v1.tgz");
        var access = new TenantArtifactAccessRepository(_db);
        await access.UpsertAsync("o1", a!.Id, t, TenantContentBinding.None);

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        await svc.RunOnceAsync();

        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
            new { id = a.Id });
        Assert.Equal(0, count);
    }

    // ── OCI participates in cache-plane eviction ──────────────────────────────
    // An OCI row is evicted by releasing every holding org's digest claim before the shared
    // cache_artifact row goes. The physical bytes are never deleted here — that is
    // OciBlobReclaimer's sweep, which also collects the layer closure the manifest was holding up.

    [Fact]
    public async Task AgeCap_MixedOciAndNpm_BothEvicted()
    {
        // Both rows are far older than the cap, and the age arm no longer skips OCI: the manifest
        // is evicted by releasing its holder's digest claim, leaving the bytes to OciBlobReclaimer.
        var t = _clock.GetUtcNow();
        string digest = new('b', 64);
        await SeedOciAsync(digest, t.AddDays(-100));
        await SeedAsync("old-npm", t.AddDays(-100));

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        var result = await svc.RunOnceAsync();

        Assert.Equal(2, result.ArtifactsEvicted);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "old-npm", "lodash-old-npm.tgz"));
        Assert.Null(await repo.GetByCoordinateAsync(
            "oci", "library/ubuntu", "sha256:" + digest, "manifest"));
        Assert.Equal(0, await OciBlobRowCountAsync(digest));
    }

    [Fact]
    public async Task SizeCap_CountsOciBytesAndEvictsItToRelieveTheCap()
    {
        // The whole point of the issue: a huge OCI row now counts toward CACHE_MAX_SIZE_BYTES and
        // is evicted to get back under it. Previously the total omitted it, so the cap read as
        // satisfied at 50 bytes while 100 KB of manifest sat uncounted and unreclaimable.
        var t = _clock.GetUtcNow();
        string digest = new('c', 64);
        await SeedOciAsync(digest, t.AddDays(-2), size: 100_000);
        await SeedAsync("small-npm", t.AddDays(-1), size: 50);

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_SIZE_BYTES"] = "1000" });
        var result = await svc.RunOnceAsync();

        // 100_050 bytes against a 1000-byte cap: the OCI row is both the largest and the
        // least-recently-accessed, and evicting it alone brings the total to 50.
        Assert.Equal(1, result.ArtifactsEvicted);
        Assert.Equal(100_000, result.BytesFreed);
        var repo = new CacheArtifactRepository(_db);
        Assert.Null(await repo.GetByCoordinateAsync(
            "oci", "library/ubuntu", "sha256:" + digest, "manifest"));
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "small-npm", "lodash-small-npm.tgz"));
        Assert.Equal(0, await OciBlobRowCountAsync(digest));
    }

    // ── A persistently failing blob delete must not livelock the pass ─────────

    [Fact]
    public async Task AgeCap_BlobDeleteAlwaysFails_TerminatesWithoutRelistingForever()
    {
        // Every row is past the age cap, so a naive re-list loop keeps handing the same rows
        // back after each failed blob delete. With three rows and a self-cancelling safety cap
        // far above the row count, the fixed service attempts exactly one delete per row and
        // stops on the no-progress batch; the unfixed service spins until the safety cap trips.
        var t = _clock.GetUtcNow();
        await SeedAsync("a", t.AddDays(-100));
        await SeedAsync("b", t.AddDays(-100));
        await SeedAsync("c", t.AddDays(-100));

        using var safety = new CancellationTokenSource();
        var failing = new FailingDeleteBlobStore(_blobs, safety, safetyCap: 30);

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" }, failing);
        var result = await svc.RunOnceAsync(safety.Token);

        // Nothing was actually removed (blob delete failed every time) so the count must be 0 —
        // the old code both looped forever AND counted the un-evicted rows as evicted.
        Assert.Equal(0, result.ArtifactsEvicted);
        Assert.Equal(0, result.BytesFreed);
        // Exactly one delete attempt per row: the pass terminated on no-progress, not on the cap.
        Assert.Equal(3, failing.DeleteAttempts);
        Assert.False(safety.IsCancellationRequested);

        // Rows are left in place for a later pass.
        var repo = new CacheArtifactRepository(_db);
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "a", "lodash-a.tgz"));
    }

    [Fact]
    public async Task SizeCap_BlobDeleteAlwaysFails_TerminatesWithoutRelistingForever()
    {
        // The size total stays above the cap because no row is ever removed, so a naive loop
        // re-reads the same over-cap total and re-lists the same rows forever.
        var t = _clock.GetUtcNow();
        await SeedAsync("v1", t.AddDays(-3), size: 100);
        await SeedAsync("v2", t.AddDays(-2), size: 100);
        await SeedAsync("v3", t.AddDays(-1), size: 100);

        using var safety = new CancellationTokenSource();
        var failing = new FailingDeleteBlobStore(_blobs, safety, safetyCap: 30);

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_SIZE_BYTES"] = "150" }, failing);
        var result = await svc.RunOnceAsync(safety.Token);

        Assert.Equal(0, result.ArtifactsEvicted);
        Assert.Equal(0, result.BytesFreed);
        // The size pass evicts oldest-first and stops as soon as the batch makes no progress —
        // it never re-reads the total and re-lists the same rows past the safety cap.
        Assert.True(failing.DeleteAttempts <= 3,
            $"expected the pass to stop after the first no-progress batch, saw {failing.DeleteAttempts} delete attempts");
        Assert.False(safety.IsCancellationRequested);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns an active <see cref="MeterListener"/> that invokes the supplied callbacks
    /// with each measurement emitted by <c>dependably.cache.evictions</c> and
    /// <c>dependably.cache.evicted_bytes</c>. Must be disposed after the assertion.
    /// </summary>
    private static MeterListener EvictionMeterListener(Action<long> onEvictions, Action<long> onBytes)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName &&
                    (instrument.Name == "dependably.cache.evictions" ||
                     instrument.Name == "dependably.cache.evicted_bytes"))
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, _, _) =>
        {
            if (instrument.Name == "dependably.cache.evictions")
            {
                onEvictions(measurement);
            }
            else if (instrument.Name == "dependably.cache.evicted_bytes")
            {
                onBytes(measurement);
            }
        });
        listener.Start();
        return listener;
    }

    /// <summary>
    /// Cache-tier <see cref="IBlobStore"/> whose <see cref="DeleteAsync"/> always throws —
    /// modelling a persistently unreachable cache backend (bad S3 credentials, network
    /// partition). Reads and writes delegate to the wrapped store so seeding still works.
    /// After <paramref name="safetyCap"/> delete attempts it cancels the supplied token so a
    /// service that livelocks re-listing the same failing rows still terminates the test
    /// (via the pass's cancellation check) instead of hanging the run forever.
    /// </summary>
    private sealed class FailingDeleteBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private readonly CancellationTokenSource _safety;
        private readonly int _safetyCap;

        public int DeleteAttempts { get; private set; }

        public FailingDeleteBlobStore(IBlobStore inner, CancellationTokenSource safety, int safetyCap)
        {
            _inner = inner;
            _safety = safety;
            _safetyCap = safetyCap;
        }

        public Task DeleteAsync(string key, CancellationToken ct = default)
        {
            DeleteAttempts++;
            if (DeleteAttempts >= _safetyCap)
            {
                _safety.Cancel();
            }
            throw new IOException("cache backend unreachable");
        }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => _inner.PutAsync(key, data, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) =>
            _inner.GetRangeAsync(key, from, to, ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) =>
            _inner.ListAsync(prefix, ct);
    }
}
