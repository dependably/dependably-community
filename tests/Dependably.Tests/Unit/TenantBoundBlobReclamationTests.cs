using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// What the tenant content binding costs the rest of the system. A tenant whose upstream served
/// content other than the coordinate's shared row records its own <c>blob_key</c> on
/// <c>tenant_artifact_access</c>, and those bytes are a real file on the cache tier that NO
/// <c>cache_artifact.blob_key</c> anywhere names.
///
/// <para>Every path that measures or reclaims the cache plane reads <c>cache_artifact</c>, so
/// without these behaviours a divergent tenant's blob is invisible to all of them: never counted
/// toward the size cap, never evicted, and — once the coordinate is evicted and the binding
/// cascades away — unreachable forever. That is not a bounded one-copy overhead; it accumulates
/// with every re-fetched coordinate.</para>
///
/// <para>The quota view is the same story from the tenant's side: <c>org_storage_bytes</c> is the
/// authoritative quota read, so summing the shared row's size charges a divergent tenant for
/// another tenant's bytes and disagrees with <c>artifact_inventory</c> about the same row.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantBoundBlobReclamationTests : IAsyncLifetime
{
    private const string SharedHash = "1111111111111111111111111111111111111111111111111111111111111111";
    private const string DivergentHash = "2222222222222222222222222222222222222222222222222222222222222222";

    private static readonly string SharedKey = BlobKeys.Proxy(SharedHash);
    private static readonly string DivergentKey = BlobKeys.Proxy(DivergentHash);

    private const long SharedSize = 1_000;
    private const long DivergentSize = 900_000;

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-shared','shared'), ('o-diverged','diverged')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>
    /// One coordinate, two tenants. o-shared has no binding and is served the shared row;
    /// o-diverged fetched different bytes from its own upstream and is bound to them.
    /// </summary>
    private async Task<string> SeedDivergedCoordinateAsync(DateTimeOffset accessed)
    {
        await _blobs.PutAsync(SharedKey, new MemoryStream(new byte[SharedSize]));
        await _blobs.PutAsync(DivergentKey, new MemoryStream(new byte[DivergentSize]));

        string id = Guid.NewGuid().ToString("D");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                 first_cached_at, last_accessed_at)
            VALUES (@id,'npm','left-pad','1.0.0','left-pad-1.0.0.tgz',
                    @sharedKey, @sharedHash, @sharedSize, @accessed, @accessed)
            """,
            new { id, sharedKey = SharedKey, sharedHash = SharedHash, sharedSize = SharedSize, accessed = accessed.ToUtcIso() });

        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access
                (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count)
            VALUES ('o-shared', @id, @accessed, @accessed, 1)
            """,
            new { id, accessed = accessed.ToUtcIso() });

        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access
                (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count,
                 content_hash, blob_key, size_bytes)
            VALUES ('o-diverged', @id, @accessed, @accessed, 1, @hash, @key, @size)
            """,
            new { id, accessed = accessed.ToUtcIso(), hash = DivergentHash, key = DivergentKey, size = DivergentSize });

        return id;
    }

    [Fact]
    public async Task OrgStorageBytes_ChargesEachTenantTheBytesItIsActuallyServed()
    {
        await SeedDivergedCoordinateAsync(_clock.GetUtcNow());

        await using var conn = await _db.OpenAsync();
        var totals = (await conn.QueryAsync<(string OrgId, long TotalBytes)>(
            "SELECT org_id AS OrgId, total_bytes AS TotalBytes FROM org_storage_bytes ORDER BY org_id"))
            .ToDictionary(r => r.OrgId, r => r.TotalBytes);

        // The quota read and the inventory read must not disagree about the same row: one of them
        // is what an operator sees and the other is what the quota gate enforces.
        Assert.Equal(DivergentSize, totals["o-diverged"]);
        Assert.Equal(SharedSize, totals["o-shared"]);

        var inventory = (await conn.QueryAsync<(string OrgId, string BlobKey, long SizeBytes)>(
            """
            SELECT org_id AS OrgId, blob_key AS BlobKey, size_bytes AS SizeBytes
            FROM artifact_inventory WHERE owner_kind = 'cache_artifact'
            """)).ToDictionary(r => r.OrgId, r => (r.BlobKey, r.SizeBytes));

        Assert.Equal((DivergentKey, DivergentSize), inventory["o-diverged"]);
        Assert.Equal((SharedKey, SharedSize), inventory["o-shared"]);
    }

    [Fact]
    public async Task TotalCacheSize_CountsBytesThatOnlyATenantBindingNames()
    {
        await SeedDivergedCoordinateAsync(_clock.GetUtcNow());

        long total = await new CacheArtifactRepository(_db).GetTotalSizeBytesAsync();

        // Both physical blobs are on the cache tier. A cap that only sums cache_artifact sees
        // 1 KB of a 901 KB cache and never evicts.
        Assert.Equal(SharedSize + DivergentSize, total);
    }

    [Fact]
    public async Task Eviction_ReclaimsTheBlobOnlyATenantBindingNames()
    {
        var t = _clock.GetUtcNow();
        await SeedDivergedCoordinateAsync(t.AddDays(-100));

        var summary = await BuildEvictionService(
            new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "30" }).RunOnceAsync();

        Assert.Equal(1, summary.ArtifactsEvicted);
        Assert.False(await _blobs.ExistsAsync(SharedKey));

        // The binding cascaded away with the row, so nothing records this blob any more. If the
        // eviction pass did not take it, no pass ever can.
        Assert.False(await _blobs.ExistsAsync(DivergentKey));
    }

    [Fact]
    public async Task Eviction_LeavesABoundBlobAnotherCoordinateStillNames()
    {
        var t = _clock.GetUtcNow();
        string id = await SeedDivergedCoordinateAsync(t.AddDays(-100));

        // A second, fresh coordinate whose shared row resolved to the very same divergent bytes.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                     first_cached_at, last_accessed_at)
                VALUES ('ca-sibling','npm','right-pad','1.0.0','right-pad-1.0.0.tgz',
                        @key, @hash, @size, @fresh, @fresh)
                """,
                new { key = DivergentKey, hash = DivergentHash, size = DivergentSize, fresh = t.ToUtcIso() });
        }

        await BuildEvictionService(
            new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "30" }).RunOnceAsync();

        await using var check = await _db.OpenAsync();
        Assert.Equal(0, await check.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE id = @id", new { id }));

        // Content-addressed keys are shared by construction: "this coordinate is gone" is not
        // "nobody needs these bytes".
        Assert.True(await _blobs.ExistsAsync(DivergentKey));
    }

    [Fact]
    public async Task RetentionVersionLimit_ReclaimsThePurgedOrgsOwnBoundBlob()
    {
        var t = _clock.GetUtcNow();
        string id = await SeedDivergedCoordinateAsync(t.AddDays(-100));

        // A second, newer version of the same package so the keep_versions cut has something to
        // keep — the pass evicts the older version for the org it is running against.
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                     first_cached_at, last_accessed_at)
                VALUES ('ca-newer','npm','left-pad','2.0.0','left-pad-2.0.0.tgz',
                        'proxy/3333333333333333333333333333333333333333333333333333333333333333/left-pad-2.0.0.tgz',
                        '3333333333333333333333333333333333333333333333333333333333333333', 10, @fresh, @fresh)
                """,
                new { fresh = t.ToUtcIso() });
            await seed.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access
                    (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count)
                VALUES ('o-diverged','ca-newer', @fresh, @fresh, 1)
                """,
                new { fresh = t.ToUtcIso() });
        }

        await using (var conn = await _db.OpenAsync())
        {
            await BuildRetentionService().EnforceVersionLimitAsync(conn, "o-diverged", keepVersions: 1, default);
        }

        await using var check = await _db.OpenAsync();
        Assert.Equal(0, await check.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = 'o-diverged' AND cache_artifact_id = @id",
            new { id }));

        // The purged org's own bytes go with its access row: no cache_artifact row anywhere names
        // that key, so nothing would ever find it again.
        Assert.False(await _blobs.ExistsAsync(DivergentKey));

        // The shared row still has a tenant, so its blob stays.
        Assert.True(await _blobs.ExistsAsync(SharedKey));
    }

    private RetentionService BuildRetentionService()
    {
        var cfg = new ConfigurationBuilder().Build();
        return new RetentionService(new RetentionService.Dependencies(
            _db, _blobs, new JwtRevocationRepository(_db, time: _clock),
            new InviteRepository(_db, _clock), new SamlConfigRepository(_db, _clock),
            new TrustedDeviceService(_db, _clock, cfg),
            cfg, new AirGapMode(cfg), NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new TieredBlobStorage(_blobs, _blobs), new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg)));
    }

    private CacheEvictionService BuildEvictionService(IDictionary<string, string?> cfg)
    {
        var repo = new CacheArtifactRepository(_db);
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var deps = new CacheEvictionService.Dependencies(
            repo,
            tiered,
            new CacheOrphanBlobDeleter(repo, new CacheBlobKeyLock()),
            new TenantArtifactAccessRepository(_db),
            new PackageRepository(_db, time: _clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, tiered, new Dependably.Protocol.OciBlobKeyLock()));
        return new CacheEvictionService(
            deps,
            new ConfigurationBuilder().AddInMemoryCollection(cfg).Build(),
            NullLogger<CacheEvictionService>.Instance,
            _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));
    }
}
