using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
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

    private CacheEvictionService Build(IDictionary<string, string?> cfg)
    {
        var repo = new CacheArtifactRepository(_db);
        // Tier-shared bootstrap: in unit tests the cache and registry tiers point to the
        // same in-memory store. The eviction service only ever calls Cache.DeleteAsync.
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        return new CacheEvictionService(repo, tiered, Config(cfg), NullLogger<CacheEvictionService>.Instance, _clock);
    }

    [Fact]
    public async Task NoCapsConfigured_DoesNothing()
    {
        await SeedAsync("1.0.0", _clock.GetUtcNow().AddDays(-100));
        var svc = Build(new Dictionary<string, string?>());
        var result = await svc.RunOnceAsync();
        Assert.Equal(0, result.ArtifactsEvicted);

        var repo = new CacheArtifactRepository(_db);
        Assert.NotNull(await repo.GetByCoordinateAsync("npm", "lodash", "1.0.0", "lodash-1.0.0.tgz"));
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
    public async Task Eviction_CascadesTenantArtifactAccess()
    {
        var t = _clock.GetUtcNow();
        await SeedAsync("v1", t.AddDays(-30));
        var repo = new CacheArtifactRepository(_db);
        var a = await repo.GetByCoordinateAsync("npm", "lodash", "v1", "lodash-v1.tgz");
        var access = new TenantArtifactAccessRepository(_db);
        await access.UpsertAsync("o1", a!.Id, t);

        var svc = Build(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" });
        await svc.RunOnceAsync();

        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @id",
            new { id = a.Id });
        Assert.Equal(0, count);
    }
}
