using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class CacheArtifactRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static CacheArtifact Sample(string version, DateTimeOffset accessed) => new()
    {
        Id = Guid.NewGuid().ToString("D"),
        Ecosystem = "npm",
        Name = "lodash",
        Version = version,
        Filename = $"lodash-{version}.tgz",
        BlobKey = $"proxy/abc/{version}",
        ContentHash = "sha256:abc",
        SizeBytes = 100,
        FirstCachedAt = accessed,
        LastAccessedAt = accessed
    };

    [Fact]
    public async Task GetByCoordinate_RoundTrip()
    {
        var repo = new CacheArtifactRepository(_db);
        var a = Sample("1.0.0", DateTimeOffset.UtcNow);
        await repo.InsertAsync(a);

        var loaded = await repo.GetByCoordinateAsync("npm", "lodash", "1.0.0", "lodash-1.0.0.tgz");
        Assert.NotNull(loaded);
        Assert.Equal(a.Id, loaded!.Id);
        Assert.Equal(100, loaded.SizeBytes);
    }

    [Fact]
    public async Task ListLruCandidates_ReturnsOldestFirst()
    {
        var repo = new CacheArtifactRepository(_db);
        var t = DateTimeOffset.UtcNow;
        await repo.InsertAsync(Sample("1.0.0", t.AddDays(-30)));
        await repo.InsertAsync(Sample("2.0.0", t.AddDays(-10)));
        await repo.InsertAsync(Sample("3.0.0", t.AddDays(-1)));

        var candidates = await repo.ListLruCandidatesAsync(t.AddDays(-5), limit: 10);
        Assert.Equal(2, candidates.Count);
        Assert.Equal("1.0.0", candidates[0].Version);
        Assert.Equal("2.0.0", candidates[1].Version);
    }

    [Fact]
    public async Task GetTotalSizeBytes_SumsAll()
    {
        var repo = new CacheArtifactRepository(_db);
        await repo.InsertAsync(Sample("1.0.0", DateTimeOffset.UtcNow));
        await repo.InsertAsync(Sample("2.0.0", DateTimeOffset.UtcNow));
        long total = await repo.GetTotalSizeBytesAsync();
        Assert.Equal(200, total);
    }

    [Fact]
    public async Task TouchAccess_UpdatesLastAccessedAt()
    {
        var repo = new CacheArtifactRepository(_db);
        var a = Sample("1.0.0", DateTimeOffset.UtcNow.AddDays(-100));
        await repo.InsertAsync(a);

        var newer = DateTimeOffset.UtcNow;
        await repo.TouchAccessAsync(a.Id, newer);

        var loaded = await repo.GetByCoordinateAsync("npm", "lodash", "1.0.0", "lodash-1.0.0.tgz");
        Assert.True(loaded!.LastAccessedAt > a.LastAccessedAt);
    }

    [Fact]
    public async Task Delete_Removes()
    {
        var repo = new CacheArtifactRepository(_db);
        var a = Sample("1.0.0", DateTimeOffset.UtcNow);
        await repo.InsertAsync(a);
        await repo.DeleteAsync(a.Id);
        Assert.Null(await repo.GetByCoordinateAsync("npm", "lodash", "1.0.0", "lodash-1.0.0.tgz"));
    }
}
