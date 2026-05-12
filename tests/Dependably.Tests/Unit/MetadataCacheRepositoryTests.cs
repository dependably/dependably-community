using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class MetadataCacheRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static MetadataCacheEntry Sample(string name, DateTimeOffset fetched, TimeSpan ttl) => new()
    {
        Id = Guid.NewGuid().ToString("D"),
        Ecosystem = "npm",
        Name = name,
        Document = "{}",
        ContentHash = "sha256:zero",
        UpstreamEtag = "W/\"abc\"",
        FetchedAt = fetched,
        ExpiresAt = fetched + ttl
    };

    [Fact]
    public async Task GetFresh_WithinTTL_Returns()
    {
        var repo = new MetadataCacheRepository(_db);
        var t = DateTimeOffset.UtcNow;
        await repo.UpsertAsync(Sample("lodash", t, TimeSpan.FromMinutes(5)));

        var loaded = await repo.GetFreshAsync("npm", "lodash", t.AddMinutes(2));
        Assert.NotNull(loaded);
        Assert.Equal("lodash", loaded!.Name);
    }

    [Fact]
    public async Task GetFresh_AfterTTL_ReturnsNull()
    {
        var repo = new MetadataCacheRepository(_db);
        var t = DateTimeOffset.UtcNow;
        await repo.UpsertAsync(Sample("lodash", t, TimeSpan.FromMinutes(1)));

        var loaded = await repo.GetFreshAsync("npm", "lodash", t.AddMinutes(10));
        Assert.Null(loaded);
    }

    [Fact]
    public async Task Upsert_OnConflict_Replaces()
    {
        var repo = new MetadataCacheRepository(_db);
        var t = DateTimeOffset.UtcNow;
        await repo.UpsertAsync(Sample("lodash", t, TimeSpan.FromMinutes(5)));

        var newer = new MetadataCacheEntry
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "lodash",
            Document = "{\"new\":true}",
            ContentHash = "sha256:new",
            UpstreamEtag = "W/\"def\"",
            FetchedAt = t.AddMinutes(1),
            ExpiresAt = t.AddMinutes(11)
        };
        await repo.UpsertAsync(newer);

        var loaded = await repo.GetFreshAsync("npm", "lodash", t.AddMinutes(2));
        Assert.NotNull(loaded);
        Assert.Equal("{\"new\":true}", loaded!.Document);
        Assert.Equal("sha256:new", loaded.ContentHash);
    }

    [Fact]
    public async Task PurgeExpired_DeletesOlderThanCutoff()
    {
        var repo = new MetadataCacheRepository(_db);
        var t = DateTimeOffset.UtcNow;
        await repo.UpsertAsync(Sample("expired", t.AddDays(-2), TimeSpan.FromMinutes(5)));
        await repo.UpsertAsync(Sample("fresh",   t, TimeSpan.FromMinutes(5)));

        var purged = await repo.PurgeExpiredAsync(t.AddMinutes(1));
        Assert.Equal(1, purged);
        Assert.NotNull(await repo.GetFreshAsync("npm", "fresh", t));
    }
}
