using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class TenantArtifactAccessRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'globex')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task<string> InsertCacheArtifact(string version)
    {
        var id = Guid.NewGuid().ToString("D");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
            VALUES (@id, 'npm', 'lodash', @version, @filename, 'k', 'h')
            """, new { id, version, filename = $"lodash-{version}.tgz" });
        return id;
    }

    [Fact]
    public async Task Upsert_FirstCallInserts_SecondBumpsCount()
    {
        var caId = await InsertCacheArtifact("1.0.0");
        var repo = new TenantArtifactAccessRepository(_db);
        var t = DateTimeOffset.UtcNow;

        await repo.UpsertAsync("o1", caId, t);
        await repo.UpsertAsync("o1", caId, t.AddMinutes(1));

        await using var conn = await _db.OpenAsync();
        var row = await conn.QuerySingleAsync<(int Count, string FirstAt, string LastAt)>(
            "SELECT access_count AS Count, first_accessed_at AS FirstAt, last_accessed_at AS LastAt " +
            "FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = @caId",
            new { caId });

        Assert.Equal(2, row.Count);
        Assert.NotEqual(row.FirstAt, row.LastAt);
    }

    [Fact]
    public async Task ListAffectedTenants_DistinctAcrossOrgs()
    {
        var caId = await InsertCacheArtifact("4.17.21");
        var repo = new TenantArtifactAccessRepository(_db);
        var t = DateTimeOffset.UtcNow;

        await repo.UpsertAsync("o1", caId, t);
        await repo.UpsertAsync("o2", caId, t);
        await repo.UpsertAsync("o1", caId, t.AddMinutes(1));  // duplicate org → still one entry

        var tenants = await repo.ListAffectedTenantsAsync("npm", "lodash", "4.17.21");
        Assert.Equal(2, tenants.Count);
        Assert.Contains("o1", tenants);
        Assert.Contains("o2", tenants);
    }

    [Fact]
    public async Task ListAffectedTenants_NoMatches_Empty()
    {
        var repo = new TenantArtifactAccessRepository(_db);
        var tenants = await repo.ListAffectedTenantsAsync("npm", "ghost", "9.9.9");
        Assert.Empty(tenants);
    }
}
