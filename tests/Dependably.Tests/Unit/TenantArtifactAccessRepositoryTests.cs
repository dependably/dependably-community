using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

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
        string id = Guid.NewGuid().ToString("D");
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
        string caId = await InsertCacheArtifact("1.0.0");
        var repo = new TenantArtifactAccessRepository(_db);
        var t = TestTime.KnownNow;

        await repo.UpsertAsync("o1", caId, t, TenantContentBinding.None);
        await repo.UpsertAsync("o1", caId, t.AddMinutes(1), TenantContentBinding.None);

        await using var conn = await _db.OpenAsync();
        var (Count, FirstAt, LastAt) = await conn.QuerySingleAsync<(int Count, string FirstAt, string LastAt)>(
            "SELECT access_count AS Count, first_accessed_at AS FirstAt, last_accessed_at AS LastAt " +
            "FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = @caId",
            new { caId });

        Assert.Equal(2, Count);
        Assert.NotEqual(FirstAt, LastAt);
    }

    [Fact]
    public async Task Upsert_LastAccessedAt_MatchesExplicitCanonicalWriterShape()
    {
        // Regression: UpsertAsync binds `at` as a raw DateTimeOffset through the global Dapper
        // DateTimeOffsetHandler (SchemaInitializer.OwnerPlane.cs). Before the fix, Dapper's
        // built-in typeMap claimed the parameter ahead of the registered handler, so SetValue
        // never ran; Microsoft.Data.Sqlite's own serialization wrote it space-separated with the
        // offset preserved instead (e.g. "2026-05-01 08:09:10+00:00"), disagreeing in shape with
        // every column that goes through UtcTimestamp.ToUtcIso() explicitly — including this same
        // column's own schema DEFAULT.
        string caId = await InsertCacheArtifact("5.0.0");
        var repo = new TenantArtifactAccessRepository(_db);
        var instant = new DateTimeOffset(2026, 5, 1, 8, 9, 10, TimeSpan.Zero);

        await repo.UpsertAsync("o1", caId, instant, TenantContentBinding.None);

        await using var conn = await _db.OpenAsync();
        var (firstAt, lastAt) = await conn.QuerySingleAsync<(string FirstAt, string LastAt)>(
            "SELECT first_accessed_at AS FirstAt, last_accessed_at AS LastAt " +
            "FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = @caId",
            new { caId });

        Assert.Equal(instant.ToUtcIso(), firstAt);
        Assert.Equal(instant.ToUtcIso(), lastAt);
    }

    [Fact]
    public async Task Upsert_NonZeroOffsetInstant_NormalizesToCanonicalUtc()
    {
        // +02:00 offset representing 2026-05-01T06:09:10Z. Before the fix SetValue never ran
        // (see the comment above) — the provider's own serialization preserved the +02:00 offset
        // instead of converting to UTC first, so the stored row would sort by its wall-clock time
        // rather than its real instant.
        string caId = await InsertCacheArtifact("5.0.1");
        var repo = new TenantArtifactAccessRepository(_db);
        var instant = new DateTimeOffset(2026, 5, 1, 8, 9, 10, TimeSpan.FromHours(2));

        await repo.UpsertAsync("o1", caId, instant, TenantContentBinding.None);

        await using var conn = await _db.OpenAsync();
        string stored = await conn.QuerySingleAsync<string>(
            "SELECT last_accessed_at FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = @caId",
            new { caId });

        Assert.Equal("2026-05-01T06:09:10Z", stored);
    }

    [Fact]
    public async Task ListAffectedTenants_DistinctAcrossOrgs()
    {
        string caId = await InsertCacheArtifact("4.17.21");
        var repo = new TenantArtifactAccessRepository(_db);
        var t = TestTime.KnownNow;

        await repo.UpsertAsync("o1", caId, t, TenantContentBinding.None);
        await repo.UpsertAsync("o2", caId, t, TenantContentBinding.None);
        await repo.UpsertAsync("o1", caId, t.AddMinutes(1), TenantContentBinding.None);  // duplicate org → still one entry

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

    // ── RecordDownloadHitAsync — cache-hit serve path ────────────────────────
    // The row is seeded via UpsertStateAsync first (the first-fetch durable insert this
    // repository still performs synchronously), mirroring how the real serve path only ever
    // calls RecordDownloadHitAsync after a prior first-fetch created the row.

    [Fact]
    public async Task RecordDownloadHitAsync_WithoutWriter_WritesSynchronously()
    {
        string caId = await InsertCacheArtifact("2.0.0");
        var repo = new TenantArtifactAccessRepository(_db);
        var t = TestTime.KnownNow;

        await repo.UpsertStateAsync("o1", caId, t); // first-fetch seed — download_count = 1
        await repo.RecordDownloadHitAsync("o1", caId, t.AddMinutes(1));

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = @caId",
            new { caId });
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task RecordDownloadHitAsync_WithWriter_DoesNotWriteSynchronously()
    {
        string caId = await InsertCacheArtifact("2.0.1");
        var writer = new DownloadCountWriter();
        var repo = new TenantArtifactAccessRepository(_db, writer);
        var t = TestTime.KnownNow;

        await repo.UpsertStateAsync("o1", caId, t); // first-fetch seed — download_count = 1
        await repo.RecordDownloadHitAsync("o1", caId, t.AddMinutes(1));

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = @caId",
            new { caId });
        Assert.Equal(1, count); // hit not yet flushed by the drainer
    }

    [Fact]
    public async Task RecordDownloadHitAsync_WithWriter_DrainerAppliesBatchedUpdate()
    {
        string caId = await InsertCacheArtifact("2.0.2");
        var writer = new DownloadCountWriter();
        var repo = new TenantArtifactAccessRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);
        var t = TestTime.KnownNow;

        await repo.UpsertStateAsync("o1", caId, t); // first-fetch seed — download_count = 1
        for (int i = 0; i < 4; i++)
        {
            await repo.RecordDownloadHitAsync("o1", caId, t.AddMinutes(i + 1));
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = @caId",
            new { caId });
        Assert.Equal(5, count); // 1 seeded + 4 batched hits
    }
}
