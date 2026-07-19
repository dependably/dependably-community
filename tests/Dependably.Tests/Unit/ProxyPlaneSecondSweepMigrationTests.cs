using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// A ledger entry runs once. The first <c>migrate_proxy_versions_to_cache_plane</c> /
/// <c>delete_migrated_proxy_package_versions</c> pass therefore cannot clean an
/// <c>origin='proxy'</c> <c>package_versions</c> row written to the same database after that pass
/// recorded itself as applied — the fetch path could still mint one until it was made to catalogue
/// exclusively on the cache plane and refuse a fetch it cannot record there.
///
/// The <c>_2</c>-suffixed second pass is a fresh ledger entry that re-runs the identical, idempotent
/// backfill+delete once more, catching exactly those rows. These tests hold the first pass's ledger
/// entries in place (so only the second pass can act) and assert a zombie row is catalogued onto the
/// cache plane and removed from <c>package_versions</c>, while a genuine hosted row is untouched.
/// </summary>
[Trait("Category", "Schema")]
public sealed class ProxyPlaneSecondSweepMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    // Bring the DB to a fully-migrated state (first pass applied and ledgered), then inject a proxy
    // package_versions row as if a fetch minted it after the first pass ran — WITHOUT touching the
    // first pass's ledger entries, so only the _2 pass is eligible to run on the next init.
    private async Task<(string ZombieId, string HostedId)> SeedPostFirstPassZombieAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // The first pass and its _2 twin are all recorded as applied by the init above. Re-arm ONLY
        // the second pass: the first pass stays ledgered, so it cannot be what cleans the zombie.
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN " +
            "('migrate_proxy_versions_to_cache_plane_2'," +
            " 'delete_migrated_proxy_package_versions_2')");

        // Confirm the first pass really is still ledgered — the test is meaningless otherwise.
        long firstPassApplied = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name IN " +
            "('migrate_proxy_versions_to_cache_plane'," +
            " 'delete_migrated_proxy_package_versions')");
        Assert.Equal(2, firstPassApplied);

        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o-sweep','sweep')");

        // The zombie: a genuine npm proxy artifact that was minted with only a package_versions row
        // (origin='proxy', proxy/ blob_key) and no cache_artifact row.
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-zombie','o-sweep','npm','left-pad','left-pad',1)");
        string zombieId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin) " +
            "VALUES (@id,'pkg-zombie','1.0.0','pkg:npm/left-pad@1.0.0'," +
            "'proxy/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890/left-pad-1.0.0.tgz'," +
            "'left-pad-1.0.0.tgz',512,'proxy')",
            new { id = zombieId });

        // A genuine hosted row that must never be touched by the sweep.
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg-hosted','o-sweep','npm','my-app','my-app',0)");
        string hostedId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin) " +
            "VALUES (@id,'pkg-hosted','2.0.0','pkg:npm/my-app@2.0.0'," +
            "'hosted/o-sweep/npm/my-app/2.0.0/my-app-2.0.0.tgz','my-app-2.0.0.tgz',1024,'uploaded')",
            new { id = hostedId });

        return (zombieId, hostedId);
    }

    [Fact]
    public async Task ZombieMintedAfterFirstPass_IsSweptBySecondPass()
    {
        var (zombieId, _) = await SeedPostFirstPassZombieAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Dropped from the hosted plane by the second-pass delete.
        Assert.Null(await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE id = @id", new { id = zombieId }));

        // Catalogued onto the cache plane by the second-pass backfill.
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'left-pad' AND version = '1.0.0'"));
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access ta " +
            "JOIN cache_artifact ca ON ca.id = ta.cache_artifact_id " +
            "WHERE ta.org_id = 'o-sweep' AND ca.name = 'left-pad'"));
    }

    [Fact]
    public async Task HostedRow_IsUntouchedBySecondPass()
    {
        var (_, hostedId) = await SeedPostFirstPassZombieAsync();

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Still present, still hosted, never catalogued onto the cache plane.
        Assert.Equal("uploaded", await conn.ExecuteScalarAsync<string?>(
            "SELECT origin FROM package_versions WHERE id = @id", new { id = hostedId }));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'my-app'"));
    }

    [Fact]
    public async Task SecondPass_OnCleanDatabase_IsANoOp()
    {
        // No zombie seeded: init twice and confirm the second pass leaves package_versions empty of
        // proxy rows and mints no spurious cache_artifact rows.
        await new SchemaInitializer(_db).InitializeAsync();
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE origin = 'proxy'"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM cache_artifact"));

        // Both second-pass entries are ledgered exactly once.
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'migrate_proxy_versions_to_cache_plane_2'"));
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'delete_migrated_proxy_package_versions_2'"));
    }
}
