using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression for the rpm_metadata surrogate-id reshape. The old rpm_metadata declared
/// <c>package_version_id TEXT PRIMARY KEY</c>; SQLite reports a bare TEXT PRIMARY KEY column as
/// <c>notnull=0</c>, so a detection that read only the notnull flag concluded the table was already
/// reshaped, skipped adding the surrogate <c>id</c> column, and still recorded the migration as
/// applied. Any later insert naming <c>rpm_metadata.id</c> — including
/// <c>migrate_proxy_versions_to_cache_plane</c> — then failed host startup. The detection now reads
/// <c>MAX(notnull, pk)</c>, and a separately named <c>repair_rpm_metadata_surrogate_id</c> one-shot
/// re-runs the reshape on databases the buggy version already marked applied.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmMetadataSurrogateIdRepairMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    // The pre-reshape rpm_metadata: package_version_id is the bare TEXT PRIMARY KEY and there is no
    // surrogate id column. owner_kind / cache_artifact_id are present (added by the earlier additive
    // migration) so this matches the exact shape seen on affected production databases.
    private const string OldShapeRpmMetadata = """
        CREATE TABLE rpm_metadata (
            package_version_id  TEXT PRIMARY KEY REFERENCES package_versions(id) ON DELETE CASCADE,
            rpm_name            TEXT NOT NULL,
            epoch               INTEGER NOT NULL DEFAULT 0,
            rpm_version         TEXT NOT NULL,
            rpm_release         TEXT NOT NULL,
            arch                TEXT NOT NULL,
            summary             TEXT,
            description         TEXT,
            build_host          TEXT,
            build_time          INTEGER,
            packager            TEXT,
            vendor              TEXT,
            rpm_group           TEXT,
            source_rpm          TEXT,
            url                 TEXT,
            installed_size      INTEGER NOT NULL DEFAULT 0,
            archive_size        INTEGER NOT NULL DEFAULT 0,
            header_start        INTEGER NOT NULL DEFAULT 0,
            header_end          INTEGER NOT NULL DEFAULT 0,
            requires_json       TEXT NOT NULL DEFAULT '[]',
            provides_json       TEXT NOT NULL DEFAULT '[]',
            conflicts_json      TEXT NOT NULL DEFAULT '[]',
            obsoletes_json      TEXT NOT NULL DEFAULT '[]',
            files_json          TEXT NOT NULL DEFAULT '[]',
            changelogs_json     TEXT NOT NULL DEFAULT '[]',
            rpm_license         TEXT,
            created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
            owner_kind          TEXT NOT NULL DEFAULT 'package_version'
        )
        """;

    // Recreate an affected database: the new-shape table is dropped and replaced with the old shape,
    // make_rpm_metadata_pv_nullable is marked applied (the buggy run that skipped the reshape), and
    // repair_rpm_metadata_surrogate_id is left un-applied so re-init runs it.
    private async Task SeedAffectedDatabaseAsync(Action<string>? onTable = null)
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var setup = await _db.OpenAsync();
        await setup.ExecuteAsync("DROP TABLE IF EXISTS rpm_metadata");
        await setup.ExecuteAsync(OldShapeRpmMetadata);
        // Simulate the buggy prior run: recorded as applied even though the reshape was skipped.
        await setup.ExecuteAsync(
            "INSERT OR IGNORE INTO _applied_migrations (name) VALUES ('make_rpm_metadata_pv_nullable')");
        await setup.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = 'repair_rpm_metadata_surrogate_id'");
        onTable?.Invoke("seeded");
    }

    [Fact]
    public async Task RepairMigration_AddsSurrogateIdColumn_OnDatabaseStuckInOldShape()
    {
        await SeedAffectedDatabaseAsync();
        await using (var pre = await _db.OpenAsync())
        {
            long hasIdBefore = await pre.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM pragma_table_info('rpm_metadata') WHERE name = 'id'");
            Assert.Equal(0, hasIdBefore); // confirm the stuck old shape really lacks id
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        long hasIdAfter = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('rpm_metadata') WHERE name = 'id'");
        Assert.Equal(1, hasIdAfter); // surrogate id column now present
        long pvIdStillPk = await verify.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('rpm_metadata') WHERE name = 'package_version_id'");
        Assert.Equal(0, pvIdStillPk); // package_version_id is no longer NOT NULL / part of the PK
    }

    [Fact]
    public async Task ProxyBackfill_Completes_AfterRepair_OnAffectedDatabase()
    {
        await SeedAffectedDatabaseAsync();
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-rpm','rpm')");
            await seed.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
                "VALUES ('pkg1','o-rpm','npm','left-pad','left-pad',1)");
            await seed.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin) " +
                "VALUES ('ver1','pkg1','1.0.0','pkg:npm/left-pad@1.0.0','proxy/deadbeef/left-pad-1.0.0.tgz','left-pad-1.0.0.tgz',42,'proxy')");
            // Re-arm the backfill so re-init runs it against the seeded proxy row.
            await seed.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'migrate_proxy_versions_to_cache_plane'");
        }

        // Before the fix this re-init threw 'table rpm_metadata has no column named id' and faulted boot.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        long cacheArtifacts = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'left-pad' AND version = '1.0.0'");
        Assert.Equal(1, cacheArtifacts); // proxy version was backfilled onto the global plane
        long tenantAccess = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = 'o-rpm'");
        Assert.Equal(1, tenantAccess);
    }
}
