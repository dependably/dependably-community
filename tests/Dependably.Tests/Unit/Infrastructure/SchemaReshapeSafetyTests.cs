using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Proves the three safety rules applied to all SQLite recreate-table reshapes in
/// SchemaInitializer.Reshapes.cs:
///
/// 1. No-WHERE row-preserving copy — INSERT INTO t_new SELECT … FROM t copies every row,
///    including orphans whose parent FK row has been deleted.
/// 2. FK-off wrap — WithForeignKeysOffAsync disables FK enforcement so the DROP+RENAME
///    does not cascade-delete or FK-reject child rows. SQLite does not retroactively
///    validate rows when FK enforcement is re-enabled, so orphans survive.
/// 3. Retry guard — DROP TABLE IF EXISTS t_new prefix so a crash between CREATE and RENAME
///    does not wedge the next boot with "table t_new already exists".
///
/// Each test MUST reconstruct the old pre-migration table shape so the detection query
/// (MAX("notnull", pk)) sees the constrained column and actually fires the reshape.
/// Running the test against a freshly initialized schema would only exercise the
/// early-return (no-op) branch and prove nothing.
///
/// FK enforcement is explicitly enabled on each test connection to mirror production
/// (SqliteMetadataStore.cs sets PRAGMA foreign_keys = ON). Do not change the shared
/// TestMetadataStore default — these tests enable FK per-connection to get the desired
/// enforcement.
///
/// The add_*_owner_invariant_check migrations in SchemaInitializer.OwnerPlane.cs share
/// the same three rules (DROP IF EXISTS guard, WithForeignKeysOffAsync wrap, no-WHERE
/// SELECT). The pattern extends to that family if deeper coverage is wanted later.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SchemaReshapeSafetyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static SchemaInitializer NewInitializer(IMetadataStore db)
        => new(db, NullLogger<SchemaInitializer>.Instance);

    private async Task ResetMigrationAsync(string name)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = @name", new { name });
    }

    // Seeds the minimal parent rows needed to own a valid child row.
    private static async Task SeedParentPackageVersionAsync(
        System.Data.Common.DbConnection conn,
        string orgId = "org-safety-seed",
        string pkgId = "pkg-safety-seed",
        string pvId = "pv-safety-seed")
    {
        await conn.ExecuteAsync("""
            INSERT OR IGNORE INTO orgs (id, slug) VALUES (@orgId, @orgId)
            """, new { orgId });
        await conn.ExecuteAsync("""
            INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@pkgId, @orgId, 'npm', 'test', 'test', 0)
            """, new { pkgId, orgId });
        await conn.ExecuteAsync("""
            INSERT OR IGNORE INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES (@pvId, @pkgId, '1.0.0', 'pkg:npm/test@1.0.0',
                    'npm/registry/test/1.0.0/test-1.0.0.tgz')
            """, new { pvId, pkgId });
    }

    // Seeds one vulnerability row so package_version_vulns can reference it.
    private static async Task SeedVulnerabilityAsync(
        System.Data.Common.DbConnection conn, string vulnId = "GHSA-test-0001")
    {
        await conn.ExecuteAsync("""
            INSERT OR IGNORE INTO vulnerabilities (id, osv_id, ecosystem, package_name)
            VALUES (@vulnId, @vulnId, 'npm', 'test')
            """, new { vulnId });
    }

    // ── package_version_vulns — make_pvv_package_version_id_nullable ────────────────────────

    /// <summary>
    /// Reconstructs the pre-reshape package_version_vulns schema (composite PK, package_version_id
    /// NOT NULL), seeds one valid row and one orphan row, then verifies that after the reshape:
    /// (a) both rows survive — the no-WHERE INSERT…SELECT copies every row including orphans,
    /// (b) the orphan row is still present — the FK-off wrap prevented cascade-delete, and
    /// (c) the table is in the new shape — a surrogate id column now exists.
    /// </summary>
    [Fact]
    public async Task MakePvvPackageVersionIdNullable_OrphanRowSurvivesReshape()
    {
        await NewInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        // Reconstruct the OLD shape: composite PK (package_version_id, vuln_id),
        // package_version_id NOT NULL, no surrogate id column. This is the exact pre-reshape
        // DDL: the _new column list from Reshapes.cs with NOT NULL restored and id dropped.
        await conn.ExecuteAsync("DROP TABLE package_version_vulns");
        await conn.ExecuteAsync("""
            CREATE TABLE package_version_vulns (
                package_version_id TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
                vuln_id            TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                checked_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id  TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind         TEXT NOT NULL DEFAULT 'package_version'
                                   CHECK (owner_kind IN ('package_version','cache_artifact')),
                PRIMARY KEY (package_version_id, vuln_id)
            )
            """);

        // Verify the reconstructed shape actually trips detection: MAX(notnull, pk) must return 1.
        long constrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('package_version_vulns') WHERE name = 'package_version_id'");
        Assert.Equal(1, constrained);

        // Seed parent + vulnerability so the valid row can satisfy FK constraints.
        await SeedParentPackageVersionAsync(conn);
        await SeedVulnerabilityAsync(conn, "GHSA-pvv-valid-01");

        // Seed inside FK-off: one valid row (parent exists) and one orphan (parent absent).
        await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
        await conn.ExecuteAsync("""
            INSERT INTO package_version_vulns (package_version_id, vuln_id, owner_kind)
            VALUES ('pv-safety-seed', 'GHSA-pvv-valid-01', 'package_version')
            """);
        await conn.ExecuteAsync("""
            INSERT INTO package_version_vulns (package_version_id, vuln_id, owner_kind)
            VALUES ('pv-ORPHAN-DOES-NOT-EXIST', 'GHSA-pvv-valid-01', 'package_version')
            """);
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        // Run the reshape.
        await ResetMigrationAsync("make_pvv_package_version_id_nullable");
        await NewInitializer(_db).InitializeAsync();

        // Both rows must survive (total count == 2).
        long total = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_version_vulns");
        Assert.Equal(2, total);

        // The orphan row specifically must still be present.
        long orphanCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns WHERE package_version_id = 'pv-ORPHAN-DOES-NOT-EXIST'");
        Assert.Equal(1, orphanCount);

        // New shape: surrogate id column must exist now.
        long hasId = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('package_version_vulns') WHERE name = 'id'");
        Assert.Equal(1, hasId);
    }

    /// <summary>
    /// Retry-guard test for package_version_vulns: a stray package_version_vulns_new table
    /// left over from a crash between CREATE and RENAME must not wedge the next boot.
    /// The DROP TABLE IF EXISTS prefix in the reshape SQL handles this case.
    /// </summary>
    [Fact]
    public async Task MakePvvPackageVersionIdNullable_RetryGuard_StrayNewTableDoesNotWedge()
    {
        await NewInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // Reconstruct old shape.
        await conn.ExecuteAsync("DROP TABLE package_version_vulns");
        await conn.ExecuteAsync("""
            CREATE TABLE package_version_vulns (
                package_version_id TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
                vuln_id            TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                checked_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id  TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind         TEXT NOT NULL DEFAULT 'package_version'
                                   CHECK (owner_kind IN ('package_version','cache_artifact')),
                PRIMARY KEY (package_version_id, vuln_id)
            )
            """);

        // Simulate a crash between CREATE and RENAME: a stray _new table already exists.
        await conn.ExecuteAsync("CREATE TABLE package_version_vulns_new (id TEXT)");

        // Seed a row (FK off since parent may not exist in this reconstructed schema).
        await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
        await conn.ExecuteAsync("""
            INSERT INTO package_version_vulns (package_version_id, vuln_id, owner_kind)
            VALUES ('pv-guard-parent', 'GHSA-guard-v01', 'package_version')
            """);
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        // The reshape must succeed despite the stray _new table.
        await ResetMigrationAsync("make_pvv_package_version_id_nullable");
        var ex = await Record.ExceptionAsync(() => NewInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        // The seeded row survives the retry.
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns WHERE package_version_id = 'pv-guard-parent'");
        Assert.Equal(1, count);
    }

    // ── package_version_licenses — make_pvl_package_version_id_nullable ─────────────────────

    /// <summary>
    /// Reconstructs the pre-reshape package_version_licenses schema (package_version_id NOT NULL,
    /// no cache_artifact UNIQUE arm), seeds a valid row and an orphan row, then verifies both
    /// survive the reshape and the column is nullable afterwards.
    /// </summary>
    [Fact]
    public async Task MakePvlPackageVersionIdNullable_OrphanRowSurvivesReshape()
    {
        await NewInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        // Reconstruct the OLD shape: package_version_id NOT NULL, no cache_artifact UNIQUE arm.
        await conn.ExecuteAsync("DROP TABLE package_version_licenses");
        await conn.ExecuteAsync("""
            CREATE TABLE package_version_licenses (
                id                 TEXT PRIMARY KEY,
                package_version_id TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
                license_spdx       TEXT NOT NULL,
                source             TEXT NOT NULL DEFAULT 'upstream',
                created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id  TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind         TEXT NOT NULL DEFAULT 'package_version',
                UNIQUE (package_version_id, license_spdx)
            )
            """);

        // Verify detection fires.
        long constrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('package_version_licenses') WHERE name = 'package_version_id'");
        Assert.Equal(1, constrained);

        await SeedParentPackageVersionAsync(conn);

        // Seed valid + orphan rows inside FK-off.
        await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
        await conn.ExecuteAsync("""
            INSERT INTO package_version_licenses (id, package_version_id, license_spdx, owner_kind)
            VALUES ('pvl-valid', 'pv-safety-seed', 'MIT', 'package_version')
            """);
        await conn.ExecuteAsync("""
            INSERT INTO package_version_licenses (id, package_version_id, license_spdx, owner_kind)
            VALUES ('pvl-orphan', 'pv-ORPHAN-PVL-GONE', 'Apache-2.0', 'package_version')
            """);
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        await ResetMigrationAsync("make_pvl_package_version_id_nullable");
        await NewInitializer(_db).InitializeAsync();

        long total = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_version_licenses");
        Assert.Equal(2, total);

        long orphanCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_licenses WHERE id = 'pvl-orphan'");
        Assert.Equal(1, orphanCount);

        // New shape: column is nullable (MAX(notnull, pk) returns 0).
        long stillConstrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('package_version_licenses') WHERE name = 'package_version_id'");
        Assert.Equal(0, stillConstrained);
    }

    // ── rpm_metadata — make_rpm_metadata_pv_nullable ─────────────────────────────────────────

    /// <summary>
    /// Reconstructs the pre-reshape rpm_metadata schema (package_version_id TEXT PRIMARY KEY,
    /// no surrogate id), seeds a valid row and an orphan row, then verifies both survive and the
    /// new shape has a surrogate id column.
    /// </summary>
    [Fact]
    public async Task MakeRpmMetadataPvNullable_OrphanRowSurvivesReshape()
    {
        await NewInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        // Reconstruct the OLD shape: package_version_id is the sole PRIMARY KEY, no surrogate id.
        // SQLite reports a bare "TEXT PRIMARY KEY" as pk=1, notnull=0, so MAX(notnull,pk)=1.
        await conn.ExecuteAsync("DROP TABLE rpm_metadata");
        await conn.ExecuteAsync("""
            CREATE TABLE rpm_metadata (
                package_version_id TEXT PRIMARY KEY REFERENCES package_versions(id) ON DELETE CASCADE,
                rpm_name           TEXT NOT NULL,
                epoch              INTEGER NOT NULL DEFAULT 0,
                rpm_version        TEXT NOT NULL,
                rpm_release        TEXT NOT NULL,
                arch               TEXT NOT NULL,
                summary            TEXT,
                description        TEXT,
                build_host         TEXT,
                build_time         INTEGER,
                packager           TEXT,
                vendor             TEXT,
                rpm_group          TEXT,
                source_rpm         TEXT,
                url                TEXT,
                installed_size     INTEGER NOT NULL DEFAULT 0,
                archive_size       INTEGER NOT NULL DEFAULT 0,
                header_start       INTEGER NOT NULL DEFAULT 0,
                header_end         INTEGER NOT NULL DEFAULT 0,
                requires_json      TEXT NOT NULL DEFAULT '[]',
                provides_json      TEXT NOT NULL DEFAULT '[]',
                conflicts_json     TEXT NOT NULL DEFAULT '[]',
                obsoletes_json     TEXT NOT NULL DEFAULT '[]',
                files_json         TEXT NOT NULL DEFAULT '[]',
                changelogs_json    TEXT NOT NULL DEFAULT '[]',
                rpm_license        TEXT,
                created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id  TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind         TEXT NOT NULL DEFAULT 'package_version'
                                   CHECK (owner_kind IN ('package_version','cache_artifact'))
            )
            """);

        // Verify detection fires: pk=1 for a TEXT PRIMARY KEY column.
        long constrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('rpm_metadata') WHERE name = 'package_version_id'");
        Assert.Equal(1, constrained);

        await SeedParentPackageVersionAsync(conn);

        await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (package_version_id, rpm_name, epoch, rpm_version, rpm_release, arch, owner_kind)
            VALUES ('pv-safety-seed', 'hello', 0, '2.10', '1.el9', 'x86_64', 'package_version')
            """);
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (package_version_id, rpm_name, epoch, rpm_version, rpm_release, arch, owner_kind)
            VALUES ('pv-ORPHAN-RPM-GONE', 'world', 0, '1.0', '1.el9', 'x86_64', 'package_version')
            """);
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        // Reset both the original migration and the repair migration so neither no-ops.
        await ResetMigrationAsync("make_rpm_metadata_pv_nullable");
        await ResetMigrationAsync("repair_rpm_metadata_surrogate_id");
        await NewInitializer(_db).InitializeAsync();

        long total = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM rpm_metadata");
        Assert.Equal(2, total);

        long orphanCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM rpm_metadata WHERE package_version_id = 'pv-ORPHAN-RPM-GONE'");
        Assert.Equal(1, orphanCount);

        // New shape: surrogate id column must exist.
        long hasId = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('rpm_metadata') WHERE name = 'id'");
        Assert.Equal(1, hasId);
    }

    // ── maven_version_files — make_mvf_pv_nullable ───────────────────────────────────────────

    /// <summary>
    /// Reconstructs the pre-reshape maven_version_files schema (package_version_id NOT NULL,
    /// plain UNIQUE(package_version_id, filename)), seeds a valid row and an orphan row, then
    /// verifies both survive and the new shape has nullable package_version_id.
    /// </summary>
    [Fact]
    public async Task MakeMvfPvNullable_OrphanRowSurvivesReshape()
    {
        await NewInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        // Reconstruct the OLD shape: package_version_id NOT NULL with plain UNIQUE.
        await conn.ExecuteAsync("DROP TABLE maven_version_files");
        await conn.ExecuteAsync("""
            CREATE TABLE maven_version_files (
                id                 TEXT PRIMARY KEY,
                package_version_id TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
                filename           TEXT NOT NULL,
                classifier         TEXT,
                extension          TEXT NOT NULL,
                blob_key           TEXT NOT NULL,
                size_bytes         INTEGER NOT NULL DEFAULT 0,
                checksum_sha256    TEXT,
                checksum_sha1      TEXT,
                checksum_md5       TEXT,
                origin             TEXT NOT NULL DEFAULT 'uploaded',
                created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id  TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind         TEXT NOT NULL DEFAULT 'package_version'
                                   CHECK (owner_kind IN ('package_version','cache_artifact')),
                UNIQUE (package_version_id, filename)
            )
            """);

        // Verify detection fires.
        long constrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('maven_version_files') WHERE name = 'package_version_id'");
        Assert.Equal(1, constrained);

        await SeedParentPackageVersionAsync(conn);

        await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
        await conn.ExecuteAsync("""
            INSERT INTO maven_version_files
                (id, package_version_id, filename, extension, blob_key, owner_kind)
            VALUES ('mvf-valid', 'pv-safety-seed', 'lib-1.0.jar', 'jar', 'proxy/k', 'package_version')
            """);
        await conn.ExecuteAsync("""
            INSERT INTO maven_version_files
                (id, package_version_id, filename, extension, blob_key, owner_kind)
            VALUES ('mvf-orphan', 'pv-ORPHAN-MVF-GONE', 'lib-2.0.jar', 'jar', 'proxy/k2', 'package_version')
            """);
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        await ResetMigrationAsync("make_mvf_pv_nullable");
        await NewInitializer(_db).InitializeAsync();

        long total = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM maven_version_files");
        Assert.Equal(2, total);

        long orphanCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM maven_version_files WHERE id = 'mvf-orphan'");
        Assert.Equal(1, orphanCount);

        // New shape: package_version_id is nullable.
        long stillConstrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('maven_version_files') WHERE name = 'package_version_id'");
        Assert.Equal(0, stillConstrained);
    }

    // ── cargo_metadata — make_cargo_metadata_vid_nullable ───────────────────────────────────

    /// <summary>
    /// Reconstructs the pre-reshape cargo_metadata schema (version_id NOT NULL, plain
    /// UNIQUE(version_id)), seeds a valid row and an orphan row, then verifies both survive
    /// and the new shape has nullable version_id.
    /// </summary>
    [Fact]
    public async Task MakeCargoMetadataVidNullable_OrphanRowSurvivesReshape()
    {
        await NewInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        // Reconstruct the OLD shape: version_id NOT NULL with plain UNIQUE(version_id).
        await conn.ExecuteAsync("DROP TABLE cargo_metadata");
        await conn.ExecuteAsync("""
            CREATE TABLE cargo_metadata (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
                index_line TEXT NOT NULL,
                cache_artifact_id TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind TEXT NOT NULL DEFAULT 'package_version'
                           CHECK (owner_kind IN ('package_version','cache_artifact')),
                UNIQUE (version_id)
            )
            """);

        // Verify detection fires.
        long constrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('cargo_metadata') WHERE name = 'version_id'");
        Assert.Equal(1, constrained);

        await SeedParentPackageVersionAsync(conn);

        await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
        await conn.ExecuteAsync("""
            INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
            VALUES ('pv-safety-seed',
                    '{"name":"test","vers":"1.0.0","deps":[],"cksum":"abc","features":{},"yanked":false}',
                    'package_version')
            """);
        await conn.ExecuteAsync("""
            INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
            VALUES ('pv-ORPHAN-CARGO-GONE',
                    '{"name":"test","vers":"2.0.0","deps":[],"cksum":"xyz","features":{},"yanked":false}',
                    'package_version')
            """);
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");

        await ResetMigrationAsync("make_cargo_metadata_vid_nullable");
        await NewInitializer(_db).InitializeAsync();

        long total = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM cargo_metadata");
        Assert.Equal(2, total);

        long orphanCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cargo_metadata WHERE version_id = 'pv-ORPHAN-CARGO-GONE'");
        Assert.Equal(1, orphanCount);

        // New shape: version_id is nullable.
        long stillConstrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('cargo_metadata') WHERE name = 'version_id'");
        Assert.Equal(0, stillConstrained);
    }
}
