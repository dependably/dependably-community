using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Dapper;
using Dependably.Protocol;
using Dependably.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Infrastructure;

/// <summary>Polymorphic-ownership reshape migrations and the proxy→cache-plane data
/// migration for <see cref="SchemaInitializer"/>, plus its Dapper type handlers.</summary>
public sealed partial class SchemaInitializer
{
    // Drops the global UNIQUE on package_versions.purl. The constraint was added when purl was a
    // globally-unique coordinate but fails in multi-tenant deployments where the same upstream
    // package can be fetched by multiple tenants — each proxy-fetch creates its own
    // package_versions row with the same purl under a different packages.org_id. The
    // per-tenant UNIQUE(package_id, version) constraint is retained and is the correct guard.
    //
    // SQLite: recreate-table pattern (ALTER TABLE cannot drop a UNIQUE index inline). The new
    // table definition is identical to Schema.sql except purl loses its UNIQUE keyword.
    // All data and FK-dependent child rows are preserved via the ON DELETE CASCADE chain;
    // child tables reference package_versions.id (the PK), not the purl column, so they are
    // not affected by the recreate.
    //
    // Postgres: DROP CONSTRAINT IF EXISTS on the auto-named unique constraint.
    //
    // transactional: false on both providers because the SQLite recreate-table pattern
    // (DROP + RENAME) does not compose with an explicit outer transaction; the PG branch
    // uses a simple DDL statement that is already auto-committed. Both branches are idempotent
    // (SQLite checks for the unique index before acting; PG uses IF EXISTS).
    private Task DropPackageVersionsPurlUniqueAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE package_versions
                    DROP CONSTRAINT IF EXISTS package_versions_purl_key;
                """)
            : DropPackageVersionsPurlUniqueSqliteAsync(conn);
    }

    private static async Task DropPackageVersionsPurlUniqueSqliteAsync(DbConnection conn)
    {
        // Check whether the purl-only UNIQUE constraint still exists by inspecting the indexes
        // on package_versions via pragma_index_list + pragma_index_info. The purl UNIQUE is a
        // single-column unique index covering only `purl`; after migration, only the two-column
        // UNIQUE(package_id, version) autoindex remains. This avoids relying on autoindex numbering
        // (sqlite_autoindex_*_N), which changes after the recreate and would cause false positives.
        // Detect whether the purl-only UNIQUE constraint exists by counting single-column
        // unique indexes on package_versions that cover the 'purl' column. The autoindex
        // numbering (sqlite_autoindex_*_N) is not used because it changes after the recreate
        // (the renamed (package_id, version) constraint would become index 1 and trigger false
        // positives on re-run). Instead: for each index on the table that is marked unique, check
        // whether it covers exactly one column named 'purl'.
        bool hasPurlUnique = false;
        // pragma_index_list returns columns: seq, name, unique, origin, partial.
        // SQLite 3.7.17+ supports pragma_index_list as a TVF. The 'unique' column is an INTEGER.
        // We use positional column access to avoid keyword collision with the column alias.
        var indexNames = (await conn.QueryAsync<(string IndexName, int IsUnique)>(
            "SELECT il.name AS IndexName, il.\"unique\" AS IsUnique " +
            "FROM pragma_index_list('package_versions') il")).ToList();
        foreach (var (indexName, isUnique) in indexNames)
        {
            if (isUnique == 0) { continue; }
            var cols = (await conn.QueryAsync<string?>(
                "SELECT ii.name FROM pragma_index_info(@i) ii ORDER BY ii.seqno",
                new { i = indexName })).ToList();
            if (cols.Count == 1 && string.Equals(cols[0], "purl", StringComparison.OrdinalIgnoreCase))
            {
                hasPurlUnique = true;
                break;
            }
        }
        if (!hasPurlUnique)
        {
            // Fresh installs and already-migrated databases: no purl UNIQUE to drop.
            return;
        }

        // Recreate package_versions without the purl UNIQUE. The column list below must exactly
        // match the full current schema (base + all additive migrations applied before this point).
        // IMPORTANT: do NOT include DEFAULT values for created_at in the copied rows — they carry
        // their original timestamps. The DEFAULT on the new table applies only to future inserts.
        //
        // After DROP TABLE package_versions, the named indexes idx_package_versions_package and
        // idx_package_versions_filename are also dropped (SQLite drops all indexes with their
        // table). RunAdditiveMigrationsAsync already ran earlier this boot, so those indexes are
        // recreated here explicitly rather than waiting until the next startup.
        // xtenant: DDL-only schema migration; no row query across tenants
        const string recreateSql = """
            DROP TABLE IF EXISTS package_versions_new;
            CREATE TABLE package_versions_new (
                id          TEXT PRIMARY KEY,
                package_id  TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                version     TEXT NOT NULL,
                purl        TEXT NOT NULL,
                blob_key    TEXT NOT NULL,
                size_bytes  INTEGER NOT NULL DEFAULT 0,
                checksum_sha256 TEXT,
                yanked      INTEGER NOT NULL DEFAULT 0,
                yank_reason TEXT,
                first_fetch INTEGER NOT NULL DEFAULT 0,
                last_used   TEXT,
                download_count INTEGER NOT NULL DEFAULT 0,
                vuln_checked_at TEXT,
                manual_block_state TEXT,
                deprecated  TEXT,
                origin      TEXT NOT NULL DEFAULT 'proxy',
                published_at TEXT,
                checksum_sha1 TEXT,
                upstream_integrity_value TEXT,
                upstream_integrity_algorithm TEXT,
                filename    TEXT,
                deprecation_checked_at TEXT,
                has_install_script INTEGER NOT NULL DEFAULT 0,
                install_script_kind TEXT,
                provenance_status TEXT,
                provenance_signer TEXT,
                created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                UNIQUE (package_id, version)
            );
            INSERT INTO package_versions_new
            SELECT id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, yanked,
                   yank_reason, first_fetch, last_used, download_count, vuln_checked_at,
                   manual_block_state, deprecated, origin, published_at, checksum_sha1,
                   upstream_integrity_value, upstream_integrity_algorithm, filename,
                   deprecation_checked_at, has_install_script, install_script_kind,
                   provenance_status, provenance_signer, created_at
            FROM package_versions;
            DROP TABLE package_versions;
            ALTER TABLE package_versions_new RENAME TO package_versions;
            CREATE INDEX IF NOT EXISTS idx_package_versions_package ON package_versions(package_id);
            CREATE INDEX IF NOT EXISTS idx_package_versions_filename ON package_versions(filename);
            """;
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync(recreateSql));
    }

    // Makes package_version_licenses.package_version_id nullable so the global-plane arm
    // (owner_kind='cache_artifact') can insert rows without a package_versions FK. Also adds
    // UNIQUE(cache_artifact_id, license_spdx) as the dedup guard for the global arm.
    //
    // Fresh installs: the CREATE TABLE already has the nullable column and both UNIQUE constraints,
    // so the check on Postgres returns false and the SQLite branch detects no NOT NULL to drop.
    //
    // Postgres: ALTER COLUMN … DROP NOT NULL (idempotent on an already-nullable column) +
    // CREATE UNIQUE INDEX IF NOT EXISTS for the cache_artifact arm.
    //
    // SQLite: the column nullability is encoded in the CREATE TABLE text — ALTER TABLE can't change it.
    // The recreate-table pattern drops and recreates the table with the nullable column and both
    // UNIQUE constraints, preserving all existing rows.
    // xtenant: DDL-only migration; no row query across tenants.
    private Task MakePvlPackageVersionIdNullableAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE package_version_licenses
                    ALTER COLUMN package_version_id DROP NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_pvl_cache_artifact_license
                    ON package_version_licenses (cache_artifact_id, license_spdx);
                """)
            : MakePvlPackageVersionIdNullableSqliteAsync(conn);
    }

    private static async Task MakePvlPackageVersionIdNullableSqliteAsync(DbConnection conn)
    {
        // The reshape is needed while package_version_id is still constrained — either NOT NULL
        // or part of a PRIMARY KEY. SQLite reports a bare "TEXT PRIMARY KEY" column as notnull=0,
        // so the pk flag must be checked too. 'notnull' is a reserved word in SQLite and must be
        // double-quoted as a column ref.
        long stillConstrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('package_version_licenses') WHERE name = 'package_version_id'");
        if (stillConstrained == 0)
        {
            // Column already nullable (fresh install or already migrated). Ensure the UNIQUE
            // index for the cache_artifact arm exists (idempotent CREATE IF NOT EXISTS).
            await conn.ExecuteAsync(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_pvl_cache_artifact_license " +
                "ON package_version_licenses (cache_artifact_id, license_spdx)");
            return;
        }

        // Recreate the table with package_version_id nullable and both UNIQUE constraints.
        // Column list covers: base columns (id, package_version_id, license_spdx, source,
        // created_at) + P0 additive columns (cache_artifact_id, owner_kind).
        // xtenant: DDL-only; no data query across tenants.
        const string recreateSql = """
            DROP TABLE IF EXISTS package_version_licenses_new;
            CREATE TABLE package_version_licenses_new (
                id                  TEXT PRIMARY KEY,
                package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                license_spdx        TEXT NOT NULL,
                source              TEXT NOT NULL DEFAULT 'upstream',
                created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version',
                UNIQUE (package_version_id, license_spdx),
                UNIQUE (cache_artifact_id, license_spdx)
            );
            INSERT INTO package_version_licenses_new
                (id, package_version_id, license_spdx, source, created_at,
                 cache_artifact_id, owner_kind)
            SELECT id, package_version_id, license_spdx, source, created_at,
                   cache_artifact_id, owner_kind
            FROM package_version_licenses;
            DROP TABLE package_version_licenses;
            ALTER TABLE package_version_licenses_new RENAME TO package_version_licenses;
            CREATE INDEX IF NOT EXISTS idx_pkg_version_licenses
                ON package_version_licenses (package_version_id);
            CREATE INDEX IF NOT EXISTS idx_package_version_licenses_cache_artifact
                ON package_version_licenses (cache_artifact_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pvl_cache_artifact_license
                ON package_version_licenses (cache_artifact_id, license_spdx);
            """;
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync(recreateSql));
    }

    // Restructure package_version_vulns: add surrogate id TEXT PRIMARY KEY, make
    // package_version_id nullable, replace the composite PK (package_version_id, vuln_id)
    // with two partial unique indexes (one per owner_kind arm). This allows cache_artifact-owned
    // rows to exist without a package_versions FK.
    //
    // Fresh installs: CREATE TABLE already has the new shape; the SQLite branch detects no
    // composite PK and the Postgres branch uses IF NOT EXISTS guards. Both no-op cleanly.
    //
    // Postgres: add the id column if absent, backfill ids, drop the old PK constraint,
    // alter nullability, add new PK, create partial unique indexes.
    //
    // SQLite: recreate-table (ALTER TABLE cannot change PK or nullability). Existing rows
    // get a generated id via hex(randomblob(16)).
    // xtenant: DDL-only migration; no row query across tenants.
    private Task MakePvvPackageVersionIdNullableAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? MakePvvPackageVersionIdNullablePostgresAsync(conn)
            : MakePvvPackageVersionIdNullableSqliteAsync(conn);
    }

    private static async Task MakePvvPackageVersionIdNullablePostgresAsync(DbConnection conn)
    {
        // Fresh installs and already-migrated databases both carry the surrogate `id` column —
        // the CREATE TABLE block ships the new shape. Only a pre-restructure database lacks it,
        // and that is the sole case needing the reshape. Detecting on the PK constraint name does
        // NOT work: Postgres names both the old composite PK and the new single-column PK
        // `package_version_vulns_pkey`, so the presence of the `id` column is the reliable signal.
        long hasIdColumn = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'package_version_vulns' AND column_name = 'id'
            """);
        if (hasIdColumn > 0)
        {
            // Already migrated or fresh install — ensure partial unique indexes exist idempotently.
            await conn.ExecuteAsync("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_pv_vuln
                    ON package_version_vulns (package_version_id, vuln_id)
                    WHERE owner_kind = 'package_version';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_ca_vuln
                    ON package_version_vulns (cache_artifact_id, vuln_id)
                    WHERE owner_kind = 'cache_artifact';
                """);
            return;
        }

        // Old shape (composite PK, no `id` column) → reshape. The hasIdColumn == 0 guard above
        // guarantees the id column is absent here; separate statements so the
        // SchemaSyncComplianceTests regex does not pick up NOT NULL from a later statement.
        await conn.ExecuteAsync(
            "ALTER TABLE package_version_vulns ADD COLUMN id TEXT");
        await conn.ExecuteAsync(
            "UPDATE package_version_vulns SET id = lower(left(md5(random()::text || '-' || package_version_id || '-' || vuln_id), 32)) WHERE id IS NULL");
        await conn.ExecuteAsync(
            "ALTER TABLE package_version_vulns DROP CONSTRAINT IF EXISTS package_version_vulns_pkey");
        await conn.ExecuteAsync(
            "ALTER TABLE package_version_vulns ALTER COLUMN package_version_id DROP NOT NULL");
        await conn.ExecuteAsync(
            "ALTER TABLE package_version_vulns ADD PRIMARY KEY (id)");
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_pv_vuln
                ON package_version_vulns (package_version_id, vuln_id)
                WHERE owner_kind = 'package_version'
            """);
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_ca_vuln
                ON package_version_vulns (cache_artifact_id, vuln_id)
                WHERE owner_kind = 'cache_artifact'
            """);
    }

    private static async Task MakePvvPackageVersionIdNullableSqliteAsync(DbConnection conn)
    {
        // The reshape is needed while package_version_id is still constrained — either NOT NULL
        // or part of a PRIMARY KEY. SQLite reports a bare "TEXT PRIMARY KEY" column as notnull=0,
        // so the pk flag must be checked too; otherwise the reshape is skipped and recorded as
        // applied while the surrogate id column is never added.
        long stillConstrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('package_version_vulns') WHERE name = 'package_version_id'");
        if (stillConstrained == 0)
        {
            // Already migrated (fresh install or prior run). Ensure partial unique indexes exist.
            await conn.ExecuteAsync("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_pv_vuln
                    ON package_version_vulns (package_version_id, vuln_id)
                    WHERE owner_kind = 'package_version';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_ca_vuln
                    ON package_version_vulns (cache_artifact_id, vuln_id)
                    WHERE owner_kind = 'cache_artifact';
                """);
            return;
        }

        // Recreate the table with id as the surrogate PK and package_version_id nullable.
        // Column list covers: base columns + P0 additive columns (cache_artifact_id, owner_kind).
        // xtenant: DDL-only; no data query across tenants.
        const string recreateSql = """
            DROP TABLE IF EXISTS package_version_vulns_new;
            CREATE TABLE package_version_vulns_new (
                id                  TEXT PRIMARY KEY,
                package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                checked_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                                    CHECK (owner_kind IN ('package_version','cache_artifact'))
            );
            INSERT INTO package_version_vulns_new
                (id, package_version_id, vuln_id, checked_at, cache_artifact_id, owner_kind)
            SELECT lower(hex(randomblob(16))), package_version_id, vuln_id, checked_at,
                   cache_artifact_id, owner_kind
            FROM package_version_vulns;
            DROP TABLE package_version_vulns;
            ALTER TABLE package_version_vulns_new RENAME TO package_version_vulns;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_pv_vuln
                ON package_version_vulns (package_version_id, vuln_id)
                WHERE owner_kind = 'package_version';
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_ca_vuln
                ON package_version_vulns (cache_artifact_id, vuln_id)
                WHERE owner_kind = 'cache_artifact';
            CREATE INDEX IF NOT EXISTS idx_package_version_vulns_cache_artifact
                ON package_version_vulns (cache_artifact_id);
            CREATE INDEX IF NOT EXISTS idx_pkg_version_vulns_vuln
                ON package_version_vulns (vuln_id);
            """;
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync(recreateSql));
    }

    // Restructure rpm_metadata: add surrogate id TEXT PRIMARY KEY (replacing the package_version_id
    // single-column PK), make package_version_id nullable, add two partial unique indexes (one per
    // owner_kind arm). Fresh installs already have the new shape from Schema.sql; the id column is
    // the reliable detection signal because Postgres reuses `rpm_metadata_pkey` for both the old
    // single-column PK and any new PK.
    //
    // SQLite: recreate-table (ALTER TABLE cannot change PK or nullability).
    // Postgres: add id column, backfill ids, drop old PK constraint, drop NOT NULL, add new PK
    //   and partial unique indexes.
    // xtenant: DDL-only migration; no row query across tenants.
    private Task MakeRpmMetadataPvNullableAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? MakeRpmMetadataPvNullablePostgresAsync(conn)
            : MakeRpmMetadataPvNullableSqliteAsync(conn);
    }

    private static async Task MakeRpmMetadataPvNullablePostgresAsync(DbConnection conn)
    {
        // The id column is present on fresh installs and already-migrated databases.
        // Only a pre-restructure database lacks it; that is the sole case needing the reshape.
        long hasIdColumn = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'rpm_metadata' AND column_name = 'id'
            """);
        if (hasIdColumn > 0)
        {
            // Already migrated or fresh install — ensure partial unique indexes exist idempotently.
            await conn.ExecuteAsync("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_pv
                    ON rpm_metadata (package_version_id)
                    WHERE owner_kind = 'package_version';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_ca
                    ON rpm_metadata (cache_artifact_id)
                    WHERE owner_kind = 'cache_artifact';
                """);
            return;
        }

        // Old shape (package_version_id TEXT PRIMARY KEY, no `id` column) → reshape.
        await conn.ExecuteAsync(
            "ALTER TABLE rpm_metadata ADD COLUMN id TEXT");
        await conn.ExecuteAsync(
            "UPDATE rpm_metadata SET id = lower(left(md5(random()::text || '-' || package_version_id), 32)) WHERE id IS NULL");
        await conn.ExecuteAsync(
            "ALTER TABLE rpm_metadata DROP CONSTRAINT IF EXISTS rpm_metadata_pkey");
        await conn.ExecuteAsync(
            "ALTER TABLE rpm_metadata ALTER COLUMN package_version_id DROP NOT NULL");
        await conn.ExecuteAsync(
            "ALTER TABLE rpm_metadata ADD PRIMARY KEY (id)");
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_pv
                ON rpm_metadata (package_version_id)
                WHERE owner_kind = 'package_version'
            """);
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_ca
                ON rpm_metadata (cache_artifact_id)
                WHERE owner_kind = 'cache_artifact'
            """);
    }

    private static async Task MakeRpmMetadataPvNullableSqliteAsync(DbConnection conn)
    {
        // The reshape is needed while package_version_id is still constrained. In the old shape it
        // is a bare "TEXT PRIMARY KEY" (pk=1), and SQLite reports such a column as notnull=0 — so
        // the pk flag must be checked alongside notnull. Checking notnull alone skipped the reshape
        // and recorded it as applied while the surrogate id column was never added. The recreated
        // table has id as the sole PK and package_version_id nullable, so both flags read 0.
        long stillConstrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('rpm_metadata') WHERE name = 'package_version_id'");
        if (stillConstrained == 0)
        {
            // Already migrated (fresh install or prior run). Ensure partial unique indexes exist.
            await conn.ExecuteAsync("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_pv
                    ON rpm_metadata (package_version_id)
                    WHERE owner_kind = 'package_version';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_ca
                    ON rpm_metadata (cache_artifact_id)
                    WHERE owner_kind = 'cache_artifact';
                """);
            return;
        }

        // Recreate the table with id as surrogate PK and package_version_id nullable.
        // Column list covers all columns including P3a additive (cache_artifact_id, owner_kind).
        // xtenant: DDL-only; no data query across tenants.
        const string recreateSql = """
            DROP TABLE IF EXISTS rpm_metadata_new;
            CREATE TABLE rpm_metadata_new (
                id                  TEXT PRIMARY KEY,
                package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
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
                                    CHECK (owner_kind IN ('package_version','cache_artifact'))
            );
            INSERT INTO rpm_metadata_new
                (id, package_version_id,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, build_host, build_time, packager, vendor,
                 rpm_group, source_rpm, url, installed_size, archive_size,
                 header_start, header_end,
                 requires_json, provides_json, conflicts_json, obsoletes_json,
                 files_json, changelogs_json, rpm_license, created_at,
                 cache_artifact_id, owner_kind)
            SELECT lower(hex(randomblob(16))), package_version_id,
                   rpm_name, epoch, rpm_version, rpm_release, arch,
                   summary, description, build_host, build_time, packager, vendor,
                   rpm_group, source_rpm, url, installed_size, archive_size,
                   header_start, header_end,
                   requires_json, provides_json, conflicts_json, obsoletes_json,
                   files_json, changelogs_json, rpm_license, created_at,
                   cache_artifact_id, owner_kind
            FROM rpm_metadata;
            DROP TABLE rpm_metadata;
            ALTER TABLE rpm_metadata_new RENAME TO rpm_metadata;
            CREATE INDEX IF NOT EXISTS idx_rpm_metadata_arch ON rpm_metadata(arch);
            CREATE INDEX IF NOT EXISTS idx_rpm_metadata_cache_artifact ON rpm_metadata(cache_artifact_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_pv
                ON rpm_metadata (package_version_id)
                WHERE owner_kind = 'package_version';
            CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_ca
                ON rpm_metadata (cache_artifact_id)
                WHERE owner_kind = 'cache_artifact';
            """;
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync(recreateSql));
    }

    // Restructure maven_version_files: make package_version_id nullable, replace the plain
    // UNIQUE(package_version_id, filename) constraint with two partial unique indexes
    // (one per owner_kind arm). The surrogate id TEXT PRIMARY KEY is preserved unchanged.
    //
    // Fresh installs already have the new shape (no inline UNIQUE in the CREATE TABLE block);
    // detect by checking package_version_id nullability.
    //
    // SQLite: recreate-table. Postgres: DROP NOT NULL, add partial unique indexes.
    // xtenant: DDL-only migration; no row query across tenants.
    private Task MakeMvfPvNullableAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? MakeMvfPvNullablePostgresAsync(conn)
            : MakeMvfPvNullableSqliteAsync(conn);
    }

    private static async Task MakeMvfPvNullablePostgresAsync(DbConnection conn)
    {
        long notNull = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'maven_version_files' AND column_name = 'package_version_id'
              AND is_nullable = 'NO'
            """);
        if (notNull == 0)
        {
            // Already migrated or fresh install. Ensure partial unique indexes exist idempotently.
            await conn.ExecuteAsync("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_pv_filename
                    ON maven_version_files (package_version_id, filename)
                    WHERE owner_kind = 'package_version';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_ca_filename
                    ON maven_version_files (cache_artifact_id, filename)
                    WHERE owner_kind = 'cache_artifact';
                """);
            return;
        }

        // Old shape: package_version_id NOT NULL with UNIQUE(package_version_id, filename).
        await conn.ExecuteAsync(
            "ALTER TABLE maven_version_files DROP CONSTRAINT IF EXISTS maven_version_files_package_version_id_filename_key");
        await conn.ExecuteAsync(
            "ALTER TABLE maven_version_files ALTER COLUMN package_version_id DROP NOT NULL");
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_pv_filename
                ON maven_version_files (package_version_id, filename)
                WHERE owner_kind = 'package_version'
            """);
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_ca_filename
                ON maven_version_files (cache_artifact_id, filename)
                WHERE owner_kind = 'cache_artifact'
            """);
    }

    private static async Task MakeMvfPvNullableSqliteAsync(DbConnection conn)
    {
        // Reshape while package_version_id is still constrained — NOT NULL or part of a PRIMARY KEY.
        // SQLite reports a bare "TEXT PRIMARY KEY" column as notnull=0, so check the pk flag too.
        long stillConstrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('maven_version_files') WHERE name = 'package_version_id'");
        if (stillConstrained == 0)
        {
            // Already migrated (fresh install or prior run). Ensure partial unique indexes exist.
            await conn.ExecuteAsync("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_pv_filename
                    ON maven_version_files (package_version_id, filename)
                    WHERE owner_kind = 'package_version';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_ca_filename
                    ON maven_version_files (cache_artifact_id, filename)
                    WHERE owner_kind = 'cache_artifact';
                """);
            return;
        }

        // Recreate the table with package_version_id nullable and partial unique indexes.
        // Column list covers all columns including P3a additive (cache_artifact_id, owner_kind).
        // xtenant: DDL-only; no data query across tenants.
        const string recreateSql = """
            DROP TABLE IF EXISTS maven_version_files_new;
            CREATE TABLE maven_version_files_new (
                id                  TEXT PRIMARY KEY,
                package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                filename            TEXT NOT NULL,
                classifier          TEXT,
                extension           TEXT NOT NULL,
                blob_key            TEXT NOT NULL,
                size_bytes          INTEGER NOT NULL DEFAULT 0,
                checksum_sha256     TEXT,
                checksum_sha1       TEXT,
                checksum_md5        TEXT,
                origin              TEXT NOT NULL DEFAULT 'uploaded',
                created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                                    CHECK (owner_kind IN ('package_version','cache_artifact'))
            );
            INSERT INTO maven_version_files_new
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin, created_at,
                 cache_artifact_id, owner_kind)
            SELECT id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                   checksum_sha256, checksum_sha1, checksum_md5, origin, created_at,
                   cache_artifact_id, owner_kind
            FROM maven_version_files;
            DROP TABLE maven_version_files;
            ALTER TABLE maven_version_files_new RENAME TO maven_version_files;
            CREATE INDEX IF NOT EXISTS idx_maven_version_files_version ON maven_version_files(package_version_id);
            CREATE INDEX IF NOT EXISTS idx_maven_version_files_filename ON maven_version_files(filename);
            CREATE INDEX IF NOT EXISTS idx_maven_version_files_cache_artifact ON maven_version_files(cache_artifact_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_pv_filename
                ON maven_version_files (package_version_id, filename)
                WHERE owner_kind = 'package_version';
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_ca_filename
                ON maven_version_files (cache_artifact_id, filename)
                WHERE owner_kind = 'cache_artifact';
            """;
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync(recreateSql));
    }

    // Restructure cargo_metadata: make version_id nullable, replace the plain UNIQUE(version_id)
    // constraint with two partial unique indexes (one per owner_kind arm). The INTEGER AUTOINCREMENT
    // (SQLite) / BIGSERIAL (Postgres) PK is preserved unchanged.
    //
    // Fresh installs already have the new shape (no inline UNIQUE in the CREATE TABLE block);
    // detect by checking version_id nullability.
    //
    // SQLite: ALTER + DROP unique index cannot change nullability, so recreate-table is not needed —
    // SQLite allows dropping the UNIQUE constraint via index removal, but cannot drop NOT NULL via
    // ALTER. Use recreate-table pattern here too for correctness.
    // Postgres: DROP NOT NULL, drop old unique constraint, add partial unique indexes.
    // xtenant: DDL-only migration; no row query across tenants.
    private Task MakeCargoMetadataVidNullableAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? MakeCargoMetadataVidNullablePostgresAsync(conn)
            : MakeCargoMetadataVidNullableSqliteAsync(conn);
    }

    private static async Task MakeCargoMetadataVidNullablePostgresAsync(DbConnection conn)
    {
        long notNull = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'cargo_metadata' AND column_name = 'version_id'
              AND is_nullable = 'NO'
            """);
        if (notNull == 0)
        {
            // Already migrated or fresh install. Ensure partial unique indexes exist idempotently.
            await conn.ExecuteAsync("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_pv
                    ON cargo_metadata (version_id)
                    WHERE owner_kind = 'package_version';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_ca
                    ON cargo_metadata (cache_artifact_id)
                    WHERE owner_kind = 'cache_artifact';
                """);
            return;
        }

        // Old shape: version_id NOT NULL with UNIQUE(version_id).
        await conn.ExecuteAsync(
            "ALTER TABLE cargo_metadata DROP CONSTRAINT IF EXISTS cargo_metadata_version_id_key");
        await conn.ExecuteAsync(
            "ALTER TABLE cargo_metadata ALTER COLUMN version_id DROP NOT NULL");
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_pv
                ON cargo_metadata (version_id)
                WHERE owner_kind = 'package_version'
            """);
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_ca
                ON cargo_metadata (cache_artifact_id)
                WHERE owner_kind = 'cache_artifact'
            """);
    }

    private static async Task MakeCargoMetadataVidNullableSqliteAsync(DbConnection conn)
    {
        // Reshape while version_id is still constrained — NOT NULL or part of a PRIMARY KEY.
        // SQLite reports a bare "TEXT PRIMARY KEY" column as notnull=0, so check the pk flag too.
        long stillConstrained = await conn.ExecuteScalarAsync<long>(
            "SELECT MAX(\"notnull\", pk) FROM pragma_table_info('cargo_metadata') WHERE name = 'version_id'");
        if (stillConstrained == 0)
        {
            // Already migrated (fresh install or prior run). Ensure partial unique indexes exist.
            await conn.ExecuteAsync("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_pv
                    ON cargo_metadata (version_id)
                    WHERE owner_kind = 'package_version';
                CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_ca
                    ON cargo_metadata (cache_artifact_id)
                    WHERE owner_kind = 'cache_artifact';
                """);
            return;
        }

        // Recreate the table with version_id nullable and partial unique indexes.
        // The INTEGER AUTOINCREMENT PK cannot be changed; copy all rows preserving existing ids.
        // Column list covers base columns + P3a additive (cache_artifact_id, owner_kind).
        // xtenant: DDL-only; no data query across tenants.
        const string recreateSql = """
            DROP TABLE IF EXISTS cargo_metadata_new;
            CREATE TABLE cargo_metadata_new (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                index_line  TEXT NOT NULL,
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                                    CHECK (owner_kind IN ('package_version','cache_artifact'))
            );
            INSERT INTO cargo_metadata_new
                (id, version_id, index_line, cache_artifact_id, owner_kind)
            SELECT id, version_id, index_line, cache_artifact_id, owner_kind
            FROM cargo_metadata;
            DROP TABLE cargo_metadata;
            ALTER TABLE cargo_metadata_new RENAME TO cargo_metadata;
            CREATE INDEX IF NOT EXISTS idx_cargo_metadata_version ON cargo_metadata(version_id);
            CREATE INDEX IF NOT EXISTS idx_cargo_metadata_cache_artifact ON cargo_metadata(cache_artifact_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_pv
                ON cargo_metadata (version_id)
                WHERE owner_kind = 'package_version';
            CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_ca
                ON cargo_metadata (cache_artifact_id)
                WHERE owner_kind = 'cache_artifact';
            """;
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync(recreateSql));
    }

}
