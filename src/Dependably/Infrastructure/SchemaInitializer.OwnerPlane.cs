using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Dapper;
using Dependably.Protocol;
using Dependably.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Infrastructure;

/// <summary>Proxy package_versions → cache_artifact data migration, owner-invariant CHECK
/// migrations, and Dapper type handlers for <see cref="SchemaInitializer"/>.</summary>
public sealed partial class SchemaInitializer
{
    // Backfills proxy package_versions rows onto the global cache_artifact / tenant_artifact_access
    // plane. For each proxy version, this migration:
    //   1. Resolves or inserts a cache_artifact row keyed on (ecosystem, name, version, filename).
    //   2. Copies global supply-chain facts (purl, checksum_sha1, published_at, etc.) via COALESCE.
    //   3. Upserts tenant_artifact_access (org_id, cache_artifact_id) merging per-tenant state.
    //   4. Copies additive-twin metadata (vulns, licenses, rpm_metadata, maven_version_files,
    //      cargo_metadata) owned by cache_artifact, leaving the original version-owned rows intact.
    // Source rows remain; P4 drops them.
    // xtenant: one-shot cross-tenant migration; cache_artifact is a global table.
    [SuppressMessage("Major Code Smell", "S138:Functions should not have too many lines of code",
        Justification = "One-shot idempotent data migration kept as one auditable transaction; covered by schema regression tests.")]
    [SuppressMessage("Major Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "One-shot idempotent data migration; complexity reflects the SQLite/Postgres and per-row reshape cases. Covered by schema regression tests.")]
    private async Task MigrateProxyVersionsToCachePlaneAsync(DbConnection conn)
    {
        // now-ok: one-shot migration timestamp; no TimeProvider injected into SchemaInitializer.
        string now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        // xtenant: cross-tenant SELECT; results are keyed by org so tenant state is preserved.
        var proxyRows = (await conn.QueryAsync<(
            string VersionId, string PackageId, string Version, string Purl,
            string BlobKey, string Filename, long SizeBytes, string? ChecksumSha256,
            string? VulnCheckedAt, string? Deprecated, string? DeprecationCheckedAt,
            string? PublishedAt, string? ChecksumSha1, string? UpstreamIntegrityValue,
            string? UpstreamIntegrityAlgorithm, bool HasInstallScript, string? InstallScriptKind,
            string? ProvenanceStatus, string? ProvenanceSigner,
            string? ManualBlockState, bool Yanked, string? YankReason, string? LastUsed,
            long DownloadCount, string OrgId, string Ecosystem, string PackageName)>(
            """
            SELECT pv.id, pv.package_id, pv.version, pv.purl,
                   pv.blob_key, pv.filename, pv.size_bytes, pv.checksum_sha256,
                   pv.vuln_checked_at, pv.deprecated, pv.deprecation_checked_at,
                   pv.published_at, pv.checksum_sha1, pv.upstream_integrity_value,
                   pv.upstream_integrity_algorithm, pv.has_install_script, pv.install_script_kind,
                   pv.provenance_status, pv.provenance_signer,
                   pv.manual_block_state, pv.yanked, pv.yank_reason, pv.last_used,
                   pv.download_count, p.org_id, p.ecosystem, p.purl_name
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.origin = 'proxy' AND pv.blob_key NOT LIKE 'hosted/%'
            """)).ToList();

        if (proxyRows.Count == 0)
        {
            return;
        }

        _logger.LogInformation(
            "migrate_proxy_versions_to_cache_plane: processing {Count} proxy version rows.",
            proxyRows.Count);

        foreach (var row in proxyRows)
        {
            string filename = row.Filename ?? (row.BlobKey.Contains('/') ? row.BlobKey[(row.BlobKey.LastIndexOf('/') + 1)..] : row.BlobKey);
            // Strip the "/filename" suffix from the DB blob_key to get the store key (proxy/{sha256}).
            string blobKey = row.BlobKey;
            // content_hash is the sha256 from the blob_key path segment after "proxy/".
            int proxyIdx = blobKey.IndexOf("proxy/", StringComparison.OrdinalIgnoreCase);
            string contentHash = proxyIdx >= 0 ? blobKey[(proxyIdx + 6)..].Split('/')[0] : blobKey;

            // Step 1: resolve or insert cache_artifact.
            // xtenant: cache_artifact is global; keyed by coordinate, not org.
            string? caId = await conn.ExecuteScalarAsync<string?>(
                """
                SELECT id FROM cache_artifact
                WHERE ecosystem = @ecosystem AND name = @name
                  AND version = @version AND filename = @filename
                """,
                new { ecosystem = row.Ecosystem, name = row.PackageName, version = row.Version, filename });

            if (caId is null)
            {
                caId = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    """
                    INSERT INTO cache_artifact
                        (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                         first_cached_at, last_accessed_at, purl, checksum_sha1, published_at,
                         deprecated, deprecation_checked_at, has_install_script, install_script_kind,
                         provenance_status, provenance_signer, upstream_integrity_value,
                         upstream_integrity_algorithm, vuln_checked_at)
                    VALUES
                        (@caId, @ecosystem, @name, @version, @filename, @blobKey, @contentHash,
                         @sizeBytes, @now, @now, @purl, @checksumSha1, @publishedAt,
                         @deprecated, @deprecationCheckedAt, @hasInstallScript, @installScriptKind,
                         @provenanceStatus, @provenanceSigner, @upstreamIntegrityValue,
                         @upstreamIntegrityAlgorithm, @vulnCheckedAt)
                    ON CONFLICT (ecosystem, name, version, filename) DO NOTHING
                    """,
                    new
                    {
                        caId,
                        ecosystem = row.Ecosystem,
                        name = row.PackageName,
                        version = row.Version,
                        filename,
                        blobKey = BlobKeys.StoreKey(blobKey),
                        contentHash,
                        sizeBytes = row.SizeBytes,
                        now,
                        purl = row.Purl,
                        checksumSha1 = row.ChecksumSha1,
                        publishedAt = row.PublishedAt,
                        deprecated = row.Deprecated,
                        deprecationCheckedAt = row.DeprecationCheckedAt,
                        hasInstallScript = row.HasInstallScript ? 1 : 0,
                        installScriptKind = row.InstallScriptKind,
                        provenanceStatus = row.ProvenanceStatus,
                        provenanceSigner = row.ProvenanceSigner,
                        upstreamIntegrityValue = row.UpstreamIntegrityValue,
                        upstreamIntegrityAlgorithm = row.UpstreamIntegrityAlgorithm,
                        vulnCheckedAt = row.VulnCheckedAt,
                    });
                // Re-read in case of concurrent insert race.
                caId = await conn.ExecuteScalarAsync<string?>(
                    """
                    SELECT id FROM cache_artifact
                    WHERE ecosystem = @ecosystem AND name = @name
                      AND version = @version AND filename = @filename
                    """,
                    new { ecosystem = row.Ecosystem, name = row.PackageName, version = row.Version, filename });
                if (caId is null)
                {
                    _logger.LogWarning(
                        "migrate_proxy_versions_to_cache_plane: failed to resolve cache_artifact for {Purl}.",
                        row.Purl);
                    continue;
                }
            }

            // Step 2: copy global facts unconditionally after caId is resolved — covers the
            // just-inserted path, the pre-existing path (second same-coordinate row in the
            // sequential loop), and the concurrent multi-replica race path (ON CONFLICT DO NOTHING
            // + re-read lands in the if-branch but still reaches this UPDATE). COALESCE keeps any
            // non-null value already on the row and fills only nulls from the incoming row;
            // running after a fresh INSERT is a no-op because the INSERT already wrote the values.
            // xtenant: cache_artifact is global; keyed by caId resolved above.
            await conn.ExecuteAsync(
                """
                UPDATE cache_artifact SET
                    purl                         = COALESCE(purl, @purl),
                    checksum_sha1                = COALESCE(checksum_sha1, @checksumSha1),
                    published_at                 = COALESCE(published_at, @publishedAt),
                    deprecated                   = COALESCE(deprecated, @deprecated),
                    deprecation_checked_at       = COALESCE(deprecation_checked_at, @deprecationCheckedAt),
                    has_install_script           = CASE WHEN @hasInstallScript = 1 THEN 1 ELSE has_install_script END,
                    install_script_kind          = COALESCE(install_script_kind, @installScriptKind),
                    provenance_status            = COALESCE(provenance_status, @provenanceStatus),
                    provenance_signer            = COALESCE(provenance_signer, @provenanceSigner),
                    upstream_integrity_value     = COALESCE(upstream_integrity_value, @upstreamIntegrityValue),
                    upstream_integrity_algorithm = COALESCE(upstream_integrity_algorithm, @upstreamIntegrityAlgorithm),
                    vuln_checked_at              = COALESCE(vuln_checked_at, @vulnCheckedAt)
                WHERE id = @caId
                """,
                new
                {
                    caId,
                    purl = row.Purl,
                    checksumSha1 = row.ChecksumSha1,
                    publishedAt = row.PublishedAt,
                    deprecated = row.Deprecated,
                    deprecationCheckedAt = row.DeprecationCheckedAt,
                    hasInstallScript = row.HasInstallScript ? 1 : 0,
                    installScriptKind = row.InstallScriptKind,
                    provenanceStatus = row.ProvenanceStatus,
                    provenanceSigner = row.ProvenanceSigner,
                    upstreamIntegrityValue = row.UpstreamIntegrityValue,
                    upstreamIntegrityAlgorithm = row.UpstreamIntegrityAlgorithm,
                    vulnCheckedAt = row.VulnCheckedAt,
                });

            // Step 3: upsert tenant_artifact_access for this org. Merge per-tenant state:
            // take max download_count and latest last_used to avoid losing counts from other tenants
            // that may have already been backfilled for the same cache_artifact.
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access
                    (org_id, cache_artifact_id, first_accessed_at, last_accessed_at,
                     access_count, manual_block_state, yanked, yank_reason, last_used, download_count)
                VALUES (@orgId, @caId, @now, @now, 1, @manualBlockState, @yanked, @yankReason,
                        @lastUsed, @downloadCount)
                ON CONFLICT (org_id, cache_artifact_id) DO UPDATE SET
                    manual_block_state = COALESCE(tenant_artifact_access.manual_block_state, excluded.manual_block_state),
                    yanked             = CASE WHEN excluded.yanked = 1 THEN 1 ELSE tenant_artifact_access.yanked END,
                    yank_reason        = COALESCE(tenant_artifact_access.yank_reason, excluded.yank_reason),
                    last_used          = CASE
                        WHEN tenant_artifact_access.last_used IS NULL THEN excluded.last_used
                        WHEN excluded.last_used IS NULL THEN tenant_artifact_access.last_used
                        WHEN excluded.last_used > tenant_artifact_access.last_used THEN excluded.last_used
                        ELSE tenant_artifact_access.last_used
                    END,
                    download_count     = tenant_artifact_access.download_count + excluded.download_count
                """,
                new
                {
                    orgId = row.OrgId,
                    caId,
                    now,
                    manualBlockState = row.ManualBlockState,
                    yanked = row.Yanked ? 1 : 0,
                    yankReason = row.YankReason,
                    lastUsed = row.LastUsed,
                    downloadCount = row.DownloadCount,
                });

            // Step 4a: additive-twin vulns (owner_kind='cache_artifact').
            // xtenant: INSERT pinned to caId (cache_artifact-scoped, global).
            await conn.ExecuteAsync(
                """
                INSERT INTO package_version_vulns
                    (id, cache_artifact_id, vuln_id, checked_at, owner_kind)
                SELECT lower(hex(randomblob(16))), @caId, pvv.vuln_id, pvv.checked_at, 'cache_artifact'
                FROM package_version_vulns pvv
                WHERE pvv.package_version_id = @versionId
                  AND pvv.owner_kind = 'package_version'
                  AND NOT EXISTS (
                    SELECT 1 FROM package_version_vulns x
                    WHERE x.cache_artifact_id = @caId AND x.vuln_id = pvv.vuln_id
                      AND x.owner_kind = 'cache_artifact'
                  )
                """,
                new { caId, versionId = row.VersionId });

            // Step 4b: additive-twin licenses.
            // xtenant: INSERT pinned to caId (cache_artifact-scoped, global).
            await conn.ExecuteAsync(
                """
                INSERT INTO package_version_licenses
                    (id, cache_artifact_id, license_spdx, source, owner_kind)
                SELECT lower(hex(randomblob(16))), @caId, pvl.license_spdx, pvl.source, 'cache_artifact'
                FROM package_version_licenses pvl
                WHERE pvl.package_version_id = @versionId
                  AND pvl.owner_kind = 'package_version'
                ON CONFLICT (cache_artifact_id, license_spdx) DO NOTHING
                """,
                new { caId, versionId = row.VersionId });

            // Step 4c: additive-twin rpm_metadata (for RPM proxy versions). One row per artifact.
            // xtenant: INSERT pinned to caId (cache_artifact-scoped, global).
            await conn.ExecuteAsync(
                """
                INSERT INTO rpm_metadata
                    (id, cache_artifact_id, owner_kind,
                     rpm_name, epoch, rpm_version, rpm_release, arch,
                     summary, description, build_host, build_time, packager, vendor,
                     rpm_group, source_rpm, url, installed_size, archive_size,
                     header_start, header_end,
                     requires_json, provides_json, conflicts_json, obsoletes_json,
                     files_json, changelogs_json, rpm_license, created_at)
                SELECT lower(hex(randomblob(16))), @caId, 'cache_artifact',
                       rm.rpm_name, rm.epoch, rm.rpm_version, rm.rpm_release, rm.arch,
                       rm.summary, rm.description, rm.build_host, rm.build_time,
                       rm.packager, rm.vendor, rm.rpm_group, rm.source_rpm, rm.url,
                       rm.installed_size, rm.archive_size, rm.header_start, rm.header_end,
                       rm.requires_json, rm.provides_json, rm.conflicts_json, rm.obsoletes_json,
                       rm.files_json, rm.changelogs_json, rm.rpm_license, rm.created_at
                FROM rpm_metadata rm
                WHERE rm.package_version_id = @versionId
                  AND rm.owner_kind = 'package_version'
                ON CONFLICT (cache_artifact_id) WHERE owner_kind = 'cache_artifact' DO NOTHING
                """,
                new { caId, versionId = row.VersionId });

            // Step 4d: additive-twin maven_version_files (for Maven proxy versions). One row per file.
            // xtenant: INSERT pinned to caId (cache_artifact-scoped, global).
            await conn.ExecuteAsync(
                """
                INSERT INTO maven_version_files
                    (id, cache_artifact_id, filename, classifier, extension, blob_key, size_bytes,
                     checksum_sha256, checksum_sha1, checksum_md5, origin, created_at, owner_kind)
                SELECT lower(hex(randomblob(16))), @caId, mvf.filename, mvf.classifier,
                       mvf.extension, mvf.blob_key, mvf.size_bytes,
                       mvf.checksum_sha256, mvf.checksum_sha1, mvf.checksum_md5,
                       mvf.origin, mvf.created_at, 'cache_artifact'
                FROM maven_version_files mvf
                WHERE mvf.package_version_id = @versionId
                  AND mvf.owner_kind = 'package_version'
                ON CONFLICT (cache_artifact_id, filename) WHERE owner_kind = 'cache_artifact' DO NOTHING
                """,
                new { caId, versionId = row.VersionId });

            // Step 4e: additive-twin cargo_metadata (for Cargo proxy versions). One row per version.
            // xtenant: INSERT pinned to caId (cache_artifact-scoped, global).
            await conn.ExecuteAsync(
                """
                INSERT INTO cargo_metadata
                    (cache_artifact_id, index_line, owner_kind)
                SELECT @caId, cm.index_line, 'cache_artifact'
                FROM cargo_metadata cm
                WHERE cm.version_id = @versionId
                  AND cm.owner_kind = 'package_version'
                ON CONFLICT (cache_artifact_id) WHERE owner_kind = 'cache_artifact' DO NOTHING
                """,
                new { caId, versionId = row.VersionId });
        }

        _logger.LogInformation(
            "migrate_proxy_versions_to_cache_plane: completed {Count} rows.", proxyRows.Count);
    }

    // ── Owner-invariant CHECK migrations ────────────────────────────────────────────────────────
    //
    // Each of the five polymorphic metadata tables must enforce the invariant:
    //   owner_kind='package_version' ↔ package_version_id (or version_id) NOT NULL AND ca-FK NULL
    //   owner_kind='cache_artifact'  ↔ cache_artifact_id NOT NULL AND pv-FK NULL
    //
    // Fresh installs get the CHECK from the CREATE TABLE blocks in Schema.sql / Schema.pg.sql.
    // Upgraded DBs were recreated by the make_*_nullable one-shots but without the invariant, so
    // these migrations add it post-hoc by:
    //   Postgres: ADD CONSTRAINT IF NOT EXISTS (named constraint, idempotent).
    //   SQLite:   check sqlite_master for the invariant text and recreate the table if absent.

    // Detection constant used by all SQLite branches: substring present in the invariant CHECK body.
    private const string OwnerInvariantSignature = "owner_kind = 'package_version' AND";

    private Task AddPvvOwnerInvariantCheckAsync(DbConnection conn) =>
        _db.Provider == DbProvider.Postgres
            ? AddPvvOwnerInvariantCheckPostgresAsync(conn)
            : AddPvvOwnerInvariantCheckSqliteAsync(conn);

    private static async Task AddPvvOwnerInvariantCheckPostgresAsync(DbConnection conn)
    {
        long hasConstraint = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.table_constraints
            WHERE table_name = 'package_version_vulns'
              AND constraint_name = 'package_version_vulns_owner_invariant_check'
            """);
        if (hasConstraint > 0)
        {
            return;
        }

        await conn.ExecuteAsync("""
            ALTER TABLE package_version_vulns
            ADD CONSTRAINT package_version_vulns_owner_invariant_check CHECK (
                (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                OR
                (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
            )
            """);
    }

    private static async Task AddPvvOwnerInvariantCheckSqliteAsync(DbConnection conn)
    {
        string? sql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'package_version_vulns'");
        if (sql is not null && sql.Contains(OwnerInvariantSignature, StringComparison.Ordinal))
        {
            return;
        }

        // xtenant: DDL-only; no data query across tenants.
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync("""
            DROP TABLE IF EXISTS package_version_vulns_new;
            CREATE TABLE package_version_vulns_new (
                id                  TEXT PRIMARY KEY,
                package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                checked_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                                    CHECK (owner_kind IN ('package_version','cache_artifact')),
                CHECK (
                    (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                    OR
                    (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
                )
            );
            INSERT INTO package_version_vulns_new
                (id, package_version_id, vuln_id, checked_at, cache_artifact_id, owner_kind)
            SELECT id, package_version_id, vuln_id, checked_at, cache_artifact_id, owner_kind
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
            """));
    }

    private Task AddPvlOwnerInvariantCheckAsync(DbConnection conn) =>
        _db.Provider == DbProvider.Postgres
            ? AddPvlOwnerInvariantCheckPostgresAsync(conn)
            : AddPvlOwnerInvariantCheckSqliteAsync(conn);

    private static async Task AddPvlOwnerInvariantCheckPostgresAsync(DbConnection conn)
    {
        long hasConstraint = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.table_constraints
            WHERE table_name = 'package_version_licenses'
              AND constraint_name = 'package_version_licenses_owner_invariant_check'
            """);
        if (hasConstraint > 0)
        {
            return;
        }

        await conn.ExecuteAsync("""
            ALTER TABLE package_version_licenses
            ADD CONSTRAINT package_version_licenses_owner_invariant_check CHECK (
                (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                OR
                (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
            )
            """);
    }

    private static async Task AddPvlOwnerInvariantCheckSqliteAsync(DbConnection conn)
    {
        string? sql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'package_version_licenses'");
        if (sql is not null && sql.Contains(OwnerInvariantSignature, StringComparison.Ordinal))
        {
            return;
        }

        // xtenant: DDL-only; no data query across tenants.
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync("""
            DROP TABLE IF EXISTS package_version_licenses_new;
            CREATE TABLE package_version_licenses_new (
                id                  TEXT PRIMARY KEY,
                package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                license_spdx        TEXT NOT NULL,
                source              TEXT NOT NULL DEFAULT 'upstream',
                created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                                    CHECK (owner_kind IN ('package_version','cache_artifact')),
                UNIQUE (package_version_id, license_spdx),
                UNIQUE (cache_artifact_id, license_spdx),
                CHECK (
                    (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                    OR
                    (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
                )
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
            """));
    }

    private Task AddRpmMetadataOwnerInvariantCheckAsync(DbConnection conn) =>
        _db.Provider == DbProvider.Postgres
            ? AddRpmMetadataOwnerInvariantCheckPostgresAsync(conn)
            : AddRpmMetadataOwnerInvariantCheckSqliteAsync(conn);

    private static async Task AddRpmMetadataOwnerInvariantCheckPostgresAsync(DbConnection conn)
    {
        long hasConstraint = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.table_constraints
            WHERE table_name = 'rpm_metadata'
              AND constraint_name = 'rpm_metadata_owner_invariant_check'
            """);
        if (hasConstraint > 0)
        {
            return;
        }

        await conn.ExecuteAsync("""
            ALTER TABLE rpm_metadata
            ADD CONSTRAINT rpm_metadata_owner_invariant_check CHECK (
                (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                OR
                (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
            )
            """);
    }

    private static async Task AddRpmMetadataOwnerInvariantCheckSqliteAsync(DbConnection conn)
    {
        string? sql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'rpm_metadata'");
        if (sql is not null && sql.Contains(OwnerInvariantSignature, StringComparison.Ordinal))
        {
            return;
        }

        // xtenant: DDL-only; no data query across tenants.
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync("""
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
                                    CHECK (owner_kind IN ('package_version','cache_artifact')),
                CHECK (
                    (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                    OR
                    (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
                )
            );
            INSERT INTO rpm_metadata_new SELECT * FROM rpm_metadata;
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
            """));
    }

    private Task AddMvfOwnerInvariantCheckAsync(DbConnection conn) =>
        _db.Provider == DbProvider.Postgres
            ? AddMvfOwnerInvariantCheckPostgresAsync(conn)
            : AddMvfOwnerInvariantCheckSqliteAsync(conn);

    private static async Task AddMvfOwnerInvariantCheckPostgresAsync(DbConnection conn)
    {
        long hasConstraint = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.table_constraints
            WHERE table_name = 'maven_version_files'
              AND constraint_name = 'maven_version_files_owner_invariant_check'
            """);
        if (hasConstraint > 0)
        {
            return;
        }

        await conn.ExecuteAsync("""
            ALTER TABLE maven_version_files
            ADD CONSTRAINT maven_version_files_owner_invariant_check CHECK (
                (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                OR
                (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
            )
            """);
    }

    private static async Task AddMvfOwnerInvariantCheckSqliteAsync(DbConnection conn)
    {
        string? sql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'maven_version_files'");
        if (sql is not null && sql.Contains(OwnerInvariantSignature, StringComparison.Ordinal))
        {
            return;
        }

        // xtenant: DDL-only; no data query across tenants.
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync("""
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
                                    CHECK (owner_kind IN ('package_version','cache_artifact')),
                CHECK (
                    (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                    OR
                    (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
                )
            );
            INSERT INTO maven_version_files_new SELECT * FROM maven_version_files;
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
            """));
    }

    private Task AddCargoMetadataOwnerInvariantCheckAsync(DbConnection conn) =>
        _db.Provider == DbProvider.Postgres
            ? AddCargoMetadataOwnerInvariantCheckPostgresAsync(conn)
            : AddCargoMetadataOwnerInvariantCheckSqliteAsync(conn);

    private static async Task AddCargoMetadataOwnerInvariantCheckPostgresAsync(DbConnection conn)
    {
        long hasConstraint = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.table_constraints
            WHERE table_name = 'cargo_metadata'
              AND constraint_name = 'cargo_metadata_owner_invariant_check'
            """);
        if (hasConstraint > 0)
        {
            return;
        }

        await conn.ExecuteAsync("""
            ALTER TABLE cargo_metadata
            ADD CONSTRAINT cargo_metadata_owner_invariant_check CHECK (
                (owner_kind = 'package_version' AND version_id IS NOT NULL AND cache_artifact_id IS NULL)
                OR
                (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND version_id IS NULL)
            )
            """);
    }

    private static async Task AddCargoMetadataOwnerInvariantCheckSqliteAsync(DbConnection conn)
    {
        string? sql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'cargo_metadata'");
        if (sql is not null && sql.Contains(OwnerInvariantSignature, StringComparison.Ordinal))
        {
            return;
        }

        // cargo_metadata uses INTEGER AUTOINCREMENT PK — AUTOINCREMENT requires the table name
        // to remain in sqlite_sequence after the rename; DROP + RENAME preserves that correctly
        // because the sequence is keyed on the live table name.
        // xtenant: DDL-only; no data query across tenants.
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync("""
            DROP TABLE IF EXISTS cargo_metadata_new;
            CREATE TABLE cargo_metadata_new (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                index_line  TEXT NOT NULL,
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                                    CHECK (owner_kind IN ('package_version','cache_artifact')),
                CHECK (
                    (owner_kind = 'package_version' AND version_id IS NOT NULL AND cache_artifact_id IS NULL)
                    OR
                    (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND version_id IS NULL)
                )
            );
            INSERT INTO cargo_metadata_new (id, version_id, index_line, cache_artifact_id, owner_kind)
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
            """));
    }

    // Removes proxy-origin rows from package_versions now that all proxy artifacts live on the
    // global cache_artifact plane. The ON DELETE CASCADE on the FK columns of package_version_vulns,
    // package_version_licenses, rpm_metadata, maven_version_files, and cargo_metadata drops only the
    // owner_kind='package_version' metadata rows for the deleted versions; the owner_kind='cache_artifact'
    // twins (package_version_id NULL) survive intact.
    // The NOT LIKE 'hosted/%' guard is a second discriminator: even if backfill_hosted_origin_by_blob_key
    // has not run (e.g. ledger reset), rows whose blob_key is 'hosted/…' are not deleted.
    // Proxy artifacts may use any of the prefixes proxy/, cargo/, or go/ — all are genuine proxy
    // rows and must be deleted. The only hosted prefix is hosted/; any row with that prefix is
    // never a proxy artifact regardless of the origin column value.
    // xtenant: cross-tenant DELETE; scoped to the proxy discriminator and has no tenant boundary.
    private static Task DeleteMigratedProxyPackageVersionsAsync(DbConnection conn) =>
        conn.ExecuteAsync("DELETE FROM package_versions WHERE origin = 'proxy' AND blob_key NOT LIKE 'hosted/%'");

    private static async Task MigrateSqliteAsync(DbConnection conn, string ddl)
    {
        try { await conn.ExecuteAsync(ddl); }
        // SQLite returns the generic code 1 (SQLITE_ERROR) for many failures — no such table,
        // no such column, syntax errors. Only "duplicate column" means the additive migration
        // already applied and is safely ignorable; anything else is a real schema problem that
        // must surface rather than be silently swallowed.
        catch (Microsoft.Data.Sqlite.SqliteException ex)
            when (ex.SqliteErrorCode == 1
                  && ex.Message.Contains("duplicate column", StringComparison.OrdinalIgnoreCase))
        { /* column already present — idempotent re-run, ignore */ }
    }

    // Adds CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')) to vulnerabilities.severity.
    // NULL values satisfy the constraint because NULL IN (...) is NULL (not FALSE) in SQL.
    //
    // Postgres: drop + re-add the auto-named constraint so the migration is idempotent on both
    // DBs that were created before this migration and DBs already at the target shape.
    //
    // SQLite: rewrite the stored CREATE TABLE text via writable_schema. The old schema text
    // carries a bare `severity TEXT,` column (with an inline comment); the replacement inserts
    // the CHECK clause. The REPLACE is a no-op when the CHECK is already present.
    private Task AddSeverityCheckConstraintAsync(DbConnection conn) =>
        _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_severity_check;
                ALTER TABLE vulnerabilities ADD  CONSTRAINT vulnerabilities_severity_check
                    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW'));
                """)
            : AddSeverityCheckConstraintSqliteAsync(conn);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task AddSeverityCheckConstraintSqliteAsync(DbConnection conn)
    {
        const string oldText = "severity        TEXT,           -- 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | NULL";
        const string newText = "severity        TEXT            -- NULL when the advisory carries no CVSS severity classification\n" +
                               "                    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),";

        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name = 'vulnerabilities'
                """, new { old = oldText, @new = newText });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
        await conn.ExecuteAsync("PRAGMA integrity_check");
    }

    private static async Task<string> ReadSchemaAsync(DbProvider provider, CancellationToken ct)
    {
        var assembly = typeof(SchemaInitializer).Assembly;
        string suffix = provider == DbProvider.Postgres ? "Schema.pg.sql" : "Schema.sql";
        string resourceName = assembly.GetManifestResourceNames()
            .Single(n => n.EndsWith(suffix));

        await using var stream = assembly.GetManifestResourceStream(resourceName)!;
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(ct);
    }

    private sealed class DateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset>
    {
        public override void SetValue(IDbDataParameter parameter, DateTimeOffset value)
            => parameter.Value = value.ToString("o");

        public override DateTimeOffset Parse(object value)
            => DateTimeOffset.Parse((string)value, null,
                System.Globalization.DateTimeStyles.RoundtripKind);
    }
}
