using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Dapper;
using Dependably.Protocol;
using Dependably.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Infrastructure;

/// <summary>Applies the embedded SQL schema on startup (idempotent — uses CREATE IF NOT EXISTS).</summary>
[SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out",
    Justification = "Migration-rationale comments contain SQL/DDL keywords that trip S125; they are documentation, not commented-out code.")]
public sealed partial class SchemaInitializer
{
    private readonly IMetadataStore _db;
    private readonly ILogger<SchemaInitializer> _logger;
    private readonly SpdxLicenseSeeder _spdxSeeder;
    private readonly IConfiguration? _config;

    static SchemaInitializer()
    {
        // SQLite stores dates as TEXT (ISO 8601). Register a type handler so Dapper
        // can map TEXT columns to DateTimeOffset in record constructors.
        SqlMapper.AddTypeHandler(new DateTimeOffsetHandler());
    }

    public SchemaInitializer(
        IMetadataStore db,
        ILogger<SchemaInitializer>? logger = null,
        SpdxLicenseSeeder? spdxSeeder = null,
        IConfiguration? config = null)
    {
        _db = db;
        _logger = logger ?? NullLogger<SchemaInitializer>.Instance;
        // Test ctors that pass only the IMetadataStore get a seeder with a null logger —
        // the embedded JSON is still read so the spdx_license table is populated.
        _spdxSeeder = spdxSeeder ?? new SpdxLicenseSeeder(NullLogger<SpdxLicenseSeeder>.Instance);
        // Optional: drives upstream-registry default URLs from config overrides during the
        // backfill. Null in lightweight test ctors — falls back to the hard-coded public defaults.
        _config = config;
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        string sql = await ReadSchemaAsync(_db.Provider, ct);
        await using var conn = await _db.OpenAsync(ct);

        // Table renames must happen BEFORE the CREATE TABLE IF NOT EXISTS pass — otherwise the
        // schema would create empty sibling tables under the new names alongside the original
        // data. _applied_migrations is ensured up front so RunOnceAsync can record the ledger.
        await EnsureMigrationsTableAsync(conn);
        await RunOnceAsync(conn, "rename_tokens_to_user_tokens", RenameTokensTableAsync);
        await RunOnceAsync(conn, "rename_cicd_tokens_to_service_tokens", RenameCicdTokensTableAsync);

        await conn.ExecuteAsync(sql);

        await RunAdditiveMigrationsAsync(conn);
        await _spdxSeeder.RunAsync(conn, ct);

        await RunOnceAsync(conn, "reset_nuget_vuln_checked_at", ResetNuGetVulnCheckedAtAsync);
        await RunOnceAsync(conn, "fix_npm_purl_encoding", FixNpmPurlEncodingAsync);
        await RunOnceAsync(conn, "fix_npm_purl_name_unencoded", FixNpmPurlNameUnencodedAsync);
        await RunOnceAsync(conn, "fix_npm_version_purl_at_encoding", FixNpmVersionPurlAtEncodingAsync);
        await RunOnceAsync(conn, "fix_npm_version_purl_slash_encoding", FixNpmVersionPurlSlashEncodingAsync);
        await RunOnceAsync(conn, "fix_npm_activity_purl_encoding", FixNpmActivityPurlEncodingAsync);
        await RunOnceAsync(conn, "fix_nuget_proxy_purl_names", FixNuGetProxyPurlNamesAsync);
        await RunOnceAsync(conn, "backfill_users_account_type_saml", BackfillUsersAccountTypeSamlAsync);
        // transactional: false — ExpandRoleCheckSqliteAsync drives PRAGMA writable_schema + a
        // schema_version bump that don't compose with an enclosing transaction. Safe because the
        // migration is idempotent (PG drops-then-adds the constraint; SQLite REPLACEs the stored
        // CREATE text), so an un-recorded partial run is harmlessly repeated next boot.
        await RunOnceAsync(conn, "expand_role_check_with_auditor", ExpandRoleCheckWithAuditorAsync, transactional: false);
        await RunOnceAsync(conn, "collapse_origin_to_uploaded", CollapseOriginToUploadedAsync);
        await RunOnceAsync(conn, "drop_legacy_token_scope_column", DropLegacyTokenScopeColumnAsync);
        await RunOnceAsync(conn, "drop_package_versions_sbom_column", DropPackageVersionsSbomColumnAsync);
        await RunOnceAsync(conn, "drop_org_settings_disable_job_columns", DropOrgSettingsDisableJobColumnsAsync);
        await RunOnceAsync(conn, "drop_allowlist_blocklist_ecosystem", DropAllowlistBlocklistEcosystemAsync);
        await RunOnceAsync(conn, "backfill_package_versions_filename", BackfillPackageVersionsFilenameAsync);
        await RunOnceAsync(conn, "backfill_oci_catalog", BackfillOciCatalogAsync);
        await RunOnceAsync(conn, "seed_default_upstream_registries", SeedDefaultUpstreamRegistriesAsync);
        await RunOnceAsync(conn, "seed_go_cargo_upstream_registries", SeedGoCargoUpstreamRegistriesAsync);
        // Seed the two default OCI upstream rows (MCR + Docker Hub) for every org that has no
        // 'oci' upstream_registry rows yet. Hardcoded defaults; does not read Oci:Upstreams config
        // (that config key is no longer used). Idempotent via the per-(org, ecosystem) existence
        // check and the UNIQUE(org_id, ecosystem, url) constraint.
        // xtenant: one-shot backfill across every tenant on the instance.
        await RunOnceAsync(conn, "seed_oci_upstream_registries", SeedOciUpstreamRegistriesAsync);
        // transactional: false — the SQLite branch drives PRAGMA writable_schema + a schema_version
        // bump that don't compose with an enclosing transaction (same shape as the auditor CHECK
        // rewrite above). Idempotent on both providers, so an un-recorded partial run is repeated
        // harmlessly next boot. Must run before migrate_block_deprecated_to_block_all so the widened
        // CHECK permits the 'block_all' value the data rewrite writes.
        await RunOnceAsync(conn, "expand_block_deprecated_check", ExpandBlockDeprecatedCheckAsync, transactional: false);
        await RunOnceAsync(conn, "migrate_block_deprecated_to_block_all", MigrateBlockDeprecatedToBlockAllAsync);
        await RunOnceAsync(conn, "migrate_maven_reserved_prefixes_to_table", MigrateMavenReservedPrefixesToTableAsync);
        await RunOnceAsync(conn, "drop_redundant_pkg_version_vulns_version_index", DropRedundantPkgVersionVulnsVersionIndexAsync);
        // Drop the global UNIQUE on package_versions.purl. The constraint was added when purl was a
        // globally-unique coordinate but fails in multi-tenant mode where the same upstream package can
        // be pulled by multiple tenants — each proxy-fetch creates its own package_versions row with the
        // same purl under a different packages.org_id. The UNIQUE(package_id, version) constraint is
        // retained and is the correct per-tenant uniqueness guard.
        // transactional: false on SQLite — the recreate-table pattern does not compose with an outer
        // transaction on SQLite (PRAGMA writable_schema is not used here, but the DROP/RENAME sequence
        // requires implicit DDL autocommit behavior). Idempotent: both providers check for the constraint's
        // existence before acting.
        await RunOnceAsync(conn, "drop_package_versions_purl_unique", DropPackageVersionsPurlUniqueAsync, transactional: false);

        // Make package_version_licenses.package_version_id nullable and add the dedup UNIQUE for the
        // global (cache_artifact) arm. On fresh installs the CREATE TABLE already has the nullable
        // column, so the check-then-act pattern is a no-op. On upgraded DBs the column is still NOT
        // NULL (the P0 additive migration added cache_artifact_id/owner_kind but could not alter
        // package_version_id's nullability); the SQLite branch recreates the table while the Postgres
        // branch uses ALTER COLUMN ... DROP NOT NULL + CREATE UNIQUE INDEX IF NOT EXISTS.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_pvl_package_version_id_nullable", MakePvlPackageVersionIdNullableAsync, transactional: false);

        // Restructure package_version_vulns: add surrogate id PK, make package_version_id nullable,
        // replace the composite PK with two partial unique indexes. Fresh installs already have the
        // new shape from Schema.sql. Upgraded DBs carry the old composite PK with package_version_id
        // NOT NULL; the SQLite branch recreates the table while the Postgres branch uses ALTER + DDL.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_pvv_package_version_id_nullable", MakePvvPackageVersionIdNullableAsync, transactional: false);

        // Restructure rpm_metadata: add surrogate id TEXT PRIMARY KEY, make package_version_id
        // nullable (removing it from the PK), add per-arm partial unique indexes. Allows
        // cache_artifact-owned rows to exist without a package_versions FK.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_rpm_metadata_pv_nullable", MakeRpmMetadataPvNullableAsync, transactional: false);

        // Restructure maven_version_files: make package_version_id nullable, replace the plain
        // UNIQUE(package_version_id, filename) with two partial unique indexes.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_mvf_pv_nullable", MakeMvfPvNullableAsync, transactional: false);

        // Restructure cargo_metadata: make version_id nullable, replace the plain UNIQUE(version_id)
        // with two partial unique indexes. The INTEGER AUTOINCREMENT PK is preserved.
        // transactional: false on SQLite — DDL does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_cargo_metadata_vid_nullable", MakeCargoMetadataVidNullableAsync, transactional: false);

        // Repair databases where make_rpm_metadata_pv_nullable mis-detected the old shape. That
        // migration keyed off package_version_id's notnull flag, but the old rpm_metadata declared
        // it as a bare "TEXT PRIMARY KEY", which SQLite reports as notnull=0 — so the reshape was
        // skipped and recorded as applied while the surrogate id column was never added, leaving
        // migrate_proxy_versions_to_cache_plane (and rpm_metadata inserts generally) unable to
        // reference rpm_metadata.id. This separately named one-shot re-runs the now pk-aware
        // reshape: it adds id on affected databases and no-ops on healthy ones. Must run before
        // migrate_proxy_versions_to_cache_plane.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "repair_rpm_metadata_surrogate_id", MakeRpmMetadataPvNullableAsync, transactional: false);

        // Repair rows whose origin was defaulted to 'proxy' by the ALTER TABLE ADD COLUMN but whose
        // blob_key starts with 'hosted/'. Hosted artifacts published before the origin column existed
        // received the column default ('proxy') even though their blob_key is 'hosted/…'. This
        // backfill reclassifies exactly those rows to 'uploaded'; genuine proxy rows with cargo/ or
        // go/ prefixes are not touched. The cache-plane migrate and purge steps use the complementary
        // NOT LIKE 'hosted/%' predicate, so both defences are independent and exact complements.
        // xtenant: one-shot cross-tenant backfill; touches only mis-defaulted rows.
        await RunOnceAsync(conn, "backfill_hosted_origin_by_blob_key", BackfillHostedOriginByBlobKeyAsync);

        // Backfill proxy package_versions rows onto the global cache_artifact plane. Per proxy
        // version row: resolve/insert cache_artifact, copy global facts, upsert tenant_artifact_access,
        // copy additive-twin metadata (vulns, licenses, rpm, maven-files, cargo-index).
        // xtenant: cross-tenant backfill migration; the cache_artifact table is global.
        // transactional: false — the batch loop is idempotent via ON CONFLICT DO NOTHING; wrapping
        // the entire backfill in one transaction would hold a write lock for too long on large DBs.
        await RunOnceAsync(conn, "migrate_proxy_versions_to_cache_plane", MigrateProxyVersionsToCachePlaneAsync, transactional: false);

        // Add owner-invariant CHECK to the five polymorphic metadata tables. Fresh installs get it
        // from the CREATE TABLE blocks above; upgraded DBs were recreated by the make_*_nullable
        // migrations but without the invariant. Each migration detects the current shape and
        // recreates (SQLite) or adds the named constraint (Postgres) only when absent.
        // transactional: false — SQLite recreate-table does not compose with an outer transaction.
        await RunOnceAsync(conn, "add_pvv_owner_invariant_check", AddPvvOwnerInvariantCheckAsync, transactional: false);
        await RunOnceAsync(conn, "add_pvl_owner_invariant_check", AddPvlOwnerInvariantCheckAsync, transactional: false);
        await RunOnceAsync(conn, "add_rpm_metadata_owner_invariant_check", AddRpmMetadataOwnerInvariantCheckAsync, transactional: false);
        await RunOnceAsync(conn, "add_mvf_owner_invariant_check", AddMvfOwnerInvariantCheckAsync, transactional: false);
        await RunOnceAsync(conn, "add_cargo_metadata_owner_invariant_check", AddCargoMetadataOwnerInvariantCheckAsync, transactional: false);

        // Delete proxy rows from package_versions that were backfilled to the global plane by
        // migrate_proxy_versions_to_cache_plane. The ON DELETE CASCADE drops only the
        // owner_kind='package_version' metadata rows; the owner_kind='cache_artifact' twins
        // (package_version_id NULL) survive. Idempotent: re-running deletes nothing.
        // xtenant: cross-tenant DELETE scoped to the proxy discriminator column.
        await RunOnceAsync(conn, "delete_migrated_proxy_package_versions", DeleteMigratedProxyPackageVersionsAsync);

        // Add CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')) to vulnerabilities.severity.
        // Fresh installs get this from the CREATE TABLE block in Schema.sql / Schema.pg.sql.
        // Existing databases carry severity TEXT with no constraint (the column was present in the
        // original CREATE TABLE before this migration). NULL values satisfy the CHECK because
        // NULL IN (...) evaluates to NULL (not FALSE) in both SQLite and Postgres.
        // transactional: false on SQLite — PRAGMA writable_schema does not compose with an
        // enclosing transaction. Idempotent: the Postgres branch uses IF NOT EXISTS detection;
        // the SQLite branch is a no-op REPLACE when the CHECK is already present.
        await RunOnceAsync(conn, "add_severity_check_constraint", AddSeverityCheckConstraintAsync, transactional: false);

        // Normalize existing RPM cache_artifact rows whose name was stored in mixed case (e.g.
        // 'perl-AutoLoader' instead of 'perl-autoloader'). The cross-plane join uses
        // ca.name = p.purl_name; packages.purl_name is always lowercased, so mixed-case
        // cache_artifact.name rows never matched and their proxy versions showed a 0 version count.
        // Idempotent: the WHERE name <> lower(name) predicate is a no-op on already-normalized rows.
        await RunOnceAsync(conn, "normalize_rpm_cache_artifact_names", NormalizeRpmCacheArtifactNamesAsync);
        // Backfill version_overwrite_policy from the legacy allow_version_overwrite boolean for
        // orgs that had it set to 1. The tri-state policy supersedes the boolean; the boolean
        // column is kept but dual-written going forward. Idempotent via the applied-migrations ledger.
        // xtenant: one-shot data migration across every tenant on the instance.
        await RunOnceAsync(conn, "migrate_allow_version_overwrite_to_policy", MigrateAllowVersionOverwriteToPolicyAsync);
    }

    // Copies each entry of the legacy org_settings.maven_reserved_prefixes JSON column into a
    // reserved_namespace row (ecosystem 'maven'), the generalized never-proxy pattern table that
    // all ecosystems share. The JSON column stays physically in place for back-compat but is no
    // longer read anywhere. Unparseable JSON is skipped with a warning rather than failing boot.
    // xtenant: one-shot data migration, runs across every tenant on the instance.
    private async Task MigrateMavenReservedPrefixesToTableAsync(DbConnection conn)
    {
        var rows = (await conn.QueryAsync<(string OrgId, string Json)>(
            """
            SELECT org_id AS OrgId, maven_reserved_prefixes AS Json
            FROM org_settings
            WHERE maven_reserved_prefixes IS NOT NULL AND maven_reserved_prefixes != '[]'
            """)).ToList();
        foreach (var (OrgId, Json) in rows)
        {
            List<string> prefixes;
            try
            {
                prefixes = System.Text.Json.JsonSerializer.Deserialize<List<string>>(Json) ?? [];
            }
            catch (System.Text.Json.JsonException)
            {
                _logger.LogWarning(
                    "Skipping unparseable maven_reserved_prefixes JSON for org {OrgId} during " +
                    "migrate_maven_reserved_prefixes_to_table.", OrgId);
                continue;
            }

            foreach (string prefix in prefixes.Where(p => !string.IsNullOrWhiteSpace(p)))
            {
                await conn.ExecuteAsync(
                    """
                    INSERT INTO reserved_namespace (id, org_id, ecosystem, pattern)
                    VALUES (@id, @orgId, 'maven', @pattern)
                    ON CONFLICT DO NOTHING
                    """,
                    new { id = Guid.NewGuid().ToString("N"), orgId = OrgId, pattern = prefix.Trim() });
            }
        }
    }

    // Populate package_versions.filename for rows that pre-date the column. The new
    // download lookup path (FindVersionByBlobKeySuffixAsync) hits an equality index instead
    // of a leading-wildcard LIKE, but it can only do so when filename is set. We derive
    // the value from blob_key's trailing path segment — the same suffix the old query
    // matched on — for backwards-compatible behaviour. xtenant: one-shot, cross-tenant.
    private static async Task BackfillPackageVersionsFilenameAsync(DbConnection conn)
    {
        var rows = (await conn.QueryAsync<(string Id, string BlobKey)>(
            "SELECT id, blob_key FROM package_versions WHERE filename IS NULL"))
            .ToList();
        foreach (var (Id, BlobKey) in rows)
        {
            int lastSlash = BlobKey.LastIndexOf('/');
            string filename = lastSlash >= 0 ? BlobKey[(lastSlash + 1)..] : BlobKey;
            await conn.ExecuteAsync(
                "UPDATE package_versions SET filename = @filename WHERE id = @id",
                new { id = Id, filename });
        }
    }

    // Backfills the package catalogue for OCI/Docker images pulled before they were recorded in
    // packages/package_versions (these were stored only in oci_blobs/oci_tags, so every
    // dashboard counted Docker as zero). One catalogue version per tagged manifest: the digest is
    // the content-addressed version identity, the resolving tag is captured in the PURL. Idempotent
    // — the version insert is skipped on any unique hit (re-run, many-tags-to-one-digest, or the
    // globally-unique purl already held by another org that pulled the same image first).
    private async Task BackfillOciCatalogAsync(DbConnection conn)
    {
        // Schema.sql creates oci_tags/oci_blobs earlier this same boot, so they should always
        // exist here. The query below reads both, so guard both — keeping a partial/corrupt
        // schema from being hosting-fatal. The backfill is best-effort catalogue data, not a
        // structural prerequisite. (A genuinely-absent table still surfaces loudly at the
        // additive ALTER step; this only stops the crash we saw.)
        if (!await TableExistsAsync(conn, "oci_tags") || !await TableExistsAsync(conn, "oci_blobs"))
        {
            _logger.LogWarning(
                "Skipping backfill_oci_catalog: oci_tags/oci_blobs not both present. Schema.sql " +
                "should have created them earlier this boot — this indicates a partial or corrupt schema.");
            return;
        }

        var rows = (await conn.QueryAsync<(string OrgId, string Repository, string Tag, string Digest, long SizeBytes, string BlobKey)>(
            """
            SELECT t.org_id AS OrgId, t.repository AS Repository, t.tag AS Tag, t.digest AS Digest,
                   b.size_bytes AS SizeBytes, b.blob_key AS BlobKey
            FROM oci_tags t
            JOIN oci_blobs b ON b.digest = t.digest AND b.org_id = t.org_id
            """)).ToList();

        foreach (var (OrgId, Repository, Tag, Digest, SizeBytes, BlobKey) in rows)
        {
            // get-or-create the parent package (one per org+repository); single-threaded migration,
            // so SELECT-then-INSERT needs no conflict guard.
            string? pkgId = await conn.ExecuteScalarAsync<string?>(
                "SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = 'oci' AND purl_name = @repo",
                new { orgId = OrgId, repo = Repository });
            if (pkgId is null)
            {
                pkgId = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    """
                    INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
                    VALUES (@id, @orgId, 'oci', @name, @purlName, 1)
                    """,
                    new { id = pkgId, orgId = OrgId, name = Repository, purlName = Repository });
            }

            int lastSlash = BlobKey.LastIndexOf('/');
            string filename = lastSlash >= 0 ? BlobKey[(lastSlash + 1)..] : BlobKey;
            string? sha256Hex = Digest.StartsWith("sha256:", StringComparison.Ordinal)
                ? Digest["sha256:".Length..]
                : null;
            // xtenant: one-shot backfill across every tenant; package_id was just resolved/created
            // for this row's own org (packages.org_id), so the version inherits that org scope.
            await conn.ExecuteAsync(
                """
                INSERT INTO package_versions
                    (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, first_fetch, origin)
                VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, @sizeBytes, @sha256, 1, 'proxy')
                ON CONFLICT DO NOTHING
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    pkgId,
                    version = Digest,
                    purl = PurlNormalizer.Oci(Repository, Digest, Tag),
                    blobKey = BlobKey,
                    filename,
                    sizeBytes = SizeBytes,
                    sha256 = sha256Hex,
                });
        }
    }

    // Backfills the per-org upstream_registry table for installs that predate configurable
    // upstreams. The proxy treats "no configured registry" as "proxying disabled", so an org with
    // no rows for an ecosystem inherits the default URL as a real row rather than losing proxying.
    // For each org that has zero registries for an ecosystem, the default URL (config override or
    // hard-coded public default, RPM only when Rpm:Upstream is set) is inserted. Idempotent via the
    // (org_id, ecosystem, url) unique constraint and the per-ecosystem existence check.
    // xtenant: one-shot backfill across every tenant on the instance.
    private async Task SeedDefaultUpstreamRegistriesAsync(DbConnection conn)
    {
        var defaults = UpstreamRegistrySeeder.ResolveDefaults(_config);
        if (defaults.Count == 0)
        {
            return;
        }

        var orgIds = (await conn.QueryAsync<string>("SELECT id FROM orgs")).ToList();
        int seeded = 0;
        int skipped = 0;
        foreach (string? orgId in orgIds)
        {
            foreach (var (eco, url) in defaults)
            {
                int existing = await conn.ExecuteScalarAsync<int>(
                    "SELECT COUNT(*) FROM upstream_registry WHERE org_id = @orgId AND ecosystem = @eco",
                    new { orgId, eco });
                if (existing > 0) { skipped++; continue; }

                await conn.ExecuteAsync(
                    """
                    INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
                    VALUES (@id, @orgId, @eco, @url, 0)
                    ON CONFLICT (org_id, ecosystem, url) DO NOTHING
                    """,
                    new { id = Guid.NewGuid().ToString("N"), orgId, eco, url });
                seeded++;
            }
        }
        _logger.LogInformation(
            "Backfilled upstream registries: {Seeded} seeded, {Skipped} already-configured across {Orgs} orgs.",
            seeded, skipped, orgIds.Count);
    }

    // Targeted backfill for the golang and cargo upstreams. These two ecosystems were added to the
    // default sources after the original seed_default_upstream_registries backfill already ran, so
    // existing orgs never received their default rows and silently had Go/Cargo proxying disabled.
    // This seeds ONLY golang and cargo — not the full default set — because an operator may have
    // deliberately deleted an upstream row (e.g. removed npm to disable npm proxying) since
    // configurable upstreams shipped; re-running the full backfill would resurrect such a removal.
    // golang and cargo are safe to seed unconditionally: no existing org could have deliberately
    // removed a row it never had. Config overrides (Go:Upstream / Cargo:Upstream) are honoured via
    // ResolveDefaults. Idempotent via the per-(org, ecosystem) existence check and the
    // (org_id, ecosystem, url) unique constraint.
    // xtenant: one-shot backfill across every tenant on the instance.
    private async Task SeedGoCargoUpstreamRegistriesAsync(DbConnection conn)
    {
        var defaults = UpstreamRegistrySeeder.ResolveDefaults(_config)
            .Where(d => d.Ecosystem is "golang" or "cargo")
            .ToList();
        if (defaults.Count == 0)
        {
            return;
        }

        var orgIds = (await conn.QueryAsync<string>("SELECT id FROM orgs")).ToList();
        int seeded = 0;
        int skipped = 0;
        foreach (string? orgId in orgIds)
        {
            foreach (var (eco, url) in defaults)
            {
                int existing = await conn.ExecuteScalarAsync<int>(
                    "SELECT COUNT(*) FROM upstream_registry WHERE org_id = @orgId AND ecosystem = @eco",
                    new { orgId, eco });
                if (existing > 0) { skipped++; continue; }

                await conn.ExecuteAsync(
                    """
                    INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
                    VALUES (@id, @orgId, @eco, @url, 0)
                    ON CONFLICT (org_id, ecosystem, url) DO NOTHING
                    """,
                    new { id = Guid.NewGuid().ToString("N"), orgId, eco, url });
                seeded++;
            }
        }
        _logger.LogInformation(
            "Backfilled Go/Cargo upstream registries: {Seeded} seeded, {Skipped} already-configured across {Orgs} orgs.",
            seeded, skipped, orgIds.Count);
    }

    // Seeds the two default OCI upstream registries (MCR at position 0, Docker Hub at position 1)
    // for every org that has no 'oci' rows in upstream_registry. MCR is first so the dotnet/
    // and playwright prefix paths match before Docker Hub's catch-all "". Idempotent via the
    // per-(org, ecosystem) existence check and the UNIQUE(org_id, ecosystem, url) constraint.
    // xtenant: one-shot backfill across every tenant on the instance.
    private async Task SeedOciUpstreamRegistriesAsync(DbConnection conn)
    {
        var orgIds = (await conn.QueryAsync<string>("SELECT id FROM orgs")).ToList();
        int seeded = 0;
        int skipped = 0;
        foreach (string orgId in orgIds)
        {
            int existing = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'oci'",
                new { orgId });
            if (existing > 0) { skipped++; continue; }

            await UpstreamRegistrySeeder.SeedOciDefaultsForOrgAsync(conn, orgId);
            seeded++;
        }
        _logger.LogInformation(
            "Seeded OCI upstream registries: {Seeded} orgs seeded, {Skipped} already configured.",
            seeded, skipped);
    }

    // Drops the `ecosystem` column from `allowlist` and `blocklist`. The ecosystem is already
    // encoded in every valid PURL (per the PURL spec), so the column was structurally
    // redundant — allowlist entries match against the PURL string directly, and blocklist
    // regexes match against the full PURL. The UNIQUE constraint contracts to (org_id, pattern).
    //
    // Rows that previously differed only by ecosystem collapse on the new UNIQUE; we keep the
    // earliest id/created_at so any audit references to the surviving id remain valid.
    //
    // Behaviour change for blocklist: a loose pattern such as `evil-.*` (no `pkg:` anchor) is
    // no longer scoped to a single ecosystem. Operators relying on the implicit scoping must
    // re-anchor manually (e.g. `^pkg:npm/evil-.*`). Flagged in the release notes.
    private Task DropAllowlistBlocklistEcosystemAsync(DbConnection conn)
    {
        // SQLite's ALTER TABLE DROP COLUMN refuses when the column participates in a UNIQUE
        // index, so for both providers we use the recreate-table pattern. The CREATE TABLE
        // text below intentionally omits the DEFAULT clause for created_at — copied rows
        // carry their original timestamps, and fresh inserts always provide their own value.
        const string sqliteSql = """
            CREATE TABLE allowlist_new (
                id           TEXT PRIMARY KEY,
                org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                purl_pattern TEXT NOT NULL,
                created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                UNIQUE (org_id, purl_pattern)
            );
            INSERT INTO allowlist_new (id, org_id, purl_pattern, created_at)
            SELECT MIN(id), org_id, purl_pattern, MIN(created_at)
            FROM allowlist GROUP BY org_id, purl_pattern;
            DROP TABLE allowlist;
            ALTER TABLE allowlist_new RENAME TO allowlist;

            CREATE TABLE blocklist_new (
                id         TEXT PRIMARY KEY,
                org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                pattern    TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                UNIQUE (org_id, pattern)
            );
            INSERT INTO blocklist_new (id, org_id, pattern, created_at)
            SELECT MIN(id), org_id, pattern, MIN(created_at)
            FROM blocklist GROUP BY org_id, pattern;
            DROP TABLE blocklist;
            ALTER TABLE blocklist_new RENAME TO blocklist;
            """;

        const string pgSql = """
            CREATE TABLE allowlist_new (
                id           TEXT PRIMARY KEY,
                org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                purl_pattern TEXT NOT NULL,
                created_at   TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
                UNIQUE (org_id, purl_pattern)
            );
            INSERT INTO allowlist_new (id, org_id, purl_pattern, created_at)
            SELECT MIN(id), org_id, purl_pattern, MIN(created_at)
            FROM allowlist GROUP BY org_id, purl_pattern;
            DROP TABLE allowlist;
            ALTER TABLE allowlist_new RENAME TO allowlist;

            CREATE TABLE blocklist_new (
                id         TEXT PRIMARY KEY,
                org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                pattern    TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
                UNIQUE (org_id, pattern)
            );
            INSERT INTO blocklist_new (id, org_id, pattern, created_at)
            SELECT MIN(id), org_id, pattern, MIN(created_at)
            FROM blocklist GROUP BY org_id, pattern;
            DROP TABLE blocklist;
            ALTER TABLE blocklist_new RENAME TO blocklist;
            """;

        return conn.ExecuteAsync(_db.Provider == DbProvider.Postgres ? pgSql : sqliteSql);
    }

    // Drops the legacy `scope` column from `user_tokens` and `service_tokens`. Capabilities
    // is the single source of truth; scope was only retained while the cutover was in flight.
    // SQLite (≥3.35) and Postgres both support ALTER TABLE ... DROP COLUMN natively.
    // Conditional on the column being present so the migration is safe on databases
    // already at the target shape (fresh installs, partial-state restores).
    private async Task DropLegacyTokenScopeColumnAsync(DbConnection conn)
    {
        if (await ColumnExistsAsync(conn, "user_tokens", "scope"))
        {
            await conn.ExecuteAsync("ALTER TABLE user_tokens DROP COLUMN scope");
        }

        if (await ColumnExistsAsync(conn, "service_tokens", "scope"))
        {
            await conn.ExecuteAsync("ALTER TABLE service_tokens DROP COLUMN scope");
        }
    }

    // Renames the legacy `tokens` table to `user_tokens` (and its index). Runs before the
    // CREATE TABLE IF NOT EXISTS pass so the schema doesn't spawn an empty sibling. Fresh
    // installs hit the existence guard and no-op; the ledger then prevents re-execution.
    private static async Task RenameTokensTableAsync(DbConnection conn)
    {
        if (!await TableExistsAsync(conn, "tokens"))
        {
            return;
        }

        await conn.ExecuteAsync("ALTER TABLE tokens RENAME TO user_tokens");
        // SQLite carries the old index name along with the renamed table; drop it so the
        // upcoming CREATE INDEX IF NOT EXISTS creates one with the correct new name.
        await conn.ExecuteAsync("DROP INDEX IF EXISTS idx_tokens_hash");
    }

    private static async Task RenameCicdTokensTableAsync(DbConnection conn)
    {
        if (!await TableExistsAsync(conn, "cicd_tokens"))
        {
            return;
        }

        await conn.ExecuteAsync("ALTER TABLE cicd_tokens RENAME TO service_tokens");
        await conn.ExecuteAsync("DROP INDEX IF EXISTS idx_cicd_tokens_hash");
    }

    private static async Task<bool> TableExistsAsync(DbConnection conn, string table)
    {
        // Works on both SQLite and Postgres: information_schema.tables is supported by both
        // (SQLite emulates it as a view since 3.39). For older SQLite we fall back below.
        try
        {
            long count = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM information_schema.tables
                WHERE table_name = @table
                """, new { table });
            return count > 0;
        }
        catch
        {
            // SQLite without information_schema view — query sqlite_master directly.
            long hits = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = @table",
                new { table });
            return hits > 0;
        }
    }

    // Drops `package_versions.sbom`. The "SBOM" stored there was a re-encoding of the
    // coordinate fields already present on the row (name/version/purl wrapped in CycloneDX
    // boilerplate, single-component, no dep graph). The GET endpoint, generator, and
    // write call were all removed; the column is now unreferenced. Real SBOMs — when we
    // build them — will come from manifest parsing on demand, not from this column.
    private async Task DropPackageVersionsSbomColumnAsync(DbConnection conn)
    {
        if (!await ColumnExistsAsync(conn, "package_versions", "sbom"))
        {
            return;
        }

        await conn.ExecuteAsync("ALTER TABLE package_versions DROP COLUMN sbom");
    }

    // Collapses the retired per-tenant disable_vuln_scan / disable_deprecation_refresh flags into
    // the single air_gapped posture, then drops both columns. A tenant that had either job
    // disabled is treated as air-gapped (no outbound). Runs after the additive air_gapped add so
    // the target column always exists; guards each old column independently so the migration is
    // safe on fresh installs (neither column present) and partial-state restores.
    // xtenant: one-shot data migration, runs across every tenant on the instance.
    private async Task DropOrgSettingsDisableJobColumnsAsync(DbConnection conn)
    {
        bool hasVulnScan = await ColumnExistsAsync(conn, "org_settings", "disable_vuln_scan");
        bool hasDeprecation = await ColumnExistsAsync(conn, "org_settings", "disable_deprecation_refresh");

        if (hasVulnScan && hasDeprecation)
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET air_gapped = 1 WHERE disable_vuln_scan = 1 OR disable_deprecation_refresh = 1");
        }
        else if (hasVulnScan)
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET air_gapped = 1 WHERE disable_vuln_scan = 1");
        }
        else if (hasDeprecation)
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET air_gapped = 1 WHERE disable_deprecation_refresh = 1");
        }

        if (hasVulnScan)
        {
            await conn.ExecuteAsync("ALTER TABLE org_settings DROP COLUMN disable_vuln_scan");
        }

        if (hasDeprecation)
        {
            await conn.ExecuteAsync("ALTER TABLE org_settings DROP COLUMN disable_deprecation_refresh");
        }
    }

    private async Task<bool> ColumnExistsAsync(DbConnection conn, string table, string column)
    {
        if (_db.Provider == DbProvider.Postgres)
        {
            long count = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM information_schema.columns
                WHERE table_name = @table AND column_name = @column
                """, new { table, column });
            return count > 0;
        }

        // SQLite: pragma_table_info(...) returns one row per column.
        long hits = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info(@table) WHERE name = @column",
            new { table, column });
        return hits > 0;
    }

    // Collapses the three-state origin enum ('proxy'|'imported'|'private') to two states
    // ('proxy'|'uploaded'). The split between user-published and operator-imported was
    // cosmetic — both are bytes a user pushed. The remaining distinction is upstream-cache
    // versus user-supplied, which is what gates dedup/claim/audit decisions.
    private static Task CollapseOriginToUploadedAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "UPDATE package_versions SET origin = 'uploaded' WHERE origin IN ('imported','private')");

    // Repairs package_versions rows whose origin is 'proxy' (the column default) but whose
    // blob_key starts with 'hosted/'. Hosted artifacts published before the origin column existed
    // received 'proxy' as the DEFAULT backfill even though they are user-supplied; the 'hosted/'
    // prefix is the reliable discriminator. Reclassifying them to 'uploaded' prevents the cache-plane
    // migrate and purge steps from treating them as proxy artifacts.
    // Only rows with blob_key LIKE 'hosted/%' are reclassified; genuine proxy rows with cargo/ or
    // go/ prefixes are left as origin='proxy' so the migrate and purge steps include them.
    // xtenant: one-shot cross-tenant UPDATE; scoped to the mis-defaulted discriminator.
    private static Task BackfillHostedOriginByBlobKeyAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "UPDATE package_versions SET origin = 'uploaded' WHERE origin = 'proxy' AND blob_key LIKE 'hosted/%'");

    // Each DDL statement is a single additive change (column add or index create). SQLite
    // has no native "IF NOT EXISTS" guard for column additions; MigrateSqliteAsync swallows
    // error 1 (duplicate column) instead. Postgres rewrites ADD COLUMN to ADD COLUMN IF NOT EXISTS.
    [SuppressMessage("Major Code Smell", "S138:Functions should not have too many lines of code",
        Justification = "Flat, ordered list of additive ALTER-TABLE migrations; sub-method grouping adds arbitrary boundaries without improving readability.")]
    private static string[] BuildAdditiveMigrations() => new[]
    {
            "ALTER TABLE package_versions ADD COLUMN vuln_checked_at TEXT",
            "ALTER TABLE activity ADD COLUMN detail TEXT",
            "ALTER TABLE activity ADD COLUMN source_ip TEXT",
            "ALTER TABLE org_settings ADD COLUMN license_enforcement_mode TEXT NOT NULL DEFAULT 'off'",
            "ALTER TABLE org_settings ADD COLUMN proxy_passthrough_enabled INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE org_settings ADD COLUMN max_osv_score_tolerance REAL NOT NULL DEFAULT 10.0",
            "ALTER TABLE org_settings ADD COLUMN default_language TEXT NOT NULL DEFAULT 'en'",
            "ALTER TABLE users ADD COLUMN language TEXT",
            "ALTER TABLE system_admins ADD COLUMN language TEXT",
            "ALTER TABLE package_versions ADD COLUMN manual_block_state TEXT",
            "ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'forms' CHECK (account_type IN ('forms','saml'))",
            "ALTER TABLE package_versions ADD COLUMN deprecated TEXT",
            // origin: 'proxy' (default; upstream cache) or 'uploaded' (user-pushed file via
            // protocol push or admin /admin/upload). Existing rows backfill to 'proxy'.
            // Legacy 'imported'/'private' rows are rewritten to 'uploaded' by the
            // collapse_origin_to_uploaded one-shot migration below.
            "ALTER TABLE package_versions ADD COLUMN origin TEXT NOT NULL DEFAULT 'proxy'",
            // Replacement policy: opt-in per-tenant. Default 0 (off) preserves the strict
            // immutable-coordinate behaviour. When 1, the publish service overwrites the row
            // and emits a package.replace audit event recording both old and new hashes.
            "ALTER TABLE org_settings ADD COLUMN allow_version_overwrite INTEGER NOT NULL DEFAULT 0",
            // Capabilities JSON array on tokens. Required for new mints; existing legacy
            // rows pre-dating this column get NULL on backfill and are denied at auth time.
            "ALTER TABLE user_tokens ADD COLUMN capabilities TEXT",
            "ALTER TABLE service_tokens ADD COLUMN capabilities TEXT",
            // Remote IP for tenant- and system-scope audit events (logins, config changes,
            // tenant lifecycle). activity already has its own source_ip; audit_log was the
            // one operator-visible sink without it.
            "ALTER TABLE audit_log ADD COLUMN source_ip TEXT",
            // Schema capacity reserved for a potential future enterprise hierarchy. Dormant
            // in community — no query reads it, no FK enforces it, no model field exposes it.
            // Lives here (rather than only in Schema.sql) so upgraded databases get the column.
            "ALTER TABLE orgs ADD COLUMN parent_tenant_id TEXT",
            "CREATE INDEX IF NOT EXISTS idx_orgs_parent_tenant_id ON orgs(parent_tenant_id)",
            // System-admin CRUD on /api/v1/system/admins requires the same active|locked|disabled
            // triplet that users carry. CHECK constraint applies on fresh installs only — upgraded
            // databases rely on controller validation (mirrors how users.account_status was added).
            "ALTER TABLE system_admins ADD COLUMN account_status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE system_admins ADD COLUMN password_reset_issued_at TEXT",
            // Tenancy bridge-model additions. Status is the resolver gate (suspended/archived
            // tenants are refused at write time); region is dormant capacity for future
            // multi-region routing; features holds per-tenant entitlements as JSON (canonical
            // schema + strict binding live in enterprise). CHECK on status applies on fresh
            // installs only — upgraded databases rely on resolver validation, mirroring how
            // users.account_status was added.
            "ALTER TABLE orgs ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE orgs ADD COLUMN region TEXT",
            "ALTER TABLE orgs ADD COLUMN features TEXT NOT NULL DEFAULT '{}'",
            // Per-tenant aggregate storage quota (multi-tenant noisy-neighbour guard).
            // NULL = unlimited; positive integer = byte cap on the sum of size_bytes across
            // the tenant's package_versions. Checked in PackagePublishService.
            "ALTER TABLE orgs ADD COLUMN storage_quota_bytes INTEGER",
            // Operator-facing label + freshness signal for both token tables. `description`
            // is captured at issuance so operators can identify tokens after the raw value
            // is gone. `last_used_at` is touched on successful auth (throttled ~60s, see
            // TokenRepository.TouchLastUsedAsync) so stale tokens can be spotted before
            // revocation. Both nullable; existing rows backfill to NULL.
            "ALTER TABLE user_tokens ADD COLUMN description TEXT",
            "ALTER TABLE user_tokens ADD COLUMN last_used_at TEXT",
            "ALTER TABLE service_tokens ADD COLUMN description TEXT",
            "ALTER TABLE service_tokens ADD COLUMN last_used_at TEXT",
            // Upstream first-publish timestamp captured on the proxy first-fetch path. ISO 8601
            // UTC; NULL for legacy rows and for origin='uploaded'.
            "ALTER TABLE package_versions ADD COLUMN published_at TEXT",
            // Hex SHA-1 of the artefact bytes. Required for npm's packument dist.shasum (hex
            // SHA-1 by spec). Computed at publish time for npm and captured from upstream
            // packuments on proxy first-fetch. NULL for non-npm and legacy rows.
            "ALTER TABLE package_versions ADD COLUMN checksum_sha1 TEXT",
            // Upstream-published integrity hash captured at proxy first-fetch, stored in
            // upstream's native encoding for direct copy-paste comparison with the public
            // registry's UI. Algorithm tag describes how to interpret the value.
            "ALTER TABLE package_versions ADD COLUMN upstream_integrity_value TEXT",
            "ALTER TABLE package_versions ADD COLUMN upstream_integrity_algorithm TEXT",
            // Minimum upstream-release age (hours) before a proxy-fetched version clears the
            // block gate. NULL = policy off. Lets community detection catch malicious uploads
            // before tenants pull them. Enforced first-fetch in BlockGateService.
            "ALTER TABLE org_settings ADD COLUMN min_release_age_hours INTEGER",
            // Maven per-ecosystem upload cap.
            "ALTER TABLE org_settings ADD COLUMN max_upload_bytes_maven INTEGER",
            // RPM per-ecosystem upload cap.
            "ALTER TABLE org_settings ADD COLUMN max_upload_bytes_rpm INTEGER",
            // OCI (Docker) per-ecosystem upload cap. OCI artefacts are routinely multi-GB
            // (multi-layer ML / CUDA bases); the column is INTEGER so SQLite stores a 64-bit
            // value transparently, and every consumer carries long? end-to-end.
            "ALTER TABLE org_settings ADD COLUMN max_upload_bytes_oci INTEGER",
            // Cargo per-ecosystem upload cap. Cargo gained hosted publish without a per-ecosystem
            // cap (only the org global limit applied); this column gives it parity with every other
            // publishable ecosystem. Falls back to max_upload_bytes when null.
            "ALTER TABLE org_settings ADD COLUMN max_upload_bytes_cargo INTEGER",
            // Trailing path segment of blob_key, populated at insert time so the
            // PyPI/npm/NuGet download lookups can equality-probe an index instead of
            // running a leading-wildcard LIKE. Backfilled by
            // backfill_package_versions_filename for rows that pre-date the column.
            "ALTER TABLE package_versions ADD COLUMN filename TEXT",
            "CREATE INDEX IF NOT EXISTS idx_package_versions_filename ON package_versions(filename)",
            // Discriminator for actor_id: 'user' (users.id) or 'service' (service_tokens.id).
            // NULL on legacy rows + truly-anonymous pulls. Without this, service-token-attributed
            // events were stored with actor_id=NULL (TokenRepository.ResolveAsync sets UserId=null
            // for service tokens) and rendered as "anonymous" in the audit UI, indistinguishable
            // from real anonymous pulls.
            "ALTER TABLE activity ADD COLUMN actor_kind TEXT",
            "ALTER TABLE audit_log ADD COLUMN actor_kind TEXT",
            // Maven reserved-prefix list (JSON array of groupId prefix strings).
            // Coordinates matching these prefixes are NEVER forwarded to upstream — dep confusion
            // protection. Empty array by default (no restrictions). Stored as JSON so per-org
            // lists can grow without schema changes.
            "ALTER TABLE org_settings ADD COLUMN maven_reserved_prefixes TEXT NOT NULL DEFAULT '[]'",
            // OCI origin tracking — 'uploaded' (local push) or 'proxy' (upstream cache).
            // Additive on oci_blobs; existing rows default to 'uploaded' to preserve the
            // existing semantics (all rows before this column were locally stored).
            "ALTER TABLE oci_blobs ADD COLUMN origin TEXT NOT NULL DEFAULT 'uploaded'",
            // Per-tag TTL revalidation timestamp. NULL on existing rows (forces a
            // re-check on first access, which is the correct conservative default).
            "ALTER TABLE oci_tags ADD COLUMN last_revalidated TEXT",
            // Timestamp of the last upstream deprecation metadata refresh for a proxy version.
            // NULL = never checked. Set by DeprecationRefreshService on each pass.
            "ALTER TABLE package_versions ADD COLUMN deprecation_checked_at TEXT",
            // Cumulative served-download counter (every 'download' + 'first_fetch' event:
            // proxy first-fetch, protocol-client pulls, UI downloads). Monotonic and durable,
            // so it survives activity-log pruning and stays an all-time total. Existing rows
            // backfill to 0.
            "ALTER TABLE package_versions ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0",
            // Per-tenant air-gap posture. When 1, the org makes no outbound requests: proxy
            // passthrough is forced off and the vuln/deprecation scan passes skip it. Composes
            // with the instance AIR_GAPPED env var. Backfilled from the retired disable_* flags
            // by drop_org_settings_disable_job_columns below.
            "ALTER TABLE org_settings ADD COLUMN air_gapped INTEGER NOT NULL DEFAULT 0",
            // Policy for upstream-deprecated/abandoned packages at the proxy gate.
            // 'off' (default) = allow through; 'warn' = surface in UI only; 'block_new' = refuse a
            // deprecated version on cache miss (never fetch/cache/serve it) but keep serving
            // already-cached versions; 'block_all' = block_new plus deny already-cached versions.
            // Added without a CHECK (SQLite ALTER can't add one); upgraded DBs rely on controller
            // validation. Fresh installs get the CHECK from Schema.sql, widened on existing DBs by
            // the expand_block_deprecated_check one-shot; legacy 'block' rows are rewritten to
            // 'block_all' by migrate_block_deprecated_to_block_all.
            "ALTER TABLE org_settings ADD COLUMN block_deprecated TEXT NOT NULL DEFAULT 'off'",
            // Persist the full claim set from the latest SAML test run for diagnostics.
            "ALTER TABLE tenant_saml_config ADD COLUMN last_test_claims TEXT",
            // Admin-provided IdP signing cert override for pin-based trust anchoring.
            "ALTER TABLE tenant_saml_config ADD COLUMN idp_signing_cert_override TEXT",
            // IdP role/group claim → Dependably role mapping.
            "ALTER TABLE tenant_saml_config ADD COLUMN role_attribute TEXT",
            "ALTER TABLE tenant_saml_config ADD COLUMN role_mapping TEXT",
            "ALTER TABLE tenant_saml_config ADD COLUMN default_role TEXT NOT NULL DEFAULT 'member'",
            // Full OSV advisory JSON, captured at hydration. Source of truth for the rich
            // vulnerability detail panel; lets us surface fields beyond the extracted columns
            // without re-fetching. NULL on legacy rows — backfilled naturally on the next rescan.
            "ALTER TABLE vulnerabilities ADD COLUMN osv_json TEXT",
            // Upstream's declared latest version (npm dist-tags.latest / PyPI info.version) and the
            // timestamp of the last refresh. Set by DeprecationRefreshService on each pass. NULL =
            // no upstream baseline known (uploaded-only packages, unsupported ecosystems, or not
            // yet refreshed). Drives the packages-list "Latest" indicator.
            "ALTER TABLE packages ADD COLUMN upstream_latest_version TEXT",
            "ALTER TABLE packages ADD COLUMN upstream_latest_checked_at TEXT",
            // Monotonic session-invalidation counter, embedded in tenant JWTs as the `tver`
            // claim and bumped on password change so outstanding sessions go stale. Existing
            // rows backfill to 1, matching the implicit version of pre-existing sessions.
            "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1",
            // Opt-in ceiling raise for SAML IdP-driven role assignment. 0 (default) caps
            // IdP-assignable roles at member/auditor; 1 additionally permits admin. 'owner'
            // is never IdP-assignable regardless of this flag.
            "ALTER TABLE tenant_saml_config ADD COLUMN idp_can_assign_admin INTEGER NOT NULL DEFAULT 0",
            // Policy for versions carrying a malicious-package advisory (OSV MAL- ids, sourced
            // from the OpenSSF malicious-packages feed via the regular OSV scan). Those advisories
            // usually have no CVSS score, so the max_osv_score_tolerance gate never sees them —
            // this gate keys on the advisory id prefix instead. Defaults to 'block' on existing
            // orgs deliberately: a known-malware advisory passing the gate is the security gap
            // the column closes. Added without a CHECK (SQLite ALTER can't add one); upgraded DBs
            // rely on controller validation, fresh installs get the CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN block_malicious TEXT NOT NULL DEFAULT 'block'",
            // Threat-feed enrichment on the shared vulnerabilities table: CISA KEV catalog
            // membership (recomputed each refresh pass so removals clear it) and the max
            // FIRST.org EPSS exploitation probability across the advisory's CVE aliases.
            // NULL *_checked_at = never refreshed.
            "ALTER TABLE vulnerabilities ADD COLUMN is_kev INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE vulnerabilities ADD COLUMN kev_checked_at TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN epss_score REAL",
            "ALTER TABLE vulnerabilities ADD COLUMN epss_checked_at TEXT",
            // KEV/EPSS proxy-gate policies. Both default off so existing orgs see no
            // behaviour change until an operator opts in.
            "ALTER TABLE org_settings ADD COLUMN block_kev TEXT NOT NULL DEFAULT 'off'",
            "ALTER TABLE org_settings ADD COLUMN max_epss_tolerance REAL",
            // Atomic storage-usage counter for the publish quota check. Replaces the live
            // SUM aggregate that was subject to a TOCTOU race under concurrent publishes.
            // New rows default to 0 (back-compat); the publish path backfills from
            // SUM(package_versions.size_bytes) on first access when the counter is 0 and
            // the real sum is positive.
            "ALTER TABLE org_settings ADD COLUMN storage_used_bytes INTEGER NOT NULL DEFAULT 0",
            // Tracks the stage of the most recently emitted SAML IdP cert-expiry audit event
            // ('30','14','7','1','expired'). NULL = no alert emitted (or cert replaced). Reset
            // to NULL by the cert-upload/clear paths so the sweep re-evaluates on the new cert.
            "ALTER TABLE tenant_saml_config ADD COLUMN cert_expiry_alert_stage TEXT",
            // Install/lifecycle-script supply-chain signal on package_versions. 1 when the
            // artefact ships a script that runs automatically on install; the kind column
            // records which (npm:postinstall, pypi:setup.py, nuget:install.ps1, …). Captured
            // at proxy first-fetch and hosted publish. Existing rows backfill to 0/NULL and are
            // re-evaluated naturally on the next fetch/republish.
            "ALTER TABLE package_versions ADD COLUMN has_install_script INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE package_versions ADD COLUMN install_script_kind TEXT",
            // Per-tenant install-script proxy gate: 'off' (default) / 'warn' / 'block'. Opt-in,
            // so existing orgs see no behaviour change until an operator enables it. Added
            // without a CHECK (SQLite ALTER can't add one); upgraded DBs rely on controller
            // validation, fresh installs get the CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN block_install_scripts TEXT NOT NULL DEFAULT 'off'",
            // Provenance/signature-verification outcome on package_versions: 'verified' / 'failed'
            // / 'unsigned', or NULL when not applicable. Captured at proxy first-fetch when the
            // tenant verify policy is on. Existing rows stay NULL and are re-evaluated on the next
            // fetch. provenance_signer holds the verifying trust-anchor keyid for 'verified' rows.
            "ALTER TABLE package_versions ADD COLUMN provenance_status TEXT",
            "ALTER TABLE package_versions ADD COLUMN provenance_signer TEXT",
            // Per-tenant npm signature-verification gate: 'off' (default) / 'warn' / 'block'.
            // Opt-in; existing orgs see no behaviour change until an operator enables it and pins
            // Npm:SignatureKeys. Added without a CHECK (SQLite ALTER can't add one); upgraded DBs
            // rely on controller validation, fresh installs get the CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN verify_npm_signatures TEXT NOT NULL DEFAULT 'off'",
            // Per-tenant NuGet signature-verification gate: 'off' (default) / 'warn' / 'block'.
            // Opt-in; existing orgs see no behaviour change until an operator enables it and pins
            // NuGet:SignatureCertificates. Added without a CHECK (SQLite ALTER can't add one);
            // upgraded DBs rely on controller validation, fresh installs get the CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN verify_nuget_signatures TEXT NOT NULL DEFAULT 'off'",
            // Per-tenant PyPI PEP 740 attestation-verification gate: 'off' (default) / 'warn' /
            // 'block'. Opt-in; existing orgs see no behaviour change until an operator enables it and
            // pins PyPI:SigstoreRoots + PyPI:TrustedPublishers. Added without a CHECK (SQLite ALTER
            // can't add one); upgraded DBs rely on controller validation, fresh installs get the
            // CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN verify_pypi_attestations TEXT NOT NULL DEFAULT 'off'",
            // Per-tenant RPM per-package GPG header signature-verification gate: 'off' (default) /
            // 'warn' / 'block'. Enabling requires operator-pinned Rpm:GpgKey; without it the verifier
            // reports not-applicable and nothing blocks. Added without a CHECK (SQLite ALTER can't add
            // one); upgraded DBs rely on controller validation, fresh installs get the CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN verify_rpm_signatures TEXT NOT NULL DEFAULT 'off'",
            // Per-tenant Maven detached .asc OpenPGP signature-verification gate: 'off' (default) /
            // 'warn' / 'block'. Enabling requires operator-pinned Maven:SignatureKeys; without them the
            // verifier reports not-applicable and nothing blocks. Added without a CHECK (SQLite ALTER
            // can't add one); upgraded DBs rely on controller validation, fresh installs get the CHECK.
            "ALTER TABLE org_settings ADD COLUMN verify_maven_signatures TEXT NOT NULL DEFAULT 'off'",
            // Global proxy-cache artifact enrichment. These columns extend cache_artifact with the
            // same supply-chain signals package_versions already carries so ingest can populate them
            // before a package_versions row exists. All are nullable/defaulted; existing rows stay
            // NULL and are re-evaluated naturally on the next proxy fetch. Written at ingest but not
            // yet read by any query in community (reserved capacity — see community/enterprise boundary rule).
            "ALTER TABLE cache_artifact ADD COLUMN purl TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN checksum_sha1 TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN published_at TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN deprecated TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN deprecation_checked_at TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN has_install_script INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE cache_artifact ADD COLUMN install_script_kind TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN provenance_status TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN provenance_signer TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN upstream_integrity_value TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN upstream_integrity_algorithm TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN vuln_checked_at TEXT",
            "CREATE INDEX IF NOT EXISTS idx_cache_artifact_purl ON cache_artifact (purl)",
            // Per-tenant policy state on cache_artifact rows (before a package_versions row exists).
            // Mirrors the same columns on package_versions; all nullable/defaulted.
            "ALTER TABLE tenant_artifact_access ADD COLUMN manual_block_state TEXT",
            "ALTER TABLE tenant_artifact_access ADD COLUMN yanked INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE tenant_artifact_access ADD COLUMN yank_reason TEXT",
            "ALTER TABLE tenant_artifact_access ADD COLUMN last_used TEXT",
            "ALTER TABLE tenant_artifact_access ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0",
            // Polymorphic metadata ownership: lets vulns, licenses, rpm, maven-files, and cargo-index
            // rows attach to a cache_artifact instead of a package_versions row. owner_kind added
            // without a CHECK (SQLite ALTER can't add one); upgraded DBs rely on app-side validation;
            // fresh installs get the CHECK from the CREATE TABLE block in Schema.sql / Schema.pg.sql.
            // FK index on cache_artifact_id so parent deletes (cache_artifact eviction) don't full-scan.
            "ALTER TABLE package_version_vulns ADD COLUMN cache_artifact_id TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE",
            "ALTER TABLE package_version_vulns ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'package_version'",
            "CREATE INDEX IF NOT EXISTS idx_package_version_vulns_cache_artifact ON package_version_vulns (cache_artifact_id)",
            "ALTER TABLE package_version_licenses ADD COLUMN cache_artifact_id TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE",
            "ALTER TABLE package_version_licenses ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'package_version'",
            "CREATE INDEX IF NOT EXISTS idx_package_version_licenses_cache_artifact ON package_version_licenses (cache_artifact_id)",
            "ALTER TABLE rpm_metadata ADD COLUMN cache_artifact_id TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE",
            "ALTER TABLE rpm_metadata ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'package_version'",
            "CREATE INDEX IF NOT EXISTS idx_rpm_metadata_cache_artifact ON rpm_metadata (cache_artifact_id)",
            "ALTER TABLE maven_version_files ADD COLUMN cache_artifact_id TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE",
            "ALTER TABLE maven_version_files ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'package_version'",
            "CREATE INDEX IF NOT EXISTS idx_maven_version_files_cache_artifact ON maven_version_files (cache_artifact_id)",
            "ALTER TABLE cargo_metadata ADD COLUMN cache_artifact_id TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE",
            "ALTER TABLE cargo_metadata ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'package_version'",
            "CREATE INDEX IF NOT EXISTS idx_cargo_metadata_cache_artifact ON cargo_metadata (cache_artifact_id)",
            // OCI upstream columns: operator-pinned token-exchange realm URL and repository-prefix
            // routing list (JSON TEXT array). Both are OCI-only; all other ecosystems leave them NULL.
            "ALTER TABLE upstream_registry ADD COLUMN token_endpoint TEXT",
            "ALTER TABLE upstream_registry ADD COLUMN prefixes TEXT",
            // Tri-state same-version-push org policy. 'block' (default) = always reject duplicates;
            // 'exception' = blocked by default but per-package grant allowed;
            // 'allow' = allowed by default but per-package block allowed.
            // Added without a CHECK (SQLite ALTER can't add one); upgraded DBs rely on controller
            // validation; fresh installs get the CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN version_overwrite_policy TEXT NOT NULL DEFAULT 'block'",
            // Per-package same-version-push override. NULL = inherit org policy. 'allow' or 'block'.
            // Added without a CHECK for the same SQLite ALTER reason as above.
            "ALTER TABLE packages ADD COLUMN same_version_push_override TEXT",
    };

    private async Task RunAdditiveMigrationsAsync(DbConnection conn)
    {
        foreach (string? ddl in BuildAdditiveMigrations())
        {
            if (_db.Provider == DbProvider.Sqlite)
            {
                await MigrateSqliteAsync(conn, ddl);
            }
            else
            {
                await conn.ExecuteAsync(ddl.Replace("ADD COLUMN ", "ADD COLUMN IF NOT EXISTS "));
            }
        }

        // Cargo sparse registry index metadata. CREATE TABLE syntax is provider-specific
        // (SQLite uses AUTOINCREMENT; Postgres uses BIGSERIAL), so this migration runs
        // outside the shared loop with explicit branching.
        const string cargoSqlite =
            "CREATE TABLE IF NOT EXISTS cargo_metadata " +
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, version_id TEXT NOT NULL " +
            "REFERENCES package_versions(id) ON DELETE CASCADE, index_line TEXT NOT NULL, UNIQUE(version_id))";
        const string cargoPg =
            "CREATE TABLE IF NOT EXISTS cargo_metadata " +
            "(id BIGSERIAL PRIMARY KEY, version_id TEXT NOT NULL " +
            "REFERENCES package_versions(id) ON DELETE CASCADE, index_line TEXT NOT NULL, UNIQUE(version_id))";
        if (_db.Provider == DbProvider.Sqlite)
        {
            await MigrateSqliteAsync(conn, cargoSqlite);
        }
        else
        {
            await conn.ExecuteAsync(cargoPg);
        }
        await conn.ExecuteAsync("CREATE INDEX IF NOT EXISTS idx_cargo_metadata_version ON cargo_metadata(version_id)");
    }

    // Drops the redundant index on package_version_vulns(package_version_id). That column is
    // the leftmost component of the table's PRIMARY KEY (package_version_id, vuln_id), so the
    // index never provides any query benefit. DROP INDEX IF EXISTS is idempotent on both SQLite
    // and Postgres, so no existence guard is needed beyond the RunOnceAsync ledger.
    private static async Task DropRedundantPkgVersionVulnsVersionIndexAsync(DbConnection conn)
    {
        await conn.ExecuteAsync("DROP INDEX IF EXISTS idx_pkg_version_vulns_version");
    }

    // Normalizes RPM cache_artifact.name to lowercase. Proxy RPMs were historically stored with the
    // raw NEVRA name (e.g. 'perl-AutoLoader') while packages.purl_name was already lowercased. The
    // cross-plane join uses ca.name = p.purl_name, so mixed-case rows never matched and their proxy
    // versions reported a 0 version count. lower() is the same function on both SQLite and Postgres.
    // Idempotent: rows already in lowercase satisfy name <> lower(name) = false and are not touched.
    // xtenant: cache_artifact is the global plane (no tenant column); the WHERE clause keys only on
    // ecosystem and the case-mismatch predicate, leaving rows from other ecosystems unchanged.
    private static async Task NormalizeRpmCacheArtifactNamesAsync(DbConnection conn)
    {
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET name = lower(name) WHERE ecosystem = 'rpm' AND name <> lower(name)");
    }

    // Promotes the legacy allow_version_overwrite boolean to the tri-state version_overwrite_policy
    // column. Org rows where allow_version_overwrite = 1 are set to 'allow'; all others stay at the
    // column default 'block'. The boolean column is retained for blue-green safety and dual-written
    // by UpsertSettingsAsync going forward.
    // xtenant: one-shot data migration, runs across every tenant on the instance.
    private static async Task MigrateAllowVersionOverwriteToPolicyAsync(DbConnection conn)
    {
        await conn.ExecuteAsync(
            "UPDATE org_settings SET version_overwrite_policy = 'allow' WHERE allow_version_overwrite = 1");
    }

    private async Task EnsureMigrationsTableAsync(DbConnection conn)
    {
        // Tracks one-time data migrations so they only run once per database. The applied_at
        // default is provider-specific: SQLite has strftime, Postgres does not — emitting strftime
        // to Postgres fails CREATE TABLE outright, and since this is the FIRST DDL on startup it
        // would abort a fresh Postgres boot. Mirror the to_char pattern used by Schema.pg.sql.
        const string sqliteSql = """
            CREATE TABLE IF NOT EXISTS _applied_migrations (
                name TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            )
            """;
        const string pgSql = """
            CREATE TABLE IF NOT EXISTS _applied_migrations (
                name TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
            )
            """;
        await conn.ExecuteAsync(_db.Provider == DbProvider.Postgres ? pgSql : sqliteSql);
    }

    // Runs a one-time migration exactly once per database, recording it in the _applied_migrations
    // ledger. By default the migration body AND its ledger insert run inside a single transaction —
    // SQLite and Postgres both support transactional DDL — so a process killed mid-migration rolls
    // back cleanly: no half-applied state, no orphan rebuild tables (e.g. allowlist_new), and the
    // ledger can never record a migration that didn't fully commit. A failed retry therefore always
    // starts from a clean slate instead of wedging on a leftover artefact.
    //
    // Migrations that manage their own transaction semantics opt out with transactional: false —
    // currently only the SQLite CHECK rewrite, which drives PRAGMA writable_schema + a
    // schema_version bump that don't compose with an enclosing transaction. Such migrations MUST be
    // idempotent so an un-recorded partial run is safely repeated on the next boot.
    // internal (not private) so SchemaInitializerTests can drive the rollback path directly.
    internal async Task RunOnceAsync(DbConnection conn, string name, Func<DbConnection, Task> action, bool transactional = true)
    {
        int already = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = @name", new { name });
        if (already > 0)
        {
            _logger.LogDebug("Schema migration {Migration} already applied; skipping.", name);
            return;
        }
        _logger.LogInformation("Schema migration {Migration} applying…", name);
        if (transactional)
        {
            await RunInTransactionAsync(conn, name, action);
        }
        else
        {
            await RunUnwrappedAsync(conn, name, action);
        }

        _logger.LogInformation("Schema migration {Migration} applied.", name);
    }

    // Raw BEGIN/COMMIT (not DbTransaction) so the existing action delegates — which call
    // conn.ExecuteAsync without a transaction parameter — participate in the transaction. A
    // SqliteTransaction object would instead make Microsoft.Data.Sqlite reject those un-enlisted
    // commands as "pending transaction".
    private static async Task RunInTransactionAsync(DbConnection conn, string name, Func<DbConnection, Task> action)
    {
        await ExecRawAsync(conn, "BEGIN");
        try
        {
            await action(conn);
            await conn.ExecuteAsync("INSERT INTO _applied_migrations (name) VALUES (@name)", new { name });
            await ExecRawAsync(conn, "COMMIT");
        }
        catch
        {
            // Roll the partial migration back so a retry starts clean. Swallow only the rollback's
            // own failure (e.g. no transaction is open) so the original exception still propagates.
            try { await ExecRawAsync(conn, "ROLLBACK"); }
            catch (DbException) { /* nothing to roll back */ }
            throw;
        }
    }

    private static async Task RunUnwrappedAsync(DbConnection conn, string name, Func<DbConnection, Task> action)
    {
        await action(conn);
        await conn.ExecuteAsync("INSERT INTO _applied_migrations (name) VALUES (@name)", new { name });
    }

    // Disables FK enforcement for the duration of action, then re-enables it regardless of
    // outcome. Required for SQLite recreate-table reshapes: rows copied from the old table may
    // have stale FK references (e.g. proxy package_version rows deleted by a prior migration
    // while FK enforcement was off). SQLite does not retroactively validate existing rows when
    // FK enforcement is re-enabled, so orphaned rows survive the reshape intact.
    // Must only be called on the transactional: false (RunUnwrappedAsync) path — SQLite rejects
    // PRAGMA foreign_keys inside an open transaction.
    private static async Task WithForeignKeysOffAsync(DbConnection conn, Func<Task> action)
    {
        await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
        try
        {
            await action();
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA foreign_keys = ON");
        }
    }

    // Transaction-control statements go through raw ADO.NET, not Dapper: Dapper infers
    // CommandType.StoredProcedure for a single-word command ("BEGIN"/"COMMIT"/"ROLLBACK"), which
    // Microsoft.Data.Sqlite rejects. A raw command keeps the default CommandType.Text on both providers.
    private static async Task ExecRawAsync(DbConnection conn, string sql)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }

    // Clear vuln_checked_at for NuGet proxy packages so the scan service re-queries OSV
    // with the corrected PURLs after the purl_name migration.
    // xtenant: one-shot data migration, runs across every tenant on the instance.
    private static Task ResetNuGetVulnCheckedAtAsync(DbConnection conn) =>
        conn.ExecuteAsync("""
            UPDATE package_versions SET vuln_checked_at = NULL
            WHERE id IN (
                SELECT pv.id FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.ecosystem = 'nuget'
            )
            """);

    // Fix npm proxy packages where purl_name/name were stored with URL-encoded characters
    // (%2F, %40) instead of their decoded equivalents (old GetTarball passed raw route values).
    private static async Task FixNpmPurlEncodingAsync(DbConnection conn)
    {
        var npmRows = (await conn.QueryAsync(
            "SELECT id, name, purl_name FROM packages WHERE ecosystem = 'npm'")).ToList();
        foreach (var row in npmRows)
        {
            string name = (string)row.name;
            string purlName = (string)row.purl_name;
            if (!name.Contains("%40", StringComparison.OrdinalIgnoreCase) &&
                !name.Contains("%2F", StringComparison.OrdinalIgnoreCase) &&
                !purlName.Contains("%2F", StringComparison.OrdinalIgnoreCase) &&
                !purlName.StartsWith('@'))
            {
                continue;
            }

            string fixedName = name
                .Replace("%40", "@", StringComparison.OrdinalIgnoreCase)
                .Replace("%2F", "/", StringComparison.OrdinalIgnoreCase);
            string fixedPurlName = fixedName.StartsWith('@')
                ? "%40" + fixedName[1..]
                : purlName.Replace("%2F", "/", StringComparison.OrdinalIgnoreCase);
            await conn.ExecuteAsync(
                "UPDATE packages SET name = @n, purl_name = @p WHERE id = @id",
                new { n = fixedName, p = fixedPurlName, id = (string)row.id });
        }
        var versionRows = (await conn.QueryAsync(
            "SELECT pv.id, pv.purl FROM package_versions pv " +
            "JOIN packages p ON p.id = pv.package_id WHERE p.ecosystem = 'npm'")).ToList();
        foreach (var row in versionRows)
        {
            string purl = (string)row.purl;
            if (!purl.Contains("%2F", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            await conn.ExecuteAsync(
                "UPDATE package_versions SET purl = @p WHERE id = @id",
                new { p = purl.Replace("%2F", "/", StringComparison.OrdinalIgnoreCase), id = (string)row.id });
        }
    }

    // purl_name for npm scoped packages should be the plain name (@scope/pkg), not the
    // PURL-encoded form (%40scope/pkg). The prior migration over-encoded it.
    private static Task FixNpmPurlNameUnencodedAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "UPDATE packages SET purl_name = '@' || substr(purl_name, 4) " +
            "WHERE ecosystem = 'npm' AND substr(purl_name, 1, 3) = '%40'");

    // Fix stored npm PURLs that used %40 for @ in scoped package names.
    private static Task FixNpmVersionPurlAtEncodingAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "UPDATE package_versions SET purl = replace(purl, 'pkg:npm/%40', 'pkg:npm/@') " +
            "WHERE purl LIKE 'pkg:npm/%40%'");

    // Fix any npm PURLs still containing %2F (encoded /) in the package name.
    private static async Task FixNpmVersionPurlSlashEncodingAsync(DbConnection conn)
    {
        await conn.ExecuteAsync(
            "UPDATE package_versions SET purl = replace(replace(purl, '%2F', '/'), '%2f', '/') " +
            "WHERE purl LIKE 'pkg:npm/%' AND (purl LIKE '%2F%' OR purl LIKE '%2f%')");
        await conn.ExecuteAsync(
            "DELETE FROM package_versions WHERE version = 'unknown'");
    }

    // Fix npm PURLs in activity log that were stored with %40/%2F encoding.
    private static Task FixNpmActivityPurlEncodingAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "UPDATE activity SET purl = replace(replace(replace(purl, '%40', '@'), '%2F', '/'), '%2f', '/') " +
            "WHERE purl LIKE 'pkg:npm/%' AND (purl LIKE '%40%' OR purl LIKE '%2f%' OR purl LIKE '%2F%')");

    // Fix NuGet proxy packages that stored versioned PURL as purl_name instead of the plain name.
    // Idempotent: the first DELETE only fires when a duplicate-correct row exists; the rename
    // is idempotent because a successful run leaves no rows matching `purl_name LIKE 'pkg:%'`.
    private static async Task FixNuGetProxyPurlNamesAsync(DbConnection conn)
    {
        // Step 1: drop broken rows where a correct row (purl_name = name) already exists.
        await conn.ExecuteAsync(@"
            DELETE FROM packages
            WHERE ecosystem = 'nuget' AND is_proxy = 1 AND purl_name LIKE 'pkg:%'
              AND EXISTS (
                SELECT 1 FROM packages p2
                WHERE p2.org_id = packages.org_id
                  AND p2.ecosystem = 'nuget'
                  AND p2.purl_name = packages.name
              )");
        // Step 2: among remaining broken rows, keep only the oldest per (org_id, name).
        await conn.ExecuteAsync(@"
            DELETE FROM packages
            WHERE ecosystem = 'nuget' AND is_proxy = 1 AND purl_name LIKE 'pkg:%'
              AND id NOT IN (
                SELECT MIN(id) FROM packages
                WHERE ecosystem = 'nuget' AND is_proxy = 1 AND purl_name LIKE 'pkg:%'
                GROUP BY org_id, name
              )");
        // Step 3: rename the surviving broken rows.
        await conn.ExecuteAsync(
            "UPDATE packages SET purl_name = name WHERE ecosystem = 'nuget' AND is_proxy = 1 AND purl_name LIKE 'pkg:%'");
    }

    // Extend the users.role + invites.role CHECK constraint to include 'auditor'.
    // New databases pick this up from the CREATE TABLE statements in Schema.sql /
    // Schema.pg.sql; this migration brings existing databases in line.
    //
    // Postgres: drop + re-add the auto-named CHECK constraint. Postgres names CHECK
    // constraints as <table>_<column>_check by default.
    //
    // SQLite: there's no ALTER for CHECK, but the canonical writable_schema pattern lets
    // us rewrite the stored CREATE TABLE text in place. We do a literal-substring replace
    // — the CREATE TABLE text in sqlite_schema is whatever was emitted by Schema.sql, so
    // the substring match is exact. Wrapping in writable_schema=ON/OFF with an
    // integrity_check is the documented SQLite recipe.
    private Task ExpandRoleCheckWithAuditorAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE users   DROP CONSTRAINT IF EXISTS users_role_check;
                ALTER TABLE users   ADD  CONSTRAINT users_role_check
                    CHECK (role IN ('member','admin','owner','auditor'));
                ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_role_check;
                ALTER TABLE invites ADD  CONSTRAINT invites_role_check
                    CHECK (role IN ('member','admin','owner','auditor'));
                """)
            : ExpandRoleCheckSqliteAsync(conn);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task ExpandRoleCheckSqliteAsync(DbConnection conn)
    {
        const string oldCheck = "CHECK (role IN ('member','admin','owner'))";
        const string newCheck = "CHECK (role IN ('member','admin','owner','auditor'))";

        // Bumping schema_version forces SQLite to reload the schema on the next read; without
        // this, in-memory schema caches on existing connections continue to enforce the old
        // CHECK and downstream INSERTs fail. PRAGMA writable_schema = RESET disables the
        // writable mode AND forces a schema reload; we use both belt + suspenders.
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name IN ('users','invites')
                """, new { old = oldCheck, @new = newCheck });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            // SQLite doesn't permit parameter binding in PRAGMA values — they must be
            // literal tokens. `version` comes from PRAGMA schema_version itself (a long
            // we just read back), so concatenation is safe; no user input flows here.
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
        // Cheap sanity check — fails the migration if the rewrite produced malformed SQL.
        // The SchemaInitializer caller surfaces the exception and aborts startup.
        await conn.ExecuteAsync("PRAGMA integrity_check");
    }

    // Widen the org_settings.block_deprecated CHECK from the legacy 3-value set
    // ('off','warn','block') to the 4-value set ('off','warn','block_new','block_all'). Same
    // shape as ExpandRoleCheckWithAuditorAsync: new databases pick this up from Schema.sql /
    // Schema.pg.sql; this brings existing databases in line.
    //
    // Postgres: drop + re-add the auto-named CHECK constraint. IF EXISTS covers upgraded DBs
    // that added the column via ALTER (no constraint) as well as fresh installs (constraint
    // present, named org_settings_block_deprecated_check by default).
    //
    // SQLite: rewrite the stored CREATE TABLE text in place via the writable_schema pattern.
    // The substring REPLACE is a no-op on upgraded DBs whose org_settings has no CHECK clause
    // (the column was added via plain ALTER ADD COLUMN), so it only rewrites DBs that carry the
    // old constraint from a fresh CREATE TABLE.
    private Task ExpandBlockDeprecatedCheckAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_block_deprecated_check;
                ALTER TABLE org_settings ADD  CONSTRAINT org_settings_block_deprecated_check
                    CHECK (block_deprecated IN ('off', 'warn', 'block_new', 'block_all'));
                """)
            : ExpandBlockDeprecatedCheckSqliteAsync(conn);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task ExpandBlockDeprecatedCheckSqliteAsync(DbConnection conn)
    {
        const string oldCheck = "CHECK (block_deprecated IN ('off', 'warn', 'block'))";
        const string newCheck = "CHECK (block_deprecated IN ('off', 'warn', 'block_new', 'block_all'))";

        // Bumping schema_version forces SQLite to reload the schema on the next read so existing
        // connections stop enforcing the old CHECK; writable_schema = RESET both disables write
        // mode and forces the reload. See ExpandRoleCheckSqliteAsync for the full rationale.
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name = 'org_settings'
                """, new { old = oldCheck, @new = newCheck });
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

    // Rewrite legacy 'block' policy rows to 'block_all'. The old single 'block' value denied
    // every request for a deprecated version — both new fetches and already-cached artifacts —
    // which is exactly the new 'block_all' semantics, so observable behaviour is unchanged.
    // Runs after the CHECK widen so 'block_all' is a permitted value.
    // xtenant: one-shot data migration, runs across every tenant on the instance.
    private static Task MigrateBlockDeprecatedToBlockAllAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "UPDATE org_settings SET block_deprecated = 'block_all' WHERE block_deprecated = 'block'");

    // Backfill account_type for users JIT-provisioned via SAML before the column existed.
    // Signal: empty password_hash AND a row in external_identities. Forms users later linked
    // to SAML retain their password and stay 'forms'.
    // xtenant: one-shot data migration, runs across every tenant on the instance.
    private static Task BackfillUsersAccountTypeSamlAsync(DbConnection conn) =>
        conn.ExecuteAsync("""
            UPDATE users SET account_type = 'saml'
            WHERE password_hash = ''
              AND id IN (SELECT user_id FROM external_identities)
            """);

}
