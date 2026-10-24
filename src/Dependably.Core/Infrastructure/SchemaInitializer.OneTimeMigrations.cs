using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

public sealed partial class SchemaInitializer
{
    // Phase 2 — the ledgered one-time migrations, in the order the comments below justify. The
    // sequence is load-bearing: several entries state explicitly why they must follow the one
    // above them, so entries are appended, never reordered. An entry passes dropsViews: true only
    // when its body changes a table or column shape (see RunOnceAsync); a new entry that reshapes a
    // table must declare it, and one that only rewrites rows must not.
    private async Task ApplyOneTimeMigrationsAsync(DbConnection conn)
    {
        await RunUnledgeredRepairsAsync(conn);

        await RunOnceAsync(conn, "reset_nuget_vuln_checked_at", ResetNuGetVulnCheckedAtAsync);
        await RunOnceAsync(conn, "fix_npm_purl_encoding", FixNpmPurlEncodingAsync);
        await RunOnceAsync(conn, "fix_npm_purl_name_unencoded", FixNpmPurlNameUnencodedAsync);
        await RunOnceAsync(conn, "fix_npm_version_purl_at_encoding", FixNpmVersionPurlAtEncodingAsync);
        await RunOnceAsync(conn, "fix_npm_version_purl_slash_encoding", FixNpmVersionPurlSlashEncodingAsync);
        await RunOnceAsync(conn, "fix_npm_activity_purl_encoding", FixNpmActivityPurlEncodingAsync);
        await RunOnceAsync(conn, "fix_nuget_proxy_purl_names", FixNuGetProxyPurlNamesAsync);
        await RunOnceAsync(conn, "lowercase_nuget_hosted_versions", LowercaseNuGetHostedVersionsAsync);
        await RunOnceAsync(conn, "backfill_users_account_type_saml", BackfillUsersAccountTypeSamlAsync);
        // transactional: false — ExpandRoleCheckSqliteAsync drives PRAGMA writable_schema + a
        // schema_version bump that don't compose with an enclosing transaction. Safe because the
        // migration is idempotent (PG drops-then-adds the constraint; SQLite REPLACEs the stored
        // CREATE text), so an un-recorded partial run is harmlessly repeated next boot.
        await RunOnceAsync(conn, "expand_role_check_with_auditor", ExpandRoleCheckWithAuditorAsync, transactional: false);
        await RunOnceAsync(conn, "convert_legacy_timestamptz_columns", ConvertLegacyTimestamptzColumnsAsync, dropsViews: true);
        await RunOnceAsync(conn, "collapse_origin_to_uploaded", CollapseOriginToUploadedAsync);
        await RunOnceAsync(conn, "drop_legacy_token_scope_column", DropLegacyTokenScopeColumnAsync, dropsViews: true);
        // Ordered after RunAdditiveMigrationsAsync so `capabilities` exists on the databases
        // predating it — exactly the databases holding the rows this deletes.
        await RunOnceAsync(conn, "purge_legacy_null_capability_tokens", PurgeLegacyNullCapabilityTokensAsync);
        await RunOnceAsync(conn, "drop_package_versions_sbom_column", DropPackageVersionsSbomColumnAsync, dropsViews: true);
        await RunOnceAsync(conn, "drop_org_settings_disable_job_columns", DropOrgSettingsDisableJobColumnsAsync, dropsViews: true);
        await RunOnceAsync(conn, "drop_allowlist_blocklist_ecosystem", DropAllowlistBlocklistEcosystemAsync, dropsViews: true);
        await RunOnceAsync(conn, "backfill_package_versions_filename", BackfillPackageVersionsFilenameAsync);
        await RunOnceAsync(conn, "backfill_oci_catalog", BackfillOciCatalogAsync);
        await RunOnceAsync(conn, "seed_default_upstream_registries", SeedDefaultUpstreamRegistriesAsync);
        await RunOnceAsync(conn, "seed_go_cargo_upstream_registries", SeedGoCargoUpstreamRegistriesAsync);
        // Targeted backfill for the apk upstream, on the same footing as the Go/Cargo backfill
        // above: apk was added to the default sources after seed_default_upstream_registries
        // already ran for existing orgs, so it needs its own one-shot pass.
        await RunOnceAsync(conn, "seed_apk_upstream_registries", SeedApkUpstreamRegistriesAsync);
        // Same footing again for Terraform. Its absence is harsher than a missing fallback: the
        // mirror matches a requested provider's registry hostname against the org's configured
        // upstreams, so an org with no 'terraform' row mirrors no provider at all.
        await RunOnceAsync(conn, "seed_terraform_upstream_registries", SeedTerraformUpstreamRegistriesAsync);
        // Same footing for Hex: the repo.hex.pm row carries the public key the re-signing proxy
        // verifies upstream resources against, so an org without it proxies no Hex package.
        await RunOnceAsync(conn, "seed_hex_upstream_registries", SeedHexUpstreamRegistriesAsync);
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
        // transactional: false — same writable_schema + schema_version-bump shape as the other
        // CHECK widens above; idempotent on both providers, so an un-recorded partial run is
        // repeated harmlessly next boot.
        await RunOnceAsync(conn, "expand_org_status_check_with_read_only", ExpandOrgStatusCheckWithReadOnlyAsync, transactional: false);
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
        await RunOnceAsync(conn, "drop_package_versions_purl_unique", DropPackageVersionsPurlUniqueAsync, transactional: false, dropsViews: true);

        // Make package_version_licenses.package_version_id nullable and add the dedup UNIQUE for the
        // global (cache_artifact) arm. On fresh installs the CREATE TABLE already has the nullable
        // column, so the check-then-act pattern is a no-op. On upgraded DBs the column is still NOT
        // NULL (the P0 additive migration added cache_artifact_id/owner_kind but could not alter
        // package_version_id's nullability); the SQLite branch recreates the table while the Postgres
        // branch uses ALTER COLUMN ... DROP NOT NULL + CREATE UNIQUE INDEX IF NOT EXISTS.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_pvl_package_version_id_nullable", MakePvlPackageVersionIdNullableAsync, transactional: false, dropsViews: true);

        // Restructure package_version_vulns: add surrogate id PK, make package_version_id nullable,
        // replace the composite PK with two partial unique indexes. Fresh installs already have the
        // new shape from Schema.sql. Upgraded DBs carry the old composite PK with package_version_id
        // NOT NULL; the SQLite branch recreates the table while the Postgres branch uses ALTER + DDL.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_pvv_package_version_id_nullable", MakePvvPackageVersionIdNullableAsync, transactional: false, dropsViews: true);

        // Restructure rpm_metadata: add surrogate id TEXT PRIMARY KEY, make package_version_id
        // nullable (removing it from the PK), add per-arm partial unique indexes. Allows
        // cache_artifact-owned rows to exist without a package_versions FK.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_rpm_metadata_pv_nullable", MakeRpmMetadataPvNullableAsync, transactional: false, dropsViews: true);

        // Restructure maven_version_files: make package_version_id nullable, replace the plain
        // UNIQUE(package_version_id, filename) with two partial unique indexes.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_mvf_pv_nullable", MakeMvfPvNullableAsync, transactional: false, dropsViews: true);

        // Restructure cargo_metadata: make version_id nullable, replace the plain UNIQUE(version_id)
        // with two partial unique indexes. The INTEGER AUTOINCREMENT PK is preserved.
        // transactional: false on SQLite — DDL does not compose with an outer transaction.
        await RunOnceAsync(conn, "make_cargo_metadata_vid_nullable", MakeCargoMetadataVidNullableAsync, transactional: false, dropsViews: true);

        // Repair databases where make_rpm_metadata_pv_nullable mis-detected the old shape. That
        // migration keyed off package_version_id's notnull flag, but the old rpm_metadata declared
        // it as a bare "TEXT PRIMARY KEY", which SQLite reports as notnull=0 — so the reshape was
        // skipped and recorded as applied while the surrogate id column was never added, leaving
        // migrate_proxy_versions_to_cache_plane (and rpm_metadata inserts generally) unable to
        // reference rpm_metadata.id. This separately named one-shot re-runs the now pk-aware
        // reshape: it adds id on affected databases and no-ops on healthy ones. Must run before
        // migrate_proxy_versions_to_cache_plane.
        // transactional: false on SQLite — DROP + RENAME does not compose with an outer transaction.
        await RunOnceAsync(conn, "repair_rpm_metadata_surrogate_id", MakeRpmMetadataPvNullableAsync, transactional: false, dropsViews: true);

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
        await RunOnceAsync(conn, "add_pvv_owner_invariant_check", AddPvvOwnerInvariantCheckAsync, transactional: false, dropsViews: true);
        await RunOnceAsync(conn, "add_pvl_owner_invariant_check", AddPvlOwnerInvariantCheckAsync, transactional: false, dropsViews: true);
        await RunOnceAsync(conn, "add_rpm_metadata_owner_invariant_check", AddRpmMetadataOwnerInvariantCheckAsync, transactional: false, dropsViews: true);
        await RunOnceAsync(conn, "add_mvf_owner_invariant_check", AddMvfOwnerInvariantCheckAsync, transactional: false, dropsViews: true);
        // Same shape for the NuGet symbol index, which additionally needs package_version_id to
        // lose NOT NULL so a proxied .snupkg (cache_artifact-owned, no version row) can index.
        await RunOnceAsync(conn, "add_symbol_index_owner_invariant", AddSymbolIndexOwnerInvariantAsync, transactional: false, dropsViews: true);
        // Existing nuget.org upstream rows predate symbol_server_url; seed the well-known endpoint
        // so symbol proxying works on upgrade without the operator knowing the symbol host.
        await RunOnceAsync(conn, "seed_nuget_org_symbol_server_url", SeedNuGetOrgSymbolServerUrlAsync);
        await RunOnceAsync(conn, "add_cargo_metadata_owner_invariant_check", AddCargoMetadataOwnerInvariantCheckAsync, transactional: false, dropsViews: true);

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
        // Normalize existing NuGet cache_artifact rows whose name was stored in canonical case (e.g.
        // 'Newtonsoft.Json' instead of 'newtonsoft.json'). The same cross-plane join mismatch as RPM:
        // packages.purl_name is lowercased but the backfill wrote p.name (display case). Two-step:
        // delete colliding mixed-case rows that already have a lowercase twin at the same coordinate
        // (FK cascade drops their tenant_artifact_access), then lowercase the rest. Idempotent.
        // xtenant: cache_artifact is the global plane; DELETE and UPDATE key only on ecosystem and
        // the case-mismatch predicate, leaving rows from other ecosystems unchanged.
        await RunOnceAsync(conn, "normalize_nuget_cache_artifact_names", NormalizeNuGetCacheArtifactNamesAsync);
        // Backfill version_overwrite_policy from the legacy allow_version_overwrite boolean for
        // orgs that had it set to 1. The tri-state policy supersedes the boolean; the boolean
        // column is kept but dual-written going forward. Idempotent via the applied-migrations ledger.
        // xtenant: one-shot data migration across every tenant on the instance.
        await RunOnceAsync(conn, "migrate_allow_version_overwrite_to_policy", MigrateAllowVersionOverwriteToPolicyAsync);

        // Normalize existing claim.name values to the per-ecosystem canonical key
        // (PurlNormalizer.CanonicalName). Claims were stored with only ToLowerInvariant, so a
        // PyPI claim created for 'typing_extensions' never matched the enforcement sites that
        // resolve by the PEP 503 name 'typing-extensions'. Rewrites each row to its canonical
        // name; when a canonical row already occupies the (org, ecosystem, name) slot the
        // non-canonical duplicate is soft-deleted so the resolvers read the canonical one.
        await RunOnceAsync(conn, "normalize_claim_names_canonical", NormalizeClaimNamesCanonicalAsync);

        // Seed package_version_files from the pre-multi-file storage model: every hosted PyPI
        // version row carried exactly one artifact directly on its columns. One file row per
        // version, carrying the version's created_at so file timestamps stay historical truth
        // rather than boot time. The simple index and download path read exclusively from
        // package_version_files for PyPI after this.
        await RunOnceAsync(conn, "backfill_package_version_files_pypi", BackfillPackageVersionFilesPypiAsync);

        // Same seeding for NuGet, which joined the multi-file model so a .nupkg and its .snupkg
        // can share one version row. Existing hosted versions carry their single artifact on the
        // version columns alone; without a file row the parent's size_bytes would be recomputed
        // as the SUM of an empty set the first time a symbol package joined the coordinate.
        await RunOnceAsync(conn, "backfill_package_version_files_nuget", BackfillPackageVersionFilesNuGetAsync);

        // OCI proxy manifests join the shared cache_artifact / tenant_artifact_access plane like
        // every other proxy ecosystem instead of writing package_versions rows. Backfill existing
        // oci_blobs manifest rows onto the plane, then drop the now-orphan package_versions rows
        // the old write path left behind.
        await RunOnceAsync(conn, "backfill_oci_cache_artifact", BackfillOciCacheArtifactAsync);
        await RunOnceAsync(conn, "delete_oci_proxy_package_versions", DeleteOciProxyPackageVersionsAsync);

        // An image's license is an ordinary package_version_licenses fact, projected onto whichever
        // plane catalogued it. Images ingested before that projection existed carry the license only
        // on their oci_blobs manifest row, so every license reader reported them as having none.
        await RunOnceAsync(conn, "backfill_oci_licenses_to_shared_plane", BackfillOciLicensesToSharedPlaneAsync);

        // Second sweep of the proxy plane. A ledger entry runs once and never revisits rows that
        // appear after it: the first migrate/delete pass cannot see an origin='proxy' package_versions
        // row written to the same DB after that pass recorded itself as applied. The proxy fetch path
        // catalogues exclusively on the cache plane and refuses a fetch it cannot record there, so no
        // such row is produced any more — but a database that ran the first pass while the old path
        // was still live carries the ones it minted in between. They are invisible to the vulnerability
        // sweep and to retention (both read package_versions as origin='uploaded'), so they are unscanned
        // and unreclaimable. This fresh ledger entry re-runs the identical, idempotent backfill+delete
        // once more to catalogue them onto the cache plane and drop the package_versions rows; on a DB
        // with none it is a no-op.
        // xtenant: cross-tenant one-shot; cache_artifact is global and the delete keys on the proxy
        // discriminator.
        await RunOnceAsync(conn, "migrate_proxy_versions_to_cache_plane_2", MigrateProxyVersionsToCachePlaneAsync, transactional: false);
        await RunOnceAsync(conn, "delete_migrated_proxy_package_versions_2", DeleteMigratedProxyPackageVersionsAsync);

        // Seeds every tenant_artifact_access row's content binding from the cache_artifact row that
        // tenant is being served today, so the change is a no-op for existing data. Ordered here,
        // after RunAdditiveMigrationsAsync has added the columns AND after every migration that
        // inserts tenant_artifact_access rows — the proxy-plane sweeps above and the OCI catalogue
        // backfill. A ledger entry runs once and never revisits rows that appear after it, so a
        // backfill placed ahead of those would leave the rows they mint permanently unbound. That
        // is not a serving difference — an unbound row falls back to the same shared values the
        // backfill would have copied — but it would leave the schema comments claiming a coverage
        // the ledger does not give.
        await RunOnceAsync(
            conn, "backfill_tenant_artifact_access_binding", BackfillTenantArtifactAccessBindingAsync);

        // Seeds the per-tenant deprecation-refresh stamp from the shared cache_artifact stamp the
        // pass ordered by before it, so the first pass after an upgrade keeps the existing
        // stalest-first order instead of reading every group as never processed. Ordered after
        // every migration that inserts tenant_artifact_access rows, for the same reason as the
        // binding backfill above.
        // transactional: false — the body commits in bounded batches of its own, and the ledger is
        // recorded only once the last of them has committed.
        await RunOnceAsync(
            conn, "backfill_tenant_artifact_access_refresh_checked_at",
            BackfillTenantArtifactAccessRefreshCheckedAtAsync, transactional: false);

        // metadata_cache was never wired to a reader or writer (upstream-metadata caching lives
        // in memory instead); drop it so the schema doesn't advertise a TTL sweep that doesn't exist.
        await RunOnceAsync(conn, "drop_metadata_cache_table", DropMetadataCacheTableAsync, dropsViews: true);

        // Widen alert.type's closed CHECK to admit 'sbom_policy_violation'. Fresh installs get the
        // wider set from the CREATE TABLE blocks; this brings existing databases in line. Same
        // shape and same reasoning as expand_role_check_with_auditor above — transactional: false
        // because the SQLite branch drives PRAGMA writable_schema and a schema_version bump, and
        // idempotent on both providers so an un-recorded partial run repeats harmlessly.
        await RunOnceAsync(conn, "expand_alert_type_check_sbom_policy", ExpandAlertTypeCheckAsync, transactional: false);

        // Widen alert.type's CHECK a second time to admit 'vuln_kev', the KEV-independent alert
        // raised alongside (never instead of) 'vuln_severity'. A distinct migration under a new
        // ledger key: expand_alert_type_check_sbom_policy above is already recorded done on every
        // database that ran it, so RunOnceAsync would never re-run it if its old/new string pair
        // were edited in place — every already-migrated database would keep the narrower 3-value
        // CHECK forever and the first vuln_kev insert would throw. Same shape and reasoning as
        // both widenings above.
        await RunOnceAsync(conn, "expand_alert_type_check_vuln_kev", ExpandAlertTypeCheckVulnKevAsync, transactional: false);

        // Reclaim packages rows left cataloguing nothing by the two background reclaimers, which
        // remove a package's last version without GC'ing its parent row (SchemaInitializer
        // .EmptyPackageSweep.cs). Ordered after every plane migration above: those move versions
        // between package_versions and cache_artifact, and a sweep placed ahead of them would read
        // a mid-migration package as empty and delete a row whose versions were about to land.
        await RunOnceAsync(conn, "delete_empty_package_rows", DeleteEmptyPackageRowsAsync);

        await ApplyLaterOneTimeMigrationsAsync(conn);
    }

    // The tail of the ledgered sequence, split from the head only to keep each method short; the order
    // across the two is unchanged and ApplyOneTimeMigrationsAsync runs this one last.
    private async Task ApplyLaterOneTimeMigrationsAsync(DbConnection conn)
    {
        // Widen project_documents.format's closed CHECK to admit 'spdx-json', the second SBOM
        // ingest front end alongside 'cyclonedx-json'. Fresh installs get the wider set from the
        // CREATE TABLE blocks; this brings existing databases in line. Same shape and reasoning as
        // expand_alert_type_check_sbom_policy above.
        await RunOnceAsync(
            conn, "expand_project_documents_format_check_spdx", ExpandProjectDocumentsFormatCheckAsync,
            transactional: false);

        // Widen project_documents.signature_status's CHECK to admit 'unanchored' (SbomSignatureVerdict
        // .UnanchoredStatus — "this registry holds no pinned trust anchor for the document's claimed
        // keyId", distinct from a cryptographically invalid signature). Most existing databases gained
        // this column via a plain ALTER ADD COLUMN with no CHECK at all (see the additive migration's
        // own comment), so this rewrite is a no-op for them — allowMissingCheck: true covers exactly
        // that genuine-absence case. Unlike expand_block_deprecated_check, this column's clause is the
        // NULLABLE shape (CHECK (col IS NULL OR col IN (...))), not the bare one every other
        // Expand*CheckAsync migration above widens — VerifyCheckAdmitsAsync tries both clause shapes
        // before concluding the check is genuinely absent, specifically so this migration's rewrite is
        // still verified rather than silently tolerated by allowMissingCheck. The gap this closes is
        // narrower than the additive-ALTER case: a database initialized via CREATE TABLE while this
        // column's CHECK still admitted only the original three values DOES carry that narrow CHECK
        // baked in at CREATE TABLE time — and CREATE TABLE IF NOT EXISTS never re-runs against an
        // existing table, so upgrading the binary alone never widens it.
        await RunOnceAsync(
            conn, "expand_signature_status_check_unanchored", ExpandSignatureStatusCheckAsync,
            transactional: false);

        // Widen the Postgres numeric columns whose declared type is narrower there than on SQLite
        // (SchemaInitializer.NumericColumns.cs): INTEGER byte counts and caps to BIGINT, so a value
        // over 2 GiB is storable, and REAL scores and thresholds to DOUBLE PRECISION, so a policy
        // threshold round-trips exactly. Fresh installs get the wide types from the CREATE TABLE
        // blocks. Last, so every table it widens exists in its current shape.
        await RunOnceAsync(
            conn, "widen_postgres_numeric_columns", WidenPostgresNumericColumnsAsync, transactional: false, dropsViews: true);

        // Record in upstream_credential_history every credentialed upstream the retained audit log
        // shows was ever added, including ones deleted before the table existed. Once is enough for
        // the full trail; the every-boot convergence re-reads recent events for the blue-green
        // window. See SchemaInitializer.UpstreamCredentialHistory.cs.
        await RunOnceAsync(
            conn, "backfill_upstream_credential_history_from_audit", BackfillUpstreamCredentialHistoryFromAuditAsync);

        // Widen usage_daily.meter's CHECK to admit 'cache_storage_bytes', the day's high-water
        // mark of billed (but not cappable) proxy-cache storage. Fresh installs get the wider set
        // from the CREATE TABLE block; this brings existing databases in line. Same shape as
        // every other Expand*CheckAsync migration above.
        await RunOnceAsync(
            conn, "expand_usage_daily_meter_check_cache_storage", ExpandUsageDailyMeterCheckAsync,
            transactional: false);
    }
}
