using System.Data;
using System.Data.Common;
using System.Globalization;
using Dapper;
using Dependably.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Infrastructure;

/// <summary>Applies the embedded SQL schema on startup (idempotent — uses CREATE IF NOT EXISTS).</summary>
public sealed class SchemaInitializer
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
        var sql = await ReadSchemaAsync(_db.Provider, ct);
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
        // transactional: false — the SQLite branch drives PRAGMA writable_schema + a schema_version
        // bump that don't compose with an enclosing transaction (same shape as the auditor CHECK
        // rewrite above). Idempotent on both providers, so an un-recorded partial run is repeated
        // harmlessly next boot. Must run before migrate_block_deprecated_to_block_all so the widened
        // CHECK permits the 'block_all' value the data rewrite writes.
        await RunOnceAsync(conn, "expand_block_deprecated_check", ExpandBlockDeprecatedCheckAsync, transactional: false);
        await RunOnceAsync(conn, "migrate_block_deprecated_to_block_all", MigrateBlockDeprecatedToBlockAllAsync);
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
        foreach (var row in rows)
        {
            var lastSlash = row.BlobKey.LastIndexOf('/');
            var filename = lastSlash >= 0 ? row.BlobKey[(lastSlash + 1)..] : row.BlobKey;
            await conn.ExecuteAsync(
                "UPDATE package_versions SET filename = @filename WHERE id = @id",
                new { id = row.Id, filename });
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

        foreach (var row in rows)
        {
            // get-or-create the parent package (one per org+repository); single-threaded migration,
            // so SELECT-then-INSERT needs no conflict guard.
            var pkgId = await conn.ExecuteScalarAsync<string?>(
                "SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = 'oci' AND purl_name = @repo",
                new { orgId = row.OrgId, repo = row.Repository });
            if (pkgId is null)
            {
                pkgId = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    """
                    INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
                    VALUES (@id, @orgId, 'oci', @name, @purlName, 1)
                    """,
                    new { id = pkgId, orgId = row.OrgId, name = row.Repository, purlName = row.Repository });
            }

            var lastSlash = row.BlobKey.LastIndexOf('/');
            var filename  = lastSlash >= 0 ? row.BlobKey[(lastSlash + 1)..] : row.BlobKey;
            var sha256Hex = row.Digest.StartsWith("sha256:", StringComparison.Ordinal)
                ? row.Digest["sha256:".Length..]
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
                    version = row.Digest,
                    purl = PurlNormalizer.Oci(row.Repository, row.Digest, row.Tag),
                    blobKey = row.BlobKey,
                    filename,
                    sizeBytes = row.SizeBytes,
                    sha256 = sha256Hex,
                });
        }
    }

    // Backfills the per-org upstream_registry table for installs that predate configurable
    // upstreams. Before this feature every ecosystem proxied through a single hard-coded default;
    // the proxy now treats "no configured registry" as "proxying disabled", so existing orgs must
    // inherit those defaults as real rows or they'd silently lose proxying on upgrade. For each
    // org that has zero registries for an ecosystem, the default URL (config override or hard-coded
    // public default; RPM only when Rpm:Upstream is set) is inserted. Idempotent via the
    // (org_id, ecosystem, url) unique constraint and the per-ecosystem existence check.
    // xtenant: one-shot backfill across every tenant on the instance.
    private async Task SeedDefaultUpstreamRegistriesAsync(DbConnection conn)
    {
        var defaults = UpstreamRegistrySeeder.ResolveDefaults(_config);
        if (defaults.Count == 0) return;

        var orgIds = (await conn.QueryAsync<string>("SELECT id FROM orgs")).ToList();
        var seeded = 0;
        var skipped = 0;
        foreach (var orgId in orgIds)
        {
            foreach (var (eco, url) in defaults)
            {
                var existing = await conn.ExecuteScalarAsync<int>(
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
            await conn.ExecuteAsync("ALTER TABLE user_tokens DROP COLUMN scope");
        if (await ColumnExistsAsync(conn, "service_tokens", "scope"))
            await conn.ExecuteAsync("ALTER TABLE service_tokens DROP COLUMN scope");
    }

    // Renames the legacy `tokens` table to `user_tokens` (and its index). Runs before the
    // CREATE TABLE IF NOT EXISTS pass so the schema doesn't spawn an empty sibling. Fresh
    // installs hit the existence guard and no-op; the ledger then prevents re-execution.
    private static async Task RenameTokensTableAsync(DbConnection conn)
    {
        if (!await TableExistsAsync(conn, "tokens")) return;
        await conn.ExecuteAsync("ALTER TABLE tokens RENAME TO user_tokens");
        // SQLite carries the old index name along with the renamed table; drop it so the
        // upcoming CREATE INDEX IF NOT EXISTS creates one with the correct new name.
        await conn.ExecuteAsync("DROP INDEX IF EXISTS idx_tokens_hash");
    }

    private static async Task RenameCicdTokensTableAsync(DbConnection conn)
    {
        if (!await TableExistsAsync(conn, "cicd_tokens")) return;
        await conn.ExecuteAsync("ALTER TABLE cicd_tokens RENAME TO service_tokens");
        await conn.ExecuteAsync("DROP INDEX IF EXISTS idx_cicd_tokens_hash");
    }

    private static async Task<bool> TableExistsAsync(DbConnection conn, string table)
    {
        // Works on both SQLite and Postgres: information_schema.tables is supported by both
        // (SQLite emulates it as a view since 3.39). For older SQLite we fall back below.
        try
        {
            var count = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM information_schema.tables
                WHERE table_name = @table
                """, new { table });
            return count > 0;
        }
        catch
        {
            // SQLite without information_schema view — query sqlite_master directly.
            var hits = await conn.ExecuteScalarAsync<long>(
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
        if (!await ColumnExistsAsync(conn, "package_versions", "sbom")) return;
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
        var hasVulnScan = await ColumnExistsAsync(conn, "org_settings", "disable_vuln_scan");
        var hasDeprecation = await ColumnExistsAsync(conn, "org_settings", "disable_deprecation_refresh");

        if (hasVulnScan && hasDeprecation)
            await conn.ExecuteAsync(
                "UPDATE org_settings SET air_gapped = 1 WHERE disable_vuln_scan = 1 OR disable_deprecation_refresh = 1");
        else if (hasVulnScan)
            await conn.ExecuteAsync(
                "UPDATE org_settings SET air_gapped = 1 WHERE disable_vuln_scan = 1");
        else if (hasDeprecation)
            await conn.ExecuteAsync(
                "UPDATE org_settings SET air_gapped = 1 WHERE disable_deprecation_refresh = 1");

        if (hasVulnScan)
            await conn.ExecuteAsync("ALTER TABLE org_settings DROP COLUMN disable_vuln_scan");
        if (hasDeprecation)
            await conn.ExecuteAsync("ALTER TABLE org_settings DROP COLUMN disable_deprecation_refresh");
    }

    private async Task<bool> ColumnExistsAsync(DbConnection conn, string table, string column)
    {
        if (_db.Provider == DbProvider.Postgres)
        {
            var count = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM information_schema.columns
                WHERE table_name = @table AND column_name = @column
                """, new { table, column });
            return count > 0;
        }

        // SQLite: pragma_table_info(...) returns one row per column.
        var hits = await conn.ExecuteScalarAsync<long>(
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

    private async Task RunAdditiveMigrationsAsync(DbConnection conn)
    {
        // SQLite has no native "if not exists" guard for column additions; MigrateSqliteAsync
        // swallows error 1 (duplicate column) instead. Postgres rewrites the same statements
        // to use native IF NOT EXISTS via the .Replace below.
        var migrations = new[]
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
        };

        foreach (var ddl in migrations)
        {
            if (_db.Provider == DbProvider.Sqlite)
                await MigrateSqliteAsync(conn, ddl);
            else
                await conn.ExecuteAsync(ddl.Replace("ADD COLUMN ", "ADD COLUMN IF NOT EXISTS "));
        }
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
        var already = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = @name", new { name });
        if (already > 0)
        {
            _logger.LogDebug("Schema migration {Migration} already applied; skipping.", name);
            return;
        }
        _logger.LogInformation("Schema migration {Migration} applying…", name);
        if (transactional)
            await RunInTransactionAsync(conn, name, action);
        else
            await RunUnwrappedAsync(conn, name, action);
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
                continue;
            var fixedName = name
                .Replace("%40", "@", StringComparison.OrdinalIgnoreCase)
                .Replace("%2F", "/", StringComparison.OrdinalIgnoreCase);
            var fixedPurlName = fixedName.StartsWith('@')
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
            if (!purl.Contains("%2F", StringComparison.OrdinalIgnoreCase)) continue;
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
        if (_db.Provider == DbProvider.Postgres)
        {
            return conn.ExecuteAsync("""
                ALTER TABLE users   DROP CONSTRAINT IF EXISTS users_role_check;
                ALTER TABLE users   ADD  CONSTRAINT users_role_check
                    CHECK (role IN ('member','admin','owner','auditor'));
                ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_role_check;
                ALTER TABLE invites ADD  CONSTRAINT invites_role_check
                    CHECK (role IN ('member','admin','owner','auditor'));
                """);
        }

        return ExpandRoleCheckSqliteAsync(conn);
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
            var version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
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
        if (_db.Provider == DbProvider.Postgres)
        {
            return conn.ExecuteAsync("""
                ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_block_deprecated_check;
                ALTER TABLE org_settings ADD  CONSTRAINT org_settings_block_deprecated_check
                    CHECK (block_deprecated IN ('off', 'warn', 'block_new', 'block_all'));
                """);
        }

        return ExpandBlockDeprecatedCheckSqliteAsync(conn);
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
            var version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
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

    private static async Task<string> ReadSchemaAsync(DbProvider provider, CancellationToken ct)
    {
        var assembly = typeof(SchemaInitializer).Assembly;
        var suffix = provider == DbProvider.Postgres ? "Schema.pg.sql" : "Schema.sql";
        var resourceName = assembly.GetManifestResourceNames()
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
