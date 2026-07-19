using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>Upstream-registry seed backfills, column-drop/table-rename migrations, and the
/// flat additive-column/index migration list for <see cref="SchemaInitializer"/>.</summary>
public sealed partial class SchemaInitializer
{
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

    // Targeted backfill for the apk upstream. apk was added to UpstreamRegistrySeeder.DefaultSources
    // after seed_default_upstream_registries already ran for existing orgs, so those orgs never
    // received the default dl-cdn.alpinelinux.org row and silently had apk proxying disabled. Seeds
    // ONLY apk — not the full default set — for the same reason SeedGoCargoUpstreamRegistriesAsync
    // is scoped: an operator may have deliberately removed a different ecosystem's row since
    // configurable upstreams shipped, and re-running the full backfill would resurrect it. apk is
    // safe to seed unconditionally: no existing org could have deliberately removed a row it never
    // had. Config overrides (Apk:Upstream) are honoured via ResolveDefaults. Idempotent via the
    // per-(org, ecosystem) existence check and the (org_id, ecosystem, url) unique constraint.
    // xtenant: one-shot backfill across every tenant on the instance.
    private async Task SeedApkUpstreamRegistriesAsync(DbConnection conn)
    {
        var defaults = UpstreamRegistrySeeder.ResolveDefaults(_config)
            .Where(d => d.Ecosystem is "apk")
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
            "Backfilled apk upstream registries: {Seeded} seeded, {Skipped} already-configured across {Orgs} orgs.",
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

    // Drops `metadata_cache`. It was created for a planned upstream-metadata cache (npm packument,
    // PyPI simple HTML, NuGet registration) with TTL revalidation via idx_metadata_cache_expires,
    // but that caching is implemented in memory instead (single-flight + TTL per ecosystem, e.g.
    // the npm packument cache) and no code reads or writes this table. Safe to drop outright —
    // nothing references it.
    private async Task DropMetadataCacheTableAsync(DbConnection conn)
    {
        if (!await TableExistsAsync(conn, "metadata_cache"))
        {
            return;
        }

        await conn.ExecuteAsync("DROP TABLE metadata_cache");
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

        // Folds the retired per-org disable_* flags into air_gapped for every tenant that had
        // either set. Scoping it to one org would leave the rest of the instance on a column
        // that is about to be dropped.
        if (hasVulnScan && hasDeprecation)
        {
            // xtenant: one-shot startup migration — instance-wide by design.
            await conn.ExecuteAsync(
                "UPDATE org_settings SET air_gapped = 1 WHERE disable_vuln_scan = 1 OR disable_deprecation_refresh = 1");
        }
        else if (hasVulnScan)
        {
            // xtenant: same migration, single-column variant.
            await conn.ExecuteAsync(
                "UPDATE org_settings SET air_gapped = 1 WHERE disable_vuln_scan = 1");
        }
        else if (hasDeprecation)
        {
            // xtenant: same migration, single-column variant.
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
    // xtenant: one-shot startup migration — the enum collapse applies to every tenant's rows.
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
            // Opt-in; existing orgs see no behaviour change until an operator enables it and adds
            // a per-org npm SPKI trust anchor. Added without a CHECK (SQLite ALTER can't add one);
            // upgraded DBs rely on controller validation, fresh installs get the CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN verify_npm_signatures TEXT NOT NULL DEFAULT 'off'",
            // Per-tenant NuGet signature-verification gate: 'off' (default) / 'warn' / 'block'.
            // Opt-in; existing orgs see no behaviour change until an operator enables it and adds
            // a per-org NuGet X.509 trust anchor. Added without a CHECK (SQLite ALTER can't add
            // one); upgraded DBs rely on controller validation, fresh installs get the CHECK.
            "ALTER TABLE org_settings ADD COLUMN verify_nuget_signatures TEXT NOT NULL DEFAULT 'off'",
            // Per-tenant PyPI PEP 740 attestation-verification gate: 'off' (default) / 'warn' /
            // 'block'. Opt-in; existing orgs see no behaviour change until an operator enables it and
            // configures per-org sigstore_root + trusted_publisher anchors via Settings → Trust Anchors.
            // Added without a CHECK (SQLite ALTER can't add one); upgraded DBs rely on controller
            // validation, fresh installs get the CHECK from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN verify_pypi_attestations TEXT NOT NULL DEFAULT 'off'",
            // Per-tenant RPM per-package GPG header signature-verification gate: 'off' (default) /
            // 'warn' / 'block'. Enabling requires at least one RPM PGP anchor in signature_trust_anchor;
            // without one the verifier reports not-applicable and nothing blocks. Added without a CHECK
            // (SQLite ALTER can't add one); upgraded DBs rely on controller validation.
            "ALTER TABLE org_settings ADD COLUMN verify_rpm_signatures TEXT NOT NULL DEFAULT 'off'",
            // Per-tenant Maven detached .asc OpenPGP signature-verification gate: 'off' (default) /
            // 'warn' / 'block'. Enabling requires at least one per-org Maven PGP anchor in
            // signature_trust_anchor; without one the verifier reports not-applicable and nothing
            // blocks. Added without a CHECK (SQLite ALTER can't add one); upgraded DBs rely on
            // controller validation, fresh installs get the CHECK.
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
            // MFA fields for the ASP.NET Core Identity UserStore on tenant users. mfa_authenticator_key
            // holds the AES-GCM-encrypted TOTP key; mfa_recovery_codes holds a JSON array of SHA-256
            // hashes of the one-time recovery codes; security_stamp is a random value rotated on every
            // credential change so UserManager detects concurrent mutations. All nullable; existing
            // rows stay NULL and are populated when a user enrolls in MFA.
            "ALTER TABLE users ADD COLUMN mfa_authenticator_key TEXT",
            "ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT",
            "ALTER TABLE users ADD COLUMN security_stamp TEXT",
            // MFA fields and session-invalidation counter for system_admin accounts. Mirrors the users
            // columns so operator accounts can enroll in MFA under the same Identity spine.
            // token_version backfills to 1 (the column default), matching pre-existing session claim
            // semantics so no operator is logged out by the migration.
            "ALTER TABLE system_admins ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE system_admins ADD COLUMN mfa_authenticator_key TEXT",
            "ALTER TABLE system_admins ADD COLUMN mfa_recovery_codes TEXT",
            "ALTER TABLE system_admins ADD COLUMN security_stamp TEXT",
            "ALTER TABLE system_admins ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1",
            // Per-tenant MFA enrollment requirement. When 1, all authenticated users must
            // complete MFA enrollment before accessing any API endpoints. Composes with the
            // instance REQUIRE_MFA env var: effective requirement = instance OR tenant.
            "ALTER TABLE org_settings ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0",
            // Unlist-age timestamp on package_versions: stamped when yanked flips to 1, cleared
            // on un-yank. Legacy yanked rows backfill to NULL and stay non-age-purgeable.
            "ALTER TABLE package_versions ADD COLUMN yanked_at TEXT",
            // Opt-in hosted-retention policy: hard-delete uploaded versions unlisted longer than
            // N days. NULL (default) leaves unlisted hosted versions in place indefinitely.
            "ALTER TABLE org_settings ADD COLUMN purge_unlisted_after_days INTEGER",
            // Upstream-removal (revocation) timestamp on both planes: stamped the first time a
            // cached version is observed gone from the upstream registry, cleared if it reappears.
            // Legacy rows backfill to NULL (= still published / never checked).
            "ALTER TABLE package_versions ADD COLUMN revoked_at TEXT",
            "ALTER TABLE cache_artifact ADD COLUMN revoked_at TEXT",
            // Upstream-removal policy gate. Defaults to 'warn' so existing orgs surface the badge
            // without breaking their cached serves; no CHECK on the ALTER (SQLite can't add one) —
            // fresh installs get it from the CREATE TABLE block, upgraded DBs rely on controller
            // validation.
            "ALTER TABLE org_settings ADD COLUMN block_revoked TEXT NOT NULL DEFAULT 'warn'",
            // Same-version-repush timestamp on package_versions: stamped when a hosted version
            // is overwritten at the same version number. NULL = never overwritten, so the
            // effective pushed date falls back to created_at.
            "ALTER TABLE package_versions ADD COLUMN updated_at TEXT",
            // NuGet symbol-server (SSQP) index. New table; created here on upgraded databases
            // (fresh installs pick it up from the Schema.sql / Schema.pg.sql CREATE blocks). The
            // TEXT primary key needs no provider-specific dialect, so the CREATE runs verbatim on
            // both providers; created_at is supplied explicitly at insert, so no DEFAULT is needed.
            "CREATE TABLE IF NOT EXISTS nuget_symbol_index (" +
                "id TEXT PRIMARY KEY, " +
                "org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, " +
                "package_version_id TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE, " +
                "pdb_filename TEXT NOT NULL, ssqp_key TEXT NOT NULL, snupkg_blob_key TEXT NOT NULL, " +
                "entry_path TEXT NOT NULL, created_at TEXT NOT NULL, " +
                "UNIQUE (org_id, ssqp_key, pdb_filename, package_version_id))",
            "CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_lookup ON nuget_symbol_index(org_id, ssqp_key, pdb_filename)",
            "CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_pv ON nuget_symbol_index(package_version_id)",
            // Install-relevant manifest subset (bin, dependencies, engines, …) captured at
            // hosted npm publish from the tarball's package.json and merged into the
            // packument's per-version objects. NULL for proxy rows, non-npm rows, and hosted
            // rows published before the column existed (those keep the legacy minimal shape).
            "ALTER TABLE package_versions ADD COLUMN manifest_json TEXT",
            // Per-tenant RPM hosted-publishing posture override. Nullable, no DEFAULT: NULL means
            // "inherit the instance Rpm:UpstreamMode env value" and must stay distinguishable from
            // an explicit 'passthrough' — a NOT NULL DEFAULT would materialize 'passthrough' into
            // every existing row and permanently destroy that distinction. An explicit org value
            // overrides the env value in EITHER direction (see RpmController.IsRpmPassthroughEffective).
            // SQLite's ADD COLUMN restriction is on PRIMARY KEY/UNIQUE and non-constant DEFAULT, not
            // CHECK, so the CHECK ships here too (mirrors the users.account_type migration above).
            "ALTER TABLE org_settings ADD COLUMN rpm_upstream_mode TEXT " +
                "CHECK (rpm_upstream_mode IS NULL OR rpm_upstream_mode IN ('passthrough','merged'))",
            // Publish timestamp of upstream_latest_version, captured alongside it when the
            // ecosystem's metadata carries a per-release timestamp. NULL for pre-existing rows
            // until the next refresh pass backfills it. Drives the abandoned-package signal.
            "ALTER TABLE packages ADD COLUMN upstream_latest_published_at TEXT",
            // Operational-risk versions-behind count, dual-plane with cache_artifact below. NULL
            // for pre-existing rows until the next refresh pass backfills it.
            "ALTER TABLE package_versions ADD COLUMN versions_behind INTEGER",
            "ALTER TABLE cache_artifact ADD COLUMN versions_behind INTEGER",
            // ISO 8601 UTC; stamped by LicenseBackfillService after a license-extraction pass
            // against a cache_artifact ingested before ingest-time license capture existed. NULL =
            // never scanned for licenses. Existing rows backfill to NULL and are picked up by the
            // next backfill pass; stamped once (found, empty, or blob-missing) so nothing rescans.
            "ALTER TABLE cache_artifact ADD COLUMN license_checked_at TEXT",
            // Full SPDX license text, bundled at build time and populated by SpdxLicenseSeeder
            // on the reseed path. Nullable: identifiers absent from the bundled texts keep NULL.
            "ALTER TABLE spdx_license ADD COLUMN license_text TEXT",
            // JSON install-manifest subset (dependencies/optionalDependencies/bin/engines) extracted
            // from the tarball's package.json at npm proxy first-fetch, in the same shape as
            // package_versions.manifest_json. NULL for artifacts cached before this column existed
            // or for non-npm ecosystems; the npm proxy fetch path backfills it lazily on next fetch.
            "ALTER TABLE cache_artifact ADD COLUMN manifest_json TEXT",
            // OCI image-license capture on oci_blobs. config_digest is the config blob digest
            // parsed from an image manifest body (image manifests only; index/layer rows stay
            // NULL). license_spdx is the SPDX expression read from the config's
            // org.opencontainers.image.licenses label. license_checked_at stamps when the config
            // bytes were read — label present or not — so a label-less image is never reparsed;
            // NULL means the config has not been seen yet. All three nullable/no-DEFAULT; existing
            // rows stay NULL and are stamped on the next manifest re-fetch or config arrival. The
            // (org_id, config_digest) index backs the reverse lookup from an arriving config blob
            // to the manifest rows awaiting a license stamp.
            "ALTER TABLE oci_blobs ADD COLUMN config_digest TEXT",
            "ALTER TABLE oci_blobs ADD COLUMN license_spdx TEXT",
            "ALTER TABLE oci_blobs ADD COLUMN license_checked_at TEXT",
            "CREATE INDEX IF NOT EXISTS idx_oci_blobs_org_config_digest ON oci_blobs(org_id, config_digest)",
            // Per-org email delivery channel for admin alerts, structurally mirroring the
            // slack_* columns above. email_inherit_instance selects between the instance-level
            // SMTP transport and the org's own email_smtp_* columns; email_smtp_password is
            // envelope-encrypted at rest (enc:v1: prefix) and write-only. SQLite's ADD COLUMN
            // restriction is on PRIMARY KEY/UNIQUE and non-constant DEFAULT, not CHECK, so the
            // CHECK ships here too (mirrors the rpm_upstream_mode migration above).
            "ALTER TABLE alert_settings ADD COLUMN email_enabled INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE alert_settings ADD COLUMN email_inherit_instance INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE alert_settings ADD COLUMN email_recipients TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_smtp_host TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_smtp_port INTEGER",
            "ALTER TABLE alert_settings ADD COLUMN email_smtp_security TEXT " +
                "CHECK (email_smtp_security IS NULL OR email_smtp_security IN ('starttls','ssl','none'))",
            "ALTER TABLE alert_settings ADD COLUMN email_smtp_username TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_smtp_password TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_smtp_from TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_last_delivery_at TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_last_status TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_consecutive_failures INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE alert_settings ADD COLUMN email_failing_since TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_last_error TEXT",
            // Terminal outcome of the async email delivery attempt on the alert row, mirroring
            // slack_status/slack_error.
            "ALTER TABLE alert ADD COLUMN email_status TEXT",
            "ALTER TABLE alert ADD COLUMN email_error TEXT",
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
}
