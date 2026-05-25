using System.Data;
using System.Data.Common;
using System.Globalization;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Infrastructure;

/// <summary>Applies the embedded SQL schema on startup (idempotent — uses CREATE IF NOT EXISTS).</summary>
public sealed class SchemaInitializer
{
    private readonly IMetadataStore _db;
    private readonly ILogger<SchemaInitializer> _logger;
    private readonly SpdxLicenseSeeder _spdxSeeder;

    static SchemaInitializer()
    {
        // SQLite stores dates as TEXT (ISO 8601). Register a type handler so Dapper
        // can map TEXT columns to DateTimeOffset in record constructors.
        SqlMapper.AddTypeHandler(new DateTimeOffsetHandler());
    }

    public SchemaInitializer(
        IMetadataStore db,
        ILogger<SchemaInitializer>? logger = null,
        SpdxLicenseSeeder? spdxSeeder = null)
    {
        _db = db;
        _logger = logger ?? NullLogger<SchemaInitializer>.Instance;
        // Test ctors that pass only the IMetadataStore get a seeder with a null logger —
        // the embedded JSON is still read so the spdx_license table is populated.
        _spdxSeeder = spdxSeeder ?? new SpdxLicenseSeeder(NullLogger<SpdxLicenseSeeder>.Instance);
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
        await FixNuGetProxyPurlNamesAsync(conn); // unguarded; idempotent SQL
        await RunOnceAsync(conn, "backfill_users_account_type_saml", BackfillUsersAccountTypeSamlAsync);
        await RunOnceAsync(conn, "expand_role_check_with_auditor", ExpandRoleCheckWithAuditorAsync);
        await RunOnceAsync(conn, "collapse_origin_to_uploaded", CollapseOriginToUploadedAsync);
        await RunOnceAsync(conn, "drop_legacy_token_scope_column", DropLegacyTokenScopeColumnAsync);
        await RunOnceAsync(conn, "drop_package_versions_sbom_column", DropPackageVersionsSbomColumnAsync);
        await RunOnceAsync(conn, "drop_allowlist_blocklist_ecosystem", DropAllowlistBlocklistEcosystemAsync);
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
            // #45 replacement policy: opt-in per-tenant. Default 0 (off) preserves the strict
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
        };

        foreach (var ddl in migrations)
        {
            if (_db.Provider == DbProvider.Sqlite)
                await MigrateSqliteAsync(conn, ddl);
            else
                await conn.ExecuteAsync(ddl.Replace("ADD COLUMN ", "ADD COLUMN IF NOT EXISTS "));
        }
    }

    private static async Task EnsureMigrationsTableAsync(DbConnection conn)
    {
        // Tracks one-time data migrations so they only run once per database.
        await conn.ExecuteAsync("""
            CREATE TABLE IF NOT EXISTS _applied_migrations (
                name TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            )
            """);
    }

    private async Task RunOnceAsync(DbConnection conn, string name, Func<DbConnection, Task> action)
    {
        var already = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = @name", new { name });
        if (already > 0)
        {
            _logger.LogDebug("Schema migration {Migration} already applied; skipping.", name);
            return;
        }
        _logger.LogInformation("Schema migration {Migration} applying…", name);
        await action(conn);
        await conn.ExecuteAsync(
            "INSERT INTO _applied_migrations (name) VALUES (@name)", new { name });
        _logger.LogInformation("Schema migration {Migration} applied.", name);
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

    // #54: extend the users.role + invites.role CHECK constraint to include 'auditor'.
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
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 1) { /* duplicate column — additive migration already applied, ignore */ }
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
