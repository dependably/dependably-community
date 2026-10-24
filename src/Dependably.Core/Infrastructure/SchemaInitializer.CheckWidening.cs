using System.Data.Common;
using System.Globalization;
using Dapper;

namespace Dependably.Infrastructure;

public sealed partial class SchemaInitializer
{
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
    // the substring match is exact. The rewrite is wrapped in writable_schema=ON/RESET and
    // followed by VerifyCheckAdmitsAsync, which confirms the replace actually matched: an
    // exact-substring replace that matches nothing is a silent no-op the ledger then records
    // as applied forever.
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
        await VerifyCheckAdmitsAsync(conn, "users", "role", "auditor");
        await VerifyCheckAdmitsAsync(conn, "invites", "role", "auditor");
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
        // allowMissingCheck: org_settings.block_deprecated carries no CHECK on a database that
        // gained the column through a plain ALTER ADD COLUMN, where this rewrite no-ops by design.
        await VerifyCheckAdmitsAsync(
            conn, "org_settings", "block_deprecated", "block_all", allowMissingCheck: true);
    }

    // Extend the orgs.status CHECK constraint to include 'read_only' — the billing-dunning
    // posture between 'active' and full lockout: TenantStatusEnforcementMiddleware admits
    // GET/HEAD/OPTIONS on every plane and any write on the management plane for it, refusing only
    // a state-changing protocol-plane request. New databases pick this up from the CREATE TABLE
    // statements in Schema.sql / Schema.pg.sql; this migration brings existing databases in line.
    //
    // Postgres: drop + re-add the auto-named CHECK constraint. IF EXISTS covers an install that
    // never carried one.
    //
    // SQLite: rewrite the stored CREATE TABLE text in place via the writable_schema pattern. The
    // literal REPLACE is exact because the stored text is verbatim what Schema.sql emitted, and it
    // is a no-op on any database whose orgs table does not carry the narrower clause.
    private Task ExpandOrgStatusCheckWithReadOnlyAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE orgs DROP CONSTRAINT IF EXISTS orgs_status_check;
                ALTER TABLE orgs ADD  CONSTRAINT orgs_status_check
                    CHECK (status IN ('active', 'suspended', 'archived', 'deleting', 'read_only'));
                """)
            : ExpandOrgStatusCheckWithReadOnlySqliteAsync(conn);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task ExpandOrgStatusCheckWithReadOnlySqliteAsync(DbConnection conn)
    {
        const string oldCheck = "CHECK (status IN ('active','suspended','archived','deleting'))";
        const string newCheck = "CHECK (status IN ('active','suspended','archived','deleting','read_only'))";

        // Bumping schema_version forces SQLite to reload the schema on the next read so existing
        // connections stop enforcing the old CHECK; writable_schema = RESET both disables write
        // mode and forces the reload. See ExpandRoleCheckSqliteAsync for the full rationale.
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name = 'orgs'
                """, new { old = oldCheck, @new = newCheck });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
        // allowMissingCheck: a database that gained orgs.status through the additive ALTER ADD
        // COLUMN carries no CHECK on it at all, so this rewrite no-ops by design there, and every
        // status write is validated by SystemController instead.
        await VerifyCheckAdmitsAsync(conn, "orgs", "status", "read_only", allowMissingCheck: true);
    }

    // Extend the alert.type CHECK constraint to include 'sbom_policy_violation', the alert an
    // SBOM policy evaluation raises. New databases pick this up from the CREATE TABLE statements
    // in Schema.sql / Schema.pg.sql; this migration brings existing databases in line.
    //
    // Postgres: drop + re-add the auto-named CHECK constraint. IF EXISTS covers an install that
    // never carried one.
    //
    // SQLite: rewrite the stored CREATE TABLE text in place via the writable_schema pattern. The
    // literal REPLACE is exact because the stored text is verbatim what Schema.sql emitted, and it
    // is a no-op on any database whose alert table does not carry the narrower clause.
    private Task ExpandAlertTypeCheckAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE alert DROP CONSTRAINT IF EXISTS alert_type_check;
                ALTER TABLE alert ADD  CONSTRAINT alert_type_check
                    CHECK (type IN ('quarantine_new', 'vuln_severity', 'sbom_policy_violation'));
                """)
            : ExpandAlertTypeCheckSqliteAsync(conn);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task ExpandAlertTypeCheckSqliteAsync(DbConnection conn)
    {
        const string oldCheck = "CHECK (type IN ('quarantine_new', 'vuln_severity'))";
        const string newCheck = "CHECK (type IN ('quarantine_new', 'vuln_severity', 'sbom_policy_violation'))";

        // Bumping schema_version forces SQLite to reload the schema on the next read so existing
        // connections stop enforcing the old CHECK; writable_schema = RESET both disables write
        // mode and forces the reload. See ExpandRoleCheckSqliteAsync for the full rationale.
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name = 'alert'
                """, new { old = oldCheck, @new = newCheck });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
        await VerifyCheckAdmitsAsync(conn, "alert", "type", "sbom_policy_violation");
    }

    // Extend the alert.type CHECK constraint a second time to include 'vuln_kev', the alert
    // raised when a scanned advisory is listed in the CISA Known Exploited Vulnerabilities
    // catalog, independent of its CVSS severity. New databases pick this up from the CREATE
    // TABLE statements in Schema.sql / Schema.pg.sql; this migration brings existing databases
    // in line. Registered under its own RunOnceAsync key rather than editing
    // ExpandAlertTypeCheckAsync's old/new pair in place — that key is already recorded done on
    // every database that ran it, so editing it in place would leave those databases stuck on
    // the narrower CHECK forever.
    //
    // Postgres: drop + re-add the auto-named CHECK constraint. IF EXISTS covers an install that
    // never carried one.
    //
    // SQLite: rewrite the stored CREATE TABLE text in place via the writable_schema pattern. The
    // literal REPLACE is exact because the stored text is verbatim what the previous migration
    // (or a fresh Schema.sql) emitted, and it is a no-op on any database whose alert table does
    // not carry the narrower clause.
    private Task ExpandAlertTypeCheckVulnKevAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE alert DROP CONSTRAINT IF EXISTS alert_type_check;
                ALTER TABLE alert ADD  CONSTRAINT alert_type_check
                    CHECK (type IN ('quarantine_new', 'vuln_severity', 'sbom_policy_violation', 'vuln_kev'));
                """)
            : ExpandAlertTypeCheckVulnKevSqliteAsync(conn);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task ExpandAlertTypeCheckVulnKevSqliteAsync(DbConnection conn)
    {
        const string oldCheck = "CHECK (type IN ('quarantine_new', 'vuln_severity', 'sbom_policy_violation'))";
        const string newCheck = "CHECK (type IN ('quarantine_new', 'vuln_severity', 'sbom_policy_violation', 'vuln_kev'))";

        // Bumping schema_version forces SQLite to reload the schema on the next read so existing
        // connections stop enforcing the old CHECK; writable_schema = RESET both disables write
        // mode and forces the reload. See ExpandRoleCheckSqliteAsync for the full rationale.
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name = 'alert'
                """, new { old = oldCheck, @new = newCheck });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
        await VerifyCheckAdmitsAsync(conn, "alert", "type", "vuln_kev");
    }

    // Widen project_documents.format's closed CHECK to admit 'spdx-json' — SPDX ingest is a
    // second front end onto the same sbom_components projection CycloneDX ingest already writes,
    // not a second document kind, so only the format enum widens; doc_type stays 'sbom'. Fresh
    // installs get the wider set from the CREATE TABLE blocks; this brings existing databases in
    // line. Same shape and reasoning as the alert.type widenings above.
    //
    // Postgres: drop + re-add the auto-named CHECK constraint. IF EXISTS covers an install that
    // never carried one.
    //
    // SQLite: rewrite the stored CREATE TABLE text in place via the writable_schema pattern. The
    // literal REPLACE is exact because the stored text is verbatim what Schema.sql emitted, and it
    // is a no-op on any database whose project_documents table does not carry the narrower clause.
    private Task ExpandProjectDocumentsFormatCheckAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE project_documents DROP CONSTRAINT IF EXISTS project_documents_format_check;
                ALTER TABLE project_documents ADD  CONSTRAINT project_documents_format_check
                    CHECK (format IN ('cyclonedx-json', 'openvex-json', 'sarif-json', 'spdx-json'));
                """)
            : ExpandProjectDocumentsFormatCheckSqliteAsync(conn);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task ExpandProjectDocumentsFormatCheckSqliteAsync(DbConnection conn)
    {
        const string oldCheck = "CHECK (format IN ('cyclonedx-json','openvex-json','sarif-json'))";
        const string newCheck = "CHECK (format IN ('cyclonedx-json','openvex-json','sarif-json','spdx-json'))";

        // Bumping schema_version forces SQLite to reload the schema on the next read so existing
        // connections stop enforcing the old CHECK; writable_schema = RESET both disables write
        // mode and forces the reload. See ExpandRoleCheckSqliteAsync for the full rationale.
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name = 'project_documents'
                """, new { old = oldCheck, @new = newCheck });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
        await VerifyCheckAdmitsAsync(conn, "project_documents", "format", "spdx-json");
    }

    // Widen project_documents.signature_status's CHECK to admit 'unanchored'. See the RunOnceAsync
    // call site's own comment for why this is narrower in scope than the other Expand*CheckAsync
    // migrations: most databases never carry a CHECK on this column at all.
    //
    // Postgres: drop + re-add the auto-named CHECK constraint. IF EXISTS covers both an upgraded
    // database that added the column via ALTER (no constraint) and a fresh install (constraint
    // present, named project_documents_signature_status_check by default).
    //
    // SQLite: rewrite the stored CREATE TABLE text in place via the writable_schema pattern. The
    // literal REPLACE is a no-op on any database whose project_documents does not carry the exact
    // original 3-value clause a fresh CREATE TABLE run before this widen would have baked in.
    private Task ExpandSignatureStatusCheckAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE project_documents DROP CONSTRAINT IF EXISTS project_documents_signature_status_check;
                ALTER TABLE project_documents ADD  CONSTRAINT project_documents_signature_status_check
                    CHECK (signature_status IS NULL OR signature_status IN ('verified','failed','unsigned','unanchored'));
                """)
            : ExpandSignatureStatusCheckSqliteAsync(conn);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task ExpandSignatureStatusCheckSqliteAsync(DbConnection conn)
    {
        const string oldCheck =
            "CHECK (signature_status IS NULL OR signature_status IN ('verified','failed','unsigned'))";
        const string newCheck =
            "CHECK (signature_status IS NULL OR signature_status IN ('verified','failed','unsigned','unanchored'))";

        // Bumping schema_version forces SQLite to reload the schema on the next read so existing
        // connections stop enforcing the old CHECK; writable_schema = RESET both disables write
        // mode and forces the reload. See ExpandRoleCheckSqliteAsync for the full rationale.
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name = 'project_documents'
                """, new { old = oldCheck, @new = newCheck });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
        // allowMissingCheck: most databases gained signature_status via a plain ALTER ADD COLUMN
        // with no CHECK at all (see the additive migration's own comment) — this rewrite no-ops by
        // design for every one of them.
        await VerifyCheckAdmitsAsync(
            conn, "project_documents", "signature_status", "unanchored", allowMissingCheck: true);
    }

    // Widen usage_daily.meter's CHECK to admit 'cache_storage_bytes', the day's high-water mark of
    // billable proxy-cache storage (captured from storage_snapshot.cache_attributed_bytes, at each
    // tenant's full attributed size, the same way 'storage_bytes' is captured from billable_bytes).
    // Fresh installs get the wider set from the CREATE TABLE blocks; this brings existing databases
    // in line. Same shape and reasoning as the alert.type widenings above.
    //
    // Postgres: drop + re-add the auto-named CHECK constraint. IF EXISTS covers an install that
    // never carried one.
    //
    // SQLite: rewrite the stored CREATE TABLE text in place via the writable_schema pattern. The
    // literal REPLACE is exact because the stored text is verbatim what Schema.sql emitted, and it
    // is a no-op on any database whose usage_daily table does not carry the narrower clause.
    private Task ExpandUsageDailyMeterCheckAsync(DbConnection conn)
    {
        return _db.Provider == DbProvider.Postgres
            ? conn.ExecuteAsync("""
                ALTER TABLE usage_daily DROP CONSTRAINT IF EXISTS usage_daily_meter_check;
                ALTER TABLE usage_daily ADD  CONSTRAINT usage_daily_meter_check
                    CHECK (meter IN ('egress_bytes', 'egress_metadata_bytes', 'storage_bytes', 'cache_storage_bytes'));
                """)
            : ExpandUsageDailyMeterCheckSqliteAsync(conn);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatted SQL queries should be reviewed",
        Justification = "PRAGMA schema_version cannot be parameter-bound — SQLite's PRAGMA grammar does not " +
                        "accept ? / @name placeholders for the right-hand side. The interpolated value is a " +
                        "long we just read from PRAGMA schema_version itself; it never touches user input.")]
    private static async Task ExpandUsageDailyMeterCheckSqliteAsync(DbConnection conn)
    {
        const string oldCheck = "CHECK (meter IN ('egress_bytes', 'egress_metadata_bytes', 'storage_bytes'))";
        const string newCheck =
            "CHECK (meter IN ('egress_bytes', 'egress_metadata_bytes', 'storage_bytes', 'cache_storage_bytes'))";

        // Bumping schema_version forces SQLite to reload the schema on the next read so existing
        // connections stop enforcing the old CHECK; writable_schema = RESET both disables write
        // mode and forces the reload. See ExpandRoleCheckSqliteAsync for the full rationale.
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync("""
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @old, @new)
                WHERE type = 'table' AND name = 'usage_daily'
                """, new { old = oldCheck, @new = newCheck });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
        await VerifyCheckAdmitsAsync(conn, "usage_daily", "meter", "cache_storage_bytes");
    }
}
