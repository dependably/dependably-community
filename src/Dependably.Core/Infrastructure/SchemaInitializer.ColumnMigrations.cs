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
    // Config overrides (Go:Upstream / Cargo:Upstream) are honoured via ResolveDefaults.
    private Task SeedGoCargoUpstreamRegistriesAsync(DbConnection conn) =>
        SeedUpstreamRegistriesForAsync(conn, "Go/Cargo", e => e is "golang" or "cargo");

    // Targeted backfill for the apk upstream. apk was added to the default sources after
    // seed_default_upstream_registries already ran for existing orgs, so those orgs never received
    // the default dl-cdn.alpinelinux.org row and silently had apk proxying disabled. Config
    // overrides (Apk:Upstream) are honoured via ResolveDefaults.
    private Task SeedApkUpstreamRegistriesAsync(DbConnection conn) =>
        SeedUpstreamRegistriesForAsync(conn, "apk", e => e is "apk");

    // Targeted backfill for the Terraform upstream, added to the default sources after the
    // preceding backfills had already run. Without the row an existing org has no configured
    // upstream for the ecosystem, and TerraformController resolves a provider's registry host
    // against exactly that list — so the network mirror answers nothing at all rather than merely
    // losing a fallback. Config overrides (Terraform:Upstream) are honoured via ResolveDefaults.
    private Task SeedTerraformUpstreamRegistriesAsync(DbConnection conn) =>
        SeedUpstreamRegistriesForAsync(conn, "Terraform", e => e is "terraform");

    // Targeted backfill for the Hex upstream, added to the default sources after the preceding
    // backfills had already run. Config overrides (Hex:Upstream) are honoured via ResolveDefaults.
    private Task SeedHexUpstreamRegistriesAsync(DbConnection conn) =>
        SeedUpstreamRegistriesForAsync(conn, "Hex", e => e is "hex");

    // Shared body of the targeted per-ecosystem upstream backfills above. Each seeds ONLY the
    // ecosystems its predicate selects — never the full default set — because an operator may have
    // deliberately deleted an upstream row (e.g. removed npm to disable npm proxying) since
    // configurable upstreams shipped, and re-running the full backfill would resurrect such a
    // removal. A newly added ecosystem is safe to seed unconditionally: no existing org could have
    // deliberately removed a row it never had. Idempotent via the per-(org, ecosystem) existence
    // check and the (org_id, ecosystem, url) unique constraint.
    // xtenant: one-shot backfill across every tenant on the instance.
    private async Task SeedUpstreamRegistriesForAsync(
        DbConnection conn, string label, Func<string, bool> selector)
    {
        var defaults = UpstreamRegistrySeeder.ResolveDefaults(_config)
            .Where(d => selector(d.Ecosystem))
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
            "Backfilled {Label} upstream registries: {Seeded} seeded, {Skipped} already-configured across {Orgs} orgs.",
            label, seeded, skipped, orgIds.Count);
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
        // xtenant: recreate-table DDL plus its row-preserving copy. Every copied row carries its own
        // org_id across, and the new tables keep the UNIQUE (org_id, …) tenant key.
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

        // xtenant: recreate-table DDL plus its row-preserving copy. Every copied row carries its own
        // org_id across, and the new tables keep the UNIQUE (org_id, …) tenant key.
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

    // Deletes API tokens that carry no capability set. `capabilities` arrived as a bare
    // ALTER TABLE ADD COLUMN with no default, so every token minted before it exists with
    // NULL. The authorization layer denies such a token outright — it must never inherit its
    // owner's role — which leaves it authenticating successfully while granting nothing: a
    // token the operator sees listed as live that fails every capability-gated route. The
    // rows are deleted rather than backfilled so the invalidation is visible at the surface
    // an operator actually reads, and re-minting is the only way forward.
    //
    // Empty, whitespace-only, and canonical-empty-array values are the same inert state and
    // go with them. A malformed non-empty value is left alone: recognising it needs JSON
    // parsing neither provider does portably, and the runtime denial already covers it.
    //
    private static async Task PurgeLegacyNullCapabilityTokensAsync(DbConnection conn)
    {
        // xtenant: instance-wide one-shot; a capability-less token is invalid in every tenant,
        // so the purge is keyed on the capability column alone rather than on org_id.
        await conn.ExecuteAsync(
            "DELETE FROM user_tokens WHERE capabilities IS NULL OR TRIM(capabilities) = '' OR TRIM(capabilities) = '[]'");

        // xtenant: instance-wide one-shot; a capability-less token is invalid in every tenant,
        // so the purge is keyed on the capability column alone rather than on org_id.
        await conn.ExecuteAsync(
            "DELETE FROM service_tokens WHERE capabilities IS NULL OR TRIM(capabilities) = '' OR TRIM(capabilities) = '[]'");
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

    // Drops `package_note`. The package-note feature is retired: no code reads or writes the
    // table and neither schema file declares it. Runs on every boot rather than through
    // RunOnceAsync, because the previous release declares package_note in its own base schema and
    // re-creates it whenever one of its slots boots against this database. A ledgered drop would
    // record itself applied on a fresh database and then skip the boot that actually needed it.
    private static async Task DropPackageNoteTableAsync(DbConnection conn)
    {
        if (!await TableExistsAsync(conn, "package_note"))
        {
            return;
        }

        await conn.ExecuteAsync("DROP TABLE package_note");
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

    /// <summary>
    /// Removes the retired per-org SMTP transport columns from <c>alert_settings</c>:
    /// <c>email_inherit_instance</c> and <c>email_smtp_host/port/security/username/password/from</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SMTP is an instance-level transport (InstanceSmtpConfig): an org configures whether alert
    /// mail is sent and to whom, never how it is carried. No code path has read or written any of
    /// these columns since the release that removed the readers, and there is nothing to fold
    /// forward — a per-org relay is retired configuration, not a fact another column absorbs.
    /// </para>
    /// <para>
    /// <b>Deliberately not ledgered through <c>RunOnceAsync</c>, and this is the load-bearing
    /// detail.</b> A previous release's own <c>BuildAdditiveMigrations</c> list still contains all
    /// seven <c>ADD COLUMN</c> entries. Any slot of such a release that boots against a migrated
    /// database — a rolling restart, a crash, a second replica — silently re-adds them. Under a
    /// one-shot ledger the drop would already be recorded as done and would never run again, so the
    /// live schema would diverge permanently from the schema file, invisibly: the backward-
    /// compatibility gate is declarative and never reads a live database. Running the drop on every
    /// boot makes the two converge instead, because the next boot re-drops whatever an older slot
    /// resurrected.
    /// </para>
    /// <para>
    /// Each column is guarded independently, so the pass is a no-op on a fresh install (none
    /// present), on an already-migrated database (the overwhelmingly common case, one cheap column
    /// probe apiece), and on a partial-state restore. A plain <c>DROP COLUMN</c> suffices on both
    /// providers: <c>email_smtp_security</c> carries an inline column-level CHECK, which SQLite
    /// drops together with the column — its documented refusal applies to <i>table</i>-level CHECKs
    /// naming the column, which this schema does not use. Verified against the pinned engine by
    /// DropAlertSettingsRetiredSmtpColumns_RemovesTheCheckBearingColumn.
    /// </para>
    /// </remarks>
    private async Task DropAlertSettingsRetiredSmtpColumnsAsync(DbConnection conn)
    {
        string[] retired =
        [
            "email_inherit_instance",
            "email_smtp_host",
            "email_smtp_port",
            "email_smtp_security",
            "email_smtp_username",
            "email_smtp_password",
            "email_smtp_from",
        ];

        // Reported before the drop, because afterwards there is nothing left to count. It is the
        // operator's only signal that a stored SMTP credential existed on this database — and that
        // reclaiming the pages its ciphertext occupied needs a VACUUM, since neither DROP COLUMN
        // nor an UPDATE frees them on either provider.
        if (await ColumnExistsAsync(conn, "alert_settings", "email_smtp_password"))
        {
            // xtenant: startup migration retiring a per-org transport instance-wide — scoping it to
            // one org would leave every other tenant's stored credential behind. alert_settings is
            // keyed by org_id, so there is no caller-supplied scope to honour here.
            long withCredential = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM alert_settings WHERE email_smtp_password IS NOT NULL");

            if (withCredential > 0)
            {
                _logger.LogInformation(
                    "Dropping the retired per-org SMTP transport columns; {CredentialRowCount} alert_settings "
                    + "row(s) still held a stored credential. Alert mail for those orgs rides the "
                    + "instance-level relay. VACUUM the database to reclaim the pages the credential "
                    + "ciphertext occupied.", withCredential);
            }
        }

        foreach (string column in retired)
        {
            if (await ColumnExistsAsync(conn, "alert_settings", column))
            {
                // rawsql: column names come from the compile-time-constant list above, never from a
                // caller; ALTER TABLE takes no parameter binding for an identifier.
                await conn.ExecuteAsync($"ALTER TABLE alert_settings DROP COLUMN {column}");
            }
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

    // Seeds the tenant content binding for rows that predate the columns. Every existing
    // tenant is bound to the bytes it is being served today (the shared cache_artifact row), so
    // the binding-first serve projections are a no-op for existing data and only diverge from
    // the shared row once a tenant records its own differing first fetch. A tenant already
    // sharing a row whose bytes came from another tenant's upstream stays bound to those bytes
    // until its next miss re-records the coordinate — the binding cannot reconstruct what that
    // tenant would have fetched, only stop the substitution from happening again.
    // xtenant: one-shot backfill across every tenant on the instance.
    private static Task BackfillTenantArtifactAccessBindingAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            """
            UPDATE tenant_artifact_access
            SET content_hash = (SELECT ca.content_hash FROM cache_artifact ca
                                WHERE ca.id = tenant_artifact_access.cache_artifact_id),
                blob_key     = (SELECT ca.blob_key     FROM cache_artifact ca
                                WHERE ca.id = tenant_artifact_access.cache_artifact_id),
                size_bytes   = (SELECT ca.size_bytes   FROM cache_artifact ca
                                WHERE ca.id = tenant_artifact_access.cache_artifact_id)
            WHERE content_hash IS NULL
            """);

    // Converges first_seen_at on package_version_vulns and sbom_component_vulns rows that carry
    // no value, using each row's existing checked_at as the best available approximation of
    // first observation — no earlier instant was ever recorded for a link written before a
    // caller supplied one explicitly. Called on every boot (see the call site in
    // ApplySchemaAsync) rather than run once — a link written by the OLD binary during a
    // blue-green cutover never sets first_seen_at (the registry arms are ON CONFLICT DO NOTHING,
    // the SBOM upsert's conflict clause never touches the column), so a row can arrive NULL on
    // any boot for as long as the previous release is still deployed somewhere.
    private static async Task BackfillFindingsFirstSeenAtAsync(DbConnection conn)
    {
        // xtenant: converges every tenant and both owner_kind arms on every boot;
        // package_version_vulns carries no org_id of its own (see Schema.sql).
        await conn.ExecuteAsync(
            "UPDATE package_version_vulns SET first_seen_at = checked_at WHERE first_seen_at IS NULL");
        await conn.ExecuteAsync(
            "UPDATE sbom_component_vulns SET first_seen_at = checked_at WHERE first_seen_at IS NULL");
    }

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
            // Publish-side licence gate, independent of the serve-side license_enforcement_mode
            // above. Defaults to 'off' so no currently-succeeding hosted publish starts failing
            // on upgrade. CHECK constraint applies on fresh installs only (see Schema.sql);
            // upgraded databases rely on controller-side validation, mirroring how
            // license_enforcement_mode itself was added.
            "ALTER TABLE org_settings ADD COLUMN license_publish_enforcement_mode TEXT NOT NULL DEFAULT 'off'",
            "ALTER TABLE org_settings ADD COLUMN proxy_passthrough_enabled INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE org_settings ADD COLUMN max_osv_score_tolerance REAL NOT NULL DEFAULT 10.0",
            "ALTER TABLE org_settings ADD COLUMN default_language TEXT NOT NULL DEFAULT 'en'",
            "ALTER TABLE users ADD COLUMN language TEXT",
            "ALTER TABLE system_admins ADD COLUMN language TEXT",
            // Display-only render zone, on the same per-user-override → org-default → instance
            // chain as language. Stored instants stay UTC regardless of any value here.
            "ALTER TABLE org_settings ADD COLUMN default_timezone TEXT NOT NULL DEFAULT 'UTC'",
            "ALTER TABLE users ADD COLUMN timezone TEXT",
            "ALTER TABLE system_admins ADD COLUMN timezone TEXT",
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
            // Tenancy bridge-model additions. Status is the lockout gate: a non-active tenant is
            // refused every request — protocol, management API and login alike — by
            // TenantStatusEnforcementMiddleware, not just writes. Region is dormant capacity for future
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
            // Hex per-ecosystem upload cap; a package tarball and its docs tarball share it.
            "ALTER TABLE org_settings ADD COLUMN max_upload_bytes_hex INTEGER",
            // Hex: the upstream repository's signing public key, verified before re-signing.
            "ALTER TABLE upstream_registry ADD COLUMN public_key_pem TEXT",
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
            // Tracker enrichment overlay on the same shared table: the NIST NVD band/score and
            // the three CISA Vulnrichment SSVC decision points, plus two stamps per signal class.
            // *_checked_at is when this instance last reached the tracker; *_asserted_at is the
            // as-of the tracker claims for the source behind that answer, and staleness is always
            // read off the OLDER of the pair — a tracker that is reachable but internally days
            // behind would otherwise have its stale data recorded as current.
            //
            // Added without CHECKs (SQLite ALTER cannot add one), matching the block_malicious
            // precedent above: upgraded databases rely on the write path's own validation, fresh
            // installs get the vocabulary CHECKs from Schema.sql. All NULL on existing rows, which
            // is exactly the unenriched state, so nothing needs backfilling and no gate arm reads
            // anything different until the overlay actually runs.
            "ALTER TABLE vulnerabilities ADD COLUMN nvd_severity TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN nvd_score REAL",
            "ALTER TABLE vulnerabilities ADD COLUMN nvd_checked_at TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN nvd_asserted_at TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN ssvc_exploitation TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN ssvc_automatable TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN ssvc_technical_impact TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN ssvc_checked_at TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN ssvc_asserted_at TEXT",
            // KEV catalogue context and the EPSS percentile — fields already present in the two
            // feed responses is_kev/epss_score are parsed from, previously discarded. No CHECKs
            // on the ALTER path (SQLite cannot add one); fresh installs take the tri-state
            // constraint on kev_known_ransomware from Schema.sql. All NULL on existing rows,
            // which is correct: NULL means no assertion, and the next refresh pass fills them.
            "ALTER TABLE vulnerabilities ADD COLUMN kev_known_ransomware INTEGER",
            "ALTER TABLE vulnerabilities ADD COLUMN kev_date_added TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN kev_due_date TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN epss_percentile REAL",
            // KEV/EPSS proxy-gate policies. Both default off so existing orgs see no
            // behaviour change until an operator opts in.
            "ALTER TABLE org_settings ADD COLUMN block_kev TEXT NOT NULL DEFAULT 'off'",
            "ALTER TABLE org_settings ADD COLUMN max_epss_tolerance REAL",
            // Narrower KEV arm (ransomware-campaign use only) and the EPSS percentile ceiling.
            // Both default off, so no existing org changes behaviour on upgrade. Added without
            // CHECKs (SQLite ALTER cannot add one); fresh installs take the vocabulary from
            // Schema.sql and the write path validates on both.
            "ALTER TABLE org_settings ADD COLUMN block_kev_ransomware TEXT NOT NULL DEFAULT 'off'",
            "ALTER TABLE org_settings ADD COLUMN max_epss_percentile_tolerance REAL",
            // Enrichment-overlay SSVC gate. Defaults off, and inert without a configured
            // tracker connection, so an upgraded deployment changes behaviour in no way.
            "ALTER TABLE org_settings ADD COLUMN block_ssvc_exploitation TEXT NOT NULL DEFAULT 'off'",
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
            // Per-tenant Terraform publisher-signed SHASUMS chain verification gate: 'off' (default) /
            // 'warn' / 'block'. Enabling requires at least one per-org Terraform PGP anchor in
            // signature_trust_anchor; without one the verifier reports not-applicable and nothing
            // blocks. Added without a CHECK (SQLite ALTER can't add one); upgraded DBs rely on
            // controller validation, fresh installs get the CHECK.
            "ALTER TABLE org_settings ADD COLUMN verify_terraform_signatures TEXT NOT NULL DEFAULT 'off'",
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
            // NuGet symbol-server base URL for this upstream. A symbol server is a different host
            // from the v3 index, so it cannot be derived from url; NULL disables symbol proxying
            // for the upstream, which is the fail-closed default.
            "ALTER TABLE upstream_registry ADD COLUMN symbol_server_url TEXT",
            // Terraform: which protocol this upstream speaks ('mirror', or NULL for the ecosystem
            // default). Fresh installs carry a CHECK from the CREATE TABLE block; SQLite cannot add
            // one via ALTER, so on an upgraded database the value set is held by
            // UpstreamRegistryRepository.IsSupportedProtocol at every write instead.
            "ALTER TABLE upstream_registry ADD COLUMN upstream_protocol TEXT",
            // Polymorphic owner on the symbol index so a PROXIED .snupkg — which has a
            // cache_artifact row and no package_versions row — can be indexed alongside hosted
            // ones. package_version_id also has to lose NOT NULL, which SQLite cannot do with
            // ALTER; the recreate-table reshape handles that provider.
            "ALTER TABLE nuget_symbol_index ADD COLUMN cache_artifact_id TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE",
            "ALTER TABLE nuget_symbol_index ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'package_version'",
            "CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_ca ON nuget_symbol_index (cache_artifact_id)",
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
            // slack_* columns above: email_enabled and email_recipients are the channel, the
            // email_last_*/email_consecutive_failures/email_failing_since columns its health. SMTP
            // itself is an instance-level transport, so no per-org transport column is added here —
            // the seven a previous release added are removed on every boot by
            // DropAlertSettingsRetiredSmtpColumnsAsync above. Re-adding them here would fight that
            // pass on every start.
            "ALTER TABLE alert_settings ADD COLUMN email_enabled INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE alert_settings ADD COLUMN email_recipients TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_last_delivery_at TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_last_status TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_consecutive_failures INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE alert_settings ADD COLUMN email_failing_since TEXT",
            "ALTER TABLE alert_settings ADD COLUMN email_last_error TEXT",
            // Terminal outcome of the async email delivery attempt on the alert row, mirroring
            // slack_status/slack_error.
            "ALTER TABLE alert ADD COLUMN email_status TEXT",
            "ALTER TABLE alert ADD COLUMN email_error TEXT",
            // Package-level metadata surfaced in the UI, captured at hosted publish and proxy
            // first-fetch from the artifact manifest (npm package.json, PyPI METADATA, NuGet
            // .nuspec, Maven .pom, Cargo.toml). All nullable; existing rows stay NULL until the
            // next publish/fetch repopulates them (no historical backfill).
            "ALTER TABLE packages ADD COLUMN homepage TEXT",
            "ALTER TABLE packages ADD COLUMN repository_url TEXT",
            "ALTER TABLE packages ADD COLUMN description TEXT",
            // Tenant content binding on the shared proxy-cache plane: the bytes this tenant
            // itself fetched and hashed for the coordinate. cache_artifact is global and carries
            // no org or upstream discriminator, so without these the per-tenant serve path has no
            // tenant-scoped fact to read and every tenant is served whichever bytes the first
            // tenant to reach the coordinate resolved from its own upstream. Nullable: an
            // existing row keeps NULL until backfill_tenant_artifact_access_binding runs, and a
            // row written by a preceding release during a blue-green cutover stays NULL, both of
            // which the serve projections resolve by falling back to the shared row.
            "ALTER TABLE tenant_artifact_access ADD COLUMN content_hash TEXT",
            "ALTER TABLE tenant_artifact_access ADD COLUMN blob_key TEXT",
            // Actor display name denormalized at write time — see the column comment in
            // Schema.sql. Service actors only; a user actor stays NULL so no email is
            // stored past the fixed column lists the erasure and retention sweeps null.
            "ALTER TABLE audit_log ADD COLUMN actor_label TEXT",
            "ALTER TABLE activity ADD COLUMN actor_label TEXT",
            // OCI moving-tag promotion gate: a newer digest observed upstream but not yet
            // promoted onto the tag. min_release_age_hours gates promotion (the tag keeps
            // resolving to the accepted digest until the pending one has been locally observed
            // long enough), never availability. NULL on existing rows — no observation held.
            // pending_first_seen_at's canonical-UTC CHECK reaches fresh installs from the
            // CREATE TABLE blocks; upgraded DBs rely on the canonical UtcTimestamp writers
            // (SQLite ALTER cannot add a CHECK), same as license_checked_at.
            "ALTER TABLE oci_tags ADD COLUMN pending_digest TEXT",
            "ALTER TABLE oci_tags ADD COLUMN pending_first_seen_at TEXT",
            // Third licence-policy posture: 'conditional' means the licence is acceptable only in
            // some contexts and the condition is recorded in note. Defaults to 'allowed' so every
            // existing row keeps the posture it already had. The CHECK reaches fresh installs from
            // the CREATE TABLE block; upgraded databases rely on controller-side validation
            // (SQLite ALTER cannot add a CHECK), the same treatment license_enforcement_mode got.
            "ALTER TABLE license_allowlist ADD COLUMN disposition TEXT NOT NULL DEFAULT 'allowed'",
            // Operator rationale on a policy row. Nullable: every pre-existing entry was recorded
            // without one, and an absent note is honestly "nobody wrote one down" rather than a
            // value to invent.
            "ALTER TABLE license_allowlist ADD COLUMN note TEXT",
            "ALTER TABLE license_allowlist ADD COLUMN created_by TEXT",
            "ALTER TABLE license_blocklist ADD COLUMN note TEXT",
            "ALTER TABLE license_blocklist ADD COLUMN created_by TEXT",
            // Third alert-raising gate, structurally mirroring quarantine_alerts_enabled and
            // vuln_alerts_enabled: raises an alert when a project version's SBOM policy
            // evaluation records a violation. Defaults on, like the other two.
            "ALTER TABLE alert_settings ADD COLUMN sbom_policy_alerts_enabled INTEGER NOT NULL DEFAULT 1",
            // Opt-in projects-plane retention cap: max project versions kept per project. NULL
            // (the default an upgraded database backfills to) is unlimited, matching keep_versions
            // and keep_days rather than materializing a cap over an existing catalogue.
            "ALTER TABLE org_settings ADD COLUMN keep_project_versions INTEGER",
            // Covers the nightly SBOM policy re-evaluation's DISTINCT (org_id, project_version_id).
            // Both columns are declared in the sbom_components CREATE TABLE block, never added by
            // a migration, so the schema files are its primary declaration site and this entry
            // only covers a database whose sbom_components predates the index.
            "CREATE INDEX IF NOT EXISTS idx_sbom_components_org_pv ON sbom_components(org_id, project_version_id)",
            // Durable first-observation instant for a finding — a registry (version × advisory)
            // link or a projects-plane (component × vuln) link. checked_at moves on every re-scan;
            // this column must not. Added nullable (SQLite cannot add a NOT NULL column with a
            // non-constant DEFAULT to a populated table) and converged from checked_at by
            // BackfillFindingsFirstSeenAtAsync, called on every boot rather than once — a row
            // written by a previous release's still-live binary during a blue-green cutover can
            // arrive with no first_seen_at value on any given boot. The CHECK reaches fresh
            // installs from the CREATE TABLE blocks; upgraded databases rely on the insert paths
            // always supplying a value.
            "ALTER TABLE package_version_vulns ADD COLUMN first_seen_at TEXT",
            "ALTER TABLE sbom_component_vulns ADD COLUMN first_seen_at TEXT",
            // Three more KEV catalogue fields already present in the same feed response
            // is_kev/kev_known_ransomware are parsed from, previously discarded: CISA's
            // prescribed remediation prose (requiredAction), the CWE classification array
            // (cwes), and vendor advisory/patch notes (notes). All NULL on existing rows —
            // the next refresh pass fills them, same as the other KEV columns above.
            // kev_cwes stores the array as a JSON TEXT column, matching the `aliases`
            // convention on this same table, rather than opaque prose.
            "ALTER TABLE vulnerabilities ADD COLUMN kev_required_action TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN kev_cwes TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN kev_notes TEXT",
            // Presentation metadata the CycloneDX component entry already carried and ingest
            // previously discarded: what the component is, who wrote it, and where it lives.
            // All nullable and display-only — no gate reads them. Existing rows stay NULL until
            // their document is re-merged, which project_documents.ingest_version below forces
            // exactly once rather than leaving to the next time a dependency happens to change.
            "ALTER TABLE sbom_components ADD COLUMN description TEXT",
            "ALTER TABLE sbom_components ADD COLUMN component_author TEXT",
            "ALTER TABLE sbom_components ADD COLUMN copyright TEXT",
            "ALTER TABLE sbom_components ADD COLUMN component_group TEXT",
            "ALTER TABLE sbom_components ADD COLUMN website_url TEXT",
            "ALTER TABLE sbom_components ADD COLUMN vcs_url TEXT",
            "ALTER TABLE sbom_components ADD COLUMN issue_tracker_url TEXT",
            "ALTER TABLE sbom_components ADD COLUMN distribution_url TEXT",
            "ALTER TABLE sbom_components ADD COLUMN component_hashes TEXT",
            // Which revision of the ingest projection wrote a document's rows. Defaults to 0,
            // below every real revision, so every document stored before this column existed
            // reads as stale and is re-merged once on its next upload — the alternative is a
            // byte-identical re-upload short-circuiting on sha256 alone and leaving the columns
            // above NULL for as long as a project's dependencies happen not to change.
            "ALTER TABLE project_documents ADD COLUMN ingest_version INTEGER NOT NULL DEFAULT 0",
            // Package-level author/publisher, from the same manifest parse that already captures
            // homepage/repository/description at hosted publish and proxy first-fetch.
            "ALTER TABLE packages ADD COLUMN author TEXT",
            // Tracker enrichment overlay, second installment, on the same shared table nvd_*/ssvc_*
            // already live on: OpenSSF malicious-packages live-status, exploit-code observation, and
            // the CVE Program (cvelistV5) CVSS/CWE/SSVC overlay. The version-precise still-live
            // derived signal is DELIBERATELY NOT here — see the package_version_vulns migration
            // below for why it lives there instead. Added without CHECKs (SQLite ALTER cannot add
            // one), matching the nvd_*/ssvc_* precedent above: upgraded databases rely on the write
            // path's own validation, fresh installs get the vocabulary CHECKs from Schema.sql. All
            // NULL/0 on existing rows, which is exactly the unenriched state, so nothing needs
            // backfilling.
            "ALTER TABLE vulnerabilities ADD COLUMN mal_compromised_versions TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN mal_version_compromised INTEGER",
            "ALTER TABLE vulnerabilities ADD COLUMN mal_still_live INTEGER",
            "ALTER TABLE vulnerabilities ADD COLUMN mal_live_checked_at TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN mal_live_versions TEXT",
            // The version-precise still-live derived signal lives on package_version_vulns, not
            // vulnerabilities: "is this version still live" is a fact about the (advisory, version)
            // pair by construction (mal_compromised_versions/mal_live_versions are lists for
            // exactly that reason), and this table is already the version-precise link between one
            // owner and one advisory — see Schema.sql for the full rationale.
            "ALTER TABLE package_version_vulns ADD COLUMN mal_still_live_for_version INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE vulnerabilities ADD COLUMN exploit_code_exists INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE vulnerabilities ADD COLUMN exploit_code_max_weight INTEGER",
            "ALTER TABLE vulnerabilities ADD COLUMN exploit_code_sources TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvelist_cvss_score REAL",
            "ALTER TABLE vulnerabilities ADD COLUMN cvelist_cvss_severity TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvelist_cvss_provenance TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvelist_cwes TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvelist_ssvc_exploitation TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvelist_ssvc_automatable TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvelist_ssvc_technical_impact TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvelist_checked_at TEXT",
            // Narrower companion to block_malicious — see Schema.sql. Defaults 'off' deliberately:
            // this arm is new behaviour on an existing deployment's serving posture, so it must be
            // opt-in on upgrade, not silently active. Added without a CHECK (SQLite ALTER cannot
            // add one); upgraded DBs rely on controller validation, fresh installs get the CHECK
            // from Schema.sql.
            "ALTER TABLE org_settings ADD COLUMN block_malicious_live TEXT NOT NULL DEFAULT 'off'",
            // The two component fields CycloneDX 1.7 added. Both nullable and display-only — no
            // gate reads either. is_external carries no CHECK here because SQLite's ALTER cannot
            // add one; fresh installs get CHECK (is_external IN (0,1)) from Schema.sql and
            // upgraded databases rely on the write path, which only ever binds 0, 1 or NULL.
            // Existing rows stay NULL until their document re-merges, which the SbomIngestVersion
            // bump forces exactly once.
            "ALTER TABLE sbom_components ADD COLUMN version_range TEXT",
            "ALTER TABLE sbom_components ADD COLUMN is_external INTEGER",
            // Provenance for dependency_scope (SPEC-650's manifest fill added a second writer to a
            // column the SARIF retraction sweep previously assumed it owned outright). NULL on an
            // upgraded database's existing rows is exactly correct — nothing yet recorded who set
            // them — and the sweep in SbomIngestRepository.ResetUnnamedDependencyScopeAsync only
            // ever resets a 'scanner' row, so an existing non-'unknown' value with no source stays
            // put rather than being reset by a NULL-matches-nothing accident; the next SBOM or
            // SARIF that actually asserts something for that component stamps the source honestly
            // from then on. No CHECK here (SQLite ALTER cannot add one); fresh installs get it
            // from Schema.sql.
            "ALTER TABLE sbom_components ADD COLUMN dependency_scope_source TEXT",
            // Whether an application, and each of its releases, is still in service. Both backfill
            // to 1 on an upgraded database, which is the only honest value: the blast radius
            // counted every latest version before this column existed, so defaulting to active
            // preserves what those installs already reported instead of silently retiring a
            // catalogue nobody has triaged yet. Neither carries a CHECK — SQLite ALTER cannot add
            // one, and the write paths bind 0 or 1 and nothing else.
            "ALTER TABLE projects ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE project_versions ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1",
            // The ONLY declaration site for this index, deliberately absent from Schema.sql and
            // Schema.pg.sql: those run in full before this pass, so an index naming is_active
            // there resolves against the table shape that predates the ALTER above and throws on
            // every upgrade boot. It covers the active-but-not-latest arm of the in-service
            // predicate, and is partial because those rows are the minority in any catalogue that
            // retires anything. Fresh installs are covered too — this pass runs unconditionally.
            // It moves into the schema files a release after is_active ships.
            "CREATE INDEX IF NOT EXISTS idx_project_versions_active ON project_versions (project_id) WHERE is_active = 1",
    };

    private async Task RunAdditiveMigrationsAsync(DbConnection conn)
    {
        foreach (string? ddl in BuildAdditiveMigrations())
        {
            await ApplyAdditiveAsync(conn, ddl);
        }

        // org_settings.storage_used_bytes is dormant capacity: nothing in this release reads or
        // writes it, and every quota check derives a tenant's stored bytes from the org_storage_bytes
        // view instead. It is re-added here — and declared in both schema files — so that a slot of
        // the preceding release, which still increments the counter, keeps working against this
        // schema for the whole blue-green cutover window. The width is provider-specific (SQLite
        // INTEGER is 64-bit; Postgres INTEGER is 32-bit and would overflow at 2 GiB), so this runs
        // outside the shared loop with explicit branching, like the cargo_metadata table below.
        await ApplyAdditiveAsync(conn, _db.Provider == DbProvider.Sqlite
            ? "ALTER TABLE org_settings ADD COLUMN storage_used_bytes INTEGER NOT NULL DEFAULT 0"
            : "ALTER TABLE org_settings ADD COLUMN storage_used_bytes BIGINT NOT NULL DEFAULT 0");

        // The size half of the tenant content binding. Width is provider-specific for the same
        // reason storage_used_bytes is (SQLite INTEGER is 64-bit; Postgres INTEGER is 32-bit and
        // would overflow at 2 GiB), so it runs outside the shared loop.
        await ApplyAdditiveAsync(conn, _db.Provider == DbProvider.Sqlite
            ? "ALTER TABLE tenant_artifact_access ADD COLUMN size_bytes INTEGER"
            : "ALTER TABLE tenant_artifact_access ADD COLUMN size_bytes BIGINT");

        // The only declaration site for this index. It deliberately does NOT appear in Schema.sql /
        // Schema.pg.sql: those run in full before this pass, so on an upgrading database a
        // CREATE INDEX naming blob_key there resolves against the table shape that predates the
        // ALTER above. Fresh installs are covered here too, because this pass runs unconditionally.
        await conn.ExecuteAsync(
            "CREATE INDEX IF NOT EXISTS idx_tenant_artifact_access_blob_key "
            + "ON tenant_artifact_access (blob_key)");

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

    // Postgres-only. Three columns were declared TIMESTAMPTZ while their SQLite counterparts —
    // and every reader on both providers — use the canonical ISO-8601 TEXT form. Reading
    // upstream_negative_cache.fetched_at into a string therefore failed on Postgres, and the
    // comparisons against it depended on an implicit cast of the bound text parameter.
    // Converts in place, rendering the stored instants in UTC so they collate with the values
    // written from here on. Skips a column that is already TEXT, so this is a no-op on a fresh
    // database created from the current schema and safe to re-run.
    private async Task ConvertLegacyTimestamptzColumnsAsync(DbConnection conn)
    {
        if (_db.Provider != DbProvider.Postgres)
        {
            return;
        }

        (string Table, string Column)[] columns =
        [
            ("upstream_negative_cache", "fetched_at"),
            ("npm_dist_tags", "created_at"),
            ("npm_dist_tags", "updated_at"),
        ];

        foreach (var (table, column) in columns)
        {
            string? dataType = await conn.ExecuteScalarAsync<string?>(
                """
                SELECT data_type FROM information_schema.columns
                WHERE table_name = @table AND column_name = @column
                """,
                new { table, column });

            if (!string.Equals(dataType, "timestamp with time zone", StringComparison.Ordinal))
            {
                continue;
            }

            // rawsql: the table and column names come from the hard-coded list above, never from
            // data or configuration, and Postgres has no parameter form for a DDL identifier.
            await conn.ExecuteAsync(
                $"""
                ALTER TABLE {table}
                    ALTER COLUMN {column} DROP DEFAULT,
                    ALTER COLUMN {column} TYPE TEXT
                        USING to_char({column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    ALTER COLUMN {column} SET DEFAULT
                        (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
                """);
        }
    }

    // Applies one additive DDL statement, duplicate-column-safe on both providers: SQLite swallows
    // the duplicate-column error, Postgres gets the IF NOT EXISTS form.
    private async Task ApplyAdditiveAsync(DbConnection conn, string ddl)
    {
        if (_db.Provider == DbProvider.Sqlite)
        {
            await MigrateSqliteAsync(conn, ddl);
            return;
        }

        await conn.ExecuteAsync(ddl.Replace("ADD COLUMN ", "ADD COLUMN IF NOT EXISTS "));
    }
}
