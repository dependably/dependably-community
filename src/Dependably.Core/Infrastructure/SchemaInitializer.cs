using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using Dapper;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.RowLevelSecurity;
using Dependably.Protocol;
using Dependably.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

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
    private readonly TimeProvider _time;

    // Postgres server_version_num, read at the start of each Postgres boot; null on SQLite.
    private int? _postgresServerVersionNum;

    // [ModuleInitializer], not a static constructor: Dapper caches its compiled "add parameters"
    // emitter per (SQL text, parameter CLR type) the first time that pair is ever executed, and
    // that cached emitter is what decides whether a raw DateTimeOffset parameter goes through
    // DateTimeOffsetHandler.SetValue or the ADO.NET provider's own default serialization — the
    // decision is baked in at first compilation, not re-checked on every call. A static
    // constructor only runs the first time SchemaInitializer itself is touched, which nothing
    // guarantees happens before some OTHER query already bound a DateTimeOffset parameter (a
    // health check, a lockout-store read, anything reachable before schema init runs) and
    // permanently cached the wrong emitter for that (SQL, type) pair — silently, for the rest of
    // the process, with no ordering enforced or tested. A module initializer runs the moment this
    // assembly's module is loaded, before the first member access anywhere in
    // Dependably.Core — which every composition root (Dependably, Dependably.Edge) references
    // and touches immediately on boot — so it always wins the race regardless of what else in
    // the process happens to run first.
    [ModuleInitializer]
    [SuppressMessage("Design", "CA2255:The 'ModuleInitializer' attribute is only intended to be used in application code or advanced source generator scenarios",
        Justification = "A Dapper global type-handler registration has to win a race against every other " +
            "query's first execution, in a class library every composition root references — that is " +
            "exactly what ModuleInitializer is for, application-code framing in the analyzer's own message " +
            "notwithstanding.")]
    internal static void RegisterDateTimeOffsetHandler()
    {
        // SQLite/Postgres both store these columns as TEXT (ISO 8601). Register a type handler
        // so Dapper can map TEXT columns to DateTimeOffset in record constructors.
        //
        // RemoveTypeMap is required, not cosmetic: Dapper's built-in typeMap already recognises
        // DateTimeOffset and infers DbType.DateTimeOffset for it on the PARAMETER (write) side,
        // and that inference wins over a registered ITypeHandler unless the type is first
        // removed from typeMap — so without these two calls, DateTimeOffsetHandler.SetValue
        // below is never invoked, and every raw-DateTimeOffset parameter falls through to the
        // ADO.NET provider's own default serialization instead (Microsoft.Data.Sqlite renders
        // "yyyy-MM-dd HH:mm:ss.fffffffzzz" — space-separated, offset preserved, not the
        // canonical `Z` form every other writer of these columns uses). The READ (Parse) side is
        // unaffected by typeMap — it already went through the handler regardless.
        SqlMapper.RemoveTypeMap(typeof(DateTimeOffset));
        SqlMapper.RemoveTypeMap(typeof(DateTimeOffset?));
        SqlMapper.AddTypeHandler(new DateTimeOffsetHandler());
    }

    public SchemaInitializer(
        IMetadataStore db,
        ILogger<SchemaInitializer>? logger = null,
        SpdxLicenseSeeder? spdxSeeder = null,
        IConfiguration? config = null,
        TimeProvider? time = null)
    {
        _db = db;
        _logger = logger ?? NullLogger<SchemaInitializer>.Instance;
        // Test ctors that pass only the IMetadataStore get a seeder with a null logger —
        // the embedded JSON is still read so the spdx_license table is populated.
        _spdxSeeder = spdxSeeder ?? new SpdxLicenseSeeder(NullLogger<SpdxLicenseSeeder>.Instance);
        // Optional: drives upstream-registry default URLs from config overrides during the
        // backfill. Null in lightweight test ctors — falls back to the hard-coded public defaults.
        _config = config;
        // Drives the bounded wait for the Postgres migration lock. Lightweight test ctors that
        // pass only the store fall back to the system clock.
        _time = time ?? TimeProvider.System;
    }

    /// <param name="afterBaseSchema">
    /// Invoked once the base schema has been applied and before any one-time migration runs.
    /// <see cref="CoreStartupService"/> passes the SQLite single-writer claim here rather than
    /// taking it after the whole apply: the migration sequence is the longest and least
    /// interruptible stretch of startup, and leaving it outside the guard is what let two
    /// processes sharing one database file both enter it. It cannot be hoisted any earlier than
    /// this, because the guard's own <c>instance_lock</c> table is created by the base schema.
    /// </param>
    public async Task InitializeAsync(
        Func<CancellationToken, Task>? afterBaseSchema = null, CancellationToken ct = default)
    {
        string sql = await ReadSchemaAsync(_db.Provider, ct);
        // xtenant: schema DDL and one-time migrations run as the owner and span every tenant.
        await using var conn = await _db.OpenCrossTenantAsync("schema apply and migrations", ct);

        // Serialize the entire apply across processes so replicas booting together against one
        // Postgres run the DDL and the one-time migrations exactly once instead of racing them
        // (SchemaInitializer.MigrationLock.cs). No-op on SQLite.
        bool locked = await TryAcquireMigrationLockAsync(conn, ct);
        try
        {
            // Before the schema: the view DDL declares security_invoker wherever the server supports
            // it, whatever this node's row-level-security mode, so the server version is read first.
            await ProbePostgresServerVersionAsync(conn, ct);
            // Before anything is changed: a database below the upgrade floor is refused untouched
            // (SchemaInitializer.UpgradeFloor.cs).
            await EnforceUpgradeFloorAsync(conn);
            await ApplySchemaAsync(conn, sql, ct, afterBaseSchema);
            await ApplyRowLevelSecurityAsync(conn, ct);
        }
        finally
        {
            if (locked)
            {
                await ReleaseMigrationLockAsync(conn);
            }
        }
    }

    // Reads the server version on every Postgres boot, because the view DDL keys security_invoker on
    // it. A defaulted enforce on Postgres older than 15 falls back to owner sessions here, before the
    // view DDL runs. An explicit enforce continues with plain views, and boot verification refuses
    // it, naming both the server version and the views that are not security_invoker.
    private async Task ProbePostgresServerVersionAsync(DbConnection conn, CancellationToken ct)
    {
        if (_db.Provider != DbProvider.Postgres)
        {
            return;
        }

        int version = await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT current_setting('server_version_num')::int", cancellationToken: ct));
        _postgresServerVersionNum = version;
        if (EnforcedRowLevelSecurity is { Explicit: false }
            && version < PostgresRowLevelSecurityInstaller.MinimumServerVersionNum)
        {
            FallBackToOwnerSessions(
                $"Postgres server_version_num {version} is below {PostgresRowLevelSecurityInstaller.MinimumServerVersionNum}.");
        }
    }

    // The default never blocks startup: run with row-level security off, exactly as before the
    // backstop existed, and say why.
    private void FallBackToOwnerSessions(string reason)
    {
        ((NpgsqlMetadataStore)_db).FallBackToOwnerSessions(reason);
        DependablyMeter.RecordRowLevelSecurityEnforced(false);
        _logger.LogWarning(
            "Postgres row-level security is on by default for this multi-tenant deployment but could not be "
            + "enabled, so the node runs without it and the application's org_id filter remains the isolation "
            + "layer: {Reason} Fix the cause to enable it, or set {Setting}=off to acknowledge running without it.",
            reason, RowLevelSecurityOptions.ModeKey);
    }

    /// <summary>Row-level security settings when the store enforces them; null otherwise.</summary>
    private RowLevelSecurityOptions? EnforcedRowLevelSecurity =>
        _db is NpgsqlMetadataStore { RowLevelSecurity.Enforced: true } pg ? pg.RowLevelSecurity : null;

    // Last, after every table, migration and view exists: coverage is derived from the live
    // catalogue, so it has to see the final shape — including a table a reshape just recreated
    // without its policy. Then refuse to boot on anything that would leave the backstop open.
    private async Task ApplyRowLevelSecurityAsync(DbConnection conn, CancellationToken ct)
    {
        if (EnforcedRowLevelSecurity is not { } options)
        {
            return;
        }

        var problems = new List<string>();
        try
        {
            await PostgresRowLevelSecurityInstaller.ApplyAsync(conn, options);
            problems.AddRange(await PostgresRowLevelSecurityInstaller.FindProblemsAsync(conn, options));
            if (problems.Count == 0)
            {
                problems.AddRange(await PostgresRowLevelSecurityInstaller.ProbeTenantSessionAsync(_db, options, ct));
            }
        }
        catch (PostgresException ex) when (!options.Explicit && !ex.IsTransient)
        {
            // A defaulted enforce on a database that refuses to host it — typically a connecting
            // role without CREATEROLE — falls back below; an explicit enforce lets the error stop
            // boot. A dropped connection or a transient server error is not a refusal: it stops
            // boot too, so a blip can never switch the backstop off for the life of the process.
            problems.Add($"{ex.GetType().Name}: {ex.Message}");
        }

        if (problems.Count > 0)
        {
            if (options.Explicit)
            {
                throw new InvalidOperationException(
                    $"{RowLevelSecurityOptions.ModeKey}=enforce, but row-level security would not hold: "
                    + string.Join(" ", problems));
            }

            FallBackToOwnerSessions(string.Join(" ", problems));
            return;
        }

        DependablyMeter.RecordRowLevelSecurityEnforced(true);
        _logger.LogInformation(
            "Postgres row-level security enforced: tenant connections run as {RlsRole}", options.RoleName);
    }

    private async Task ApplySchemaAsync(
        DbConnection conn, string sql, CancellationToken ct, Func<CancellationToken, Task>? afterBaseSchema = null)
    {
        await ApplyBaseSchemaAsync(conn, sql, afterBaseSchema, ct);
        await ApplyOneTimeMigrationsAsync(conn);
        await ApplyPostMigrationConvergenceAsync(conn, sql);
    }

    // Phase 1 — the renames that must precede CREATE TABLE, the declarative schema itself, the
    // single-writer claim it makes possible, and the additive column/seed passes.
    private async Task ApplyBaseSchemaAsync(
        DbConnection conn, string sql, Func<CancellationToken, Task>? afterBaseSchema, CancellationToken ct)
    {
        // Table renames must happen BEFORE the CREATE TABLE IF NOT EXISTS pass — otherwise the
        // schema would create empty sibling tables under the new names alongside the original
        // data. _applied_migrations is ensured up front so RunOnceAsync can record the ledger.
        await EnsureMigrationsTableAsync(conn);

        // Views are dropped lazily — RunOnceAsync takes the drop immediately before the first
        // pending migration body that declares dropsViews, so a boot with no pending reshape never
        // removes an object a concurrently-serving replica is reading (see SchemaInitializer.Views.cs).
        _viewsDropped = false;

        await RunOnceAsync(conn, "rename_tokens_to_user_tokens", RenameTokensTableAsync, dropsViews: true);
        await RunOnceAsync(conn, "rename_cicd_tokens_to_service_tokens", RenameCicdTokensTableAsync, dropsViews: true);

        await conn.ExecuteAsync(sql);

        // The base schema has now created instance_lock, so the single-writer guard can finally be
        // claimed — before the one-time migrations, which are the part of startup worth guarding:
        // they are non-idempotent, some run unwrapped by transaction, and a large database can
        // spend minutes in them. The two table renames above stay outside the guard because they
        // must precede the CREATE TABLE pass that makes the lock's own table exist; both are
        // long-since ledgered on any database that has them, and on a fresh one there is nothing
        // to rename.
        if (afterBaseSchema is not null)
        {
            await afterBaseSchema(ct);
        }

        await RunAdditiveMigrationsAsync(conn);
        await _spdxSeeder.RunAsync(conn, ct);
    }

    // The repairs that run on every boot rather than once per database. Each is unledgered for
    // the reason its comment gives, and they run before any ledgered migration.
    private async Task RunUnledgeredRepairsAsync(DbConnection conn)
    {
        // Canonicalize stored account emails and install the case-insensitive unique indexes.
        // Deliberately not a ledgered one-shot and deliberately not part of the base schema file:
        // a database already holding case-variant duplicate accounts cannot take the index, and it
        // must be retried on a later boot rather than recorded as done or aborting the apply.
        await EnsureEmailCaseInsensitiveUniquenessAsync(conn);

        // Removes the retired per-org SMTP transport columns from alert_settings. Deliberately not
        // a ledgered one-shot either, and for a different reason: a previous release's own additive
        // list still re-adds all seven, so a slot of that release booting against this database
        // resurrects them. A ledgered drop would already read as done and never run again, leaving
        // the live schema permanently — and invisibly — diverged from the schema file. Repeating the
        // drop is what makes the two converge. See DropAlertSettingsRetiredSmtpColumnsAsync.
        await DropAlertSettingsRetiredSmtpColumnsAsync(conn);

        // Removes the retired package_note table. Unledgered for the same reason as the drop
        // above: the previous release still declares package_note in its own base schema, so a
        // slot of that release booting against this database re-creates it. A ledgered drop would
        // already read as done and never run again, leaving the table behind permanently and
        // invisibly — the backward-compatibility gate is declarative and never reads a live
        // database. Repeating the drop is what makes the two converge.
        await DropPackageNoteTableAsync(conn);

        // Folds stored project_vuln_analysis.purl_key values onto the canonical form every reader
        // derives, so a triage decision keyed on a client's own spelling stops being invisible to
        // the policy evaluator. Runs before the case-variant reconciliation below, so a row it
        // merges onto a canonical key is available for that pass to collapse in the same boot.
        // See SchemaInitializer.VulnAnalysisPurlKeys.cs.
        await NormalizeVulnAnalysisPurlKeysAsync(conn);

        // Folds stored quarantine.purl values for OCI onto the canonical form the block gate
        // derives, so an approval recorded against the old interpolated spelling keeps unblocking
        // after the controllers started asking under the canonical one. See
        // SchemaInitializer.OciPurlCanonicalization.cs.
        await CanonicalizeOciQuarantinePurlsAsync(conn);

        // Collapses case-variant duplicate project_vuln_analysis rows onto the one row every reader
        // already resolves to, merging both arms. Unledgered for a third reason again: the
        // remaining duplicate-producing race is a runtime one under Postgres, so the repair has to
        // be able to run after any boot, not once per database. A grouped probe makes it free on a
        // database that holds none. See SchemaInitializer.VulnAnalysisReconciliation.cs.
        await ReconcileVulnAnalysisCaseVariantsAsync(conn);

        // Rewrites the one vex_justification spelling that is not a CycloneDX value onto the one
        // that is. Unledgered for the blue-green reason: a previous-release slot serving against
        // this database still admits the retired spelling, so a one-shot recorded as applied would
        // leave cutover-window rows wrong forever. See SchemaInitializer.VexJustificationVocabulary.cs.
        await NormalizeVexJustificationVocabularyAsync(conn);
    }

    // Phase 3 — the views (which need every table and column to exist) and the convergence sweeps
    // that deliberately run on every boot rather than once, so a blue-green cutover cannot strand
    // rows the old binary writes during the window.
    private async Task ApplyPostMigrationConvergenceAsync(DbConnection conn, string sql)
    {

        // Last, after every migration: the view bodies can only be created once every table and
        // column they reference is guaranteed to exist.
        await EnsureViewsAsync(conn);

        // Deliberately NOT a RunOnceAsync migration — see the class summary on
        // SchemaInitializer.TimestampNormalization.cs for why a one-shot repair here would let a
        // blue-green cutover permanently re-poison these columns. Runs after EnsureViewsAsync so
        // it never needs the views dropped: it is a plain UPDATE against base tables, not a
        // table reshape.
        await NormalizeLegacyDateTimeOffsetColumnsAsync(conn);

        // Brings an existing Postgres database up to the canonical-timestamp CHECK a fresh install
        // gets from CREATE TABLE (SchemaInitializer.TemporalCheckRetrofit.cs). Ordered immediately
        // after the sweep so the rows it repairs are already canonical when VALIDATE CONSTRAINT
        // scans them — a legacy shape the sweep reaches never costs the column its validation.
        // Not ledger-gated: idempotency is the per-column pg_constraint probe, which is also what
        // makes a temporal column added by a future release get retrofitted with no new code.
        var retrofitPass = new RetrofitPass(_time, RetrofitPassBudget);
        await RetrofitTemporalChecksAsync(conn, sql, retrofitPass);

        // The same retrofit for every other column-level CHECK and foreign key Schema.pg.sql
        // declares: columns that reached an existing table through the additive ALTER list arrive
        // without them (SchemaInitializer.ColumnConstraintRetrofit.cs). After the temporal retrofit
        // so the two never contend for the same table lock within one boot; they share one deadline and one
        // set of locked tables, and the deferral summary is logged once here.
        await RetrofitColumnConstraintsAsync(conn, sql, retrofitPass);
        retrofitPass.LogSummary(_logger);

        // Removes the pre-owner-shape UNIQUE key on nuget_symbol_index that upgraded Postgres
        // databases kept and fresh installs never had (SchemaInitializer.SymbolOwner.cs).
        await DropLegacySymbolIndexUniqueKeyAsync(conn);

        // Re-collates oci_scan_coverage.matched_at to COLLATE "C" on a Postgres database that
        // created the table without it (SchemaInitializer.OciScanCoverageCollation.cs).
        await ConvergeOciScanCoverageMatchedAtCollationAsync(conn);

        // Converges first_seen_at on package_version_vulns/sbom_component_vulns from checked_at —
        // deliberately NOT a RunOnceAsync migration, the same posture as
        // NormalizeLegacyDateTimeOffsetColumnsAsync above and for the identical reason: a blue-green
        // cutover leaves the OLD binary's LinkVersionVulnAsync/LinkCacheArtifactVulnAsync/
        // LinkComponentVulnAsync running against the NEW schema for the whole window, inserting
        // (registry plane) or upserting (SBOM plane, whose conflict clause never touches
        // first_seen_at) rows with no first_seen_at value. A one-shot, ledger-gated backfill would
        // apply once during green's own boot and then never run again, permanently stranding every
        // row blue writes after that point at NULL. Running the sweep every boot instead converges
        // blue's writes the next time either binary boots, for the lifetime of the deployment. The
        // UPDATE is idempotent (WHERE first_seen_at IS NULL) and index-free but cheap: it matches
        // nothing once every row already carries a value.
        await BackfillFindingsFirstSeenAtAsync(conn);

        // Records every (org, ecosystem) that has a credentialed upstream in
        // upstream_credential_history, so its proxied objects never become edge-cacheable once
        // that upstream is deleted. Every boot rather than once, for the blue-green reason above:
        // the previous release writes credentialed upstreams without recording them. See
        // SchemaInitializer.UpstreamCredentialHistory.cs.
        await ConvergeUpstreamCredentialHistoryAsync(conn);

        // Derives vulnerability_aliases for every advisory whose aliases the side table does not
        // yet reflect. Every boot rather than once, for the blue-green reason above: the previous
        // release writes vulnerabilities rows without maintaining the table, and a lookup that
        // resolves through it would otherwise miss those advisories for as long as it runs. The
        // first boot after an upgrade is the backfill; afterwards the sweep matches nothing.
        // Bounded by what the boot's shared deadline has left, like the alias-donor sweep below: both
        // run inside the migration lock, so on a large instance they yield it before a peer waiting
        // for that lock gives up, and the threat-feed refresh converges the rest.
        int aliasRowsReconciled = await VulnerabilityAliasIndex.ReconcileAsync(
            conn, _time, timeBudget: retrofitPass.Remaining);
        if (aliasRowsReconciled > 0)
        {
            _logger.LogInformation(
                "Alias index reconciled for {Advisories} advisories.", aliasRowsReconciled);
        }

        // Resolves the alias-donor values of every owner with a link that has none, or whose
        // advisory changed since: the first boot after an upgrade is the backfill (about 4.5 s per
        // 100,000 links on Postgres), and afterwards the sweep reaches only what the previous
        // release wrote during a blue-green window. Every boot, for the blue-green reason above; the
        // scan service repeats it after each tick, which is where anything the deadline cut off is
        // finished. Readers resolve an unresolved link's donor in the query meanwhile.
        var (linksResolved, sweepFinished) = await VulnerabilityRepository.ResolveStaleAliasDonorsWithinAsync(
            conn, _time, retrofitPass.Remaining);
        if (linksResolved > 0)
        {
            _logger.LogInformation(
                "Alias donor values resolved for {Links} vulnerability links.", linksResolved);
        }

        if (!sweepFinished)
        {
            _logger.LogWarning(
                "The {Budget} boot convergence budget was spent before the alias donor sweep finished; the "
                + "migration lock is released now and the scan tick resolves the remaining links.",
                RetrofitPassBudget);
        }
    }

    // Projects oci_blobs.license_spdx onto whichever catalogue row the image cast — the
    // package_versions row for a tag push, the cache_artifact row for a proxy pull. Both arms key on
    // the manifest digest, which is what the version column holds for OCI on either plane.
    //
    // The id is derived by concatenation rather than generated: there is no RNG portable across both
    // providers (randomblob is SQLite-only, gen_random_uuid() is Postgres-only), and an owner carries
    // at most one label-derived license row, so 'ocilic-' || <owner id> is unique by construction.
    private static async Task BackfillOciLicensesToSharedPlaneAsync(DbConnection conn)
    {
        // xtenant: one-shot backfill across every tenant on the instance; each arm still joins the
        // image's own org through packages.org_id / tenant_artifact_access.org_id.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses (id, package_version_id, owner_kind, license_spdx, source)
            SELECT 'ocilic-' || pv.id, pv.id, 'package_version', ob.license_spdx, 'oci-label'
            FROM oci_blobs ob
            JOIN packages p ON p.org_id = ob.org_id AND p.ecosystem = 'oci'
            JOIN package_versions pv
              ON pv.package_id = p.id AND pv.version = ob.digest AND pv.origin = 'uploaded'
            WHERE ob.license_spdx IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM package_version_licenses x
                  WHERE x.package_version_id = pv.id AND x.license_spdx = ob.license_spdx)
            ON CONFLICT DO NOTHING
            """);

        // xtenant: see above — the proxy arm scopes to the holder through tenant_artifact_access.
        // cache_artifact is GLOBAL (one row per digest) while oci_blobs is per-org, so two orgs that
        // both proxied the same licensed image make the SELECT emit two rows with the same derived id
        // ('ocilic-' || ca.id). The NOT EXISTS guard only sees pre-statement state, not intra-statement
        // duplicates, so ON CONFLICT DO NOTHING is what keeps this from a PK/unique violation that
        // would roll the (transactional) migration back and crash-loop the boot on a multi-tenant
        // upgrade. One license row per cache_artifact is correct — the licence is a property of the
        // image bytes, shared across every tenant holding the digest.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses (id, cache_artifact_id, owner_kind, license_spdx, source)
            SELECT 'ocilic-' || ca.id, ca.id, 'cache_artifact', ob.license_spdx, 'oci-label'
            FROM oci_blobs ob
            JOIN cache_artifact ca ON ca.ecosystem = 'oci' AND ca.version = ob.digest
            JOIN tenant_artifact_access taa
              ON taa.cache_artifact_id = ca.id AND taa.org_id = ob.org_id
            WHERE ob.license_spdx IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM package_version_licenses x
                  WHERE x.cache_artifact_id = ca.id AND x.license_spdx = ob.license_spdx)
            ON CONFLICT DO NOTHING
            """);
    }

    private static Task BackfillPackageVersionFilesPypiAsync(DbConnection conn)
        => BackfillPackageVersionFilesAsync(conn, "pypi");

    private static Task BackfillPackageVersionFilesNuGetAsync(DbConnection conn)
        => BackfillPackageVersionFilesAsync(conn, "nuget");

    // One file row per hosted version of a multi-file ecosystem, projected from the version row's
    // own blob/filename/size/checksum columns. Idempotent under retry: rows whose
    // (version, filename) slot is already occupied are skipped.
    //
    // The parent's size_bytes is deliberately left alone. It already equals this single artifact's
    // size, which is exactly the SUM the one projected file row produces, so there is nothing to
    // restore — and recomputing it through the repository would also NULL vuln_checked_at and
    // throw every backfilled version back into the unscanned bucket on upgrade.
    private static async Task BackfillPackageVersionFilesAsync(DbConnection conn, string ecosystem)
    {
        var rows = (await conn.QueryAsync<(string VersionId, string OrgId, string? Filename, string BlobKey, long SizeBytes, string? ChecksumSha256, string CreatedAt)>(
            // xtenant: one-shot backfill over every tenant's hosted versions of this ecosystem;
            // each projected row carries its own p.org_id into the package_version_files row it
            // creates.
            """
            SELECT pv.id AS VersionId, p.org_id AS OrgId, pv.filename AS Filename,
                   pv.blob_key AS BlobKey, pv.size_bytes AS SizeBytes,
                   pv.checksum_sha256 AS ChecksumSha256, pv.created_at AS CreatedAt
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = @ecosystem AND pv.origin = 'uploaded'
              AND NOT EXISTS (SELECT 1 FROM package_version_files f WHERE f.package_version_id = pv.id)
            """, new { ecosystem })).ToList();

        foreach (var (versionId, orgId, rowFilename, blobKey, sizeBytes, checksumSha256, createdAt) in rows)
        {
            int lastSlash = blobKey.LastIndexOf('/');
            string filename = string.IsNullOrEmpty(rowFilename)
                ? (lastSlash >= 0 ? blobKey[(lastSlash + 1)..] : blobKey)
                : rowFilename;
            await conn.ExecuteAsync(
                """
                INSERT INTO package_version_files
                    (id, package_version_id, org_id, filename, blob_key, size_bytes, checksum_sha256, created_at)
                VALUES (@id, @versionId, @orgId, @filename, @blobKey, @sizeBytes, @checksumSha256, @createdAt)
                ON CONFLICT (package_version_id, filename) DO NOTHING
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    versionId,
                    orgId,
                    filename,
                    blobKey,
                    sizeBytes,
                    checksumSha256,
                    createdAt,
                });
        }
    }

    // Rewrites claim.name to the canonical per-ecosystem key so admin-created claims match the
    // name every enforcement site resolves by. Runs on both providers via the same C# path
    // (PurlNormalizer.CanonicalName); the UPDATE statements are provider-specific only for the
    // now() timestamp expression. Idempotent: already-canonical rows are skipped.
    private async Task NormalizeClaimNamesCanonicalAsync(DbConnection conn)
    {
        // xtenant: one-shot normalization reads every tenant's claim rows; the UPDATE below rewrites
        // only the row it read, keyed by that row's own PK id.
        var rows = (await conn.QueryAsync<(string Id, string OrgId, string Ecosystem, string Name)>(
            "SELECT id AS Id, org_id AS OrgId, ecosystem AS Ecosystem, name AS Name FROM claim WHERE deleted_at IS NULL")).ToList();

        bool pg = _db.Provider == DbProvider.Postgres;
        // xtenant: one-shot normalization keyed by each claim row's own PK id; the loop visits
        // every tenant's rows and rewrites only the row it read.
        string renameSql = pg
            ? "UPDATE claim SET name = @canonical, updated_at = to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') WHERE id = @id"
            : "UPDATE claim SET name = @canonical, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @id";
        // xtenant: soft-deletes the row identified by its own PK id when a canonical twin exists.
        string softDeleteSql = pg
            ? "UPDATE claim SET deleted_at = to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')," +
              " updated_at = to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') WHERE id = @id"
            : "UPDATE claim SET deleted_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')," +
              " updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @id";

        foreach (var (Id, OrgId, Ecosystem, Name) in rows)
        {
            string canonical = PurlNormalizer.CanonicalName(Ecosystem, Name);
            if (string.Equals(canonical, Name, StringComparison.Ordinal))
            {
                continue;
            }

            // xtenant: existence probe scoped to the claim row's own org_id.
            int occupied = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM claim WHERE org_id = @orgId AND ecosystem = @eco AND name = @canonical",
                new { orgId = OrgId, eco = Ecosystem, canonical });

            await conn.ExecuteAsync(occupied > 0 ? softDeleteSql : renameSql, new { id = Id, canonical });
        }
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
            // xtenant: one-shot startup migration; backfills every tenant's rows by design, keyed
            // by the PKs the instance-wide SELECT above returned.
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

    // Normalizes NuGet cache_artifact.name to lowercase. The backfill migration wrote p.name
    // (canonical display case, e.g. 'Newtonsoft.Json') instead of p.purl_name (lowercased join key).
    // The cross-plane join uses ca.name = p.purl_name, so mixed-case rows never matched. Unlike the
    // RPM equivalent, a blind UPDATE would violate the UNIQUE(ecosystem, name, version, filename)
    // constraint for coordinates where both a mixed-case backfill row and a lowercase live-path row
    // exist. Step A deletes those colliding mixed-case rows first (FK cascade drops their
    // tenant_artifact_access); step B lowercases the remaining rows. Both steps use standard SQL
    // that works on SQLite and Postgres. Idempotent: rows already lowercase satisfy name <> lower(name)
    // = false and are not touched.
    // xtenant: cache_artifact is the global plane (no tenant column); the WHERE clause keys only on
    // ecosystem and the case-mismatch predicate, leaving rows from other ecosystems unchanged.
    private static async Task NormalizeNuGetCacheArtifactNamesAsync(DbConnection conn)
    {
        // Step A: delete mixed-case rows that already have a lowercase twin at the same coordinate.
        await conn.ExecuteAsync(
            """
            DELETE FROM cache_artifact
            WHERE ecosystem = 'nuget' AND name <> lower(name)
              AND EXISTS (SELECT 1 FROM cache_artifact t
                          WHERE t.ecosystem = cache_artifact.ecosystem
                            AND t.name = lower(cache_artifact.name)
                            AND t.version = cache_artifact.version
                            AND t.filename = cache_artifact.filename)
            """);
        // Step B: lowercase the remaining mixed-case rows (no collision possible after step A).
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET name = lower(name) WHERE ecosystem = 'nuget' AND name <> lower(name)");
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
    // the SQLite CHECK rewrite, which drives PRAGMA writable_schema + a schema_version bump that
    // don't compose with an enclosing transaction, the recreate-table reshapes, which toggle
    // PRAGMA foreign_keys, and the backfills that commit in bounded batches. Such migrations MUST
    // be idempotent so an un-recorded partial run is safely repeated on the next boot.
    //
    // dropsViews declares that the body changes the shape of a table or column (a recreate, a
    // rename, a DROP TABLE / DROP COLUMN, an ALTER COLUMN ... TYPE) and so needs the read-model
    // views out of the way first. It defaults to false: a body that only touches rows, constraints
    // or indexes keeps the views resolvable throughout.
    // internal (not private) so SchemaInitializerTests can drive the rollback path directly.
    internal async Task RunOnceAsync(
        DbConnection conn, string name, Func<DbConnection, Task> action, bool transactional = true, bool dropsViews = false)
    {
        int already = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = @name", new { name });
        if (already > 0)
        {
            _logger.LogDebug("Schema migration {Migration} already applied; skipping.", name);
            return;
        }
        _logger.LogInformation("Schema migration {Migration} applying…", name);

        // A body that recreates, renames, drops or retypes a table or column is refused by SQLite
        // and Postgres while a dependent view exists, so it declares dropsViews and the views are
        // dropped once, here, before the first such body; they are recreated at the end of the same
        // apply. Every other body leaves them in place. During a blue-green cutover the previous
        // release is still reading through the views, and a dropped view fails each of those reads
        // for as long as the remaining migrations take — so a body that only reads and writes rows
        // must never pay for a drop it does not need.
        if (dropsViews)
        {
            await EnsureViewsDroppedAsync(conn);
        }

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

    // Verifies that a writable_schema CHECK rewrite actually took, in place of the
    // PRAGMA integrity_check this pattern used to end with.
    //
    // integrity_check reads and cross-checks every page of every table and index in the
    // database. That is O(the whole store) — minutes on a large one — spent verifying a rewrite
    // that touches a single row of sqlite_schema, and it is paid again by every migration that
    // uses the pattern. What it actually caught was narrow: a rewrite that produced malformed
    // SQL, which SQLite reports the next time it re-parses the schema and so is caught by any
    // statement that reads one. Its own corruption findings were discarded either way, since
    // ExecuteAsync never reads the result rows the pragma reports them in.
    //
    // Reading the rewritten table's stored text performs that same re-parse for one row, then
    // answers the question integrity_check never asked: did the REPLACE match anything? A
    // literal REPLACE that matches nothing leaves the narrow constraint in place while
    // RunOnceAsync records the migration applied for good — so the first insert of the newly
    // permitted value fails on some later release, with nothing left to point at the cause.
    //
    // The assertion is that the column's CHECK admits the new VALUE, not that the clause matches
    // an expected text. A later widen of the same column supersedes an earlier one's exact
    // clause, so matching on text would fail the earlier migration the moment it re-ran against
    // a database the later one had already widened.
    //
    // allowMissingCheck covers the one documented case where no constraint at all is the correct
    // outcome: a column introduced by a later ALTER ADD COLUMN carries no CHECK on an upgraded
    // database, and the rewrite is meant to no-op there.
    private static async Task VerifyCheckAdmitsAsync(
        DbConnection conn, string table, string column, string value, bool allowMissingCheck = false)
    {
        string storedSql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = @table", new { table })
            ?? throw new InvalidOperationException(
                $"Table '{table}' is absent from sqlite_schema after rewriting the CHECK on its "
                + $"'{column}' column.");

        // Whitespace is stripped so a database whose stored text is formatted differently is read
        // on its meaning rather than its layout; the comparison is lowercased because a CHECK's
        // value list is not case-normalized (vulnerabilities.severity holds upper-case literals).
        string flat = Flatten(storedSql);
        string col = Flatten(column);
        // Two clause shapes exist in this schema: the bare `CHECK (col IN (...))` (role,
        // block_deprecated, alert.type, project_documents.format) and the nullable
        // `CHECK (col IS NULL OR col IN (...))` (project_documents.signature_status, and every
        // other column whose absence is a real, distinct third state). Trying only the bare
        // marker against a nullable clause never matches — "check(col" is immediately followed
        // by "isnullor...", not "in(" — so `open < 0` unconditionally, and allowMissingCheck then
        // swallows a rewrite that actually failed exactly as silently as the "no CHECK at all"
        // case it exists to tolerate. Both shapes are tried; whichever one is actually present
        // in this database's stored text wins.
        string nullableMarker = "check(" + col + "isnullor" + col + "in(";
        string bareMarker = "check(" + col + "in(";
        int open = flat.IndexOf(nullableMarker, StringComparison.Ordinal);
        string marker = nullableMarker;
        if (open < 0)
        {
            open = flat.IndexOf(bareMarker, StringComparison.Ordinal);
            marker = bareMarker;
        }

        if (open < 0)
        {
            if (allowMissingCheck)
            {
                return;
            }

            throw new InvalidOperationException(
                $"{table}.{column} carries no CHECK constraint after the rewrite that was supposed "
                + $"to give it one admitting '{value}'. The literal this migration replaces no longer "
                + $"matches the text stored in this database, so the rewrite was a silent no-op. "
                + $"Stored definition: {storedSql}");
        }

        int close = flat.IndexOf(')', open + marker.Length);
        string admitted = close < 0 ? flat[(open + marker.Length)..] : flat[(open + marker.Length)..close];

        if (!admitted.Contains("'" + Flatten(value) + "'", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{table}.{column}'s CHECK does not admit '{value}' after the rewrite that was "
                + $"supposed to widen it. The literal this migration replaces no longer matches the "
                + $"text stored in this database, so the rewrite was a silent no-op and the narrower "
                + $"constraint survives. Stored definition: {storedSql}");
        }
    }

    // Whitespace-free, lower-cased form used to compare stored schema text on meaning rather than
    // on the formatting a particular release happened to emit.
    private static string Flatten(string sql)
    {
        var sb = new System.Text.StringBuilder(sql.Length);
        foreach (char c in sql)
        {
            if (!char.IsWhiteSpace(c))
            {
                sb.Append(char.ToLowerInvariant(c));
            }
        }

        return sb.ToString();
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
        // xtenant: one-shot startup migration — it repairs every tenant's mis-encoded npm rows.
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
            // xtenant: migration write keyed by a PK from the instance-wide SELECT above.
            await conn.ExecuteAsync(
                "UPDATE packages SET name = @n, purl_name = @p WHERE id = @id",
                new { n = fixedName, p = fixedPurlName, id = (string)row.id });
        }

        // xtenant: same one-shot migration, version arm — every tenant's npm PURLs are repaired.
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

            // xtenant: migration write keyed by a PK from the instance-wide SELECT above.
            await conn.ExecuteAsync(
                "UPDATE package_versions SET purl = @p WHERE id = @id",
                new { p = purl.Replace("%2F", "/", StringComparison.OrdinalIgnoreCase), id = (string)row.id });
        }
    }

    // purl_name for npm scoped packages should be the plain name (@scope/pkg), not the
    // PURL-encoded form (%40scope/pkg). The prior migration over-encoded it.
    // xtenant: one-shot startup migration — repairs the encoding for every tenant's npm rows.
    private static Task FixNpmPurlNameUnencodedAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "UPDATE packages SET purl_name = '@' || substr(purl_name, 4) " +
            "WHERE ecosystem = 'npm' AND substr(purl_name, 1, 3) = '%40'");

    // Fix stored npm PURLs that used %40 for @ in scoped package names.
    // xtenant: one-shot startup migration — instance-wide by design.
    private static Task FixNpmVersionPurlAtEncodingAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "UPDATE package_versions SET purl = replace(purl, 'pkg:npm/%40', 'pkg:npm/@') " +
            "WHERE purl LIKE 'pkg:npm/%40%'");

    // Fix any npm PURLs still containing %2F (encoded /) in the package name.
    private static async Task FixNpmVersionPurlSlashEncodingAsync(DbConnection conn)
    {
        // xtenant: one-shot startup migration — instance-wide by design.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET purl = replace(replace(purl, '%2F', '/'), '%2f', '/') " +
            "WHERE purl LIKE 'pkg:npm/%' AND (purl LIKE '%2F%' OR purl LIKE '%2f%')");
        // xtenant: same migration — drops the placeholder 'unknown' version rows the broken
        // encoding produced, in every tenant.
        await conn.ExecuteAsync(
            "DELETE FROM package_versions WHERE version = 'unknown'");
    }

    // Fix npm PURLs in activity log that were stored with %40/%2F encoding.
    // xtenant: one-shot startup migration — instance-wide by design.
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
        // xtenant: one-shot startup migration — instance-wide by design. org_id is a GROUP BY key
        // rather than a predicate here precisely so the dedup is per tenant.
        await conn.ExecuteAsync(@"
            DELETE FROM packages
            WHERE ecosystem = 'nuget' AND is_proxy = 1 AND purl_name LIKE 'pkg:%'
              AND id NOT IN (
                SELECT MIN(id) FROM packages
                WHERE ecosystem = 'nuget' AND is_proxy = 1 AND purl_name LIKE 'pkg:%'
                GROUP BY org_id, name
              )");
        // Step 3: rename the surviving broken rows.
        // xtenant: one-shot startup migration — instance-wide by design.
        await conn.ExecuteAsync(
            "UPDATE packages SET purl_name = name WHERE ecosystem = 'nuget' AND is_proxy = 1 AND purl_name LIKE 'pkg:%'");
    }

    // NuGet hosted versions are now stored in the lowercased canonical form
    // (NuGetNormalization.NormalizeVersion) every read path resolves against. Existing rows
    // published under the earlier case-preserving normalization (e.g. "1.0.0-Beta1") can never
    // match the lowercased flatcontainer/registration lookup, so this one-shot lowercases them.
    //
    // Two independent guards keep this collision-proof against UNIQUE(package_id, version):
    //   1. The NOT EXISTS clause skips a row whose lowercased slot is already taken by a
    //      separate, already-lowercase row (e.g. "beta1" published alongside a stale "Beta1").
    //   2. The id = (SELECT MIN(id) ...) clause picks exactly one deterministic winner when
    //      TWO OR MORE non-lowercase rows collide on the same lowercased target (e.g. "Beta1"
    //      and "BETA1" with no separate lowercase row already present). Without this, a single
    //      UPDATE statement evaluates its WHERE clause against the pre-update snapshot, so both
    //      colliding rows' NOT EXISTS checks pass simultaneously and both attempt to write the
    //      same lowercase value — a UNIQUE violation that fails the surrounding transaction and
    //      leaves the migration permanently unrecorded (a boot loop, since RunOnceAsync retries
    //      an unrecorded migration on every startup). Only the smallest-id row among the
    //      colliding group is updated; the rest are silently left mixed-case (unreachable, no
    //      worse than pre-fix) rather than crashing. LOWER(), NOT EXISTS, and MIN() are
    //      provider-agnostic.
    // xtenant: one-shot data migration keyed on ecosystem; runs across every tenant on the instance.
    private static Task LowercaseNuGetHostedVersionsAsync(DbConnection conn) =>
        conn.ExecuteAsync("""
            UPDATE package_versions
            SET version = LOWER(version)
            WHERE version <> LOWER(version)
              AND package_id IN (SELECT id FROM packages WHERE ecosystem = 'nuget')
              AND NOT EXISTS (
                SELECT 1 FROM package_versions pv2
                WHERE pv2.package_id = package_versions.package_id
                  AND pv2.version = LOWER(package_versions.version)
              )
              AND id = (
                SELECT MIN(pv3.id) FROM package_versions pv3
                WHERE pv3.package_id = package_versions.package_id
                  AND LOWER(pv3.version) = LOWER(package_versions.version)
                  AND pv3.version <> LOWER(pv3.version)
              )
            """);

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
