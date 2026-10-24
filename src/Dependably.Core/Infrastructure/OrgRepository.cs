using System.Collections.Concurrent;
using System.Data.Common;
using Dapper;
using Dependably.Infrastructure.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Dependably.Infrastructure;

public sealed class OrgRepository
{
    // 1-second sliding TTL on org-settings reads. The settings record is fetched 3-6
    // times per controller action on the hot paths (upload-limit resolver, allowlist
    // service, license enforcement, block gate, OSV tolerance, release-age gate). At
    // 200+ RPS that becomes 600-1200 DB opens/sec just for settings; cache amortises
    // them into a single read per second while staying short enough that policy
    // changes via the admin UI take effect within a CI run.
    private static readonly TimeSpan SettingsCacheTtl = TimeSpan.FromSeconds(1);

    // Keys whose values are encrypted at rest when a master key is configured. Only
    // these keys are wrapped on write; quota integers and other settings pass through.
    // smtp_password and system_slack_webhook_url are written only via their dedicated
    // email/Slack-config endpoints, never the generic instance-settings PUT.
    internal static readonly HashSet<string> SecretKeys =
        ["jwt_secret", "mfa_encryption_key", "smtp_password", "system_slack_webhook_url", "vuln_tracker_token"];

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;
    private readonly TimeProvider _time;
    private readonly UserTokenVersionStore? _tokenVersions;
    private readonly EnvelopeProtector? _envelope;
    private readonly ITenantSlugCacheInvalidator? _tenantCache;

    // In-flight quota reservations for this process. Owned here rather than injected because
    // OrgRepository is the single gate every write path goes through (hosted publish, OCI push,
    // proxy cache fill all call TryReserveStorageAsync) and is registered as a singleton — so one
    // repository instance is one ledger is one view of a tenant's uncommitted bytes.
    private readonly StorageQuotaLedger _storageLedger = new();

    // Per-org generation token for the settings cache, bound to each settings entry as an
    // expiration trigger. InvalidateSettingsCache retires it, so a fill that read the row before
    // a settings write and stores after the write's invalidation installs an already-expired
    // entry instead of re-caching the pre-change settings.
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _settingsFillGuards =
        new(StringComparer.Ordinal);

    public OrgRepository(
        IMetadataStore db,
        IMemoryCache? cache = null,
        TimeProvider? time = null,
        UserTokenVersionStore? tokenVersions = null,
        EnvelopeProtector? envelope = null,
        ITenantSlugCacheInvalidator? tenantCache = null)
    {
        _db = db;
        _cache = cache;
        _time = time ?? TimeProvider.System;
        _tokenVersions = tokenVersions;
        _envelope = envelope;
        _tenantCache = tenantCache;
    }

    private static string SettingsCacheKey(string orgId) => "org-settings:" + orgId;

    // Test seam (InternalsVisibleTo Dependably.Tests): the live settings generation-guard count,
    // asserted to drain when a fill throws so the map cannot grow unbounded.
    internal int SettingsFillGuardCount => _settingsFillGuards.Count;

    private CancellationTokenSource GuardFor(string orgId) =>
        _settingsFillGuards.GetOrAdd(orgId, static _ => new CancellationTokenSource());

    /// <summary>
    /// Invalidates the in-memory cache for <paramref name="orgId"/>'s settings and retires its
    /// fill generation, so a <see cref="GetSettingsAsync"/> read already in flight from before
    /// this call cannot cache what it read. Called after every settings write, and by
    /// <see cref="Caching.OrgWideCacheEviction"/> before it moves the org's rendered-metadata
    /// epoch, so a render on the fresh epoch never reads settings cached from the pre-change row.
    /// </summary>
    public void InvalidateSettingsCache(string orgId)
    {
        _cache?.Remove(SettingsCacheKey(orgId));
        if (_settingsFillGuards.TryRemove(orgId, out var retired))
        {
            retired.Cancel();
        }
    }

    /// <summary>
    /// Look up a tenant by slug. By default returns active tenants only; set
    /// <paramref name="includeDeleted"/> to true to also return soft-deleted rows (used by
    /// system_admin restore flow).
    /// </summary>
    public async Task<Org?> GetBySlugAsync(string slug, bool includeDeleted = false, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string sql = includeDeleted
            ? "SELECT id, slug, deleted_at as DeletedAt, status as Status, storage_quota_bytes as StorageQuotaBytes, created_at as CreatedAt FROM orgs WHERE slug = @slug"
            : "SELECT id, slug, deleted_at as DeletedAt, status as Status, storage_quota_bytes as StorageQuotaBytes, created_at as CreatedAt FROM orgs WHERE slug = @slug AND deleted_at IS NULL";
        return await conn.QuerySingleOrDefaultAsync<Org>(sql, new { slug });
    }

    // Shared SELECT projection for org_settings, including the tenant filter. Both the
    // cached read path here and the uncached path in OrgSettingsRepository.GetSettingsAsync
    // reference this constant so the column list stays in sync across both repositories.
    internal const string OrgSettingsSelect =
        """
        SELECT org_id as OrgId, anonymous_pull as AnonymousPull, allowlist_mode as AllowlistMode,
               max_upload_bytes as MaxUploadBytes,
               max_upload_bytes_pypi as MaxUploadBytesPyPi,
               max_upload_bytes_npm as MaxUploadBytesNpm,
               max_upload_bytes_nuget as MaxUploadBytesNuGet,
               max_upload_bytes_maven as MaxUploadBytesMaven,
               max_upload_bytes_rpm as MaxUploadBytesRpm,
               max_upload_bytes_oci as MaxUploadBytesOci,
               max_upload_bytes_cargo as MaxUploadBytesCargo,
               max_upload_bytes_hex as MaxUploadBytesHex,
               keep_versions as KeepVersions, keep_days as KeepDays,
               keep_project_versions as KeepProjectVersions,
               activity_retention_days as ActivityRetentionDays,
               purge_unlisted_after_days as PurgeUnlistedAfterDays,
               COALESCE(license_enforcement_mode, 'off') as LicenseEnforcementMode,
               COALESCE(license_publish_enforcement_mode, 'off') as LicensePublishEnforcementMode,
               COALESCE(proxy_passthrough_enabled, 1) as ProxyPassthroughEnabled,
               COALESCE(max_osv_score_tolerance, 10.0) as MaxOsvScoreTolerance,
               min_release_age_hours as MinReleaseAgeHours,
               COALESCE(default_language, 'en') as DefaultLanguage,
               COALESCE(default_timezone, 'UTC') as DefaultTimezone,
               COALESCE(allow_version_overwrite, 0) as AllowVersionOverwrite,
               COALESCE(version_overwrite_policy, 'block') as VersionOverwritePolicy,
               COALESCE(air_gapped, 0) as AirGapped,
               COALESCE(require_mfa, 0) as RequireMfa,
               COALESCE(block_deprecated, 'off') as BlockDeprecated,
               COALESCE(block_revoked, 'warn') as BlockRevoked,
               COALESCE(block_malicious, 'block') as BlockMalicious,
               COALESCE(block_malicious_live, 'off') as BlockMaliciousLive,
               COALESCE(block_kev, 'off') as BlockKev,
               COALESCE(block_kev_ransomware, 'off') as BlockKevRansomware,
               COALESCE(block_ssvc_exploitation, 'off') as BlockSsvcExploitation,
               COALESCE(oci_scan_enforcement, 'off') as OciScanEnforcement,
               max_epss_percentile_tolerance as MaxEpssPercentileTolerance,
               max_epss_tolerance as MaxEpssTolerance,
               COALESCE(block_install_scripts, 'off') as BlockInstallScripts,
               COALESCE(verify_npm_signatures, 'off') as VerifyNpmSignatures,
               COALESCE(verify_nuget_signatures, 'off') as VerifyNuGetSignatures,
               COALESCE(verify_pypi_attestations, 'off') as VerifyPyPiAttestations,
               COALESCE(verify_rpm_signatures, 'off') as VerifyRpmSignatures,
               COALESCE(verify_maven_signatures, 'off') as VerifyMavenSignatures,
               COALESCE(verify_terraform_signatures, 'off') as VerifyTerraformSignatures,
               COALESCE(verify_sbom_signatures, 'off') as VerifySbomSignatures,
               rpm_upstream_mode as RpmUpstreamMode
        FROM org_settings WHERE org_id = @orgId
        """;

    public async Task<OrgSettings?> GetSettingsAsync(string orgId, CancellationToken ct = default)
    {
        string key = SettingsCacheKey(orgId);
        if (_cache is not null && _cache.TryGetValue(key, out OrgSettings? cached))
        {
            return cached;
        }

        if (_cache is null)
        {
            return await ReadSettingsAsync(orgId, ct);
        }

        // The generation is snapshotted before the read, so a read that overlaps an
        // InvalidateSettingsCache stores an entry that is already expired. From here on the guard
        // MUST end up either tied to a cache entry or retired in the finally; the map lives as long
        // as this singleton, so a read that throws would otherwise leak it.
        var guardSource = GuardFor(orgId);
        bool tied = false;
        try
        {
            var result = await ReadSettingsAsync(orgId, ct);

            // Cache both hit and miss so a non-existent org_id doesn't repeatedly hit the DB.
            // Size = 1 counts as one logical slot against the global SizeLimit; the actual
            // OrgSettings record is small (<1 KB) compared to the byte-array metadata entries.
            var options = new MemoryCacheEntryOptions
            {
                SlidingExpiration = SettingsCacheTtl,
                AbsoluteExpirationRelativeToNow = SettingsCacheTtl,
                Size = 1,
            };
            options.AddExpirationToken(new CancellationChangeToken(guardSource.Token));
            CacheFillGuard.TieToEntryLifetime(options, _settingsFillGuards, orgId, guardSource);
            _cache.Set(key, result, options);
            tied = true;
            return result;
        }
        finally
        {
            if (!tied)
            {
                CacheFillGuard.RetireUnbound(_settingsFillGuards, orgId, guardSource);
            }
        }
    }

    private async Task<OrgSettings?> ReadSettingsAsync(string orgId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<OrgSettings>(
            OrgSettingsSelect,
            new { orgId });
    }

    public async Task<Org?> GetByIdAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<Org>(
            "SELECT id, slug, deleted_at as DeletedAt, status as Status, storage_quota_bytes as StorageQuotaBytes, created_at as CreatedAt FROM orgs WHERE id = @id",
            new { id });
    }

    /// <summary>
    /// List tenants with per-tenant aggregates (member count, storage bytes used) for the
    /// system_admin tenants page. system_admin sees both active and soft-deleted (so it can
    /// render the restore UI within the grace window); business surfaces should filter to
    /// active only.
    ///
    /// Storage bytes span three org-scoped sources, summed per tenant so this list reports the
    /// same total the tenant dashboard shows (<see cref="PackageAnalyticsRepository.GetOrgStatsAsync"/>):
    /// (1) uploaded hosted versions in <c>package_versions</c> (origin='uploaded', non-OCI,
    /// org-scoped via <c>packages.org_id</c>); (2) proxy artifacts on the shared
    /// <c>cache_artifact</c> plane, attributed per-tenant via <c>tenant_artifact_access</c>;
    /// (3) OCI blob bytes in <c>oci_blobs</c> (content-addressed, deduped within an org).
    ///
    /// Aggregates are computed inline using pre-aggregated subqueries so each tenant produces
    /// exactly one outer row — a naive <c>LEFT JOIN users LEFT JOIN packages LEFT JOIN
    /// package_versions</c> would produce N×M rows and inflate both counts. Indexes
    /// (<c>users.tenant_id</c>, <c>idx_packages_org_ecosystem</c>,
    /// <c>idx_package_versions_package</c>, <c>tenant_artifact_access</c>'s org-prefixed primary
    /// key, <c>idx_oci_blobs_org</c>) keep this sub-100ms at the page-size cap of 200.
    /// </summary>
    // xtenant: system-admin tenant list — aggregates roll up across all tenants by design.
    public async Task<(IReadOnlyList<OrgListItem> Items, int Total)> ListOrgsAsync(int limit, int offset, bool includeDeleted = true, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int includeDeletedFlag = includeDeleted ? 1 : 0;
        const string countSql =
            "SELECT COUNT(*) FROM orgs WHERE (@includeDeleted = 1 OR deleted_at IS NULL)";
        // xtenant: system-admin tenant list — aggregates roll up across all tenants by design.
        const string listSql = """
            SELECT o.id                AS Id,
                   o.slug              AS Slug,
                   o.deleted_at        AS DeletedAt,
                   o.status            AS Status,
                   o.storage_quota_bytes AS StorageQuotaBytes,
                   o.created_at        AS CreatedAt,
                   COALESCE(u.member_count, 0)  AS MemberCount,
                   COALESCE(s.total_bytes, 0) AS StorageBytes,
                   sn.stats_json       AS StatsJson,
                   sn.computed_at      AS StatsComputedAt
            FROM orgs o
            LEFT JOIN (
                SELECT tenant_id, COUNT(*) AS member_count
                FROM users
                GROUP BY tenant_id
            ) u ON u.tenant_id = o.id
            LEFT JOIN org_storage_bytes s ON s.org_id = o.id
            LEFT JOIN org_stats_snapshot sn ON sn.org_id = o.id
            WHERE (@includeDeleted = 1 OR o.deleted_at IS NULL)
            ORDER BY o.created_at ASC, o.id ASC
            LIMIT @limit OFFSET @offset
            """;
        int total = await conn.ExecuteScalarAsync<int>(countSql, new { includeDeleted = includeDeletedFlag });
        var rows = await conn.QueryAsync<OrgListItem>(listSql, new { limit, offset, includeDeleted = includeDeletedFlag });
        return (rows.ToList(), total);
    }

    /// <summary>
    /// Sets (or clears, when <paramref name="quotaBytes"/> is null) the tenant's aggregate
    /// storage quota. Operator-only knob — there is no tenant-facing UI for this in community.
    /// </summary>
    public async Task SetStorageQuotaBytesAsync(string orgId, long? quotaBytes, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE orgs SET storage_quota_bytes = @quotaBytes WHERE id = @orgId",
            new { orgId, quotaBytes });
    }

    /// <summary>
    /// Bucketed counts of orgs for the sysadmin dashboard. One round-trip; soft-deleted overrides
    /// status (a row with deleted_at NOT NULL counts as soft-deleted regardless of its status).
    /// 'archived' and 'deleting' are enterprise-only states and intentionally not surfaced —
    /// community queries collapse them into the active/suspended/read-only/soft-deleted view.
    /// </summary>
    // xtenant: dashboard rollup spans every tenant by design.
    public async Task<(int Active, int Suspended, int ReadOnly, int SoftDeleted)> CountByStatusAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleAsync<(int Active, int Suspended, int ReadOnly, int SoftDeleted)>(
            """
            SELECT
                COALESCE(SUM(CASE WHEN deleted_at IS NULL AND status = 'active'    THEN 1 ELSE 0 END), 0) AS Active,
                COALESCE(SUM(CASE WHEN deleted_at IS NULL AND status = 'suspended' THEN 1 ELSE 0 END), 0) AS Suspended,
                COALESCE(SUM(CASE WHEN deleted_at IS NULL AND status = 'read_only' THEN 1 ELSE 0 END), 0) AS ReadOnly,
                COALESCE(SUM(CASE WHEN deleted_at IS NOT NULL                       THEN 1 ELSE 0 END), 0) AS SoftDeleted
            FROM orgs
            """);
    }

    /// <summary>
    /// Toggle the tenant lifecycle gate between <c>'active'</c>, <c>'suspended'</c>, and
    /// <c>'read_only'</c>. Other states (<c>'archived'</c>, <c>'deleting'</c>) are enterprise-only
    /// and rejected. Soft-deleted tenants are not updated — use restore first. The result says
    /// whether a row was changed and what the write revoked.
    ///
    /// Suspending a tenant is how an operator contains an incident, so it ends the tenant's
    /// access for good rather than only while the tenant stays suspended: in the same transaction
    /// as the status write it revokes every credential the tenant's members and integrations hold
    /// (<see cref="RevokeTenantAccessAsync"/>) — sessions, remembered devices, personal access
    /// tokens, service tokens, pending password-reset and email-change links, and pending invites
    /// — so restoring the tenant later never revives one that existed before or during the
    /// suspension. Revoked tokens are deleted, as a single-token revoke deletes them, and are
    /// re-issued after the restore. Revoking on entry is the containment guarantee: the old
    /// credentials are dead from the moment of suspension, whatever the request gate does
    /// afterwards, and none can be minted while the tenant is locked out, because
    /// <see cref="TenantStatusEnforcementMiddleware"/> refuses login and the whole management
    /// plane too. A transition out of a lockout status revokes again, so a lockout status written
    /// by any other path (an enterprise <c>'archived'</c> or <c>'deleting'</c>, a direct database
    /// edit) cannot revive old credentials either. Nothing can be issued while the tenant is
    /// locked out, so everything still present on the way out predates the lockout or was written
    /// around the application, and all of it is revoked.
    ///
    /// The lockout statuses are every status other than <c>'active'</c> and <c>'read_only'</c>,
    /// matching the middleware. <c>'read_only'</c> is not one: its members keep using the
    /// management plane, keep signing in and keep pulling with their tokens, so moving a tenant
    /// into or out of it revokes nothing.
    /// </summary>
    public async Task<TenantLifecycleResult> UpdateOrgStatusAsync(string orgId, string status, CancellationToken ct = default)
    {
        if (status is not ("active" or "suspended" or "read_only"))
        {
            return TenantLifecycleResult.NotApplied;
        }

        var revoked = RevokedAccess.Nothing;
        await using (var conn = await OpenLifecycleConnectionAsync(ct))
        {
            await using var tx = await conn.BeginTransactionAsync(ct);

            // Lock the org row before deciding, so a concurrent status write cannot land between
            // this read and the update below: on Postgres FOR UPDATE makes the other writer wait
            // for this commit (or this read wait for its commit, then read what it wrote). SQLite
            // has no row locks and needs none: its transactions begin IMMEDIATE, so writers are
            // already serialized. A missing or soft-deleted tenant reads null and is not updated.
            string? prior = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
                _db.Provider == DbProvider.Postgres
                    ? "SELECT status FROM orgs WHERE id = @orgId AND deleted_at IS NULL FOR UPDATE"
                    : "SELECT status FROM orgs WHERE id = @orgId AND deleted_at IS NULL",
                new { orgId }, transaction: tx, cancellationToken: ct));
            if (prior is null)
            {
                await tx.RollbackAsync(ct);
                return TenantLifecycleResult.NotApplied;
            }

            if (RevokesAccess(prior, status))
            {
                revoked = await RevokeTenantAccessAsync(conn, tx, orgId, ct);
            }

            await conn.ExecuteAsync(new CommandDefinition(
                "UPDATE orgs SET status = @status WHERE id = @orgId AND deleted_at IS NULL",
                new { orgId, status }, transaction: tx, cancellationToken: ct));
            await tx.CommitAsync(ct);
        }

        EvictRevoked(revoked);
        return new TenantLifecycleResult(true, revoked.Counts);
    }

    /// <summary>
    /// The statuses <see cref="TenantStatusEnforcementMiddleware"/> refuses every request for:
    /// every status except <c>'active'</c> and <c>'read_only'</c>.
    /// </summary>
    internal static bool IsLockoutStatus(string status) => status is not ("active" or "read_only");

    /// <summary>
    /// A status write revokes the tenant's credentials when the tenant enters a lockout status or
    /// leaves one. <paramref name="prior"/> is the status read under the row lock.
    /// </summary>
    internal static bool RevokesAccess(string prior, string next) =>
        IsLockoutStatus(next) || IsLockoutStatus(prior);

    /// <summary>
    /// Soft-delete: set deleted_at = now. Idempotent (re-deleting just refreshes the timestamp).
    /// A soft-deleted tenant is locked out like a suspended one, so the same transaction revokes
    /// every credential of the tenant (see <see cref="UpdateOrgStatusAsync"/>), and a restore
    /// within the grace window never revives one.
    /// </summary>
    public async Task<TenantLifecycleResult> SoftDeleteOrgAsync(string orgId, CancellationToken ct = default)
    {
        RevokedAccess revoked;
        await using (var conn = await OpenLifecycleConnectionAsync(ct))
        {
            await using var tx = await conn.BeginTransactionAsync(ct);
            int rows = await conn.ExecuteAsync(new CommandDefinition(
                "UPDATE orgs SET deleted_at = @now WHERE id = @orgId",
                new { orgId, now = _time.GetUtcNow().ToUtcIso() }, transaction: tx, cancellationToken: ct));
            if (rows == 0)
            {
                await tx.RollbackAsync(ct);
                return TenantLifecycleResult.NotApplied;
            }

            revoked = await RevokeTenantAccessAsync(conn, tx, orgId, ct);
            await tx.CommitAsync(ct);
        }

        EvictRevoked(revoked);
        return new TenantLifecycleResult(true, revoked.Counts);
    }

    /// <summary>
    /// Restore: clear deleted_at. The result is not applied when the tenant was not soft-deleted.
    /// Revokes every credential of the tenant again in the same transaction, for the same reason a
    /// transition out of a lockout status does (see <see cref="UpdateOrgStatusAsync"/>). Tokens
    /// revoked by the deletion stay revoked: the tenant's integrations need new ones.
    /// </summary>
    public async Task<TenantLifecycleResult> RestoreOrgAsync(string orgId, CancellationToken ct = default)
    {
        RevokedAccess revoked;
        await using (var conn = await OpenLifecycleConnectionAsync(ct))
        {
            await using var tx = await conn.BeginTransactionAsync(ct);
            int rows = await conn.ExecuteAsync(new CommandDefinition(
                "UPDATE orgs SET deleted_at = NULL WHERE id = @orgId AND deleted_at IS NOT NULL",
                new { orgId }, transaction: tx, cancellationToken: ct));
            if (rows == 0)
            {
                await tx.RollbackAsync(ct);
                return TenantLifecycleResult.NotApplied;
            }

            revoked = await RevokeTenantAccessAsync(conn, tx, orgId, ct);
            await tx.CommitAsync(ct);
        }

        EvictRevoked(revoked);
        return new TenantLifecycleResult(true, revoked.Counts);
    }

    /// <summary>
    /// The connection a tenant lifecycle write runs on. It must see every member and token of the
    /// target tenant whatever scope the caller declared: under row-level security a connection
    /// bound to another tenant would see none of them, and the <c>orgs</c> write (no tenant
    /// column) would still succeed, flipping the status with nothing revoked.
    /// </summary>
    private Task<DbConnection> OpenLifecycleConnectionAsync(CancellationToken ct) =>
        // xtenant: an operator's tenant lifecycle write revokes every member of the target tenant,
        // whichever tenant scope the caller runs under; each statement filters on that tenant.
        _db.OpenCrossTenantAsync("tenant lifecycle write revokes the target tenant's members", ct);

    /// <summary>What <see cref="RevokeTenantAccessAsync"/> removed, plus what to evict after the commit.</summary>
    private sealed record RevokedAccess(
        IReadOnlyList<string> UserIds, IReadOnlyList<string> TokenHashes, TenantAccessRevocation Counts)
    {
        public static readonly RevokedAccess Nothing = new([], [], TenantAccessRevocation.None);
    }

    /// <summary>
    /// Revokes every credential that lets someone act as <paramref name="orgId"/>, inside the
    /// caller's transaction, every statement scoped by the tenant id:
    /// <list type="bullet">
    /// <item>sessions and remembered devices (<see cref="RevokeTenantSessionsAsync"/>);</item>
    /// <item>personal access tokens and service tokens, deleted the way a single-token revoke
    /// deletes them. That includes the reader token an edge node pulls with, so edge sync stops
    /// until the tenant issues the edge a new one;</item>
    /// <item>pending password-reset and email-change links. A reset link mailed before the lockout
    /// would otherwise set a password after it, and an email-change link would repoint the
    /// account's recovery address;</item>
    /// <item>pending invites, which would otherwise mint a new member after the restore on the
    /// strength of an invite sent before or during the incident.</item>
    /// </list>
    /// Consumed links and accepted invites are history and stay.
    /// </summary>
    private static async Task<RevokedAccess> RevokeTenantAccessAsync(
        DbConnection conn, DbTransaction tx, string orgId, CancellationToken ct)
    {
        var (userIds, devices) = await RevokeTenantSessionsAsync(conn, tx, orgId, ct);

        var userTokenHashes = (await conn.QueryAsync<string>(new CommandDefinition(
            "DELETE FROM user_tokens WHERE org_id = @orgId RETURNING token_hash",
            new { orgId }, transaction: tx, cancellationToken: ct))).AsList();
        var serviceTokenHashes = (await conn.QueryAsync<string>(new CommandDefinition(
            "DELETE FROM service_tokens WHERE org_id = @orgId RETURNING token_hash",
            new { orgId }, transaction: tx, cancellationToken: ct))).AsList();
        int resetLinks = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM password_reset_tokens WHERE org_id = @orgId AND consumed_at IS NULL",
            new { orgId }, transaction: tx, cancellationToken: ct));
        int emailChangeLinks = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM email_change_tokens WHERE org_id = @orgId AND consumed_at IS NULL",
            new { orgId }, transaction: tx, cancellationToken: ct));
        int invites = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM invites WHERE org_id = @orgId AND accepted_at IS NULL",
            new { orgId }, transaction: tx, cancellationToken: ct));

        return new RevokedAccess(
            userIds,
            [.. userTokenHashes, .. serviceTokenHashes],
            new TenantAccessRevocation(
                Members: userIds.Count,
                TrustedDevices: devices,
                UserTokens: userTokenHashes.Count,
                ServiceTokens: serviceTokenHashes.Count,
                PasswordResetLinks: resetLinks,
                EmailChangeLinks: emailChangeLinks,
                PendingInvites: invites));
    }

    /// <summary>
    /// Ends every session and remembered device held by a member of <paramref name="orgId"/>,
    /// inside the caller's transaction: bumps <c>users.token_version</c> (so each outstanding
    /// session JWT carries a stale <c>tver</c>), rotates <c>security_stamp</c> alongside it, and
    /// deletes the tenant-realm trusted devices. Returns the affected user ids, whose cached
    /// versions the caller evicts after the commit, and the number of devices deleted.
    /// </summary>
    private static async Task<(List<string> UserIds, int Devices)> RevokeTenantSessionsAsync(
        DbConnection conn, DbTransaction tx, string orgId, CancellationToken ct)
    {
        var revoked = (await conn.QueryAsync<string>(new CommandDefinition(
            """
            UPDATE users
            SET token_version = token_version + 1, security_stamp = @stamp
            WHERE tenant_id = @orgId
            RETURNING id
            """,
            new { orgId, stamp = Guid.NewGuid().ToString() }, transaction: tx, cancellationToken: ct))).AsList();
        int devices = revoked.Count > 0
            ? await DeleteTenantTrustedDevicesAsync(conn, tx, orgId, ct)
            : 0;

        return (revoked, devices);
    }

    private static Task<int> DeleteTenantTrustedDevicesAsync(
        DbConnection conn, DbTransaction tx, string orgId, CancellationToken ct) =>
        conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM mfa_trusted_devices WHERE tenant_id = @orgId AND realm = 'tenant'",
            new { orgId }, transaction: tx, cancellationToken: ct));

    // After the commit, per the cache fill guard's invalidate-after-write rule: a version fill
    // that read the pre-change row holds a generation this call cancels. A cached token
    // resolution is dropped here too, so a revoked token is refused on its next request rather
    // than when the resolve cache's one-second entry lapses.
    private void EvictRevoked(RevokedAccess revoked)
    {
        if (_tokenVersions is not null)
        {
            foreach (string userId in revoked.UserIds)
            {
                _tokenVersions.Invalidate(userId);
            }
        }

        if (_cache is not null)
        {
            foreach (string tokenHash in revoked.TokenHashes)
            {
                TokenRepository.EvictResolution(_cache, tokenHash);
            }
        }
    }

    /// <summary>List org IDs that have been soft-deleted longer than <paramref name="graceDays"/>.</summary>
    public async Task<IReadOnlyList<string>> ListExpiredSoftDeletedOrgIdsAsync(int graceDays, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string cutoff = _time.GetUtcNow().AddDays(-graceDays).ToUtcIso();
        var rows = await conn.QueryAsync<string>(
            "SELECT id FROM orgs WHERE deleted_at IS NOT NULL AND deleted_at < @cutoff",
            new { cutoff });
        return rows.ToList();
    }

    /// <summary>
    /// Creates an org with its settings row and the standard public upstreams. The operator's
    /// tenant-create endpoint does the same inside one transaction and also creates the owner;
    /// this is the bare form. Either way the subdomain resolver's cached "no such tenant" for the
    /// slug is evicted once the rows are committed.
    /// </summary>
    public async Task<Org> CreateOrgAsync(string slug, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync(ct))
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id, slug });
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id) VALUES (@id)",
                new { id });
            // Seed the standard public upstreams so a new org proxies out of the box. No IConfiguration
            // here, so config overrides aren't visible — falls back to the hard-coded public defaults.
            await UpstreamRegistrySeeder.SeedForOrgAsync(conn, id, config: null, ct: ct);
        }

        _tenantCache?.InvalidateSlug(slug);
        return new Org { Id = id, Slug = slug, CreatedAt = _time.GetUtcNow() };
    }

    /// <summary>
    /// Sets the serve-path licence enforcement mode (<paramref name="mode"/>, always applied)
    /// and, optionally, the independent publish-path mode (<paramref name="publishMode"/>).
    /// <paramref name="publishMode"/> is leave-unchanged-on-absent (COALESCE) — a caller that
    /// omits it (an older client hitting this endpoint before the publish-side gate existed)
    /// must never silently reset an operator's stored publish policy back to 'off'.
    /// </summary>
    public async Task UpsertLicensePolicyModeAsync(
        string orgId, string mode, string? publishMode = null, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, license_enforcement_mode, license_publish_enforcement_mode)
            VALUES (@orgId, @mode, COALESCE(@publishMode, 'off'))
            ON CONFLICT(org_id) DO UPDATE SET
                license_enforcement_mode = @mode,
                license_publish_enforcement_mode = COALESCE(@publishMode, org_settings.license_publish_enforcement_mode)
            """,
            new { orgId, mode, publishMode });
        InvalidateSettingsCache(orgId);
    }

    public async Task<string?> GetInstanceSettingAsync(string key, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? raw = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key });
        return raw is null
            ? null
            : (_envelope?.Unprotect(raw, new ProtectedSecretRow(key, "instance_settings", key, null)) ?? raw);
    }

    /// <summary>
    /// Resolves the effective per-upload size limit for the given ecosystem, applying the
    /// cascade documented in <c>CLAUDE.md</c> ("Upload size limits"):
    ///   1. org per-ecosystem limit (<c>org_settings.max_upload_bytes_{eco}</c>)
    ///   2. org global limit         (<c>org_settings.max_upload_bytes</c>)
    ///   3. instance per-ecosystem limit (<c>instance_settings.max_upload_bytes_{eco}</c>)
    /// Returns <see cref="long.MaxValue"/> when nothing is configured. Callers compare the
    /// in-flight upload size against the returned value and return 413 on overflow.
    /// </summary>
    /// <param name="settings">Already-fetched <see cref="OrgSettings"/> for the org; null OK.</param>
    /// <param name="ecosystem">One of <c>pypi</c>, <c>npm</c>, <c>nuget</c>, <c>maven</c>, <c>rpm</c>, <c>oci</c>, <c>cargo</c> (case-insensitive).</param>
    public async Task<long> GetUploadLimitAsync(OrgSettings? settings, string ecosystem, CancellationToken ct = default)
    {
        string eco = ecosystem.ToLowerInvariant();
        long? orgEco = eco switch
        {
            "pypi" => settings?.MaxUploadBytesPyPi,
            "npm" => settings?.MaxUploadBytesNpm,
            "nuget" => settings?.MaxUploadBytesNuGet,
            "maven" => settings?.MaxUploadBytesMaven,
            "rpm" => settings?.MaxUploadBytesRpm,
            "oci" => settings?.MaxUploadBytesOci,
            "cargo" => settings?.MaxUploadBytesCargo,
            "hex" => settings?.MaxUploadBytesHex,
            _ => null,
        };
        if (orgEco is { } orgEcoLimit)
        {
            return orgEcoLimit;
        }

        if (settings?.MaxUploadBytes is { } orgGlobal)
        {
            return orgGlobal;
        }

        string? instanceKey = eco switch
        {
            "pypi" => "max_upload_bytes_pypi",
            "npm" => "max_upload_bytes_npm",
            "nuget" => "max_upload_bytes_nuget",
            "maven" => "max_upload_bytes_maven",
            "rpm" => "max_upload_bytes_rpm",
            "oci" => "max_upload_bytes_oci",
            "cargo" => "max_upload_bytes_cargo",
            "hex" => "max_upload_bytes_hex",
            _ => null,
        };
        if (instanceKey is null)
        {
            return long.MaxValue;
        }

        string? raw = await GetInstanceSettingAsync(instanceKey, ct);
        return raw is not null && long.TryParse(raw, out long parsed) ? parsed : long.MaxValue;
    }

    /// <summary>
    /// Lists every <c>instance_settings</c> row except the ones in <see cref="SecretKeys"/>.
    /// The exclusion is bound to the same set the encrypt-on-write path consults (rather than a
    /// second hardcoded literal list) so the two can never drift — a key added to
    /// <see cref="SecretKeys"/> is automatically hidden from this generic listing without a
    /// second edit.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, string>> ListInstanceSettingsAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        const string sql = "SELECT key as Key, value as Value FROM instance_settings WHERE key NOT IN @secretKeys";
        // See DapperInClause: Dapper's own IN/NOT IN @secretKeys auto-expansion binds the whole
        // set as one Postgres array parameter instead of expanding the SQL text, which NOT IN
        // never accepts.
        var (secretKeysClause, secretKeysParams) = DapperInClause.Expand("secretKey", SecretKeys.ToList());
        var rows = await conn.QueryAsync<(string Key, string Value)>(
            sql.Replace("@secretKeys", secretKeysClause), secretKeysParams);
        return rows.ToDictionary(r => r.Key, r => r.Value);
    }

    public async Task SetInstanceSettingAsync(string key, string value, CancellationToken ct = default)
    {
        string stored = value;
        if (_envelope is not null && _envelope.IsConfigured && SecretKeys.Contains(key) && !EnvelopeProtector.IsEncrypted(value))
        {
            stored = _envelope.Protect(value);
        }
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES (@key, @value) ON CONFLICT(key) DO UPDATE SET value = @value",
            new { key, value = stored });
    }

    /// <summary>
    /// system_admin support flow: locks/unlocks/disables a tenant user account. Returns false
    /// if the (email, tenantSlug) pair doesn't resolve.
    ///
    /// Locking or disabling a user is how an operator cuts them off, so it ends their access at
    /// once rather than when their session expires: the same UPDATE bumps
    /// <c>users.token_version</c> (rotating <c>security_stamp</c> alongside), so every
    /// outstanding session JWT carries a stale <c>tver</c>; the cached version is evicted after
    /// the commit; and the user's tenant-realm remembered devices are dropped in the same
    /// transaction.
    ///
    /// Re-activating bumps too. A lock or disable through this method has already staled the old
    /// sessions, but a status written by any other path may not have, and a non-active user holds
    /// no working session to lose (<see cref="UserTokenVersionStore"/> answers null for one), so
    /// the extra bump guarantees re-activation never revives a pre-lock session. Every transition
    /// that bumps also drops the remembered devices, re-activation included, so a device row
    /// written while the user was not active cannot skip the second factor afterwards. Setting
    /// an active user to active changes nothing.
    /// </summary>
    public async Task<bool> SetUserAccountStatusAsync(
        string email, string tenantSlug, string accountStatus, CancellationToken ct = default)
    {
        if (accountStatus is not ("active" or "locked" or "disabled"))
        {
            return false;
        }

        string stamp = Guid.NewGuid().ToString();
        List<(string Id, string? Stamp)> updated;
        await using (var conn = await _db.OpenAsync(ct))
        {
            await using var tx = await conn.BeginTransactionAsync(ct);

            // SET expressions read the pre-update row on both providers, so the CASE compares the
            // previous status with the new one. RETURNING reads the post-update row, so a returned
            // stamp equals the fresh one exactly when this write bumped that user.
            // xtenant: system_admin flow that resolves a user by email + org slug across tenants.
            updated = (await conn.QueryAsync<(string Id, string? Stamp)>(new CommandDefinition(
                """
                UPDATE users
                SET token_version = CASE WHEN account_status = 'active' AND @status = 'active'
                                         THEN token_version ELSE token_version + 1 END,
                    security_stamp = CASE WHEN account_status = 'active' AND @status = 'active'
                                          THEN security_stamp ELSE @stamp END,
                    account_status = @status
                WHERE id IN (
                    SELECT u.id FROM users u
                    JOIN orgs o ON o.id = u.tenant_id
                    WHERE lower(u.email) = lower(@email) AND o.slug = @tenantSlug
                )
                RETURNING id, security_stamp
                """,
                new { status = accountStatus, stamp, email, tenantSlug },
                transaction: tx, cancellationToken: ct))).AsList();

            foreach (var (userId, returnedStamp) in updated)
            {
                if (!string.Equals(returnedStamp, stamp, StringComparison.Ordinal))
                {
                    continue;
                }

                // xtenant: user_id is FK-bound to the user the UPDATE above just resolved; realm
                // pins the tenant realm (system-realm rows reference system_admins, not users).
                await conn.ExecuteAsync(new CommandDefinition(
                    "DELETE FROM mfa_trusted_devices WHERE user_id = @userId AND realm = 'tenant'",
                    new { userId }, transaction: tx, cancellationToken: ct));
            }

            await tx.CommitAsync(ct);
        }

        // After the commit, per the cache fill guard's invalidate-after-write rule: a fill that
        // read the pre-change row holds a generation this call cancels.
        if (_tokenVersions is not null)
        {
            foreach (var (userId, _) in updated)
            {
                _tokenVersions.Invalidate(userId);
            }
        }

        return updated.Count > 0;
    }

    /// <summary>
    /// True when the user belongs to <paramref name="tenantId"/>, is <c>active</c>, and their
    /// <c>token_version</c> still equals <paramref name="tokenVersion"/>. Read live, not through
    /// the cached version store: the tenant second-factor step uses it to refuse a challenge
    /// issued before a lock, disable, re-activation, role change or credential change, before it
    /// mints a session or remembers a device.
    /// </summary>
    public async Task<bool> IsUserActiveAtVersionAsync(
        string userId, string tenantId, long tokenVersion, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int matches = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM users
            WHERE id = @userId AND tenant_id = @tenantId
              AND account_status = 'active' AND token_version = @tokenVersion
            """,
            new { userId, tenantId, tokenVersion });
        return matches > 0;
    }

    /// <summary>
    /// system_admin user-lookup projection: control-plane metadata only (email, tenant slug,
    /// role, last login, account status, MFA, password-reset issued). Never returns
    /// password_hash or any tenant business field. Used by <c>GET /api/v1/system/users</c>.
    /// </summary>
    public async Task<IReadOnlyList<SystemUserLookupView>> LookupUsersAsync(
        string? email, string? tenantSlug, int limit, CancellationToken ct = default)
    {
        if (email is null && tenantSlug is null)
        {
            return Array.Empty<SystemUserLookupView>();
        }

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<SystemUserLookupView>(
            """
            SELECT u.email AS Email,
                   o.slug AS TenantSlug,
                   u.role AS Role,
                   u.last_login_at AS LastLoginAt,
                   u.account_status AS AccountStatus,
                   u.mfa_enabled AS MfaEnabled,
                   u.password_reset_issued_at AS PasswordResetIssuedAt,
                   u.must_change_password AS MustChangePassword
            FROM users u
            JOIN orgs o ON o.id = u.tenant_id
            WHERE (@email IS NULL OR lower(u.email) = lower(@email))
              AND (@tenantSlug IS NULL OR o.slug = @tenantSlug)
            ORDER BY u.email ASC, o.slug ASC
            LIMIT @limit
            """,
            new { email, tenantSlug, limit });
        return rows.ToList();
    }

    /// <summary>
    /// Lists members of an org. With 1:1 user:tenant, "members" projects directly from the
    /// <c>users</c> table filtered by <c>tenant_id</c>.
    /// </summary>
    public async Task<IReadOnlyList<OrgMemberView>> ListOrgMembersAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<OrgMemberView>(
            """
            SELECT id as UserId, email as Email, role as Role, account_type as AccountType,
                   created_at as JoinedAt, mfa_enabled as MfaEnabled
            FROM users
            WHERE tenant_id = @orgId
            ORDER BY created_at ASC, id ASC
            """,
            new { orgId });
        return rows.ToList();
    }

    public async Task<int> CountOwnersAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM users WHERE tenant_id = @orgId AND role = 'owner'",
            new { orgId });
    }

    /// <summary>
    /// Changes a member's role and terminates their outstanding sessions. The role is snapshotted
    /// into the tenant session JWT, so a demotion must move <c>token_version</c> forward (and evict
    /// the in-memory version cache) or the demoted user keeps the elevated role claim until their
    /// 8h token expires — mirroring <see cref="SetUserAccountStatusAsync"/>. Returns the post-update
    /// <c>token_version</c> so a caller re-issuing a session in the same flow (self-demotion cookie
    /// refresh, SAML role resync) embeds the new value rather than self-invalidating.
    /// </summary>
    public async Task<long> UpdateMemberRoleAsync(string orgId, string userId, string role, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long newVersion = await conn.ExecuteScalarAsync<long>(
            """
            UPDATE users SET role = @role, token_version = token_version + 1
            WHERE id = @userId AND tenant_id = @orgId
            RETURNING token_version
            """,
            new { orgId, userId, role });
        _tokenVersions?.Invalidate(userId);
        return newVersion;
    }

    /// <summary>
    /// Bumps <c>token_version</c> and rotates <c>security_stamp</c> for every password-backed
    /// user in a tenant — the session-invalidation counterpart to flipping the tenant to
    /// SSO-only (<c>forms_login_enabled</c> true→false). Scoped to a non-empty
    /// <c>password_hash</c> rather than every member: JIT-provisioned SAML users are seeded with
    /// <c>password_hash = ''</c> (see <c>LoginService.ProvisionJitUserAsync</c>), not NULL, and
    /// that empty-vs-populated distinction is the same one <c>TryLoginViaEmailLinkAsync</c> uses
    /// to tell a password-backed account from an SSO-only one — so passwordless members are
    /// never touched here and their outstanding SSO sessions are left alone. Only sessions that
    /// were minted from the credential the flip is closing are cut off. Returns the number of
    /// affected users so the caller can record how many sessions it revoked. A no-op write (flag
    /// left unchanged) never reaches this method, so an unrelated settings save never churns
    /// <c>token_version</c>.
    /// </summary>
    public async Task<int> RevokePasswordSessionsAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var affectedIds = (await conn.QueryAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @orgId AND password_hash IS NOT NULL AND password_hash != ''",
            new { orgId })).ToList();

        if (affectedIds.Count == 0)
        {
            return 0;
        }

        string stamp = Guid.NewGuid().ToString();
        int rows = await conn.ExecuteAsync(
            """
            UPDATE users SET token_version = token_version + 1, security_stamp = @stamp
            WHERE tenant_id = @orgId AND password_hash IS NOT NULL AND password_hash != ''
            """,
            new { orgId, stamp });

        if (_tokenVersions is not null)
        {
            foreach (string userId in affectedIds)
            {
                _tokenVersions.Invalidate(userId);
            }
        }

        return rows;
    }

    /// <summary>
    /// Erases a user from a tenant. With 1:1 user:tenant, "remove member" is a full account erasure.
    /// A bare <c>DELETE FROM users</c> is neither complete nor reliable: ten columns across other
    /// tables carry a restrict FK to <c>users(id)</c>, so deleting a user who ever invited a
    /// colleague, reserved a namespace, decided a quarantine, dismissed an alert, created a claim,
    /// allowlisted an install script, a licence, or a package name grant would throw a foreign-key violation (an unhandled 500 during
    /// routine offboarding); and several tables with no FK (audit_log, audit_event, activity,
    /// mfa_trusted_devices, login_attempts) would otherwise retain the person's IPs, device
    /// fingerprints, a still-valid trusted-device credential, and email-derived hashes after the
    /// account is gone.
    ///
    /// This runs the whole erasure in one transaction:
    ///   * deletes invites the user created (created_by is NOT NULL + restrict, so it cannot be
    ///     nulled — the attribution goes with the invite);
    ///   * nulls the nine nullable attribution columns (reserved_namespace / quarantine / alert /
    ///     claim / claim_history / install_script_allowlist / license_allowlist / license_blocklist /
    ///     package_name_grant) — the audit value is the action, not
    ///     the actor's continued existence;
    ///   * revokes the user's trusted-device rows (a remembered-device cookie is a separate live
    ///     credential that must not outlive the account — Art. 32);
    ///   * pseudonymizes retained forensic rows (drops source_ip / detail linking to the actor in
    ///     activity and the tenant's audit_log, and source_ip / user_agent in the tenant's
    ///     audit_event rows);
    ///   * clears the login_attempts and account_send_throttle rows keyed by
    ///     <paramref name="loginAttemptKey"/>;
    ///   * deletes the user row (cascading user_tokens, password_reset_tokens, external_identities,
    ///     banner_dismissals).
    /// Encoding this as the sole delete chokepoint keeps existing databases (whose FKs are still
    /// restrict) working without a seven-table recreate reshape, and removes the personal data that
    /// FK actions alone cannot (trusted devices, login_attempts/account_send_throttle, and the
    /// source_ip/detail scrub).
    /// </summary>
    /// <param name="loginAttemptKey">
    /// The subject's <c>login_attempts</c>/<c>account_send_throttle</c> primary-key pseudonym —
    /// <see cref="Dependably.Infrastructure.LoginService.HashLockoutKey"/> over the subject's
    /// (realm, tenant, email), computed by the caller (Management) since the hash helper lives in
    /// the Management assembly. Mirrors the shape <c>PersonalDataExportRepository.ExportAsync</c>
    /// already uses for its own <c>loginAttemptKey</c> parameter.
    /// </param>
    public async Task RemoveOrgMemberAsync(
        string orgId, string userId, string loginAttemptKey, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        // invites.created_by is NOT NULL with a restrict FK, so it cannot be nulled — the user's
        // created invites (pending and accepted) go with the erasure.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM invites WHERE org_id = @orgId AND created_by = @userId",
            new { orgId, userId }, transaction: tx, cancellationToken: ct));

        // Nine nullable attribution columns carry a restrict FK (RemoveOrgMemberRestrictFkComplianceTests
        // derives the set from both schema files and fails when one is missing here): null them so the row (the action's
        // forensic record) survives while the actor reference is removed.
        foreach (string sql in new[]
        {
            "UPDATE reserved_namespace   SET created_by  = NULL WHERE org_id = @orgId AND created_by  = @userId",
            "UPDATE quarantine           SET decided_by  = NULL WHERE org_id = @orgId AND decided_by  = @userId",
            "UPDATE alert                SET dismissed_by = NULL WHERE org_id = @orgId AND dismissed_by = @userId",
            "UPDATE claim                SET created_by  = NULL WHERE org_id = @orgId AND created_by  = @userId",
            "UPDATE claim_history        SET actor_id    = NULL WHERE org_id = @orgId AND actor_id    = @userId",
            "UPDATE install_script_allowlist SET created_by = NULL WHERE org_id = @orgId AND created_by = @userId",
            "UPDATE license_allowlist    SET created_by  = NULL WHERE org_id = @orgId AND created_by  = @userId",
            "UPDATE license_blocklist    SET created_by  = NULL WHERE org_id = @orgId AND created_by  = @userId",
            "UPDATE package_name_grant   SET created_by  = NULL WHERE org_id = @orgId AND created_by  = @userId",
        })
        {
            await conn.ExecuteAsync(new CommandDefinition(sql, new { orgId, userId }, transaction: tx, cancellationToken: ct));
        }

        // Revoke remembered-device credentials — a live cookie must not authenticate a deleted user.
        // xtenant: user_id is FK-bound to the user, already tenant-scoped via the users table; realm
        // pins the tenant realm (system-realm rows reference system_admins, not users).
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM mfa_trusted_devices WHERE user_id = @userId AND realm = 'tenant'",
            new { userId }, transaction: tx, cancellationToken: ct));

        // Pseudonymize retained forensic rows: keep the actor_id skeleton, drop the identifiers.
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE activity SET source_ip = NULL WHERE org_id = @orgId AND actor_id = @userId",
            new { orgId, userId }, transaction: tx, cancellationToken: ct));
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE audit_log SET source_ip = NULL, detail = NULL WHERE org_id = @orgId AND actor_id = @userId",
            new { orgId, userId }, transaction: tx, cancellationToken: ct));
        // audit_event's structured counterpart to audit_log: same pseudonymization, adapted to its
        // own columns (source_ip/user_agent, no detail/payload equivalent worth dropping — payload
        // is never given raw email/IP, only hashed or structural fields). actor_type = 'user'
        // scopes the match to this subject: actor_id is not FK-bound to users, so an api_token or
        // system row could in principle carry the same id string.
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE audit_event SET source_ip = NULL, user_agent = NULL WHERE org_id = @orgId AND actor_id = @userId AND actor_type = 'user'",
            new { orgId, userId }, transaction: tx, cancellationToken: ct));

        // Clear the lockout throttle and send-throttle rows. loginAttemptKey is
        // HashLockoutKey("tenant", orgId, email) — the tenant-scoped pseudonym the lockout store
        // and the send throttle actually key on, not the bare unsalted email hash. Neither table
        // has a tenant column of its own; the tenant is folded into the key, so this bare equality
        // predicate is already tenant-scoped.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM login_attempts WHERE email_hash = @loginAttemptKey",
            new { loginAttemptKey }, transaction: tx, cancellationToken: ct));
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM account_send_throttle WHERE email_hash = @loginAttemptKey",
            new { loginAttemptKey }, transaction: tx, cancellationToken: ct));

        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM users WHERE id = @userId AND tenant_id = @orgId",
            new { orgId, userId }, transaction: tx, cancellationToken: ct));

        await tx.CommitAsync(ct);

        // Invalidate the cached session-version so the erased user's tokens fail closed immediately
        // rather than lingering until the in-memory cache entry expires.
        _tokenVersions?.Invalidate(userId);
    }

    /// <summary>
    /// Resolves the effective storage quota for <paramref name="orgId"/>: the tenant's explicit
    /// override takes precedence; when that is null, the instance-level
    /// <c>default_storage_quota_bytes</c> setting applies. Returns null when neither is set,
    /// meaning the tenant has no storage ceiling (unlimited).
    /// </summary>
    public async Task<long?> GetEffectiveStorageQuotaAsync(string orgId, CancellationToken ct = default)
    {
        var org = await GetByIdAsync(orgId, ct);
        if (org?.StorageQuotaBytes is long tenantQuota)
        {
            return tenantQuota;
        }

        string? raw = await GetInstanceSettingAsync("default_storage_quota_bytes", ct);
        return raw is not null && long.TryParse(raw, out long instanceDefault) && instanceDefault > 0
            ? instanceDefault
            : null;
    }

    /// <summary>
    /// The authoritative definition of an org's stored bytes: <c>org_storage_bytes</c> spans every
    /// plane — hosted versions, the shared cache plane (<c>cache_artifact</c> reachable through
    /// <c>tenant_artifact_access</c>), and OCI blobs. One constant so the quota gate and the
    /// counter baseline below can never disagree about what "bytes this org holds" means.
    /// </summary>
    private const string LiveStorageBytesSql =
        "SELECT COALESCE(SUM(total_bytes), 0) FROM org_storage_bytes WHERE org_id = @orgId";

    /// <summary>
    /// Bytes the tenant currently holds, read live from <c>org_storage_bytes</c>.
    ///
    /// Derived, never accumulated: a row leaving any plane (a version deleted, a
    /// <c>cache_artifact</c> evicted or aged out by retention) leaves this sum by itself, so it
    /// cannot drift away from the bytes actually stored and needs nothing released back into it.
    /// Every quota gate — hosted publish, OCI push, proxy cache fill — enforces against this one
    /// reading, so no two paths can disagree about what "bytes this org holds" means.
    /// </summary>
    public async Task<long> GetLiveStorageBytesAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<long>(LiveStorageBytesSql, new { orgId });
    }

    /// <summary>
    /// Reserves <paramref name="delta"/> bytes of quota headroom for <paramref name="orgId"/>.
    /// Returns the reservation the caller must dispose once its write is committed (or has
    /// failed), or <c>null</c> when the write would carry the tenant past
    /// <paramref name="quota"/> — the caller's 413. A null <paramref name="quota"/> means
    /// unlimited and yields <see cref="StorageReservation.None"/>, so callers dispose
    /// unconditionally.
    ///
    /// Usage is derived from <c>org_storage_bytes</c> (<see cref="GetLiveStorageBytesAsync"/>),
    /// never accumulated onto a counter. A counter has to be decremented by every path that frees
    /// bytes — version delete, cache eviction, retention age-out — and a single missed decrement
    /// ratchets the tenant into refusals it cannot recover from. Deriving the number means
    /// deleting the row IS the release. The cache plane also has no single owning tenant to charge
    /// symmetrically: one <c>cache_artifact</c> row is charged to every tenant holding
    /// <c>tenant_artifact_access</c> on it.
    ///
    /// What the committed sum cannot do alone is see a write in flight: the bytes are invisible
    /// until the row commits after the blob write. <see cref="StorageQuotaLedger"/> charges
    /// admitted-but-uncommitted bytes so concurrent writes — publish and proxy fill alike — weigh
    /// each other rather than all reading the same pre-write sum.
    /// </summary>
    public async Task<StorageReservation?> TryReserveStorageAsync(
        string orgId, long delta, long? quota, CancellationToken ct = default)
    {
        if (quota is null)
        {
            return StorageReservation.None;
        }

        long usedBytes = await GetLiveStorageBytesAsync(orgId, ct);
        return _storageLedger.TryReserve(orgId, usedBytes, delta, quota.Value);
    }

    /// <summary>
    /// Counts active (non-expired, non-revoked) tokens for the given org across both
    /// <c>user_tokens</c> and <c>service_tokens</c> — a point-in-time read for reporting.
    ///
    /// <para>It is <em>not</em> how the cap is enforced, and must not become that: a count read
    /// here and an insert issued afterwards is a check-then-act that concurrent creates all pass.
    /// <see cref="TokenRepository"/> counts and inserts inside one per-tenant serialized
    /// transaction, which is the only place the ceiling actually holds.</para>
    /// </summary>
    public async Task<int> CountActiveTokensAsync(string orgId, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(
            """
            SELECT
                (SELECT COUNT(*) FROM user_tokens
                 WHERE org_id = @orgId AND (expires_at IS NULL OR expires_at > @now)) +
                (SELECT COUNT(*) FROM service_tokens
                 WHERE org_id = @orgId AND (expires_at IS NULL OR expires_at > @now))
            """,
            new { orgId, now });
    }

    /// <summary>
    /// Returns the maximum number of active tokens allowed per tenant. Reads
    /// <c>instance_settings.max_active_tokens_per_tenant</c>, falling back to
    /// <see cref="InstanceSettingDefaults.MaxActiveTokensPerTenant"/> when not set. Shares its
    /// parsing with the enforcing read in <see cref="TokenRepository"/> so the number reported
    /// and the number enforced cannot drift.
    /// </summary>
    public async Task<int> GetMaxActiveTokensPerTenantAsync(CancellationToken ct = default)
    {
        string? raw = await GetInstanceSettingAsync("max_active_tokens_per_tenant", ct);
        return InstanceSettingDefaults.ParseMaxActiveTokensPerTenant(raw);
    }

    /// <summary>
    /// Returns the maximum number of pending (unexpired, unconsumed) invites allowed per
    /// tenant. Reads <c>instance_settings.max_pending_invites_per_tenant</c>, falling back
    /// to <see cref="InstanceSettingDefaults.MaxPendingInvitesPerTenant"/> when not set.
    /// </summary>
    public async Task<int> GetMaxPendingInvitesPerTenantAsync(CancellationToken ct = default)
    {
        string? raw = await GetInstanceSettingAsync("max_pending_invites_per_tenant", ct);
        return raw is not null && int.TryParse(raw, out int cap) && cap > 0
            ? cap
            : int.Parse(InstanceSettingDefaults.MaxPendingInvitesPerTenant);
    }

    /// <summary>
    /// Returns the maximum number of concurrent open OCI upload sessions allowed per tenant.
    /// Reads <c>instance_settings.max_concurrent_oci_uploads_per_tenant</c>, falling back to
    /// <see cref="InstanceSettingDefaults.MaxConcurrentOciUploadsPerTenant"/> when not set.
    /// </summary>
    public async Task<int> GetMaxConcurrentOciUploadsPerTenantAsync(CancellationToken ct = default)
    {
        string? raw = await GetInstanceSettingAsync("max_concurrent_oci_uploads_per_tenant", ct);
        return raw is not null && int.TryParse(raw, out int cap) && cap > 0
            ? cap
            : int.Parse(InstanceSettingDefaults.MaxConcurrentOciUploadsPerTenant);
    }

    /// <summary>
    /// Returns the number of open OCI upload sessions for the given tenant. Used to enforce
    /// the per-tenant concurrent-session cap before allowing a new session to be created.
    /// </summary>
    public async Task<long> GetActiveOciUploadCountAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: counted per org_id — cap applies per tenant, not fleet-wide.
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(1) FROM oci_uploads WHERE org_id = @orgId",
            new { orgId });
    }
}

public sealed record OrgSettingsUpdate(
    string OrgId,
    // Both gates are tri-state at the wire and two-state in storage: null = leave the stored
    // value unchanged (falling back to the column default, 0, when there is no stored row yet),
    // matching AirGapped / RequireMfa below. A partial PUT that omits allowlist_mode must not
    // reset an enforcing allowlist to off as a side effect of writing an unrelated field.
    bool? AnonymousPull,
    bool? AllowlistMode,
    long? MaxUploadBytes,
    long? MaxUploadBytesPyPi,
    long? MaxUploadBytesNpm,
    long? MaxUploadBytesNuGet,
    long? InstanceMaxUploadBytes,
    string? DefaultLanguage,
    // Retained for call-site compatibility; ignored by UpsertSettingsAsync (use VersionOverwritePolicy).
    bool? AllowVersionOverwrite = null,
    // New fields land at the end with defaults so the positional call sites
    // (incl. unit tests in tests/Dependably.Tests/Unit/Infrastructure) keep compiling
    // without a sweep. Callers that need the new caps pass them by name.
    long? MaxUploadBytesMaven = null,
    long? MaxUploadBytesRpm = null,
    long? MaxUploadBytesOci = null,
    long? MaxUploadBytesCargo = null,
    long? MaxUploadBytesHex = null,
    // Per-tenant air-gap posture. null = leave unchanged.
    bool? AirGapped = null,
    // Tri-state same-version-push policy. null = leave unchanged. 'block' | 'exception' | 'allow'.
    string? VersionOverwritePolicy = null,
    // Per-tenant MFA enrollment requirement. null = leave unchanged.
    bool? RequireMfa = null,
    // Per-tenant RPM hosted-publishing posture. null = leave unchanged. 'passthrough' | 'merged'.
    string? RpmUpstreamMode = null,
    // IANA zone name used to render stored instants for tenant users who have not chosen one.
    // null = leave unchanged. Display only — instants are stored in UTC regardless.
    string? DefaultTimezone = null);

/// <summary>
/// The outcome of a tenant lifecycle write (<see cref="OrgRepository.UpdateOrgStatusAsync"/>,
/// <see cref="OrgRepository.SoftDeleteOrgAsync"/>, <see cref="OrgRepository.RestoreOrgAsync"/>):
/// whether a row was changed, and what the write revoked.
/// </summary>
public sealed record TenantLifecycleResult(bool Applied, TenantAccessRevocation Revoked)
{
    public static readonly TenantLifecycleResult NotApplied = new(false, TenantAccessRevocation.None);
}

/// <summary>
/// Counts of what a tenant lifecycle write revoked, recorded on the operator's audit entry for
/// the write. <see cref="Members"/> is the number of members whose sessions were ended.
/// </summary>
public sealed record TenantAccessRevocation(
    int Members,
    int TrustedDevices,
    int UserTokens,
    int ServiceTokens,
    int PasswordResetLinks,
    int EmailChangeLinks,
    int PendingInvites)
{
    public static readonly TenantAccessRevocation None = new(0, 0, 0, 0, 0, 0, 0);
}
