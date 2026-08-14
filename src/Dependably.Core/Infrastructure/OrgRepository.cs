using Dapper;
using Dependably.Infrastructure.Identity;
using Microsoft.Extensions.Caching.Memory;

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
        ["jwt_secret", "mfa_encryption_key", "smtp_password", "system_slack_webhook_url"];

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;
    private readonly TimeProvider _time;
    private readonly UserTokenVersionStore? _tokenVersions;
    private readonly EnvelopeProtector? _envelope;

    // In-flight quota reservations for this process. Owned here rather than injected because
    // OrgRepository is the single gate every write path goes through (hosted publish, OCI push,
    // proxy cache fill all call TryReserveStorageAsync) and is registered as a singleton — so one
    // repository instance is one ledger is one view of a tenant's uncommitted bytes.
    private readonly StorageQuotaLedger _storageLedger = new();

    public OrgRepository(IMetadataStore db, IMemoryCache? cache = null, TimeProvider? time = null, UserTokenVersionStore? tokenVersions = null, EnvelopeProtector? envelope = null)
    {
        _db = db;
        _cache = cache;
        _time = time ?? TimeProvider.System;
        _tokenVersions = tokenVersions;
        _envelope = envelope;
    }

    private static string SettingsCacheKey(string orgId) => "org-settings:" + orgId;

    /// <summary>
    /// Invalidates the in-memory cache for <paramref name="orgId"/>'s settings. Called by
    /// settings-update endpoints so policy changes take effect immediately for the next
    /// request rather than waiting for the TTL.
    /// </summary>
    public void InvalidateSettingsCache(string orgId)
        => _cache?.Remove(SettingsCacheKey(orgId));

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
               keep_versions as KeepVersions, keep_days as KeepDays,
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
               COALESCE(block_kev, 'off') as BlockKev,
               max_epss_tolerance as MaxEpssTolerance,
               COALESCE(block_install_scripts, 'off') as BlockInstallScripts,
               COALESCE(verify_npm_signatures, 'off') as VerifyNpmSignatures,
               COALESCE(verify_nuget_signatures, 'off') as VerifyNuGetSignatures,
               COALESCE(verify_pypi_attestations, 'off') as VerifyPyPiAttestations,
               COALESCE(verify_rpm_signatures, 'off') as VerifyRpmSignatures,
               COALESCE(verify_maven_signatures, 'off') as VerifyMavenSignatures,
               COALESCE(verify_terraform_signatures, 'off') as VerifyTerraformSignatures,
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

        await using var conn = await _db.OpenAsync(ct);
        var result = await conn.QuerySingleOrDefaultAsync<OrgSettings>(
            OrgSettingsSelect,
            new { orgId });

        // Cache both hit and miss so a non-existent org_id doesn't repeatedly hit the DB.
        // Size = 1 counts as one logical slot against the global SizeLimit; the actual
        // OrgSettings record is small (<1 KB) compared to the byte-array metadata entries.
        _cache?.Set(key, result, new MemoryCacheEntryOptions
        {
            SlidingExpiration = SettingsCacheTtl,
            AbsoluteExpirationRelativeToNow = SettingsCacheTtl,
            Size = 1,
        });
        return result;
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
    /// community queries collapse them into the active/suspended/soft-deleted view.
    /// </summary>
    // xtenant: dashboard rollup spans every tenant by design.
    public async Task<(int Active, int Suspended, int SoftDeleted)> CountByStatusAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleAsync<(int Active, int Suspended, int SoftDeleted)>(
            """
            SELECT
                COALESCE(SUM(CASE WHEN deleted_at IS NULL AND status = 'active'    THEN 1 ELSE 0 END), 0) AS Active,
                COALESCE(SUM(CASE WHEN deleted_at IS NULL AND status = 'suspended' THEN 1 ELSE 0 END), 0) AS Suspended,
                COALESCE(SUM(CASE WHEN deleted_at IS NOT NULL                       THEN 1 ELSE 0 END), 0) AS SoftDeleted
            FROM orgs
            """);
    }

    /// <summary>
    /// Toggle the tenant lifecycle gate between <c>'active'</c> and <c>'suspended'</c>. Other states
    /// (<c>'archived'</c>, <c>'deleting'</c>) are enterprise-only and rejected. Soft-deleted tenants
    /// are not updated — use restore first. Returns true when a row was changed.
    /// </summary>
    public async Task<bool> UpdateOrgStatusAsync(string orgId, string status, CancellationToken ct = default)
    {
        if (status is not ("active" or "suspended"))
        {
            return false;
        }

        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            "UPDATE orgs SET status = @status WHERE id = @orgId AND deleted_at IS NULL",
            new { orgId, status });
        return rows > 0;
    }

    /// <summary>Soft-delete: set deleted_at = now. Idempotent (re-deleting just refreshes the timestamp).</summary>
    public async Task SoftDeleteOrgAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE orgs SET deleted_at = @now WHERE id = @orgId",
            new { orgId, now = _time.GetUtcNow().ToUtcIso() });
    }

    /// <summary>Restore: clear deleted_at. Returns true if a row was restored.</summary>
    public async Task<bool> RestoreOrgAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            "UPDATE orgs SET deleted_at = NULL WHERE id = @orgId AND deleted_at IS NOT NULL",
            new { orgId });
        return rows > 0;
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

    public async Task<Org> CreateOrgAsync(string slug, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id, slug });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@id)",
            new { id });
        // Seed the standard public upstreams so a new org proxies out of the box. No IConfiguration
        // here, so config overrides aren't visible — falls back to the hard-coded public defaults.
        await UpstreamRegistrySeeder.SeedForOrgAsync(conn, id, config: null, ct: ct);
        return new Org { Id = id, Slug = slug, CreatedAt = _time.GetUtcNow() };
    }

    public async Task DeleteOrgAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM orgs WHERE id = @orgId", new { orgId });
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
                license_publish_enforcement_mode = COALESCE(@publishMode, license_publish_enforcement_mode)
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
        return raw is null ? null : (_envelope?.Unprotect(raw) ?? raw);
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
    /// if the (email, tenantSlug) pair doesn't resolve. Idempotent on the same target status.
    /// When locking or disabling, bumps <c>users.token_version</c> to invalidate every active
    /// session JWT for the affected user (the same mechanism as a password change). The
    /// in-memory token-version cache is evicted immediately so the next request re-reads the
    /// new version rather than serving from a stale cache entry.
    /// </summary>
    public async Task<bool> SetUserAccountStatusAsync(
        string email, string tenantSlug, string accountStatus, CancellationToken ct = default)
    {
        if (accountStatus is not ("active" or "locked" or "disabled"))
        {
            return false;
        }

        await using var conn = await _db.OpenAsync(ct);

        // Resolving to locked/disabled kills active sessions by bumping token_version.
        // Restoring to active does not bump — the user has no live sessions while locked.
        bool bumpVersion = accountStatus is "locked" or "disabled";

        // xtenant: system_admin flow that resolves a user by email + org slug across tenants.
        IEnumerable<string>? affectedIds = null;
        if (bumpVersion && _tokenVersions is not null)
        {
            affectedIds = await conn.QueryAsync<string>(
                """
                SELECT u.id FROM users u
                JOIN orgs o ON o.id = u.tenant_id
                WHERE lower(u.email) = lower(@email) AND o.slug = @tenantSlug
                """,
                new { email, tenantSlug });
        }

        string sql = bumpVersion
            ? """
              UPDATE users SET account_status = @status, token_version = token_version + 1
              WHERE id IN (
                  SELECT u.id FROM users u
                  JOIN orgs o ON o.id = u.tenant_id
                  WHERE lower(u.email) = lower(@email) AND o.slug = @tenantSlug
              )
              """
            : """
              UPDATE users SET account_status = @status
              WHERE id IN (
                  SELECT u.id FROM users u
                  JOIN orgs o ON o.id = u.tenant_id
                  WHERE lower(u.email) = lower(@email) AND o.slug = @tenantSlug
              )
              """;

        int rows = await conn.ExecuteAsync(sql, new { status = accountStatus, email, tenantSlug });

        if (rows > 0 && affectedIds is not null)
        {
            foreach (string userId in affectedIds)
            {
                _tokenVersions!.Invalidate(userId);
            }
        }

        return rows > 0;
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
    /// A bare <c>DELETE FROM users</c> is neither complete nor reliable: seven columns across other
    /// tables carry a restrict FK to <c>users(id)</c>, so deleting a user who ever invited a
    /// colleague, reserved a namespace, decided a quarantine, dismissed an alert, created a claim,
    /// or allowlisted an install script would throw a foreign-key violation (an unhandled 500 during
    /// routine offboarding); and several tables with no FK (audit_log, audit_event, activity,
    /// mfa_trusted_devices, login_attempts) would otherwise retain the person's IPs, device
    /// fingerprints, a still-valid trusted-device credential, and email-derived hashes after the
    /// account is gone.
    ///
    /// This runs the whole erasure in one transaction:
    ///   * deletes invites the user created (created_by is NOT NULL + restrict, so it cannot be
    ///     nulled — the attribution goes with the invite);
    ///   * nulls the six nullable attribution columns (reserved_namespace / quarantine / alert /
    ///     claim / claim_history / install_script_allowlist) — the audit value is the action, not
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

        // Six nullable attribution columns carry a restrict FK: null them so the row (the action's
        // forensic record) survives while the actor reference is removed.
        foreach (string sql in new[]
        {
            "UPDATE reserved_namespace   SET created_by  = NULL WHERE org_id = @orgId AND created_by  = @userId",
            "UPDATE quarantine           SET decided_by  = NULL WHERE org_id = @orgId AND decided_by  = @userId",
            "UPDATE alert                SET dismissed_by = NULL WHERE org_id = @orgId AND dismissed_by = @userId",
            "UPDATE claim                SET created_by  = NULL WHERE org_id = @orgId AND created_by  = @userId",
            "UPDATE claim_history        SET actor_id    = NULL WHERE org_id = @orgId AND actor_id    = @userId",
            "UPDATE install_script_allowlist SET created_by = NULL WHERE org_id = @orgId AND created_by = @userId",
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
