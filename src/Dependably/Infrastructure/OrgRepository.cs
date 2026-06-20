using Dapper;
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

    private readonly IMetadataStore _db;
    private readonly IMemoryCache? _cache;
    private readonly TimeProvider _time;
    private readonly UserTokenVersionStore? _tokenVersions;

    public OrgRepository(IMetadataStore db, IMemoryCache? cache = null, TimeProvider? time = null, UserTokenVersionStore? tokenVersions = null)
    {
        _db = db;
        _cache = cache;
        _time = time ?? TimeProvider.System;
        _tokenVersions = tokenVersions;
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
               COALESCE(license_enforcement_mode, 'off') as LicenseEnforcementMode,
               COALESCE(proxy_passthrough_enabled, 1) as ProxyPassthroughEnabled,
               COALESCE(max_osv_score_tolerance, 10.0) as MaxOsvScoreTolerance,
               min_release_age_hours as MinReleaseAgeHours,
               COALESCE(default_language, 'en') as DefaultLanguage,
               COALESCE(allow_version_overwrite, 0) as AllowVersionOverwrite,
               COALESCE(air_gapped, 0) as AirGapped,
               COALESCE(block_deprecated, 'off') as BlockDeprecated,
               COALESCE(block_malicious, 'block') as BlockMalicious,
               COALESCE(block_kev, 'off') as BlockKev,
               max_epss_tolerance as MaxEpssTolerance,
               COALESCE(block_install_scripts, 'off') as BlockInstallScripts,
               COALESCE(verify_npm_signatures, 'off') as VerifyNpmSignatures,
               COALESCE(verify_nuget_signatures, 'off') as VerifyNuGetSignatures,
               COALESCE(verify_pypi_attestations, 'off') as VerifyPyPiAttestations,
               COALESCE(verify_rpm_signatures, 'off') as VerifyRpmSignatures,
               COALESCE(verify_maven_signatures, 'off') as VerifyMavenSignatures,
               COALESCE(storage_used_bytes, 0) as StorageUsedBytes
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
    /// Aggregates are computed inline using pre-aggregated subqueries so each tenant produces
    /// exactly one outer row — a naive <c>LEFT JOIN users LEFT JOIN packages LEFT JOIN
    /// package_versions</c> would produce N×M rows and inflate both counts. Indexes
    /// (<c>users.tenant_id</c>, <c>idx_packages_org_ecosystem</c>,
    /// <c>idx_package_versions_package</c>) keep this sub-100ms at the page-size cap of 200.
    /// </summary>
    // xtenant: system-admin tenant list — aggregates roll up across all tenants by design.
    public async Task<(IReadOnlyList<OrgListItem> Items, int Total)> ListOrgsAsync(int limit, int offset, bool includeDeleted = true, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int includeDeletedFlag = includeDeleted ? 1 : 0;
        const string countSql =
            "SELECT COUNT(*) FROM orgs WHERE (@includeDeleted = 1 OR deleted_at IS NULL)";
        const string listSql = """
            SELECT o.id                AS Id,
                   o.slug              AS Slug,
                   o.deleted_at        AS DeletedAt,
                   o.status            AS Status,
                   o.storage_quota_bytes AS StorageQuotaBytes,
                   o.created_at        AS CreatedAt,
                   COALESCE(u.member_count, 0)  AS MemberCount,
                   COALESCE(s.storage_bytes, 0) AS StorageBytes
            FROM orgs o
            LEFT JOIN (
                SELECT tenant_id, COUNT(*) AS member_count
                FROM users
                GROUP BY tenant_id
            ) u ON u.tenant_id = o.id
            LEFT JOIN (
                SELECT p.org_id, SUM(pv.size_bytes) AS storage_bytes
                FROM packages p
                JOIN package_versions pv ON pv.package_id = p.id
                GROUP BY p.org_id
            ) s ON s.org_id = o.id
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
            new { orgId, now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ") });
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
        string cutoff = _time.GetUtcNow().AddDays(-graceDays).ToString("yyyy-MM-ddTHH:mm:ssZ");
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

    public async Task UpsertLicensePolicyModeAsync(
        string orgId, string mode, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, license_enforcement_mode)
            VALUES (@orgId, @mode)
            ON CONFLICT(org_id) DO UPDATE SET license_enforcement_mode = @mode
            """,
            new { orgId, mode });
        InvalidateSettingsCache(orgId);
    }

    public async Task<string?> GetInstanceSettingAsync(string key, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key });
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

    public async Task<IReadOnlyDictionary<string, string>> ListInstanceSettingsAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Key, string Value)>(
            "SELECT key as Key, value as Value FROM instance_settings WHERE key != 'jwt_secret'");
        return rows.ToDictionary(r => r.Key, r => r.Value);
    }

    public async Task SetInstanceSettingAsync(string key, string value, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES (@key, @value) ON CONFLICT(key) DO UPDATE SET value = @value",
            new { key, value });
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
    /// system_admin support flow: issues a temporary password for a tenant user and forces
    /// rotation on next login. Returns the raw password (operator hands it to the user
    /// out-of-band) and the new <c>password_reset_issued_at</c> timestamp, or null if the
    /// (email, tenantSlug) pair doesn't resolve.
    ///
    /// This is a deliberately simple flow that works without an email service: no token table,
    /// no signed link. The temporary password is high-entropy and rotation is mandatory.
    /// </summary>
    public async Task<(string TemporaryPassword, DateTimeOffset IssuedAt)?> IssuePasswordResetAsync(
        string email, string tenantSlug, CancellationToken ct = default)
    {
        string raw = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        string hash = BCrypt.Net.BCrypt.HashPassword(raw, workFactor: 12);
        var now = _time.GetUtcNow();
        string nowStr = now.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE users SET
                password_hash = @hash,
                must_change_password = 1,
                password_reset_issued_at = @now
            WHERE id IN (
                SELECT u.id FROM users u
                JOIN orgs o ON o.id = u.tenant_id
                WHERE lower(u.email) = lower(@email) AND o.slug = @tenantSlug
            )
            """,
            new { hash, now = nowStr, email, tenantSlug });

        return rows > 0 ? (raw, now) : null;
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
            SELECT id as UserId, email as Email, role as Role, account_type as AccountType, created_at as JoinedAt
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

    public async Task UpdateMemberRoleAsync(string orgId, string userId, string role, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE users SET role = @role WHERE id = @userId AND tenant_id = @orgId",
            new { orgId, userId, role });
    }

    /// <summary>
    /// Removes a user from a tenant. With 1:1 user:tenant, this deletes the user record.
    /// </summary>
    public async Task RemoveOrgMemberAsync(string orgId, string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM users WHERE id = @userId AND tenant_id = @orgId",
            new { orgId, userId });
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
    /// Atomically reserves <paramref name="delta"/> bytes against the tenant's quota counter.
    /// Issues a single UPDATE that increments <c>storage_used_bytes</c> only when the result
    /// would not exceed <paramref name="quota"/> (NULL = unlimited). Returns true when the
    /// reservation succeeded; false when the quota would be exceeded (caller should return 413).
    ///
    /// SQLite's single-writer lock (busy_timeout=5000, DELETE journal) serialises concurrent
    /// UPDATEs, so no two publishes can both pass the guard simultaneously. The backfill guard
    /// (WHERE storage_used_bytes = 0 ... live SUM) runs first so a freshly-upgraded row with
    /// counter = 0 gets the correct baseline before the first atomic reserve attempt.
    /// </summary>
    public async Task<bool> TryReserveStorageAsync(string orgId, long delta, long? quota, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Ensure the org_settings row exists. CreateOrgAsync always creates one, but some
        // code paths (unit test seeds, operator-managed orgs pre-dating this column) may
        // omit it. ON CONFLICT DO NOTHING is a no-op when the row already exists.
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@orgId) ON CONFLICT(org_id) DO NOTHING",
            new { orgId });

        // Backfill: if the counter is still 0 and the real sum is positive, set it from the
        // live aggregate. WHERE storage_used_bytes = 0 makes this a no-op on rows that were
        // already incremented by a prior publish, so concurrent callers racing the backfill
        // can only inflate the counter, never set it to a stale-low value.
        await conn.ExecuteAsync(
            """
            UPDATE org_settings
            SET storage_used_bytes = (
                SELECT COALESCE(SUM(pv.size_bytes), 0)
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId
            )
            WHERE org_id = @orgId AND storage_used_bytes = 0
            """,
            new { orgId });

        // Atomic reserve: increment the counter only when the new value fits inside the quota.
        // 0 rows affected means quota would be exceeded; caller treats that as 413.
        int rows = await conn.ExecuteAsync(
            """
            UPDATE org_settings
            SET storage_used_bytes = storage_used_bytes + @delta
            WHERE org_id = @orgId
              AND (@quota IS NULL OR storage_used_bytes + @delta <= @quota)
            """,
            new { orgId, delta, quota });

        return rows > 0;
    }

    /// <summary>
    /// Releases a previously reserved <paramref name="delta"/> back to the quota counter.
    /// Called when a publish fails after the reservation, or when a version is deleted.
    /// Clamps at 0 to guard against counter underflow from out-of-order releases.
    /// </summary>
    public async Task ReleaseStorageAsync(string orgId, long delta, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE org_settings
            SET storage_used_bytes = MAX(0, storage_used_bytes - @delta)
            WHERE org_id = @orgId
            """,
            new { orgId, delta });
    }

    /// <summary>
    /// Counts active (non-expired, non-revoked) tokens for the given org across both
    /// <c>user_tokens</c> and <c>service_tokens</c>. Used by the token-cap enforcement in
    /// <see cref="TokenRepository"/> before issuing a new token.
    /// </summary>
    public async Task<int> CountActiveTokensAsync(string orgId, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
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
    /// <see cref="InstanceSettingDefaults.MaxActiveTokensPerTenant"/> when not set.
    /// </summary>
    public async Task<int> GetMaxActiveTokensPerTenantAsync(CancellationToken ct = default)
    {
        string? raw = await GetInstanceSettingAsync("max_active_tokens_per_tenant", ct);
        return raw is not null && int.TryParse(raw, out int cap) && cap > 0
            ? cap
            : int.Parse(InstanceSettingDefaults.MaxActiveTokensPerTenant);
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
    bool AnonymousPull,
    bool AllowlistMode,
    long? MaxUploadBytes,
    long? MaxUploadBytesPyPi,
    long? MaxUploadBytesNpm,
    long? MaxUploadBytesNuGet,
    long? InstanceMaxUploadBytes,
    string? DefaultLanguage,
    bool? AllowVersionOverwrite = null,
    // New fields land at the end with defaults so the positional call sites
    // (incl. unit tests in tests/Dependably.Tests/Unit/Infrastructure) keep compiling
    // without a sweep. Callers that need the new caps pass them by name.
    long? MaxUploadBytesMaven = null,
    long? MaxUploadBytesRpm = null,
    long? MaxUploadBytesOci = null,
    long? MaxUploadBytesCargo = null,
    // Per-tenant air-gap posture. null = leave unchanged (the controller passes the request
    // value through; tristate matches AllowVersionOverwrite). Only OrgSettingsRepository's
    // upsert persists it — see OrgSettings.AirGapped.
    bool? AirGapped = null);
