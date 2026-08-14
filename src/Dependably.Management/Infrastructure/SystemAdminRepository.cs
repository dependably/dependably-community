using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Operator identity store. system_admins are the apex-domain users in <c>multi</c>-mode
/// deployments — they manage tenants and instance settings but never see tenant business data.
/// In <c>single</c> mode this table stays empty.
/// </summary>
public sealed class SystemAdminRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly UserTokenVersionStore? _tokenVersions;
    private readonly Identity.SystemAdminTokenVersionStore? _adminTokenVersions;
    private readonly TrustedDeviceService? _trustedDevices;

    public SystemAdminRepository(
        IMetadataStore db,
        TimeProvider? time = null,
        UserTokenVersionStore? tokenVersions = null,
        TrustedDeviceService? trustedDevices = null,
        Identity.SystemAdminTokenVersionStore? adminTokenVersions = null)
    {
        _db = db;
        _time = time ?? TimeProvider.System;
        _tokenVersions = tokenVersions;
        _trustedDevices = trustedDevices;
        _adminTokenVersions = adminTokenVersions;
    }

    /// <summary>
    /// system_admin support flow: issues a temporary password for a tenant user and forces
    /// rotation on next login. Returns the raw password (operator hands it to the user
    /// out-of-band) and the new <c>password_reset_issued_at</c> timestamp, or null if the
    /// (email, tenantSlug) pair doesn't resolve.
    ///
    /// This is a deliberately simple flow that works without an email service: no token table,
    /// no signed link. The temporary password is high-entropy and rotation is mandatory.
    ///
    /// An operator reset is the compromise-response control, so it cuts off every credential
    /// minted under the old password exactly like the self-service change-password path: it bumps
    /// <c>token_version</c> (staling outstanding session JWTs via the <c>tver</c> claim), rotates
    /// the Identity <c>security_stamp</c>, revokes the user's API tokens (<c>user_tokens</c> rows),
    /// evicts the cached token version, and drops remembered trusted devices.
    /// </summary>
    public async Task<(string TemporaryPassword, DateTimeOffset IssuedAt)?> IssuePasswordResetAsync(
        string email, string tenantSlug, CancellationToken ct = default)
    {
        string raw = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        string hash = BCrypt.Net.BCrypt.HashPassword(raw, workFactor: 12);
        var now = _time.GetUtcNow();
        string nowStr = now.ToUtcIso();
        string stamp = Guid.NewGuid().ToString();

        await using var conn = await _db.OpenAsync(ct);

        // Resolve the target user across tenants so the credential-invalidation writes below can
        // key on the users PK (and so cache/trusted-device invalidation has the id to work with).
        // xtenant: operator support flow resolves a tenant user by (email, slug) across tenants.
        string? userId = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT u.id FROM users u
            JOIN orgs o ON o.id = u.tenant_id
            WHERE lower(u.email) = lower(@email) AND o.slug = @tenantSlug
            """,
            new { email, tenantSlug });
        if (userId is null)
        {
            return null;
        }

        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        // xtenant: keyed by the users PK resolved above.
        await conn.ExecuteAsync(
            """
            UPDATE users SET
                password_hash = @hash,
                must_change_password = 1,
                password_reset_issued_at = @now,
                token_version = token_version + 1,
                security_stamp = @stamp
            WHERE id = @id
            """,
            new { hash, now = nowStr, stamp, id = userId });

        // Revoke (delete) the user's API tokens — a reset credential must cut off everything
        // minted under the old one. user_id is FK-bound to users.id, which is already tenant-scoped.
        // xtenant: user_tokens.user_id is FK-bound to the resolved users row.
        await conn.ExecuteAsync(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId });

        // An operator-issued reset is itself a credential change, so any outstanding self-serve
        // reset link the user requested must be voided too — replay defense.
        // xtenant: user_id is FK-bound to the resolved users row.
        await conn.ExecuteAsync(
            "DELETE FROM password_reset_tokens WHERE user_id = @id", new { id = userId });

        // Evict the cached token_version so the stale session dies immediately on this node, and
        // drop trusted-device records so remembered devices no longer bypass TOTP.
        _tokenVersions?.Invalidate(userId);
        if (_trustedDevices is not null)
        {
            await _trustedDevices.DeleteAllForUserAsync(userId, "tenant", ct);
        }

        return (raw, now);
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM system_admins");
    }

    /// <summary>
    /// Lean check used by the request pipeline to force temp-password rotation for system
    /// admins: true when the admin must change their password before continuing. Missing row → false.
    /// </summary>
    public async Task<bool> IsPasswordChangeRequiredAsync(string adminId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long? flag = await conn.ExecuteScalarAsync<long?>(
            "SELECT must_change_password FROM system_admins WHERE id = @id", new { id = adminId });
        return flag == 1;
    }

    /// <summary>
    /// Lean check used by <see cref="Dependably.Security.MfaEnrollmentGuard"/>: true when
    /// the system admin has completed MFA enrollment. Read live from the database so enrollment
    /// takes effect immediately. Missing row → false.
    /// </summary>
    public async Task<bool> IsMfaEnabledAsync(string adminId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long? flag = await conn.ExecuteScalarAsync<long?>(
            "SELECT mfa_enabled FROM system_admins WHERE id = @id", new { id = adminId });
        return flag == 1;
    }

    /// <summary>
    /// Bucketed counts for the sysadmin dashboard. Single round-trip. Mirrors
    /// <c>OrgRepository.CountByStatusAsync</c>'s shape so the dashboard render is symmetric.
    /// </summary>
    public async Task<(int Active, int Locked, int Disabled)> CountByAccountStatusAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleAsync<(int Active, int Locked, int Disabled)>(
            """
            SELECT
                COALESCE(SUM(CASE WHEN account_status = 'active'   THEN 1 ELSE 0 END), 0) AS Active,
                COALESCE(SUM(CASE WHEN account_status = 'locked'   THEN 1 ELSE 0 END), 0) AS Locked,
                COALESCE(SUM(CASE WHEN account_status = 'disabled' THEN 1 ELSE 0 END), 0) AS Disabled
            FROM system_admins
            """);
    }

    /// <summary>
    /// Counts admins with <c>account_status = 'active'</c> excluding the supplied id. Used as
    /// the last-active guard before disabling, locking, or deleting an admin — if this returns
    /// zero, the operation would leave the instance with no way for an operator to sign in.
    /// </summary>
    public async Task<int> CountActiveExcludingAsync(string excludeId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM system_admins WHERE account_status = 'active' AND id <> @excludeId",
            new { excludeId });
    }

    /// <summary>
    /// Looks up a system_admin by email. Returns the credentials needed for login verification,
    /// including <c>account_status</c>, <c>mfa_enabled</c>, and <c>token_version</c> so the
    /// login path can evaluate MFA enrollment and issue the correct tver claim. Email match
    /// is case-insensitive.
    /// </summary>
    public async Task<(string Id, string Email, string PasswordHash, bool MustChangePassword, string AccountStatus, bool MfaEnabled, long TokenVersion)?> GetCredentialsByEmailAsync(
        string email, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var (Id, Email, PasswordHash, MustChangePassword, AccountStatus, MfaEnabled, TokenVersion) =
            await conn.QuerySingleOrDefaultAsync<(string? Id, string? Email, string? PasswordHash,
                int MustChangePassword, string? AccountStatus, int MfaEnabled, long TokenVersion)>(
            """
            SELECT id, email, password_hash, must_change_password, account_status,
                   mfa_enabled, token_version
            FROM system_admins
            WHERE lower(email) = lower(@email)
            -- Election is deterministic: a legacy database can still hold two case-variant rows
            -- for one address (they predate the canonical write form), and the oldest row is the
            -- original account rather than whichever one the query engine happens to return.
            ORDER BY created_at, id
            LIMIT 1
            """,
            new { email });

        return Id is null ? null
            : (Id, Email!, PasswordHash!, MustChangePassword == 1,
               AccountStatus ?? "active", MfaEnabled == 1, TokenVersion);
    }

    /// <summary>
    /// Atomically increments <c>token_version</c> for the given admin and returns the new value.
    /// Invalidating the version immediately stales all outstanding system-scope JWTs for this
    /// admin so MFA disable and credential rotations revoke all existing sessions.
    /// </summary>
    public async Task<long> BumpTokenVersionAsync(string adminId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();
        await conn.ExecuteAsync(
            "UPDATE system_admins SET token_version = token_version + 1, security_stamp = @stamp WHERE id = @id",
            new { stamp, id = adminId });
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id",
            new { id = adminId });
    }

    public async Task<SystemAdmin?> GetByIdAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<SystemAdmin>(
            """
            SELECT id AS Id, email AS Email,
                   must_change_password AS MustChangePassword,
                   last_login_at AS LastLoginAt,
                   account_status AS AccountStatus,
                   password_reset_issued_at AS PasswordResetIssuedAt,
                   language AS Language,
                   timezone AS Timezone,
                   created_at AS CreatedAt,
                   mfa_enabled AS MfaEnabled
            FROM system_admins WHERE id = @id
            """,
            new { id });
    }

    /// <summary>
    /// Lists all system_admins for the control-plane listing endpoint. Never includes
    /// <c>password_hash</c> — the projection returns only fields safe to expose to operators.
    /// </summary>
    public async Task<IReadOnlyList<SystemAdmin>> ListAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<SystemAdmin>(
            """
            SELECT id AS Id, email AS Email,
                   must_change_password AS MustChangePassword,
                   last_login_at AS LastLoginAt,
                   account_status AS AccountStatus,
                   password_reset_issued_at AS PasswordResetIssuedAt,
                   language AS Language,
                   created_at AS CreatedAt,
                   mfa_enabled AS MfaEnabled
            FROM system_admins
            ORDER BY created_at
            """);
        return rows.AsList();
    }

    public async Task<SystemAdmin?> GetByEmailAsync(string email, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<SystemAdmin>(
            """
            SELECT id AS Id, email AS Email,
                   must_change_password AS MustChangePassword,
                   last_login_at AS LastLoginAt,
                   account_status AS AccountStatus,
                   password_reset_issued_at AS PasswordResetIssuedAt,
                   language AS Language,
                   created_at AS CreatedAt
            FROM system_admins WHERE lower(email) = lower(@email)
            """,
            new { email });
    }

    /// <summary>
    /// Updates <c>account_status</c> to one of <c>active|locked|disabled</c>. The controller is
    /// responsible for last-active guard and self-modification checks before calling.
    /// </summary>
    public async Task<bool> SetAccountStatusAsync(string id, string status, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int affected = await conn.ExecuteAsync(
            "UPDATE system_admins SET account_status = @status WHERE id = @id",
            new { id, status });
        return affected > 0;
    }

    /// <summary>
    /// Issues a new password for another admin. Sets <c>must_change_password = 1</c>, stamps
    /// <c>password_reset_issued_at</c>, and cuts off the target admin's existing sessions and
    /// remembered devices exactly like the self-rotate path: bumps <c>token_version</c> (rotating
    /// <c>security_stamp</c> alongside) so outstanding session JWTs stale immediately, evicts the
    /// cached token version, and drops trusted-device rows. The plaintext is generated and hashed
    /// by the caller so it can be returned in the response exactly once.
    /// </summary>
    public async Task<bool> ResetPasswordAsync(string id, string newPasswordHash, DateTimeOffset issuedAt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();
        int affected = await conn.ExecuteAsync(
            """
            UPDATE system_admins
            SET password_hash = @hash,
                must_change_password = 1,
                password_reset_issued_at = @issuedAt,
                token_version = token_version + 1,
                security_stamp = @stamp
            WHERE id = @id
            """,
            new { id, hash = newPasswordHash, stamp, issuedAt = issuedAt.ToUtcIso() });
        if (affected == 0)
        {
            return false;
        }

        // Evict the cached token_version so the stale session dies immediately on this node, and
        // drop trusted-device records so remembered devices no longer bypass TOTP.
        _adminTokenVersions?.Invalidate(id);
        if (_trustedDevices is not null)
        {
            await _trustedDevices.DeleteAllForUserAsync(id, "system", ct);
        }

        return true;
    }

    /// <summary>
    /// Hard-deletes an admin, but only when <c>account_status = 'disabled'</c>. The two-step
    /// "disable, then delete" requirement prevents an active operator from being removed by a
    /// single API call. Returns the affected row count: 0 means either the id was missing or
    /// the row was not in the <c>disabled</c> state.
    /// </summary>
    public async Task<int> DeleteIfDisabledAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            "DELETE FROM system_admins WHERE id = @id AND account_status = 'disabled'",
            new { id });
    }

    public async Task UpdateLanguageAsync(string id, string language, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE system_admins SET language = @language WHERE id = @id",
            new { id, language });
    }

    /// <summary>
    /// Sets or clears the operator's display-timezone override. A null value clears it, which
    /// is how "use the instance default" is expressed — storing "UTC" by name would be
    /// indistinguishable from a deliberate choice of UTC.
    /// </summary>
    public async Task UpdateTimezoneAsync(string id, string? timezone, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE system_admins SET timezone = @timezone WHERE id = @id",
            new { id, timezone });
    }

    /// <summary>
    /// Creates a system_admin row. Used by FirstBootService (multi mode) and by migrate-flip CLI.
    /// </summary>
    public async Task<string> CreateAsync(
        string email, string passwordHash, bool mustChangePassword = true, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO system_admins (id, email, password_hash, must_change_password)
            VALUES (@id, @email, @hash, @mcp)
            """,
            new { id, email = EmailNormalizer.Normalize(email), hash = passwordHash, mcp = mustChangePassword ? 1 : 0 });
        return id;
    }

    public async Task UpdateLastLoginAsync(string id, DateTimeOffset when, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE system_admins SET last_login_at = @when WHERE id = @id",
            new { id, when = when.ToUtcIso() });
    }

    /// <summary>
    /// Verifies the current password and (on match) rotates to <paramref name="newPasswordHash"/>,
    /// clearing <c>must_change_password</c> and incrementing <c>token_version</c> to invalidate
    /// all outstanding session JWTs. Returns the new token_version on success, or null if the id
    /// is missing or the current password doesn't match. Used by the system_admin self-rotate flow.
    /// </summary>
    public async Task<long?> RotatePasswordAsync(
        string id, string currentPassword, string newPasswordHash, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? existing = await conn.QuerySingleOrDefaultAsync<string>(
            "SELECT password_hash FROM system_admins WHERE id = @id", new { id });
        if (existing is null)
        {
            return null;
        }

        if (!BCrypt.Net.BCrypt.Verify(currentPassword, existing))
        {
            return null;
        }

        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();
        await conn.ExecuteAsync(
            """
            UPDATE system_admins
            SET password_hash = @hash, must_change_password = 0, token_version = token_version + 1,
                security_stamp = @stamp
            WHERE id = @id
            """,
            new { id, hash = newPasswordHash, stamp });
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id });
    }
}
