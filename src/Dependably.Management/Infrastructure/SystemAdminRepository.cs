using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Operator identity store. system_admins are the apex-domain users in <c>multi</c>-mode
/// deployments — they manage tenants and instance settings but never see tenant business data.
/// In <c>single</c> mode this table stays empty.
/// </summary>
public sealed class SystemAdminRepository
{
    // Fixed serialization key for every account-status change. The last-active guard counts the
    // whole table, so the lock is instance-wide rather than per admin.
    private const string AccountStatusLockKey = "system-admins-account-status";

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
    /// evicts the cached token version, and drops remembered trusted devices. Every write runs in
    /// one transaction, so a fault partway through cannot leave a remembered device that skips the
    /// second factor under the new password, nor a new password with the old tokens still live.
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
        await using var tx = await conn.BeginTransactionAsync(ct);

        // Resolve the target user across tenants so the credential-invalidation writes below can
        // key on the users PK (and so cache/trusted-device invalidation has the id to work with).
        // xtenant: operator support flow resolves a tenant user by (email, slug) across tenants.
        string? userId = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            """
            SELECT u.id FROM users u
            JOIN orgs o ON o.id = u.tenant_id
            WHERE lower(u.email) = lower(@email) AND o.slug = @tenantSlug
            """,
            new { email, tenantSlug }, transaction: tx, cancellationToken: ct));
        if (userId is null)
        {
            return null;
        }

        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        // xtenant: keyed by the users PK resolved above.
        await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE users SET
                password_hash = @hash,
                must_change_password = 1,
                password_reset_issued_at = @now,
                token_version = token_version + 1,
                security_stamp = @stamp
            WHERE id = @id
            """,
            new { hash, now = nowStr, stamp, id = userId }, transaction: tx, cancellationToken: ct));

        // Revoke (delete) the user's API tokens — a reset credential must cut off everything
        // minted under the old one. user_id is FK-bound to users.id, which is already tenant-scoped.
        // xtenant: user_tokens.user_id is FK-bound to the resolved users row.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        // An operator-issued reset is itself a credential change, so any outstanding self-serve
        // reset link the user requested must be voided too — replay defense.
        // xtenant: user_id is FK-bound to the resolved users row.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM password_reset_tokens WHERE user_id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        // Drop trusted-device records so remembered devices no longer bypass TOTP.
        if (_trustedDevices is not null)
        {
            await TrustedDeviceService.DeleteAllForUserAsync(conn, tx, userId, "tenant", ct);
        }

        await tx.CommitAsync(ct);

        // After the commit, so a cache fill cannot re-read the pre-reset version: the stale
        // session dies immediately on this node.
        _tokenVersions?.Invalidate(userId);
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

    /// <summary>
    /// True when the admin is <c>active</c> and their <c>token_version</c> still equals
    /// <paramref name="tokenVersion"/>. Read live, not through the cached version store: the
    /// second-factor step uses it to refuse a challenge issued before a lock, disable,
    /// re-activation or credential change, before it mints a session or remembers a device.
    /// </summary>
    public async Task<bool> IsActiveAtVersionAsync(string id, long tokenVersion, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int matches = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM system_admins
            WHERE id = @id AND account_status = 'active' AND token_version = @tokenVersion
            """,
            new { id, tokenVersion });
        return matches > 0;
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
    /// Updates <c>account_status</c> to one of <c>active|locked|disabled</c>, refusing any
    /// non-active status that would leave the instance with no active admin. The controller is
    /// responsible for the self-modification check before calling.
    ///
    /// The last-active guard and the write run in one transaction serialized on
    /// <see cref="AccountStatusLockKey"/> (<c>BEGIN IMMEDIATE</c> on SQLite, a transaction-scoped
    /// advisory lock under READ COMMITTED on Postgres), so two operators disabling each other at
    /// the same moment cannot both pass the count: the second caller's count runs only after the
    /// first has committed, and sees its write. A conditional <c>UPDATE … WHERE (SELECT COUNT …)</c>
    /// alone is not enough on Postgres, because the two writes touch different rows and each
    /// statement's snapshot predates the other's uncommitted change. Every path that can lower the
    /// active count goes through this method; <see cref="DeleteIfDisabledAsync"/> removes only rows
    /// that are already <c>disabled</c>, and inserts only raise the count.
    ///
    /// Locking or disabling an admin is how an operator cuts off a peer, so it ends that admin's
    /// access at once rather than when their session expires: the same UPDATE bumps
    /// <c>token_version</c> (rotating <c>security_stamp</c> alongside), so every outstanding
    /// system session JWT carries a stale <c>tver</c>; the cached version is evicted after the
    /// commit; and the admin's remembered devices are dropped in the same transaction. <c>locked</c> is operator-set (failed-login throttling lives in the lockout store and
    /// never writes this column), so it revokes exactly like <c>disabled</c>, as it does for tenant
    /// users.
    ///
    /// Re-activating bumps too. A lock or disable through this method has already staled the old
    /// sessions, but a status written by any other path may not have, and a non-active admin holds
    /// no working session to lose (<see cref="Identity.SystemAdminTokenVersionStore"/> answers null
    /// for one), so the extra bump guarantees re-activation never revives a pre-lock session.
    /// Every transition that bumps also drops the remembered devices, re-activation included, so
    /// a device row written while the admin was not active cannot skip the second factor
    /// afterwards. Setting an active admin to active changes nothing.
    /// </summary>
    public async Task<AdminAccountStatusChange> SetAccountStatusAsync(string id, string status, CancellationToken ct = default)
    {
        string stamp = Guid.NewGuid().ToString();
        List<string?> returned;
        bool bumped;
        await using (var conn = await _db.OpenAsync(ct))
        {
            await conn.BeginTenantSerializedAsync(_db.Provider, AccountStatusLockKey, ct);
            try
            {
                if (!string.Equals(status, "active", StringComparison.Ordinal))
                {
                    long otherActive = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
                        "SELECT COUNT(*) FROM system_admins WHERE account_status = 'active' AND id <> @id",
                        new { id }, cancellationToken: ct));
                    if (otherActive == 0)
                    {
                        await conn.ExecuteAsync("ROLLBACK");
                        return AdminAccountStatusChange.LastActiveAdmin;
                    }
                }

                // SET expressions read the pre-update row on both providers, so the CASE compares
                // the previous status with the new one. RETURNING reads the post-update row, so the
                // returned stamp equals the fresh one exactly when this write bumped.
                returned = (await conn.QueryAsync<string?>(new CommandDefinition(
                    """
                    UPDATE system_admins
                    SET token_version = CASE WHEN account_status = 'active' AND @status = 'active'
                                             THEN token_version ELSE token_version + 1 END,
                        security_stamp = CASE WHEN account_status = 'active' AND @status = 'active'
                                              THEN security_stamp ELSE @stamp END,
                        account_status = @status
                    WHERE id = @id
                    RETURNING security_stamp
                    """,
                    new { id, status, stamp }, cancellationToken: ct))).AsList();

                // The remembered devices go in the same transaction as the status write: a fault
                // between the two would otherwise leave a device that skips the second factor once
                // the admin is re-activated.
                bumped = returned.Count > 0 && string.Equals(returned[0], stamp, StringComparison.Ordinal);
                if (bumped)
                {
                    // xtenant: system-realm rows reference system_admins, which has no tenant.
                    await conn.ExecuteAsync(new CommandDefinition(
                        "DELETE FROM mfa_trusted_devices WHERE user_id = @id AND realm = 'system'",
                        new { id }, cancellationToken: ct));
                }

                await conn.ExecuteAsync("COMMIT");
            }
            catch
            {
                await conn.ExecuteAsync("ROLLBACK");
                throw;
            }
        }

        if (returned.Count == 0)
        {
            return AdminAccountStatusChange.NotFound;
        }

        // After the commit, per the cache fill guard's invalidate-after-write rule: a fill that
        // read the pre-change row holds a generation this call cancels.
        _adminTokenVersions?.Invalidate(id);

        return AdminAccountStatusChange.Updated;
    }

    /// <summary>
    /// Issues a new password for another admin. Sets <c>must_change_password = 1</c>, stamps
    /// <c>password_reset_issued_at</c>, and cuts off the target admin's existing sessions and
    /// remembered devices exactly like the self-rotate path: bumps <c>token_version</c> (rotating
    /// <c>security_stamp</c> alongside) so outstanding session JWTs stale immediately, evicts the
    /// cached token version, and drops trusted-device rows. The plaintext is generated and hashed
    /// by the caller so it can be returned in the response exactly once. The password write and the
    /// device delete are one transaction, so a fault between them cannot leave a remembered device
    /// that skips the second factor under the new password.
    /// </summary>
    public async Task<bool> ResetPasswordAsync(string id, string newPasswordHash, DateTimeOffset issuedAt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();
        int affected = await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE system_admins
            SET password_hash = @hash,
                must_change_password = 1,
                password_reset_issued_at = @issuedAt,
                token_version = token_version + 1,
                security_stamp = @stamp
            WHERE id = @id
            """,
            new { id, hash = newPasswordHash, stamp, issuedAt = issuedAt.ToUtcIso() },
            transaction: tx, cancellationToken: ct));
        if (affected == 0)
        {
            return false;
        }

        // Drop trusted-device records so remembered devices no longer bypass TOTP.
        if (_trustedDevices is not null)
        {
            await TrustedDeviceService.DeleteAllForUserAsync(conn, tx, id, "system", ct);
        }

        await tx.CommitAsync(ct);

        // After the commit, so a cache fill cannot re-read the pre-reset version: the stale
        // session dies immediately on this node.
        _adminTokenVersions?.Invalidate(id);
        return true;
    }

    /// <summary>
    /// Hard-deletes an admin, but only when <c>account_status = 'disabled'</c>. The two-step
    /// "disable, then delete" requirement prevents an active operator from being removed by a
    /// single API call. Returns the affected row count: 0 means either the id was missing or
    /// the row was not in the <c>disabled</c> state. A successful delete evicts the admin's cached
    /// token version after the write, so a session still holding a cached entry fails on its next
    /// request instead of surviving until the entry's TTL.
    ///
    /// The <c>disabled</c> condition is part of the DELETE itself, not a value read earlier in the
    /// request, so a row re-activated after the caller's read is left alone. Removing a disabled
    /// row never changes the active count, which is why this path needs no last-active guard or
    /// serialization of its own.
    /// </summary>
    public async Task<int> DeleteIfDisabledAsync(string id, CancellationToken ct = default)
    {
        int affected;
        await using (var conn = await _db.OpenAsync(ct))
        {
            affected = await conn.ExecuteAsync(
                "DELETE FROM system_admins WHERE id = @id AND account_status = 'disabled'",
                new { id });
        }

        if (affected > 0)
        {
            _adminTokenVersions?.Invalidate(id);
        }

        return affected;
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
    /// all outstanding session JWTs, and drops the admin's remembered devices in the same transaction. Returns the new token_version on success, or null if the id
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

        // The password write and the device drop commit together, so a fault between them cannot
        // leave a remembered device that skips the second factor under the new password.
        await using var tx = await conn.BeginTransactionAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE system_admins
            SET password_hash = @hash, must_change_password = 0, token_version = token_version + 1,
                security_stamp = @stamp
            WHERE id = @id
            """,
            new { id, hash = newPasswordHash, stamp }, transaction: tx, cancellationToken: ct));
        long newVersion = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id }, transaction: tx, cancellationToken: ct));

        if (_trustedDevices is not null)
        {
            await TrustedDeviceService.DeleteAllForUserAsync(conn, tx, id, "system", ct);
        }

        await tx.CommitAsync(ct);

        // After the commit, so a cache fill cannot re-read the pre-change version.
        _adminTokenVersions?.Invalidate(id);
        return newVersion;
    }
}

/// <summary>Outcome of <see cref="SystemAdminRepository.SetAccountStatusAsync"/>.</summary>
public enum AdminAccountStatusChange
{
    /// <summary>The status was written.</summary>
    Updated,

    /// <summary>No admin has the given id.</summary>
    NotFound,

    /// <summary>The change was refused because it would leave no active admin.</summary>
    LastActiveAdmin,
}
