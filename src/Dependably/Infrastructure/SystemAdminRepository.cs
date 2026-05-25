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

    public SystemAdminRepository(IMetadataStore db)
    {
        _db = db;
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM system_admins");
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
    /// including <c>account_status</c> so the login path can reject locked/disabled operators
    /// after a constant-time hash check. Email match is case-insensitive.
    /// </summary>
    public async Task<(string Id, string Email, string PasswordHash, bool MustChangePassword, string AccountStatus)?> GetCredentialsByEmailAsync(
        string email, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<(string? Id, string? Email, string? PasswordHash, int MustChangePassword, string? AccountStatus)>(
            """
            SELECT id, email, password_hash, must_change_password, account_status
            FROM system_admins
            WHERE lower(email) = lower(@email)
            LIMIT 1
            """,
            new { email });

        if (row.Id is null) return null;
        return (row.Id, row.Email!, row.PasswordHash!, row.MustChangePassword == 1, row.AccountStatus ?? "active");
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
                   created_at AS CreatedAt
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
                   created_at AS CreatedAt
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
        var affected = await conn.ExecuteAsync(
            "UPDATE system_admins SET account_status = @status WHERE id = @id",
            new { id, status });
        return affected > 0;
    }

    /// <summary>
    /// Issues a new password for another admin. Sets <c>must_change_password = 1</c> and stamps
    /// <c>password_reset_issued_at</c>. The plaintext is generated and hashed by the caller so
    /// it can be returned in the response exactly once.
    /// </summary>
    public async Task<bool> ResetPasswordAsync(string id, string newPasswordHash, DateTimeOffset issuedAt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var affected = await conn.ExecuteAsync(
            """
            UPDATE system_admins
            SET password_hash = @hash,
                must_change_password = 1,
                password_reset_issued_at = @issuedAt
            WHERE id = @id
            """,
            new { id, hash = newPasswordHash, issuedAt = issuedAt.ToString("yyyy-MM-ddTHH:mm:ssZ") });
        return affected > 0;
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
    /// Creates a system_admin row. Used by FirstBootService (multi mode) and by migrate-flip CLI.
    /// </summary>
    public async Task<string> CreateAsync(
        string email, string passwordHash, bool mustChangePassword = true, CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO system_admins (id, email, password_hash, must_change_password)
            VALUES (@id, @email, @hash, @mcp)
            """,
            new { id, email, hash = passwordHash, mcp = mustChangePassword ? 1 : 0 });
        return id;
    }

    public async Task UpdateLastLoginAsync(string id, DateTimeOffset when, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE system_admins SET last_login_at = @when WHERE id = @id",
            new { id, when = when.ToString("yyyy-MM-ddTHH:mm:ssZ") });
    }

    /// <summary>
    /// Verifies the current password and (on match) rotates to <paramref name="newPasswordHash"/>,
    /// clearing <c>must_change_password</c>. Returns true on success, false if id is missing or
    /// the current password doesn't match. Used by the system_admin self-rotate flow.
    /// </summary>
    public async Task<bool> RotatePasswordAsync(
        string id, string currentPassword, string newPasswordHash, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var existing = await conn.QuerySingleOrDefaultAsync<string>(
            "SELECT password_hash FROM system_admins WHERE id = @id", new { id });
        if (existing is null) return false;
        if (!BCrypt.Net.BCrypt.Verify(currentPassword, existing)) return false;

        await conn.ExecuteAsync(
            """
            UPDATE system_admins SET password_hash = @hash, must_change_password = 0
            WHERE id = @id
            """,
            new { id, hash = newPasswordHash });
        return true;
    }
}
