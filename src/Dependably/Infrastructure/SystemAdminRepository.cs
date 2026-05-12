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
    /// Looks up a system_admin by email. Returns the credentials needed for login verification.
    /// Email match is case-insensitive (matches existing user-login convention).
    /// </summary>
    public async Task<(string Id, string Email, string PasswordHash, bool MustChangePassword)?> GetCredentialsByEmailAsync(
        string email, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<(string? Id, string? Email, string? PasswordHash, int MustChangePassword)>(
            """
            SELECT id, email, password_hash, must_change_password
            FROM system_admins
            WHERE lower(email) = lower(@email)
            LIMIT 1
            """,
            new { email });

        if (row.Id is null) return null;
        return (row.Id, row.Email!, row.PasswordHash!, row.MustChangePassword == 1);
    }

    public async Task<SystemAdmin?> GetByIdAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<SystemAdmin>(
            """
            SELECT id AS Id, email AS Email,
                   must_change_password AS MustChangePassword,
                   last_login_at AS LastLoginAt,
                   language AS Language,
                   created_at AS CreatedAt
            FROM system_admins WHERE id = @id
            """,
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
