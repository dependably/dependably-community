using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-user lifecycle operations used by <see cref="Dependably.Api.AuthController"/>: create
/// from invite, password change, language preference, "me" projection. The controller calls
/// these methods directly so its actions stay HTTP-shape and the SQL surface lives here,
/// matching <see cref="LoginService"/>'s role for the authentication path.
/// </summary>
public sealed class UserService
{
    private readonly IMetadataStore _db;
    private readonly OrgRepository _orgs;

    public UserService(IMetadataStore db, OrgRepository orgs)
    {
        _db = db;
        _orgs = orgs;
    }

    /// <summary>
    /// Creates a tenant user from an accepted invite. Caller is responsible for invite
    /// consumption (<see cref="InviteRepository.AcceptAsync"/>) before calling this so the
    /// invite is single-use even if user creation later fails.
    /// </summary>
    public async Task<string> CreateFromInviteAsync(InviteRecord invite, string password, CancellationToken ct = default)
    {
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        var userId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role)
            VALUES (@id, @tenantId, @email, @hash, @role)
            """,
            new
            {
                id = userId,
                tenantId = invite.OrgId,
                email = invite.Email,
                hash = passwordHash,
                role = invite.Role ?? "member",
            });
        return userId;
    }

    public async Task<PasswordChangeOutcome> ChangePasswordAsync(
        string userId, string currentPassword, string newPassword, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var hash = await conn.ExecuteScalarAsync<string?>(
            "SELECT password_hash FROM users WHERE id = @id",
            new { id = userId });
        if (hash is null) return PasswordChangeOutcome.UserNotFound;
        if (!BCrypt.Net.BCrypt.Verify(currentPassword, hash))
            return PasswordChangeOutcome.CurrentPasswordIncorrect;
        // Reject reusing the same password — users hitting forced rotation must actually rotate.
        if (BCrypt.Net.BCrypt.Verify(newPassword, hash))
            return PasswordChangeOutcome.NewPasswordSameAsOld;

        var newHash = BCrypt.Net.BCrypt.HashPassword(newPassword, workFactor: 12);
        await conn.ExecuteAsync(
            "UPDATE users SET password_hash = @hash, must_change_password = 0 WHERE id = @id",
            new { hash = newHash, id = userId });
        return PasswordChangeOutcome.Success;
    }

    /// <summary>
    /// "Me" projection: per-user must_change_password + language override + the tenant's
    /// default_language. Returns null when the user row doesn't exist.
    /// </summary>
    public async Task<UserContext?> GetUserContextAsync(string userId, string? orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<UserRow>(
            "SELECT must_change_password AS MustChangePassword, language AS Language FROM users WHERE id = @id",
            new { id = userId });
        if (row is null) return null;

        string? tenantDefault = null;
        if (orgId is not null)
            tenantDefault = (await _orgs.GetSettingsAsync(orgId, ct))?.DefaultLanguage;

        return new UserContext(
            MustChangePassword: row.MustChangePassword == 1,
            Language: string.IsNullOrEmpty(row.Language) ? null : row.Language,
            TenantDefaultLanguage: tenantDefault);
    }

    public async Task UpdateLanguageAsync(string userId, string language, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE users SET language = @lang WHERE id = @id",
            new { lang = language, id = userId });
    }

    // SQLite stores INTEGER as Int64; Dapper requires the positional record signature to
    // match exactly, so MustChangePassword is long here and converted to bool at the call site.
    private sealed record UserRow(long MustChangePassword, string? Language);
}

public enum PasswordChangeOutcome
{
    Success,
    UserNotFound,
    CurrentPasswordIncorrect,
    NewPasswordSameAsOld,
}

public sealed record UserContext(bool MustChangePassword, string? Language, string? TenantDefaultLanguage);
