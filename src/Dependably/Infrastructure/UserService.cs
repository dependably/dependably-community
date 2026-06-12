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
    private readonly UserTokenVersionStore? _tokenVersions;

    public UserService(IMetadataStore db, OrgRepository orgs, UserTokenVersionStore? tokenVersions = null)
    {
        _db = db;
        _orgs = orgs;
        _tokenVersions = tokenVersions;
    }

    /// <summary>
    /// Creates a tenant user from an accepted invite. Caller is responsible for invite
    /// consumption (<see cref="InviteRepository.AcceptAsync"/>) before calling this so the
    /// invite is single-use even if user creation later fails.
    /// </summary>
    public async Task<string> CreateFromInviteAsync(InviteRecord invite, string password, CancellationToken ct = default)
    {
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        string userId = Guid.NewGuid().ToString("N");
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

    /// <summary>
    /// Changes the user's password and cuts off every credential minted under the old one:
    /// bumps <c>users.token_version</c> (staling all outstanding session JWTs, which snapshot
    /// the version as the <c>tver</c> claim) and revokes the user's API tokens
    /// (<c>user_tokens</c> rows are deleted). The caller re-issues the changing session's own
    /// cookie from <see cref="PasswordChangeResult.NewTokenVersion"/>.
    /// </summary>
    public async Task<PasswordChangeResult> ChangePasswordAsync(
        string userId, string currentPassword, string newPassword, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? hash = await conn.ExecuteScalarAsync<string?>(
            "SELECT password_hash FROM users WHERE id = @id",
            new { id = userId });
        if (hash is null)
        {
            return new PasswordChangeResult(PasswordChangeOutcome.UserNotFound);
        }

        if (!BCrypt.Net.BCrypt.Verify(currentPassword, hash))
        {
            return new PasswordChangeResult(PasswordChangeOutcome.CurrentPasswordIncorrect);
        }
        // Reject reusing the same password — users hitting forced rotation must actually rotate.
        if (BCrypt.Net.BCrypt.Verify(newPassword, hash))
        {
            return new PasswordChangeResult(PasswordChangeOutcome.NewPasswordSameAsOld);
        }

        string newHash = BCrypt.Net.BCrypt.HashPassword(newPassword, workFactor: 12);
        await conn.ExecuteAsync(
            "UPDATE users SET password_hash = @hash, must_change_password = 0, token_version = token_version + 1 WHERE id = @id",
            new { hash = newHash, id = userId });
        long newVersion = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });

        // Revoke (delete) the user's API tokens — a rotated credential must cut off
        // everything minted under the old one. user_id is FK-bound to users.id, which is
        // already tenant-scoped.
        int revokedApiTokens = await conn.ExecuteAsync(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId });

        _tokenVersions?.Invalidate(userId);
        return new PasswordChangeResult(PasswordChangeOutcome.Success, newVersion, revokedApiTokens);
    }

    /// <summary>
    /// Lean check used by the request pipeline to force temp-password rotation: true when the
    /// user must change their password before continuing. Missing row → false.
    /// </summary>
    public async Task<bool> IsPasswordChangeRequiredAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long? flag = await conn.ExecuteScalarAsync<long?>(
            "SELECT must_change_password FROM users WHERE id = @id", new { id = userId });
        return flag == 1;
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
        if (row is null)
        {
            return null;
        }

        string? tenantDefault = null;
        if (orgId is not null)
        {
            tenantDefault = (await _orgs.GetSettingsAsync(orgId, ct))?.DefaultLanguage;
        }

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

/// <summary>
/// Outcome of a password change. On <see cref="PasswordChangeOutcome.Success"/>,
/// <see cref="NewTokenVersion"/> carries the bumped <c>users.token_version</c> (for re-issuing
/// the caller's own session) and <see cref="RevokedApiTokens"/> the number of API tokens revoked.
/// </summary>
public sealed record PasswordChangeResult(
    PasswordChangeOutcome Outcome, long? NewTokenVersion = null, int RevokedApiTokens = 0);

public sealed record UserContext(bool MustChangePassword, string? Language, string? TenantDefaultLanguage);
