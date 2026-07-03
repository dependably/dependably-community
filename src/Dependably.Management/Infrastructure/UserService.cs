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
    private readonly TrustedDeviceService? _trustedDevices;
    private readonly IRequireMfaMode? _requireMfa;

    public UserService(
        IMetadataStore db,
        OrgRepository orgs,
        UserTokenVersionStore? tokenVersions = null,
        TrustedDeviceService? trustedDevices = null,
        IRequireMfaMode? requireMfa = null)
    {
        _db = db;
        _orgs = orgs;
        _tokenVersions = tokenVersions;
        _trustedDevices = trustedDevices;
        _requireMfa = requireMfa;
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
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();
        await conn.ExecuteAsync(
            "UPDATE users SET password_hash = @hash, must_change_password = 0, token_version = token_version + 1, security_stamp = @stamp WHERE id = @id",
            new { hash = newHash, stamp, id = userId });
        long newVersion = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });

        // Revoke (delete) the user's API tokens — a rotated credential must cut off
        // everything minted under the old one. user_id is FK-bound to users.id, which is
        // already tenant-scoped.
        int revokedApiTokens = await conn.ExecuteAsync(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId });

        // Revoke trusted-device records so remembered devices no longer bypass TOTP after
        // a password change. Optional dependency keeps existing test constructors working.
        if (_trustedDevices is not null)
        {
            await _trustedDevices.DeleteAllForUserAsync(userId, "tenant", ct);
        }

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
    /// Lean check used by <see cref="Dependably.Security.MfaEnrollmentGuard"/>: true when
    /// the user has completed MFA enrollment. Read live from the database (not from the JWT
    /// claim) so enrollment takes effect immediately. Missing row → false.
    /// </summary>
    public async Task<bool> IsMfaEnabledAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long? flag = await conn.ExecuteScalarAsync<long?>(
            "SELECT mfa_enabled FROM users WHERE id = @id", new { id = userId });
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
            "SELECT must_change_password AS MustChangePassword, language AS Language, mfa_enabled AS MfaEnabled FROM users WHERE id = @id",
            new { id = userId });
        if (row is null)
        {
            return null;
        }

        OrgSettings? orgSettings = null;
        if (orgId is not null)
        {
            orgSettings = await _orgs.GetSettingsAsync(orgId, ct);
        }

        bool mfaEnabled = row.MfaEnabled == 1;
        bool requireMfa = (_requireMfa?.IsEnabled ?? false) || (orgSettings?.RequireMfa ?? false);

        return new UserContext(
            MustChangePassword: row.MustChangePassword == 1,
            Language: string.IsNullOrEmpty(row.Language) ? null : row.Language,
            TenantDefaultLanguage: orgSettings?.DefaultLanguage,
            MfaEnabled: mfaEnabled,
            MfaEnrollmentRequired: requireMfa && !mfaEnabled);
    }

    public async Task UpdateLanguageAsync(string userId, string language, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE users SET language = @lang WHERE id = @id",
            new { lang = language, id = userId });
    }

    /// <summary>
    /// Bumps <c>users.token_version</c> and revokes all API tokens for the user, then
    /// invalidates the in-process token-version cache. Returns the new version so the caller
    /// can re-issue its own session cookie. Mirrors <see cref="ChangePasswordAsync"/> but
    /// without a credential check — the caller is responsible for verifying identity before
    /// invoking this method.
    /// </summary>
    public async Task<long> BumpTokenVersionAndRevokeTokensAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();
        await conn.ExecuteAsync(
            "UPDATE users SET token_version = token_version + 1, security_stamp = @stamp WHERE id = @id",
            new { stamp, id = userId });
        long newVersion = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });

        // user_id is FK-bound to users.id, which is already tenant-scoped.
        await conn.ExecuteAsync(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId });

        _tokenVersions?.Invalidate(userId);
        return newVersion;
    }

    // SQLite stores INTEGER as Int64; Dapper requires the positional record signature to
    // match exactly, so MustChangePassword is long here and converted to bool at the call site.
    private sealed record UserRow(long MustChangePassword, string? Language, long MfaEnabled);
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

public sealed record UserContext(
    bool MustChangePassword,
    string? Language,
    string? TenantDefaultLanguage,
    bool MfaEnabled = false,
    bool MfaEnrollmentRequired = false);
