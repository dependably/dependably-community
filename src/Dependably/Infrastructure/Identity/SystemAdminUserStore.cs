using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.AspNetCore.Identity;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// ASP.NET Core Identity UserStore backed by the <c>system_admins</c> table. Mirrors
/// <see cref="DependablyUserStore"/> but operates without tenant isolation — system_admins
/// are globally unique by email (the column has a UNIQUE constraint).
/// </summary>
internal sealed class SystemAdminUserStore :
    IUserPasswordStore<SystemAdminUser>,
    IUserEmailStore<SystemAdminUser>,
    IUserTwoFactorStore<SystemAdminUser>,
    IUserAuthenticatorKeyStore<SystemAdminUser>,
    IUserTwoFactorRecoveryCodeStore<SystemAdminUser>,
    IUserSecurityStampStore<SystemAdminUser>
{
    private readonly IMetadataStore _db;
    private readonly IMfaSecretProtector _protector;

    public SystemAdminUserStore(IMetadataStore db, IMfaSecretProtector protector)
    {
        _db = db;
        _protector = protector;
    }

    // ── IUserStore ────────────────────────────────────────────────────────────

    public async Task<IdentityResult> CreateAsync(SystemAdminUser user, CancellationToken cancellationToken)
    {
        // System admin lifecycle stays on SystemAdminRepository for this release.
        return IdentityResult.Failed(new IdentityError
        {
            Code = "CreateNotSupported",
            Description = "System admin creation through Identity is not supported; use SystemAdminRepository.",
        });
    }

    public async Task<IdentityResult> DeleteAsync(SystemAdminUser user, CancellationToken cancellationToken)
    {
        // System admin lifecycle stays on SystemAdminRepository for this release.
        return IdentityResult.Failed(new IdentityError
        {
            Code = "DeleteNotSupported",
            Description = "System admin deletion through Identity is not supported; use SystemAdminRepository.",
        });
    }

    public async Task<SystemAdminUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        await using var conn = await _db.OpenAsync(cancellationToken);
        return await conn.QuerySingleOrDefaultAsync<SystemAdminUser?>(
            """
            SELECT id AS Id, email AS Email,
                   password_hash AS PasswordHash, mfa_enabled AS TwoFactorEnabled,
                   mfa_authenticator_key AS AuthenticatorKey,
                   mfa_recovery_codes AS RecoveryCodes,
                   security_stamp AS SecurityStamp,
                   token_version AS TokenVersion
            FROM system_admins WHERE id = @id
            """,
            new { id = userId });
    }

    public async Task<SystemAdminUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        // UserName == Email; email is globally unique across system_admins.
        await using var conn = await _db.OpenAsync(cancellationToken);
        return await conn.QuerySingleOrDefaultAsync<SystemAdminUser?>(
            """
            SELECT id AS Id, email AS Email,
                   password_hash AS PasswordHash, mfa_enabled AS TwoFactorEnabled,
                   mfa_authenticator_key AS AuthenticatorKey,
                   mfa_recovery_codes AS RecoveryCodes,
                   security_stamp AS SecurityStamp,
                   token_version AS TokenVersion
            FROM system_admins
            WHERE lower(email) = lower(@email)
            LIMIT 1
            """,
            new { email = normalizedUserName });
    }

    public Task<string?> GetNormalizedUserNameAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.Email.ToLowerInvariant());

    public Task<string> GetUserIdAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult(user.Id);

    public Task<string?> GetUserNameAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.UserName);

    public Task SetNormalizedUserNameAsync(SystemAdminUser user, string? normalizedName, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task SetUserNameAsync(SystemAdminUser user, string? userName, CancellationToken cancellationToken)
    {
        if (userName is not null)
        {
            user.Email = userName;
        }

        return Task.CompletedTask;
    }

    public async Task<IdentityResult> UpdateAsync(SystemAdminUser user, CancellationToken cancellationToken)
    {
        await using var conn = await _db.OpenAsync(cancellationToken);
        await conn.ExecuteAsync(
            """
            UPDATE system_admins
            SET mfa_enabled         = @e,
                mfa_authenticator_key = @k,
                mfa_recovery_codes  = @r,
                security_stamp      = @s
            WHERE id = @id
            """,
            new
            {
                e = user.TwoFactorEnabled ? 1 : 0,
                k = user.AuthenticatorKey,
                r = user.RecoveryCodes,
                s = user.SecurityStamp,
                id = user.Id,
            });
        return IdentityResult.Success;
    }

    // ── IUserPasswordStore ────────────────────────────────────────────────────

    public Task<string?> GetPasswordHashAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult(user.PasswordHash);

    public Task<bool> HasPasswordAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));

    public Task SetPasswordHashAsync(SystemAdminUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }

    // ── IUserEmailStore ───────────────────────────────────────────────────────

    public async Task<SystemAdminUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        await using var conn = await _db.OpenAsync(cancellationToken);
        return await conn.QuerySingleOrDefaultAsync<SystemAdminUser?>(
            """
            SELECT id AS Id, email AS Email,
                   password_hash AS PasswordHash, mfa_enabled AS TwoFactorEnabled,
                   mfa_authenticator_key AS AuthenticatorKey,
                   mfa_recovery_codes AS RecoveryCodes,
                   security_stamp AS SecurityStamp,
                   token_version AS TokenVersion
            FROM system_admins
            WHERE lower(email) = lower(@email)
            LIMIT 1
            """,
            new { email = normalizedEmail });
    }

    public Task<string?> GetEmailAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.Email);

    public Task<bool> GetEmailConfirmedAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult(true);

    public Task<string?> GetNormalizedEmailAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.Email.ToLowerInvariant());

    public Task SetEmailAsync(SystemAdminUser user, string? email, CancellationToken cancellationToken)
    {
        if (email is not null)
        {
            user.Email = email;
        }

        return Task.CompletedTask;
    }

    public Task SetEmailConfirmedAsync(SystemAdminUser user, bool confirmed, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task SetNormalizedEmailAsync(SystemAdminUser user, string? normalizedEmail, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    // ── IUserTwoFactorStore ───────────────────────────────────────────────────

    public Task<bool> GetTwoFactorEnabledAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult(user.TwoFactorEnabled);

    public Task SetTwoFactorEnabledAsync(SystemAdminUser user, bool enabled, CancellationToken cancellationToken)
    {
        user.TwoFactorEnabled = enabled;
        return Task.CompletedTask;
    }

    // ── IUserAuthenticatorKeyStore ────────────────────────────────────────────

    public Task<string?> GetAuthenticatorKeyAsync(SystemAdminUser user, CancellationToken cancellationToken)
    {
        if (user.AuthenticatorKey is null)
        {
            return Task.FromResult<string?>(null);
        }

        try
        {
            return Task.FromResult<string?>(_protector.Unprotect(user.AuthenticatorKey));
        }
        catch (MfaSecretProtectionException)
        {
            return Task.FromResult<string?>(user.AuthenticatorKey);
        }
    }

    public Task SetAuthenticatorKeyAsync(SystemAdminUser user, string key, CancellationToken cancellationToken)
    {
        user.AuthenticatorKey = _protector.Protect(key);
        return Task.CompletedTask;
    }

    // ── IUserTwoFactorRecoveryCodeStore ───────────────────────────────────────

    public Task<int> CountCodesAsync(SystemAdminUser user, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(user.RecoveryCodes))
        {
            return Task.FromResult(0);
        }

        try
        {
            var codes = JsonSerializer.Deserialize<List<string>>(user.RecoveryCodes);
            return Task.FromResult(codes?.Count ?? 0);
        }
        catch (JsonException)
        {
            return Task.FromResult(0);
        }
    }

    public async Task<bool> RedeemCodeAsync(SystemAdminUser user, string code, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(user.RecoveryCodes))
        {
            return false;
        }

        List<string>? hashes;
        try
        {
            hashes = JsonSerializer.Deserialize<List<string>>(user.RecoveryCodes);
        }
        catch (JsonException)
        {
            return false;
        }

        if (hashes is null || hashes.Count == 0)
        {
            return false;
        }

        string inputHash = HashCode(code);
        int matchIndex = -1;
        for (int i = 0; i < hashes.Count; i++)
        {
            if (System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(inputHash),
                    Encoding.UTF8.GetBytes(hashes[i])))
            {
                matchIndex = i;
                break;
            }
        }

        if (matchIndex < 0)
        {
            return false;
        }

        hashes.RemoveAt(matchIndex);
        user.RecoveryCodes = JsonSerializer.Serialize(hashes);
        await UpdateAsync(user, cancellationToken);
        return true;
    }

    public Task ReplaceCodesAsync(SystemAdminUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
    {
        var hashes = recoveryCodes.Select(HashCode).ToList();
        user.RecoveryCodes = JsonSerializer.Serialize(hashes);
        return Task.CompletedTask;
    }

    // ── IUserSecurityStampStore ───────────────────────────────────────────────

    public Task<string?> GetSecurityStampAsync(SystemAdminUser user, CancellationToken cancellationToken) =>
        Task.FromResult(user.SecurityStamp);

    public Task SetSecurityStampAsync(SystemAdminUser user, string stamp, CancellationToken cancellationToken)
    {
        user.SecurityStamp = stamp;
        return Task.CompletedTask;
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose() { /* No unmanaged resources; each operation opens and disposes its own connection. */ }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static string HashCode(string code)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(code));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
