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
    private readonly IRecoveryCodeHasher _recoveryCodeHasher;

    public SystemAdminUserStore(IMetadataStore db, IMfaSecretProtector protector, IRecoveryCodeHasher recoveryCodeHasher)
    {
        _db = db;
        _protector = protector;
        _recoveryCodeHasher = recoveryCodeHasher;
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

    /// <summary>
    /// Records the MFA-column values as they were just read from the database so
    /// <see cref="UpdateAsync"/> and <see cref="RedeemCodeAsync"/> can detect a concurrent
    /// mutation instead of blindly overwriting it.
    /// </summary>
    private static SystemAdminUser? StampPersistedSnapshot(SystemAdminUser? user)
    {
        if (user is not null)
        {
            user.PersistedTwoFactorEnabled = user.TwoFactorEnabled;
            user.PersistedAuthenticatorKey = user.AuthenticatorKey;
            user.PersistedRecoveryCodes = user.RecoveryCodes;
            user.PersistedSecurityStamp = user.SecurityStamp;
        }

        return user;
    }

    public async Task<SystemAdminUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        await using var conn = await _db.OpenAsync(cancellationToken);
        return StampPersistedSnapshot(await conn.QuerySingleOrDefaultAsync<SystemAdminUser?>(
            """
            SELECT id AS Id, email AS Email,
                   password_hash AS PasswordHash, mfa_enabled AS TwoFactorEnabled,
                   mfa_authenticator_key AS AuthenticatorKey,
                   mfa_recovery_codes AS RecoveryCodes,
                   security_stamp AS SecurityStamp,
                   token_version AS TokenVersion
            FROM system_admins WHERE id = @id
            """,
            new { id = userId }));
    }

    public async Task<SystemAdminUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        // UserName == Email; email is globally unique across system_admins.
        await using var conn = await _db.OpenAsync(cancellationToken);
        return StampPersistedSnapshot(await conn.QuerySingleOrDefaultAsync<SystemAdminUser?>(
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
            new { email = normalizedUserName }));
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
        // Optimistic concurrency: guard on the MFA columns as they were last read (the persisted
        // snapshot) so a stale in-memory copy cannot overwrite a value a concurrent MFA operation
        // already committed. COALESCE to '' gives a provider-portable null-safe comparison
        // (no real key/codes/stamp value is the empty string) on both SQLite and Postgres.
        int affected = await conn.ExecuteAsync(
            """
            UPDATE system_admins
            SET mfa_enabled         = @e,
                mfa_authenticator_key = @k,
                mfa_recovery_codes  = @r,
                security_stamp      = @s
            WHERE id = @id
              AND mfa_enabled = @pe
              AND COALESCE(mfa_authenticator_key, '') = COALESCE(@pk, '')
              AND COALESCE(mfa_recovery_codes, '')  = COALESCE(@pr, '')
              AND COALESCE(security_stamp, '')      = COALESCE(@ps, '')
            """,
            new
            {
                e = user.TwoFactorEnabled ? 1 : 0,
                k = user.AuthenticatorKey,
                r = user.RecoveryCodes,
                s = user.SecurityStamp,
                pe = user.PersistedTwoFactorEnabled ? 1 : 0,
                pk = user.PersistedAuthenticatorKey,
                pr = user.PersistedRecoveryCodes,
                ps = user.PersistedSecurityStamp,
                id = user.Id,
            });

        if (affected == 0)
        {
            return IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure());
        }

        StampPersistedSnapshot(user);
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
        return StampPersistedSnapshot(await conn.QuerySingleOrDefaultAsync<SystemAdminUser?>(
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
            new { email = normalizedEmail }));
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

        // Verify against each stored hash (keyed+salted new form or legacy SHA-256) without an
        // early break, so the loop's timing does not leak which slot matched.
        int matchIndex = -1;
        for (int i = 0; i < hashes.Count; i++)
        {
            if (_recoveryCodeHasher.Verify(code, hashes[i]))
            {
                matchIndex = i;
            }
        }

        if (matchIndex < 0)
        {
            return false;
        }

        hashes.RemoveAt(matchIndex);
        string? previous = user.PersistedRecoveryCodes;
        string trimmed = JsonSerializer.Serialize(hashes);

        // Column-scoped write guarded on the recovery-code list as last read: only the
        // mfa_recovery_codes column is touched, so a concurrent operation's changes to the
        // other MFA columns are not clobbered, and a mismatch (another operation already
        // rewrote the list) means this redemption loses the race and consumes nothing —
        // the previously-redeemed code is never resurrected.
        await using var conn = await _db.OpenAsync(cancellationToken);
        int affected = await conn.ExecuteAsync(
            """
            UPDATE system_admins
            SET mfa_recovery_codes = @trimmed
            WHERE id = @id
              AND COALESCE(mfa_recovery_codes, '') = COALESCE(@previous, '')
            """,
            new { trimmed, previous, id = user.Id });

        if (affected == 0)
        {
            return false;
        }

        user.RecoveryCodes = trimmed;
        user.PersistedRecoveryCodes = trimmed;
        return true;
    }

    public Task ReplaceCodesAsync(SystemAdminUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
    {
        var hashes = recoveryCodes.Select(_recoveryCodeHasher.Hash).ToList();
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
}
