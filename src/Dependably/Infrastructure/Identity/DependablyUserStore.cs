using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.AspNetCore.Identity;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// ASP.NET Core Identity UserStore backed by the <c>users</c> table. Implements the MFA
/// interface set so <see cref="Microsoft.AspNetCore.Identity.UserManager{TUser}"/> can drive
/// the full TOTP enrollment and verification flow.
///
/// Tenant isolation: every read that is not keyed by the globally-unique primary key (id)
/// includes a <c>tenant_id = @tenantId</c> predicate derived from the current request context.
/// FindByIdAsync is the exception — the PK is globally unique and tenant binding is enforced
/// at token issuance and by RouteScopeFilter.
/// </summary>
internal sealed class DependablyUserStore :
    IUserPasswordStore<DependablyUser>,
    IUserEmailStore<DependablyUser>,
    IUserTwoFactorStore<DependablyUser>,
    IUserAuthenticatorKeyStore<DependablyUser>,
    IUserTwoFactorRecoveryCodeStore<DependablyUser>,
    IUserSecurityStampStore<DependablyUser>
{
    private readonly IMetadataStore _db;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IMfaSecretProtector _protector;

    public DependablyUserStore(
        IMetadataStore db,
        IHttpContextAccessor httpContextAccessor,
        IMfaSecretProtector protector)
    {
        _db = db;
        _httpContextAccessor = httpContextAccessor;
        _protector = protector;
    }

    private string RequireTenantId()
    {
        var ctx = _httpContextAccessor.HttpContext?.Items[TenantContext.HttpItemsKey] as TenantContext;
        return ctx?.TenantId is null
            ? throw new InvalidOperationException(
                "DependablyUserStore requires a resolved tenant context; no TenantContext in HttpContext.Items.")
            : ctx.TenantId;
    }

    // ── IUserStore ────────────────────────────────────────────────────────────

    public async Task<IdentityResult> CreateAsync(DependablyUser user, CancellationToken cancellationToken)
    {
        // User lifecycle (create, delete) stays on UserService for this release.
        return IdentityResult.Failed(new IdentityError
        {
            Code = "CreateNotSupported",
            Description = "User creation through Identity is not supported; use UserService.",
        });
    }

    public async Task<IdentityResult> DeleteAsync(DependablyUser user, CancellationToken cancellationToken)
    {
        // User lifecycle (create, delete) stays on UserService for this release.
        return IdentityResult.Failed(new IdentityError
        {
            Code = "DeleteNotSupported",
            Description = "User deletion through Identity is not supported; use UserService.",
        });
    }

    public async Task<DependablyUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        await using var conn = await _db.OpenAsync(cancellationToken);
        // xtenant: PK lookup; users.id is globally unique. Tenant binding is enforced at
        // JWT issuance and by RouteScopeFilter; this read does not cross tenant data planes.
        return await conn.QuerySingleOrDefaultAsync<DependablyUser?>(
            """
            SELECT id AS Id, tenant_id AS TenantId, email AS Email,
                   password_hash AS PasswordHash, mfa_enabled AS TwoFactorEnabled,
                   mfa_authenticator_key AS AuthenticatorKey,
                   mfa_recovery_codes AS RecoveryCodes,
                   security_stamp AS SecurityStamp,
                   token_version AS TokenVersion
            FROM users WHERE id = @id
            """,
            new { id = userId });
    }

    public async Task<DependablyUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        // UserName == Email for this provider; normalizedUserName is lowercased by UserManager.
        string tenantId = RequireTenantId();
        await using var conn = await _db.OpenAsync(cancellationToken);
        return await conn.QuerySingleOrDefaultAsync<DependablyUser?>(
            """
            SELECT id AS Id, tenant_id AS TenantId, email AS Email,
                   password_hash AS PasswordHash, mfa_enabled AS TwoFactorEnabled,
                   mfa_authenticator_key AS AuthenticatorKey,
                   mfa_recovery_codes AS RecoveryCodes,
                   security_stamp AS SecurityStamp,
                   token_version AS TokenVersion
            FROM users
            WHERE lower(email) = lower(@email) AND tenant_id = @tenantId
            LIMIT 1
            """,
            new { email = normalizedUserName, tenantId });
    }

    public Task<string?> GetNormalizedUserNameAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.Email.ToLowerInvariant());

    public Task<string> GetUserIdAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult(user.Id);

    public Task<string?> GetUserNameAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.UserName);

    public Task SetNormalizedUserNameAsync(DependablyUser user, string? normalizedName, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task SetUserNameAsync(DependablyUser user, string? userName, CancellationToken cancellationToken)
    {
        if (userName is not null)
        {
            user.Email = userName;
        }

        return Task.CompletedTask;
    }

    public async Task<IdentityResult> UpdateAsync(DependablyUser user, CancellationToken cancellationToken)
    {
        string tenantId = RequireTenantId();
        await using var conn = await _db.OpenAsync(cancellationToken);
        await conn.ExecuteAsync(
            """
            UPDATE users
            SET mfa_enabled         = @e,
                mfa_authenticator_key = @k,
                mfa_recovery_codes  = @r,
                security_stamp      = @s
            WHERE id = @id AND tenant_id = @tenantId
            """,
            new
            {
                e = user.TwoFactorEnabled ? 1 : 0,
                k = user.AuthenticatorKey,
                r = user.RecoveryCodes,
                s = user.SecurityStamp,
                id = user.Id,
                tenantId,
            });
        return IdentityResult.Success;
    }

    // ── IUserPasswordStore ────────────────────────────────────────────────────

    public Task<string?> GetPasswordHashAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult(user.PasswordHash);

    public Task<bool> HasPasswordAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));

    public Task SetPasswordHashAsync(DependablyUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }

    // ── IUserEmailStore ───────────────────────────────────────────────────────

    public async Task<DependablyUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        string tenantId = RequireTenantId();
        await using var conn = await _db.OpenAsync(cancellationToken);
        return await conn.QuerySingleOrDefaultAsync<DependablyUser?>(
            """
            SELECT id AS Id, tenant_id AS TenantId, email AS Email,
                   password_hash AS PasswordHash, mfa_enabled AS TwoFactorEnabled,
                   mfa_authenticator_key AS AuthenticatorKey,
                   mfa_recovery_codes AS RecoveryCodes,
                   security_stamp AS SecurityStamp,
                   token_version AS TokenVersion
            FROM users
            WHERE lower(email) = lower(@email) AND tenant_id = @tenantId
            LIMIT 1
            """,
            new { email = normalizedEmail, tenantId });
    }

    public Task<string?> GetEmailAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.Email);

    public Task<bool> GetEmailConfirmedAsync(DependablyUser user, CancellationToken cancellationToken) =>
        // Email confirmation is not tracked by a separate column; all active accounts are considered confirmed.
        Task.FromResult(true);

    public Task<string?> GetNormalizedEmailAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.Email.ToLowerInvariant());

    public Task SetEmailAsync(DependablyUser user, string? email, CancellationToken cancellationToken)
    {
        if (email is not null)
        {
            user.Email = email;
        }

        return Task.CompletedTask;
    }

    public Task SetEmailConfirmedAsync(DependablyUser user, bool confirmed, CancellationToken cancellationToken) =>
        // No confirmation column; no-op.
        Task.CompletedTask;

    public Task SetNormalizedEmailAsync(DependablyUser user, string? normalizedEmail, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    // ── IUserTwoFactorStore ───────────────────────────────────────────────────

    public Task<bool> GetTwoFactorEnabledAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult(user.TwoFactorEnabled);

    public Task SetTwoFactorEnabledAsync(DependablyUser user, bool enabled, CancellationToken cancellationToken)
    {
        user.TwoFactorEnabled = enabled;
        return Task.CompletedTask;
    }

    // ── IUserAuthenticatorKeyStore ────────────────────────────────────────────

    public Task<string?> GetAuthenticatorKeyAsync(DependablyUser user, CancellationToken cancellationToken)
    {
        // The stored key is encrypted; return the plaintext that was set by SetAuthenticatorKeyAsync,
        // or decrypt from the raw column value when the user was loaded from the DB with an encrypted value.
        if (user.AuthenticatorKey is null)
        {
            return Task.FromResult<string?>(null);
        }

        // If the key looks like base64-encoded encrypted data (set from DB), decrypt it on the way out.
        // Keys set in-memory via SetAuthenticatorKeyAsync are stored as-is (plaintext) until UpdateAsync
        // persists them. The store always writes encrypted; reads decrypt only when the format matches.
        try
        {
            string decrypted = _protector.Unprotect(user.AuthenticatorKey);
            return Task.FromResult<string?>(decrypted);
        }
        catch (MfaSecretProtectionException)
        {
            // Not an encrypted blob — the key is already plaintext (set in memory this request).
            return Task.FromResult<string?>(user.AuthenticatorKey);
        }
    }

    public Task SetAuthenticatorKeyAsync(DependablyUser user, string key, CancellationToken cancellationToken)
    {
        // Encrypt before storing on the user object so UpdateAsync persists the ciphertext.
        user.AuthenticatorKey = _protector.Protect(key);
        return Task.CompletedTask;
    }

    // ── IUserTwoFactorRecoveryCodeStore ───────────────────────────────────────

    public Task<int> CountCodesAsync(DependablyUser user, CancellationToken cancellationToken)
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

    public async Task<bool> RedeemCodeAsync(DependablyUser user, string code, CancellationToken cancellationToken)
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
            if (CryptographicOperations.FixedTimeEquals(
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

    public Task ReplaceCodesAsync(DependablyUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
    {
        // Store SHA-256 hashes of the codes, never the plaintext values.
        var hashes = recoveryCodes.Select(HashCode).ToList();
        user.RecoveryCodes = JsonSerializer.Serialize(hashes);
        return Task.CompletedTask;
    }

    // ── IUserSecurityStampStore ───────────────────────────────────────────────

    public Task<string?> GetSecurityStampAsync(DependablyUser user, CancellationToken cancellationToken) =>
        Task.FromResult(user.SecurityStamp);

    public Task SetSecurityStampAsync(DependablyUser user, string stamp, CancellationToken cancellationToken)
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
