using Microsoft.AspNetCore.Identity;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Contract for MFA enrollment operations used by <see cref="Dependably.Api.MfaController"/>.
/// All methods accept primitive types so the interface can be public without exposing
/// the internal <see cref="DependablyUser"/> type.
/// </summary>
public interface IMfaEnrollmentService
{
    /// <summary>Generates a new authenticator key, storing it encrypted. Discards any previous key.</summary>
    Task ResetKeyAsync(string userId, CancellationToken ct = default);

    /// <summary>Returns the current base32-encoded TOTP key, or null when none is set.</summary>
    Task<string?> GetKeyAsync(string userId, CancellationToken ct = default);

    /// <summary>Returns the email address for the user, used to build the otpauth URI label.</summary>
    Task<string?> GetEmailAsync(string userId, CancellationToken ct = default);

    /// <summary>Returns the tenant id bound to the user, for tenant-isolation checks.</summary>
    Task<string?> GetTenantIdAsync(string userId, CancellationToken ct = default);

    /// <summary>Verifies a TOTP code. Returns true when valid.</summary>
    Task<bool> VerifyTotpAsync(string userId, string code, CancellationToken ct = default);

    /// <summary>Attempts to redeem a recovery code. Returns true and marks it consumed on success.</summary>
    Task<bool> RedeemRecoveryCodeAsync(string userId, string code, CancellationToken ct = default);

    /// <summary>Enables or disables TOTP MFA for the user.</summary>
    Task SetEnabledAsync(string userId, bool enabled, CancellationToken ct = default);

    /// <summary>
    /// Generates <paramref name="count"/> new recovery codes, replacing any existing ones.
    /// Pass 0 to clear all codes. Returns the plaintext codes (shown once; stored as hashes).
    /// </summary>
    Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(string userId, int count, CancellationToken ct = default);

    /// <summary>Returns whether MFA is currently enabled for the user.</summary>
    Task<bool> GetEnabledAsync(string userId, CancellationToken ct = default);

    /// <summary>Returns the number of unused recovery codes remaining.</summary>
    Task<int> CountRecoveryCodesAsync(string userId, CancellationToken ct = default);

    /// <summary>Verifies the user's password without modifying any state.</summary>
    Task<bool> CheckPasswordAsync(string userId, string password, CancellationToken ct = default);
}

/// <summary>
/// Identity-backed implementation of <see cref="IMfaEnrollmentService"/>. Delegates to
/// <see cref="UserManager{DependablyUser}"/> for all TOTP and recovery-code operations.
/// </summary>
internal sealed class MfaEnrollmentService : IMfaEnrollmentService
{
    private readonly UserManager<DependablyUser> _users;

    public MfaEnrollmentService(UserManager<DependablyUser> users) => _users = users;

    public async Task ResetKeyAsync(string userId, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId)
            ?? throw new InvalidOperationException($"User {userId} not found.");
        await _users.ResetAuthenticatorKeyAsync(user);
    }

    public async Task<string?> GetKeyAsync(string userId, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId)
            ?? throw new InvalidOperationException($"User {userId} not found.");
        return await _users.GetAuthenticatorKeyAsync(user);
    }

    public async Task<string?> GetEmailAsync(string userId, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId);
        return user?.Email;
    }

    public async Task<string?> GetTenantIdAsync(string userId, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId);
        return user?.TenantId;
    }

    public async Task<bool> VerifyTotpAsync(string userId, string code, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId);
        return user is not null
            && await _users.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, code);
    }

    public async Task<bool> RedeemRecoveryCodeAsync(string userId, string code, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId);
        if (user is null)
        {
            return false;
        }

        var result = await _users.RedeemTwoFactorRecoveryCodeAsync(user, code);
        return result.Succeeded;
    }

    public async Task SetEnabledAsync(string userId, bool enabled, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId)
            ?? throw new InvalidOperationException($"User {userId} not found.");
        await _users.SetTwoFactorEnabledAsync(user, enabled);
    }

    public async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(
        string userId, int count, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId)
            ?? throw new InvalidOperationException($"User {userId} not found.");
        if (count == 0)
        {
            // GenerateNewTwoFactorRecoveryCodesAsync with 0 serializes an empty hashed list.
            await _users.GenerateNewTwoFactorRecoveryCodesAsync(user, 0);
            return [];
        }

        var codes = await _users.GenerateNewTwoFactorRecoveryCodesAsync(user, count);
        return codes?.ToList() ?? [];
    }

    public async Task<bool> GetEnabledAsync(string userId, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId)
            ?? throw new InvalidOperationException($"User {userId} not found.");
        return await _users.GetTwoFactorEnabledAsync(user);
    }

    public async Task<int> CountRecoveryCodesAsync(string userId, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId)
            ?? throw new InvalidOperationException($"User {userId} not found.");
        return await _users.CountRecoveryCodesAsync(user);
    }

    public async Task<bool> CheckPasswordAsync(string userId, string password, CancellationToken ct = default)
    {
        var user = await _users.FindByIdAsync(userId);
        return user is not null && await _users.CheckPasswordAsync(user, password);
    }
}
