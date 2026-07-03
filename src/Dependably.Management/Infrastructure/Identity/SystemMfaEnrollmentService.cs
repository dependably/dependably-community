using Microsoft.AspNetCore.Identity;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Contract for MFA enrollment operations on system_admin accounts. Mirrors
/// <see cref="IMfaEnrollmentService"/> but operates over <see cref="SystemAdminUser"/>
/// (no tenant scoping — system_admins live outside the tenant model).
/// </summary>
public interface ISystemMfaEnrollmentService
{
    /// <summary>Generates a new authenticator key, storing it encrypted. Discards any previous key.</summary>
    Task ResetKeyAsync(string adminId, CancellationToken ct = default);

    /// <summary>Returns the current base32-encoded TOTP key, or null when none is set.</summary>
    Task<string?> GetKeyAsync(string adminId, CancellationToken ct = default);

    /// <summary>Returns the email address for the admin, used to build the otpauth URI label.</summary>
    Task<string?> GetEmailAsync(string adminId, CancellationToken ct = default);

    /// <summary>Verifies a TOTP code. Returns true when valid.</summary>
    Task<bool> VerifyTotpAsync(string adminId, string code, CancellationToken ct = default);

    /// <summary>Attempts to redeem a recovery code. Returns true and marks it consumed on success.</summary>
    Task<bool> RedeemRecoveryCodeAsync(string adminId, string code, CancellationToken ct = default);

    /// <summary>Enables or disables TOTP MFA for the admin.</summary>
    Task SetEnabledAsync(string adminId, bool enabled, CancellationToken ct = default);

    /// <summary>
    /// Generates <paramref name="count"/> new recovery codes, replacing any existing ones.
    /// Pass 0 to clear all codes. Returns the plaintext codes (shown once; stored as hashes).
    /// </summary>
    Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(string adminId, int count, CancellationToken ct = default);

    /// <summary>Returns whether MFA is currently enabled for the admin.</summary>
    Task<bool> GetEnabledAsync(string adminId, CancellationToken ct = default);

    /// <summary>Returns the number of unused recovery codes remaining.</summary>
    Task<int> CountRecoveryCodesAsync(string adminId, CancellationToken ct = default);

    /// <summary>Verifies the admin's password without modifying any state.</summary>
    Task<bool> CheckPasswordAsync(string adminId, string password, CancellationToken ct = default);
}

/// <summary>
/// Identity-backed implementation of <see cref="ISystemMfaEnrollmentService"/>. Delegates to
/// <see cref="UserManager{SystemAdminUser}"/> for all TOTP and recovery-code operations.
/// </summary>
internal sealed class SystemMfaEnrollmentService : ISystemMfaEnrollmentService
{
    private readonly UserManager<SystemAdminUser> _admins;

    public SystemMfaEnrollmentService(UserManager<SystemAdminUser> admins) => _admins = admins;

    public async Task ResetKeyAsync(string adminId, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId)
            ?? throw new InvalidOperationException($"System admin {adminId} not found.");
        await _admins.ResetAuthenticatorKeyAsync(admin);
    }

    public async Task<string?> GetKeyAsync(string adminId, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId)
            ?? throw new InvalidOperationException($"System admin {adminId} not found.");
        return await _admins.GetAuthenticatorKeyAsync(admin);
    }

    public async Task<string?> GetEmailAsync(string adminId, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId);
        return admin?.Email;
    }

    public async Task<bool> VerifyTotpAsync(string adminId, string code, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId);
        return admin is not null
            && await _admins.VerifyTwoFactorTokenAsync(admin, TokenOptions.DefaultAuthenticatorProvider, code);
    }

    public async Task<bool> RedeemRecoveryCodeAsync(string adminId, string code, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId);
        if (admin is null)
        {
            return false;
        }

        var result = await _admins.RedeemTwoFactorRecoveryCodeAsync(admin, code);
        return result.Succeeded;
    }

    public async Task SetEnabledAsync(string adminId, bool enabled, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId)
            ?? throw new InvalidOperationException($"System admin {adminId} not found.");
        await _admins.SetTwoFactorEnabledAsync(admin, enabled);
    }

    public async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(
        string adminId, int count, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId)
            ?? throw new InvalidOperationException($"System admin {adminId} not found.");
        if (count == 0)
        {
            await _admins.GenerateNewTwoFactorRecoveryCodesAsync(admin, 0);
            return [];
        }

        var codes = await _admins.GenerateNewTwoFactorRecoveryCodesAsync(admin, count);
        return codes?.ToList() ?? [];
    }

    public async Task<bool> GetEnabledAsync(string adminId, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId)
            ?? throw new InvalidOperationException($"System admin {adminId} not found.");
        return await _admins.GetTwoFactorEnabledAsync(admin);
    }

    public async Task<int> CountRecoveryCodesAsync(string adminId, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId)
            ?? throw new InvalidOperationException($"System admin {adminId} not found.");
        return await _admins.CountRecoveryCodesAsync(admin);
    }

    public async Task<bool> CheckPasswordAsync(string adminId, string password, CancellationToken ct = default)
    {
        var admin = await _admins.FindByIdAsync(adminId);
        return admin is not null && await _admins.CheckPasswordAsync(admin, password);
    }
}
