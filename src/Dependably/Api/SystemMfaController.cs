using System.Security.Claims;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Identity;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Api;

/// <summary>
/// System-admin MFA enrollment and management. Covers setup (begin/verify), disable,
/// recovery-code regeneration, and status. All routes are under <c>/api/v1/system/mfa</c>
/// and require an authenticated system-admin session (<c>scope=system</c>, enforced by
/// RouteScopeFilter). No tenant/BOLA guard — system_admins are in a single global pool;
/// the <c>sub</c> claim from the JWT is the identity.
/// </summary>
[ApiController]
[Authorize]
[Route("api/v1/system/mfa")]
public sealed class SystemMfaController : ControllerBase
{
    private readonly ISystemMfaEnrollmentService _mfa;
    private readonly AuditRepository _audit;
    private readonly SystemAdminRepository _systemAdmins;
    private readonly LoginService _login;
    private readonly IPublicUrlBuilder _urls;

    public SystemMfaController(
        ISystemMfaEnrollmentService mfa,
        AuditRepository audit,
        SystemAdminRepository systemAdmins,
        LoginService login,
        IPublicUrlBuilder urls)
    {
        _mfa = mfa;
        _audit = audit;
        _systemAdmins = systemAdmins;
        _login = login;
        _urls = urls;
    }

    /// <summary>
    /// POST /api/v1/system/mfa/setup/begin — resets the authenticator key and returns the
    /// otpauth URI and the raw base32 manual-entry key. Does not enable MFA or audit.
    /// </summary>
    [HttpPost("setup/begin")]
    public async Task<IActionResult> SetupBegin(CancellationToken ct)
    {
        string? adminId = GetAdminId();
        if (adminId is null)
        {
            return Unauthorized();
        }

        await _mfa.ResetKeyAsync(adminId, ct);
        string? key = await _mfa.GetKeyAsync(adminId, ct);
        if (key is null)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { detail = "Failed to generate authenticator key." });
        }

        string email = await _mfa.GetEmailAsync(adminId, ct) ?? adminId;
        string otpauthUri = BuildOtpauthUri(email, key);
        return Ok(new { otpauthUri, manualKey = key });
    }

    /// <summary>
    /// POST /api/v1/system/mfa/setup/verify — verifies a TOTP code against the pending key,
    /// enables MFA, generates 10 recovery codes, and records the enrollment audit event.
    /// </summary>
    [HttpPost("setup/verify")]
    public async Task<IActionResult> SetupVerify([FromBody] MfaVerifyRequest req, CancellationToken ct)
    {
        string? adminId = GetAdminId();
        if (adminId is null)
        {
            return Unauthorized();
        }

        bool valid = await _mfa.VerifyTotpAsync(adminId, req.Code, ct);
        if (!valid)
        {
            return UnprocessableEntity(new { detail = "Invalid authenticator code." });
        }

        await _mfa.SetEnabledAsync(adminId, true, ct);
        var codes = await _mfa.GenerateRecoveryCodesAsync(adminId, 10, ct);

        await _audit.LogSystemAsync(
            action: MfaEvents.TypeEnrolled,
            actorId: adminId,
            detail: new MfaEvents.Enrolled(10).ToJson(),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        return Ok(new { recoveryCodes = codes });
    }

    /// <summary>
    /// POST /api/v1/system/mfa/disable — disables MFA after verifying the admin's password and
    /// current TOTP or recovery code. Bumps token_version to invalidate outstanding sessions
    /// and re-issues the caller's own session cookie at the new version.
    /// </summary>
    [HttpPost("disable")]
    public async Task<IActionResult> Disable([FromBody] MfaDisableRequest req, CancellationToken ct)
    {
        string? adminId = GetAdminId();
        if (adminId is null)
        {
            return Unauthorized();
        }

        bool passwordOk = await _mfa.CheckPasswordAsync(adminId, req.CurrentPassword, ct);
        if (!passwordOk)
        {
            return Unauthorized(new { detail = "Current password is incorrect." });
        }

        string method;
        bool totpOk = await _mfa.VerifyTotpAsync(adminId, req.Code, ct);
        if (totpOk)
        {
            method = "totp";
        }
        else
        {
            bool codeOk = await _mfa.RedeemRecoveryCodeAsync(adminId, req.Code, ct);
            if (!codeOk)
            {
                return BadRequest(new { detail = "Invalid code. Provide a valid TOTP code or recovery code." });
            }

            method = "recovery_code";
        }

        await _mfa.SetEnabledAsync(adminId, false, ct);
        await _mfa.ResetKeyAsync(adminId, ct);
        // Clear recovery codes by requesting zero new codes.
        await _mfa.GenerateRecoveryCodesAsync(adminId, 0, ct);

        long newVersion = await _systemAdmins.BumpTokenVersionAsync(adminId, ct);

        // Invalidate the in-memory token-version cache so the next request re-reads the new value.
        var versionStore = HttpContext.RequestServices.GetRequiredService<SystemAdminTokenVersionStore>();
        versionStore.Invalidate(adminId);

        // Revoke all trusted-device records so remembered devices no longer bypass TOTP.
        var trustedDevices = HttpContext.RequestServices.GetRequiredService<TrustedDeviceService>();
        await trustedDevices.DeleteAllForUserAsync(adminId, "system", ct);

        await _audit.LogSystemAsync(
            action: MfaEvents.TypeDisabled,
            actorId: adminId,
            detail: new MfaEvents.Disabled(method).ToJson(),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        // Re-issue the caller's own session at the new token_version so this request stays authenticated.
        string fresh = await _login.IssueSystemSessionAsync(adminId, newVersion, ct);
        Response.Cookies.Append("dependably_session", fresh, _urls.SessionCookieOptions(HttpContext));

        return Ok(new { message = "MFA disabled." });
    }

    /// <summary>
    /// POST /api/v1/system/mfa/recovery-codes/regenerate — replaces the recovery-code set with
    /// 10 new codes after verifying a current TOTP or recovery code.
    /// </summary>
    [HttpPost("recovery-codes/regenerate")]
    public async Task<IActionResult> RegenerateRecoveryCodes([FromBody] MfaCodeRequest req, CancellationToken ct)
    {
        string? adminId = GetAdminId();
        if (adminId is null)
        {
            return Unauthorized();
        }

        bool enabled = await _mfa.GetEnabledAsync(adminId, ct);
        if (!enabled)
        {
            return BadRequest(new { detail = "MFA is not enabled." });
        }

        string method;
        bool totpOk = await _mfa.VerifyTotpAsync(adminId, req.Code, ct);
        if (totpOk)
        {
            method = "totp";
        }
        else
        {
            bool codeOk = await _mfa.RedeemRecoveryCodeAsync(adminId, req.Code, ct);
            if (!codeOk)
            {
                return BadRequest(new { detail = "Invalid code. Provide a valid TOTP code or recovery code." });
            }

            method = "recovery_code";
        }

        var codes = await _mfa.GenerateRecoveryCodesAsync(adminId, 10, ct);

        await _audit.LogSystemAsync(
            action: MfaEvents.TypeRecoveryCodesRegenerated,
            actorId: adminId,
            detail: new MfaEvents.RecoveryCodesRegenerated(10, method).ToJson(),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        return Ok(new { recoveryCodes = codes });
    }

    /// <summary>
    /// GET /api/v1/system/mfa/status — returns whether MFA is currently enabled and how many
    /// recovery codes remain.
    /// </summary>
    [HttpGet("status")]
    public async Task<IActionResult> Status(CancellationToken ct)
    {
        string? adminId = GetAdminId();
        if (adminId is null)
        {
            return Unauthorized();
        }

        bool enabled = await _mfa.GetEnabledAsync(adminId, ct);
        int remaining = await _mfa.CountRecoveryCodesAsync(adminId, ct);
        return Ok(new { enabled, recoveryCodesRemaining = remaining });
    }

    // Extracts the system_admin id from the JWT sub claim.
    private string? GetAdminId() =>
        User.FindFirst(ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;

    // Builds the otpauth URI for the system admin. Issuer is always "dependably" (no tenant slug
    // in the system realm).
    private static string BuildOtpauthUri(string email, string base32Key)
    {
        const string issuer = "dependably";
        string label = $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}";
        string issuerEncoded = Uri.EscapeDataString(issuer);
        return $"otpauth://totp/{label}?secret={base32Key}&issuer={issuerEncoded}&algorithm=SHA1&digits=6&period=30";
    }
}
