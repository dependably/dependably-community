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
/// Tenant-user MFA enrollment and management. Covers setup (begin/verify), disable,
/// recovery-code regeneration, and status. All routes are under <c>/api/v1/mfa</c> and
/// require an authenticated tenant session (<c>scope=tenant</c>, enforced by RouteScopeFilter).
/// </summary>
[ApiController]
[Authorize]
[Route("api/v1/mfa")]
public sealed class MfaController : OrgScopedControllerBase
{
    private readonly IMfaEnrollmentService _mfa;
    private readonly AuditRepository _audit;
    private readonly UserService _userService;
    private readonly LoginService _login;
    private readonly IPublicUrlBuilder _urls;

    public MfaController(
        IMfaEnrollmentService mfa,
        AuditRepository audit,
        UserService userService,
        LoginService login,
        IPublicUrlBuilder urls)
    {
        _mfa = mfa;
        _audit = audit;
        _userService = userService;
        _login = login;
        _urls = urls;
    }

    /// <summary>
    /// POST /api/v1/mfa/setup/begin — resets the authenticator key and returns the
    /// otpauth URI and the raw base32 manual-entry key. Does not enable MFA or audit.
    /// </summary>
    [HttpPost("setup/begin")]
    public async Task<IActionResult> SetupBegin(CancellationToken ct)
    {
        string? userId = GetUserId();
        if (userId is null)
        {
            return Unauthorized();
        }

        if (!await TenantOwnsUserAsync(userId))
        {
            return NotFound();
        }

        await _mfa.ResetKeyAsync(userId, ct);
        string? key = await _mfa.GetKeyAsync(userId, ct);
        if (key is null)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { detail = "Failed to generate authenticator key." });
        }

        string email = await _mfa.GetEmailAsync(userId, ct) ?? userId;
        string otpauthUri = BuildOtpauthUri(email, key);
        return Ok(new { otpauthUri, manualKey = key });
    }

    /// <summary>
    /// POST /api/v1/mfa/setup/verify — verifies a TOTP code against the pending key,
    /// enables MFA, generates 10 recovery codes, and records the enrollment audit event.
    /// </summary>
    [HttpPost("setup/verify")]
    public async Task<IActionResult> SetupVerify([FromBody] MfaVerifyRequest req, CancellationToken ct)
    {
        string? userId = GetUserId();
        if (userId is null)
        {
            return Unauthorized();
        }

        if (!await TenantOwnsUserAsync(userId))
        {
            return NotFound();
        }

        bool valid = await _mfa.VerifyTotpAsync(userId, req.Code, ct);
        if (!valid)
        {
            return UnprocessableEntity(new { detail = "Invalid authenticator code." });
        }

        await _mfa.SetEnabledAsync(userId, true, ct);
        var codes = await _mfa.GenerateRecoveryCodesAsync(userId, 10, ct);

        await _audit.LogAsync(
            action: MfaEvents.TypeEnrolled,
            orgId: GetCurrentTenantIdOrNull(),
            actorId: userId,
            actorKind: ActorKinds.User,
            detail: new MfaEvents.Enrolled(10).ToJson(),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        return Ok(new { recoveryCodes = codes });
    }

    /// <summary>
    /// POST /api/v1/mfa/disable — disables MFA after verifying the user's password and
    /// current TOTP or recovery code. Bumps token_version to invalidate outstanding sessions
    /// and re-issues the caller's own session cookie.
    /// </summary>
    [HttpPost("disable")]
    public async Task<IActionResult> Disable([FromBody] MfaDisableRequest req, CancellationToken ct)
    {
        string? userId = GetUserId();
        if (userId is null)
        {
            return Unauthorized();
        }

        if (!await TenantOwnsUserAsync(userId))
        {
            return NotFound();
        }

        bool passwordOk = await _mfa.CheckPasswordAsync(userId, req.CurrentPassword, ct);
        if (!passwordOk)
        {
            return Unauthorized(new { detail = "Current password is incorrect." });
        }

        string method;
        bool totpOk = await _mfa.VerifyTotpAsync(userId, req.Code, ct);
        if (totpOk)
        {
            method = "totp";
        }
        else
        {
            bool codeOk = await _mfa.RedeemRecoveryCodeAsync(userId, req.Code, ct);
            if (!codeOk)
            {
                return BadRequest(new { detail = "Invalid code. Provide a valid TOTP code or recovery code." });
            }

            method = "recovery_code";
        }

        await _mfa.SetEnabledAsync(userId, false, ct);
        await _mfa.ResetKeyAsync(userId, ct);
        // Clear recovery codes by requesting zero new codes.
        await _mfa.GenerateRecoveryCodesAsync(userId, 0, ct);

        long newVersion = await _userService.BumpTokenVersionAndRevokeTokensAsync(userId, ct);

        // Revoke all trusted-device records so remembered devices no longer bypass TOTP.
        var trustedDevices = HttpContext.RequestServices.GetRequiredService<TrustedDeviceService>();
        await trustedDevices.DeleteAllForUserAsync(userId, "tenant", ct);

        string? orgId = GetCurrentTenantIdOrNull();

        await _audit.LogAsync(
            action: MfaEvents.TypeDisabled,
            orgId: orgId,
            actorId: userId,
            actorKind: ActorKinds.User,
            detail: new MfaEvents.Disabled(method).ToJson(),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        // Re-issue the caller's own session at the new token_version so this request stays authenticated.
        if (!string.IsNullOrEmpty(orgId))
        {
            string role = User.FindFirst("role")?.Value ?? "member";
            string fresh = await _login.IssueTenantSessionAsync(userId, orgId, role, newVersion, ct);
            Response.Cookies.Append("dependably_session", fresh, _urls.SessionCookieOptions(HttpContext));
        }

        return Ok(new { message = "MFA disabled." });
    }

    /// <summary>
    /// POST /api/v1/mfa/recovery-codes/regenerate — replaces the recovery-code set with
    /// 10 new codes after verifying a current TOTP or recovery code.
    /// </summary>
    [HttpPost("recovery-codes/regenerate")]
    public async Task<IActionResult> RegenerateRecoveryCodes([FromBody] MfaCodeRequest req, CancellationToken ct)
    {
        string? userId = GetUserId();
        if (userId is null)
        {
            return Unauthorized();
        }

        if (!await TenantOwnsUserAsync(userId))
        {
            return NotFound();
        }

        bool enabled = await _mfa.GetEnabledAsync(userId, ct);
        if (!enabled)
        {
            return BadRequest(new { detail = "MFA is not enabled." });
        }

        string method;
        bool totpOk = await _mfa.VerifyTotpAsync(userId, req.Code, ct);
        if (totpOk)
        {
            method = "totp";
        }
        else
        {
            bool codeOk = await _mfa.RedeemRecoveryCodeAsync(userId, req.Code, ct);
            if (!codeOk)
            {
                return BadRequest(new { detail = "Invalid code. Provide a valid TOTP code or recovery code." });
            }

            method = "recovery_code";
        }

        var codes = await _mfa.GenerateRecoveryCodesAsync(userId, 10, ct);

        await _audit.LogAsync(
            action: MfaEvents.TypeRecoveryCodesRegenerated,
            orgId: GetCurrentTenantIdOrNull(),
            actorId: userId,
            actorKind: ActorKinds.User,
            detail: new MfaEvents.RecoveryCodesRegenerated(10, method).ToJson(),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        return Ok(new { recoveryCodes = codes });
    }

    /// <summary>
    /// GET /api/v1/mfa/status — returns whether MFA is currently enabled and how many
    /// recovery codes remain.
    /// </summary>
    [HttpGet("status")]
    public async Task<IActionResult> Status(CancellationToken ct)
    {
        string? userId = GetUserId();
        if (userId is null)
        {
            return Unauthorized();
        }

        if (!await TenantOwnsUserAsync(userId))
        {
            return NotFound();
        }

        bool enabled = await _mfa.GetEnabledAsync(userId, ct);
        int remaining = await _mfa.CountRecoveryCodesAsync(userId, ct);
        return Ok(new { enabled, recoveryCodesRemaining = remaining });
    }

    // Returns true when the current tenant context owns the user, guarding against BOLA.
    // A null tenant context (not expected in practice after RouteScopeFilter) passes through.
    private async Task<bool> TenantOwnsUserAsync(string userId)
    {
        string? tenantId = GetCurrentTenantIdOrNull();
        if (tenantId is null)
        {
            return true;
        }

        string? userTenant = await _mfa.GetTenantIdAsync(userId);
        return userTenant is null || userTenant == tenantId;
    }

    // Returns null instead of throwing when no TenantContext is resolved.
    private string? GetCurrentTenantIdOrNull() =>
        (HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext)?.TenantId;

    // Builds the otpauth URI for the user. The issuer is the tenant slug if available,
    // falling back to "dependably".
    private string BuildOtpauthUri(string email, string base32Key)
    {
        var tenantCtx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;
        string issuer = string.IsNullOrWhiteSpace(tenantCtx?.TenantSlug)
            ? "dependably"
            : tenantCtx.TenantSlug;

        string label = $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}";
        string issuerEncoded = Uri.EscapeDataString(issuer);

        return $"otpauth://totp/{label}?secret={base32Key}&issuer={issuerEncoded}&algorithm=SHA1&digits=6&period=30";
    }
}

public sealed record MfaVerifyRequest(string Code);
public sealed record MfaDisableRequest(string CurrentPassword, string Code);
public sealed record MfaCodeRequest(string Code);
