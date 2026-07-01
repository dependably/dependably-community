using System.IdentityModel.Tokens.Jwt;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Identity;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

[ApiController]
[Route("api/v1/auth")]
public sealed class AuthController : ControllerBase
{
    // MFA challenge cookies and challenge JWTs live for this many minutes.
    private const int MfaChallengeTtlMinutes = 5;

    private readonly LoginService _login;
    private readonly UserService _users;
    private readonly JwtRevocationRepository _revocations;
    private readonly AuditRepository _audit;
    private readonly IPublicUrlBuilder _urls;
    private readonly TimeProvider _time;

    private readonly OrgRepository _orgs;
    private readonly IRequireMfaMode _requireMfa;
    private readonly SystemAdminRepository _admins;

    public AuthController(
        LoginService login,
        UserService users,
        JwtRevocationRepository revocations,
        AuditRepository audit,
        IPublicUrlBuilder urls,
        TimeProvider time,
        OrgRepository orgs,
        IRequireMfaMode requireMfa,
        SystemAdminRepository admins)
    {
        _login = login;
        _users = users;
        _revocations = revocations;
        _audit = audit;
        _urls = urls;
        _time = time;
        _orgs = orgs;
        _requireMfa = requireMfa;
        _admins = admins;
    }

    /// <summary>
    /// GET /api/v1/auth/methods — anonymous probe used by the login page to decide which
    /// auth options to render. Returns the configured methods for the resolved tenant.
    /// On the apex (system_admin login), only forms is ever available.
    /// </summary>
    [HttpGet("methods")]
    [AllowAnonymous]
    [EnableRateLimiting("anon")]
    public async Task<IActionResult> Methods([FromServices] SamlConfigRepository samlConfig, CancellationToken ct)
    {
        if (HttpContext.Items[TenantContext.HttpItemsKey] is not TenantContext ctx || ctx.IsUninitialized)
        {
            return Ok(new { forms = true, saml = false, samlButtonLabel = (string?)null });
        }

        if (ctx.IsApex)
        {
            return Ok(new { forms = true, saml = false, samlButtonLabel = (string?)null });
        }

        var cfg = await samlConfig.GetAsync(ctx.TenantId!, ct);
        bool samlReady = cfg is { Enabled: true }
            && !string.IsNullOrWhiteSpace(cfg.IdpSsoUrl)
            && !string.IsNullOrWhiteSpace(cfg.IdpEntityId)
            && !string.IsNullOrWhiteSpace(cfg.IdpSigningCert);
        bool formsEnabled = cfg is null || cfg.FormsLoginEnabled || !samlReady;

        return Ok(new
        {
            forms = formsEnabled,
            saml = samlReady,
            samlButtonLabel = samlReady ? cfg!.ButtonLabel : null,
        });
    }

    /// <summary>POST /api/v1/auth/login</summary>
    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> Login(
        [FromBody] LoginRequest req,
        [FromServices] TrustedDeviceService trustedDevices,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        {
            return BadRequest(new { detail = "Email and password are required." });
        }

        // Fork on resolved TenantContext rather than route shape — login is the same endpoint
        // for both tenant users (subdomain or single-mode) and system_admins (multi-mode apex).
        var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;
        string? sourceIp = HttpContext.GetNormalizedRemoteIp();

        if (ctx is not null && ctx.IsApex)
        {
            return await HandleSystemLoginAsync(req, trustedDevices, sourceIp, ct);
        }

        if (ctx is not null && ctx.IsTenant && ctx.TenantId is not null)
        {
            return await HandleTenantLoginAsync(req, trustedDevices, ctx.TenantId, sourceIp, ct);
        }

        // Uninitialized — first-boot has not run, or unknown subdomain in multi mode.
        return NotFound();
    }

    // System-admin login (apex host, multi mode).
    private async Task<IActionResult> HandleSystemLoginAsync(
        LoginRequest req, TrustedDeviceService trustedDevices, string? sourceIp, CancellationToken ct)
    {
        // deepcode ignore LogForging,PrivateInformationExposure: email reaches LoginService which
        // SHA-256-hashes it (HashEmail) before any audit/log call; raw email never reaches the
        // RenderedCompactJsonFormatter sink. CRLF in property values is JSON-encoded regardless.
        var ff = await _login.BeginSystemLoginAsync(req.Email, req.Password, sourceIp, ct);

        if (ff.RetryAfterSeconds.HasValue)
        {
            Response.Headers.RetryAfter = ff.RetryAfterSeconds.Value.ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests, new { detail = ff.Error });
        }

        if (ff.Error is not null)
        {
            return Unauthorized(new { detail = "Invalid credentials." });
        }

        if (!ff.MfaEnabled)
        {
            // Non-MFA path: session is complete. Compute whether MFA enrollment is required so
            // the SPA can open the enrollment flow immediately without a guard bounce.
            bool enrollmentRequired = _requireMfa.IsEnabled
                && !await _admins.IsMfaEnabledAsync(ff.AdminId!, ct);
            Response.Cookies.Append("dependably_session", ff.Token!, _urls.SessionCookieOptions(HttpContext));
            return Ok(new { message = "Logged in.", enrollmentRequired });
        }

        // MFA path: a valid trusted-device cookie skips the TOTP step.
        string? deviceCookie = Request.Cookies["dependably_device"];
        if (deviceCookie is not null
            && await trustedDevices.TryConsumeAsync(ff.AdminId!, "system", null, deviceCookie, ct))
        {
            string trustedToken = await _login.IssueSystemSessionAsync(ff.AdminId!, ff.TokenVersion, ct);
            await _audit.LogSystemAsync(
                action: MfaEvents.TypeTrustedDeviceUsed,
                actorId: ff.AdminId,
                detail: new MfaEvents.TrustedDeviceUsed("system").ToJson(),
                sourceIp: sourceIp, ct: ct);
            Response.Cookies.Append("dependably_session", trustedToken, _urls.SessionCookieOptions(HttpContext));
            return Ok(new { message = "Logged in.", enrollmentRequired = false });
        }

        // No trusted device — issue system challenge cookie and ask for TOTP.
        string challenge = await _login.IssueSystemMfaChallengeAsync(ff.AdminId!, ff.Email!, ff.TokenVersion, ct);
        var challengeOpts = _urls.SessionCookieOptions(HttpContext);
        challengeOpts.Expires = _time.GetUtcNow().AddMinutes(MfaChallengeTtlMinutes);
        Response.Cookies.Append("dependably_mfa", challenge, challengeOpts);
        return Ok(new { mfaRequired = true });
    }

    // Tenant login (subdomain or single-mode host).
    private async Task<IActionResult> HandleTenantLoginAsync(
        LoginRequest req, TrustedDeviceService trustedDevices, string tenantId, string? sourceIp, CancellationToken ct)
    {
        // deepcode ignore LogForging,PrivateInformationExposure: see HandleSystemLoginAsync — HashEmail
        // is applied before audit; raw email is not logged.
        var ff = await _login.BeginTenantLoginAsync(req.Email, req.Password, tenantId, sourceIp, ct);

        if (ff.RetryAfterSeconds.HasValue)
        {
            Response.Headers.RetryAfter = ff.RetryAfterSeconds.Value.ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests, new { detail = ff.Error });
        }

        if (ff.Error is not null)
        {
            return Unauthorized(new { detail = "Invalid credentials." });
        }

        if (!ff.MfaEnabled)
        {
            // Non-MFA path: session is complete. Compute whether MFA enrollment is required so
            // the SPA can open the enrollment flow immediately without a guard bounce.
            var settings = await _orgs.GetSettingsAsync(ff.TenantId!, ct);
            bool enrollmentRequired = (_requireMfa.IsEnabled || (settings?.RequireMfa ?? false))
                && !await _users.IsMfaEnabledAsync(ff.UserId!, ct);
            Response.Cookies.Append("dependably_session", ff.Token!, _urls.SessionCookieOptions(HttpContext));
            return Ok(new { message = "Logged in.", enrollmentRequired });
        }

        // MFA path: a valid trusted-device cookie skips the TOTP step.
        string? deviceCookie = Request.Cookies["dependably_device"];
        if (deviceCookie is not null
            && await trustedDevices.TryConsumeAsync(ff.UserId!, "tenant", ff.TenantId, deviceCookie, ct))
        {
            string trustedToken = await _login.IssueTrustedDeviceSessionAsync(
                ff.UserId!, ff.TenantId!, ff.Role!, ff.TokenVersion, "forms+trusted_device", sourceIp, ct);
            await _audit.LogAsync(
                action: MfaEvents.TypeTrustedDeviceUsed,
                orgId: ff.TenantId,
                actorId: ff.UserId,
                detail: new MfaEvents.TrustedDeviceUsed("tenant").ToJson(),
                sourceIp: sourceIp, ct: ct);
            Response.Cookies.Append("dependably_session", trustedToken, _urls.SessionCookieOptions(HttpContext));
            return Ok(new { message = "Logged in.", enrollmentRequired = false });
        }

        // No trusted device — issue challenge cookie and ask for TOTP.
        string challenge = await _login.IssueMfaChallengeAsync(
            ff.UserId!, ff.TenantId!, ff.Role!, req.Email, ff.TokenVersion, ct);
        var challengeOpts = _urls.SessionCookieOptions(HttpContext);
        challengeOpts.Expires = _time.GetUtcNow().AddMinutes(MfaChallengeTtlMinutes);
        Response.Cookies.Append("dependably_mfa", challenge, challengeOpts);
        return Ok(new { mfaRequired = true });
    }

    /// <summary>POST /api/v1/auth/login/totp — step-2 TOTP or recovery-code submission</summary>
    [HttpPost("login/totp")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> LoginTotp(
        [FromBody] LoginTotpRequest req,
        [FromServices] IMfaEnrollmentService mfaService,
        [FromServices] ISystemMfaEnrollmentService systemMfaService,
        [FromServices] TrustedDeviceService trustedDevices,
        CancellationToken ct)
    {
        string? challengeCookie = Request.Cookies["dependably_mfa"];
        if (challengeCookie is null)
        {
            return Unauthorized(new { detail = "Invalid credentials." });
        }

        var (valid, sub, tid, role, eml, tver, jti, realm) = await _login.TryReadMfaChallengeAsync(challengeCookie, ct);
        if (!valid)
        {
            return Unauthorized(new { detail = "Invalid credentials." });
        }

        // jti-revocation check: the challenge is single-use so a successfully-used cookie
        // cannot be replayed even within the 5-minute window.
        if (await _revocations.IsRevokedAsync(jti!, ct))
        {
            return Unauthorized(new { detail = "Invalid credentials." });
        }

        string? sourceIp = HttpContext.GetNormalizedRemoteIp();
        var challenge = new VerifiedChallenge(challengeCookie, sub, tid, role, eml, tver, jti, sourceIp);

        // Branch on the SIGNED realm claim from the HMAC-verified challenge — never the host.
        // A tenant challenge must never mint a system session and vice-versa; the signed realm
        // claim is the authoritative discriminator. The tenant path additionally requires a
        // non-null tid so a system challenge (which carries no tid) cannot satisfy it.
        if (realm == "system")
        {
            return await CompleteSystemTotpAsync(req, systemMfaService, trustedDevices, challenge, ct);
        }

        // Tenant second factor — tid is required; a system challenge (no tid) cannot satisfy this path.
        return tid is null
            ? Unauthorized(new { detail = "Invalid credentials." })
            : await CompleteTenantTotpAsync(req, mfaService, trustedDevices, challenge, ct);
    }

    // Completes a system_admin second factor: verifies the code, mints the session, and
    // optionally remembers the device.
    private async Task<IActionResult> CompleteSystemTotpAsync(
        LoginTotpRequest req, ISystemMfaEnrollmentService systemMfaService,
        TrustedDeviceService trustedDevices, VerifiedChallenge ch, CancellationToken ct)
    {
        // System admin second factor. Lockout key scoped to system realm.
        string sysLockoutKey = LoginService.HashLockoutKey("system", null, ch.Eml!);
        string sysEmailHash = LoginService.HashEmail(ch.Eml!);

        // deepcode ignore LogForging: ch.Eml/ch.Sub come from the HMAC-verified challenge and reach
        // LoginService, which SHA-256-hashes the email (HashEmail) before any audit/log call; the raw
        // value never reaches a log sink.
        var sysResult = await _login.CompleteSystemSecondFactorAsync(
            ch.Sub!, ch.Eml!, ch.Tver,
            new LoginService.SecondFactorContext(sysLockoutKey, sysEmailHash, req.Code, ch.SourceIp), ct);

        if (sysResult.RetryAfterSeconds.HasValue)
        {
            Response.Headers.RetryAfter = sysResult.RetryAfterSeconds.Value.ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests, new { detail = sysResult.Error });
        }

        if (sysResult.Error is not null)
        {
            return Unauthorized(new { detail = "Invalid credentials." });
        }

        // Revoke the challenge jti (single-use), clear the challenge cookie, set the session.
        await RevokeChallengeAsync(ch.Cookie, ch.Jti!, ct);
        Response.Cookies.Delete("dependably_mfa");
        Response.Cookies.Append("dependably_session", sysResult.Token!, _urls.SessionCookieOptions(HttpContext));

        if (sysResult.RecoveryCodeUsed)
        {
            int remaining = await systemMfaService.CountRecoveryCodesAsync(ch.Sub!, ct);
            await _audit.LogSystemAsync(
                action: MfaEvents.TypeRecoveryCodeUsed,
                actorId: ch.Sub,
                detail: new MfaEvents.RecoveryCodeUsed(remaining).ToJson(),
                sourceIp: ch.SourceIp, ct: ct);
        }

        if (req.RememberDevice)
        {
            string? userAgent = Request.Headers.UserAgent.ToString();
            string rawDevice = await trustedDevices.CreateAsync(ch.Sub!, "system", null, userAgent, ct);
            var deviceOpts = _urls.SessionCookieOptions(HttpContext);
            deviceOpts.Expires = _time.GetUtcNow().AddDays(trustedDevices.TtlDays);
            Response.Cookies.Append("dependably_device", rawDevice, deviceOpts);
            await _audit.LogSystemAsync(
                action: MfaEvents.TypeTrustedDeviceAdded,
                actorId: ch.Sub,
                detail: new MfaEvents.TrustedDeviceAdded("system").ToJson(),
                sourceIp: ch.SourceIp, ct: ct);
        }

        return Ok(new { message = "Logged in." });
    }

    // Completes a tenant-user second factor: verifies the code, mints the session, and
    // optionally remembers the device.
    private async Task<IActionResult> CompleteTenantTotpAsync(
        LoginTotpRequest req, IMfaEnrollmentService mfaService,
        TrustedDeviceService trustedDevices, VerifiedChallenge ch, CancellationToken ct)
    {
        // Re-derive lockout key from the SIGNED claims (not client input) so the shared
        // budget from step 1 continues accumulating failures on both factors.
        string lockoutKey = LoginService.HashLockoutKey("tenant", ch.Tid!, ch.Eml!);
        string emailHash = LoginService.HashEmail(ch.Eml!);

        // deepcode ignore LogForging: ch.Eml/ch.Sub come from the HMAC-verified challenge and reach
        // LoginService, which SHA-256-hashes the email (HashEmail) before any audit/log call; the raw
        // value never reaches a log sink.
        var result = await _login.CompleteTenantSecondFactorAsync(
            ch.Sub!, ch.Tid!, ch.Role!, ch.Tver,
            new LoginService.SecondFactorContext(lockoutKey, emailHash, req.Code, ch.SourceIp), ct);

        if (result.RetryAfterSeconds.HasValue)
        {
            Response.Headers.RetryAfter = result.RetryAfterSeconds.Value.ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests, new { detail = result.Error });
        }

        if (result.Error is not null)
        {
            return Unauthorized(new { detail = "Invalid credentials." });
        }

        // Revoke the challenge jti so it cannot be replayed, clear the cookie, set the session.
        await RevokeChallengeAsync(ch.Cookie, ch.Jti!, ct);
        Response.Cookies.Delete("dependably_mfa");
        Response.Cookies.Append("dependably_session", result.Token!, _urls.SessionCookieOptions(HttpContext));

        if (result.RecoveryCodeUsed)
        {
            int remaining = await mfaService.CountRecoveryCodesAsync(ch.Sub!, ct);
            await _audit.LogAsync(
                action: MfaEvents.TypeRecoveryCodeUsed,
                orgId: ch.Tid,
                actorId: ch.Sub,
                detail: new MfaEvents.RecoveryCodeUsed(remaining).ToJson(),
                sourceIp: ch.SourceIp, ct: ct);
        }

        if (req.RememberDevice)
        {
            string? userAgent = Request.Headers.UserAgent.ToString();
            string rawDevice = await trustedDevices.CreateAsync(ch.Sub!, "tenant", ch.Tid, userAgent, ct);
            var deviceOpts = _urls.SessionCookieOptions(HttpContext);
            deviceOpts.Expires = _time.GetUtcNow().AddDays(trustedDevices.TtlDays);
            Response.Cookies.Append("dependably_device", rawDevice, deviceOpts);
            await _audit.LogAsync(
                action: MfaEvents.TypeTrustedDeviceAdded,
                orgId: ch.Tid,
                actorId: ch.Sub,
                detail: new MfaEvents.TrustedDeviceAdded("tenant").ToJson(),
                sourceIp: ch.SourceIp, ct: ct);
        }

        return Ok(new { message = "Logged in." });
    }

    // Revokes a single-use MFA challenge by its jti. The revocation expiry tracks the challenge
    // JWT's own lifetime (falling back to the standard TTL if the token is unreadable).
    private async Task RevokeChallengeAsync(string challengeCookie, string jti, CancellationToken ct)
    {
        var handler = new JwtSecurityTokenHandler();
        var expiry = handler.CanReadToken(challengeCookie)
            ? handler.ReadJwtToken(challengeCookie).ValidTo
            : _time.GetUtcNow().AddMinutes(MfaChallengeTtlMinutes).UtcDateTime;
        await _revocations.RevokeAsync(jti, new DateTimeOffset(expiry, TimeSpan.Zero), ct);
    }

    // The HMAC-verified MFA challenge claims plus the request's source IP, threaded from
    // LoginTotp into the per-realm second-factor completion helpers.
    private readonly record struct VerifiedChallenge(
        string Cookie,
        string? Sub,
        string? Tid,
        string? Role,
        string? Eml,
        long Tver,
        string? Jti,
        string? SourceIp);

    /// <summary>POST /api/v1/invites/accept — set password and create account from an invite link</summary>
    [HttpPost("/api/v1/invites/accept")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> AcceptInvite([FromBody] AcceptInviteRequest req,
        [FromServices] PasswordPolicy passwordPolicy, [FromServices] InviteRepository invites, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Token))
        {
            return BadRequest(new { detail = "Invite token is required." });
        }

        var verdict = passwordPolicy.Evaluate(req.Password, new PasswordContext());
        if (!verdict.IsOk)
        {
            return BadRequest(new { detail = verdict.ToReason(), field = "password" });
        }

        var invite = await invites.AcceptAsync(req.Token, ct);
        if (invite is null)
        {
            return StatusCode(StatusCodes.Status410Gone, new { detail = "Invite token is invalid, expired, or already used." });
        }

        // 1:1 user:tenant — invite carries the tenant the user is joining; UserService inserts
        // directly with that tenant_id and the invite's stored role.
        await _users.CreateFromInviteAsync(invite, req.Password, ct);

        // Auto-login. Invite is tenant-scoped, so we know which tenant to authenticate against.
        // deepcode ignore LogForging,PrivateInformationExposure: invite.Email is hashed by
        // LoginService.HashEmail before any audit/log call (same path as the manual login above).
        var (token, _, _) = await _login.LoginTenantAsync(invite.Email, req.Password, invite.OrgId,
            HttpContext.GetNormalizedRemoteIp(), ct);
        if (token is null)
        {
            // Account was created successfully but auto-login failed — this is unexpected.
            return Ok(new { message = "Account created. Please log in manually." });
        }

        Response.Cookies.Append("dependably_session", token, _urls.SessionCookieOptions(HttpContext));

        // Compute whether MFA enrollment is required so a freshly-invited user is guided into
        // setup without a guard bounce. Invited users never have MFA enrolled at account creation.
        var inviteSettings = await _orgs.GetSettingsAsync(invite.OrgId, ct);
        bool enrollmentRequired = _requireMfa.IsEnabled || (inviteSettings?.RequireMfa ?? false);

        return Ok(new { message = "Account created.", enrollmentRequired });
    }

    /// <summary>POST /api/v1/users/me/password — change password for the authenticated user</summary>
    [HttpPost("/api/v1/users/me/password")]
    [Authorize]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req,
        [FromServices] PasswordPolicy passwordPolicy, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.CurrentPassword))
        {
            return BadRequest(new { detail = "Current password is required." });
        }

        var verdict = passwordPolicy.Evaluate(req.NewPassword, new PasswordContext());
        if (!verdict.IsOk)
        {
            return BadRequest(new { detail = verdict.ToReason(), field = "newPassword" });
        }

        string? sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null)
        {
            return Unauthorized();
        }

        var result = await _users.ChangePasswordAsync(sub, req.CurrentPassword, req.NewPassword, ct);
        switch (result.Outcome)
        {
            case PasswordChangeOutcome.UserNotFound:
                return Unauthorized();
            case PasswordChangeOutcome.CurrentPasswordIncorrect:
                return Unauthorized(new { detail = "Current password is incorrect." });
            case PasswordChangeOutcome.NewPasswordSameAsOld:
                return BadRequest(new { detail = "New password must differ from current password." });
        }

        // The token_version bump just staled every outstanding session JWT (and the user's API
        // tokens were revoked). Re-issue the changing session's own cookie at the new version
        // so the user who rotated the password stays logged in.
        string? tenantId = User.FindFirst("tid")?.Value ?? User.FindFirst("org_id")?.Value;
        string role = User.FindFirst("role")?.Value ?? "member";
        if (!string.IsNullOrEmpty(tenantId) && result.NewTokenVersion is long newVersion)
        {
            string fresh = await _login.IssueTenantSessionAsync(sub, tenantId, role, newVersion, ct);
            Response.Cookies.Append("dependably_session", fresh, _urls.SessionCookieOptions(HttpContext));
        }

        await _audit.LogAsync(action: "user.password_changed", actorId: sub,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                sessions_invalidated = true,
                api_tokens_revoked = result.RevokedApiTokens,
            }),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return Ok(new { message = "Password changed." });
    }

    /// <summary>POST /api/v1/auth/logout</summary>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        // Revoke the current session JWT before deleting the cookie
        string? sessionCookie = Request.Cookies["dependably_session"];
        if (sessionCookie is not null)
        {
            await TryRevokeSessionCookieAsync(sessionCookie, ct);
        }

        Response.Cookies.Delete("dependably_session");
        return Ok(new { message = "Logged out." });
    }

    // Parses and revokes the session JWT embedded in the cookie. Ignores malformed tokens
    // so a corrupt or stale cookie never blocks the logout flow.
    private async Task TryRevokeSessionCookieAsync(string sessionCookie, CancellationToken ct)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(sessionCookie))
            {
                return;
            }
            var jwt = handler.ReadJwtToken(sessionCookie);
            string jti = jwt.Id;
            if (!string.IsNullOrEmpty(jti))
            {
                await _revocations.RevokeAsync(jti, jwt.ValidTo, ct);
            }
        }
        catch { /* malformed token — still delete the cookie */ }
    }

    /// <summary>GET /api/v1/auth/me</summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        string? sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        string? orgId = User.FindFirst("org_id")?.Value;
        string? role = User.FindFirst("role")?.Value;

        var ctx = sub is not null ? await _users.GetUserContextAsync(sub, orgId, ct) : null;
        string tenantDefault = string.IsNullOrEmpty(ctx?.TenantDefaultLanguage)
            ? LanguageCodes.Default : ctx.TenantDefaultLanguage;
        string resolvedLanguage = ctx?.Language ?? tenantDefault;

        return Ok(new
        {
            userId = sub,
            orgId,
            role,
            mustChangePassword = ctx?.MustChangePassword ?? false,
            mfaEnabled = ctx?.MfaEnabled ?? false,
            mfaEnrollmentRequired = ctx?.MfaEnrollmentRequired ?? false,
            language = resolvedLanguage,
            tenantDefaultLanguage = tenantDefault,
            sessionExpiresAt = User.FindFirst("exp")?.Value is string expUnix
                && long.TryParse(expUnix, out long exp)
                ? DateTimeOffset.FromUnixTimeSeconds(exp).ToString("O")
                : null,
        });
    }

    /// <summary>POST /api/v1/users/me/language — set the authenticated user's locale override.</summary>
    [HttpPost("/api/v1/users/me/language")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateLanguage([FromBody] UpdateLanguageRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Language) || !LanguageCodes.IsSupported(req.Language))
        {
            return BadRequest(new { detail = $"Unsupported language code. Allowed: {string.Join(", ", LanguageCodes.Supported)}." });
        }

        string? sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null)
        {
            return Unauthorized();
        }

        string? orgId = User.FindFirst("org_id")?.Value;

        await _users.UpdateLanguageAsync(sub, req.Language, ct);

        await _audit.LogAsync(
            action: "user.language_changed",
            orgId: orgId,
            actorId: sub,
            detail: System.Text.Json.JsonSerializer.Serialize(new { language = req.Language }),
            ct: ct);

        return NoContent();
    }
}

public sealed record LoginRequest(string Email, string Password);
public sealed record LoginTotpRequest(string Code, bool RememberDevice = false);
public sealed record AcceptInviteRequest(string Token, string Password);
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
public sealed record UpdateLanguageRequest(string Language);
