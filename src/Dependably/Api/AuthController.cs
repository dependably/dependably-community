using System.IdentityModel.Tokens.Jwt;
using Dependably.Infrastructure;
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
    private readonly LoginService _login;
    private readonly UserService _users;
    private readonly InviteRepository _invites;
    private readonly JwtRevocationRepository _revocations;
    private readonly AuditRepository _audit;
    private readonly SamlConfigRepository _samlConfig;
    private readonly IPublicUrlBuilder _urls;

    public AuthController(
        LoginService login,
        UserService users,
        InviteRepository invites,
        JwtRevocationRepository revocations,
        AuditRepository audit,
        SamlConfigRepository samlConfig,
        IPublicUrlBuilder urls)
    {
        _login = login;
        _users = users;
        _invites = invites;
        _revocations = revocations;
        _audit = audit;
        _samlConfig = samlConfig;
        _urls = urls;
    }

    /// <summary>
    /// GET /api/v1/auth/methods — anonymous probe used by the login page to decide which
    /// auth options to render. Returns the configured methods for the resolved tenant.
    /// On the apex (system_admin login), only forms is ever available.
    /// </summary>
    [HttpGet("methods")]
    [AllowAnonymous]
    [EnableRateLimiting("anon")]
    public async Task<IActionResult> Methods(CancellationToken ct)
    {
        if (HttpContext.Items[TenantContext.HttpItemsKey] is not TenantContext ctx || ctx.IsUninitialized)
        {
            return Ok(new { forms = true, saml = false, samlButtonLabel = (string?)null });
        }

        if (ctx.IsApex)
        {
            return Ok(new { forms = true, saml = false, samlButtonLabel = (string?)null });
        }

        var cfg = await _samlConfig.GetAsync(ctx.TenantId!, ct);
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
    public async Task<IActionResult> Login([FromBody] LoginRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        {
            return BadRequest(new { detail = "Email and password are required." });
        }

        // Fork on resolved TenantContext rather than route shape — login is the same endpoint
        // for both tenant users (subdomain or single-mode) and system_admins (multi-mode apex).
        var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;
        string? sourceIp = HttpContext.GetNormalizedRemoteIp();

        (string? token, string? error, int? retryAfter) result;
        if (ctx is not null && ctx.IsApex)
        {
            // deepcode ignore LogForging,PrivateInformationExposure: email reaches LoginService which
            // SHA-256-hashes it (HashEmail) before any audit/log call; raw email never reaches the
            // RenderedCompactJsonFormatter sink. CRLF in property values is JSON-encoded regardless.
            result = await _login.LoginSystemAsync(req.Email, req.Password, sourceIp, ct);
        }
        else if (ctx is not null && ctx.IsTenant && ctx.TenantId is not null)
        {
            // deepcode ignore LogForging,PrivateInformationExposure: see comment above — HashEmail
            // is applied before audit; raw email is not logged.
            result = await _login.LoginTenantAsync(req.Email, req.Password, ctx.TenantId, sourceIp, ct);
        }
        else
        {
            // Uninitialized — first-boot has not run, or unknown subdomain in multi mode.
            return NotFound();
        }

        if (result.retryAfter.HasValue)
        {
            Response.Headers.RetryAfter = result.retryAfter.Value.ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests, new { detail = result.error });
        }

        if (result.token is null)
        {
            return Unauthorized(new { detail = "Invalid credentials." });
        }

        // Domain attribute intentionally omitted — host-only cookie scoping prevents
        // tenant cookies leaking across subdomains in multi mode (RFC 6265).
        Response.Cookies.Append("dependably_session", result.token, _urls.SessionCookieOptions(HttpContext));

        return Ok(new { message = "Logged in." });
    }

    /// <summary>POST /api/v1/invites/accept — set password and create account from an invite link</summary>
    [HttpPost("/api/v1/invites/accept")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> AcceptInvite([FromBody] AcceptInviteRequest req,
        [FromServices] PasswordPolicy passwordPolicy, CancellationToken ct)
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

        var invite = await _invites.AcceptAsync(req.Token, ct);
        if (invite is null)
        {
            return StatusCode(StatusCodes.Status410Gone, new { detail = "Invite token is invalid, expired, or already used." });
        }

        // 1:1 user:tenant — invite carries the tenant the user is joining; UserService inserts
        // directly with that tenant_id and the invite's stored role.
        await _users.CreateFromInviteAsync(invite, req.Password, ct);

        // Auto-login. Invite is tenant-scoped, so we know which tenant to authenticate against.
        // deepcode ignore PrivateInformationExposure: invite.Email is hashed by LoginService.HashEmail
        // before any audit/log call (same path as the manual login above).
        var (token, _, _) = await _login.LoginTenantAsync(invite.Email, req.Password, invite.OrgId,
            HttpContext.GetNormalizedRemoteIp(), ct);
        if (token is null)
        {
            // Account was created successfully but auto-login failed — this is unexpected.
            return Ok(new { message = "Account created. Please log in manually." });
        }

        Response.Cookies.Append("dependably_session", token, _urls.SessionCookieOptions(HttpContext));

        return Ok(new { message = "Account created." });
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
            language = resolvedLanguage,
            tenantDefaultLanguage = tenantDefault,
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
public sealed record AcceptInviteRequest(string Token, string Password);
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
public sealed record UpdateLanguageRequest(string Language);
