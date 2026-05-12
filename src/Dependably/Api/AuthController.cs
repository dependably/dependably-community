using System.IdentityModel.Tokens.Jwt;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Dependably.Infrastructure;

namespace Dependably.Api;

[ApiController]
[Route("api/v1/auth")]
public sealed class AuthController : ControllerBase
{
    private readonly LoginService _login;
    private readonly InviteRepository _invites;
    private readonly JwtRevocationRepository _revocations;
    private readonly IMetadataStore _db;
    private readonly AuditRepository _audit;
    private readonly SamlConfigRepository _samlConfig;
    private readonly IPublicUrlBuilder _urls;

    public AuthController(
        LoginService login,
        InviteRepository invites,
        JwtRevocationRepository revocations,
        IMetadataStore db,
        AuditRepository audit,
        SamlConfigRepository samlConfig,
        IPublicUrlBuilder urls)
    {
        _login = login;
        _invites = invites;
        _revocations = revocations;
        _db = db;
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
    public async Task<IActionResult> Methods(CancellationToken ct)
    {
        var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;
        if (ctx is null || ctx.IsUninitialized)
            return Ok(new { forms = true, saml = false, samlButtonLabel = (string?)null });
        if (ctx.IsApex)
            return Ok(new { forms = true, saml = false, samlButtonLabel = (string?)null });

        var cfg = await _samlConfig.GetAsync(ctx.TenantId!, ct);
        var samlReady = cfg is { Enabled: true }
            && !string.IsNullOrWhiteSpace(cfg.IdpSsoUrl)
            && !string.IsNullOrWhiteSpace(cfg.IdpEntityId)
            && !string.IsNullOrWhiteSpace(cfg.IdpSigningCert);
        var formsEnabled = cfg is null || cfg.FormsLoginEnabled || !samlReady;

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
            return BadRequest(new { detail = "Email and password are required." });

        // Fork on resolved TenantContext rather than route shape — login is the same endpoint
        // for both tenant users (subdomain or single-mode) and system_admins (multi-mode apex).
        var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;

        (string? token, string? error, int? retryAfter) result;
        if (ctx is not null && ctx.IsApex)
        {
            result = await _login.LoginSystemAsync(req.Email, req.Password, ct);
        }
        else if (ctx is not null && ctx.IsTenant && ctx.TenantId is not null)
        {
            result = await _login.LoginTenantAsync(req.Email, req.Password, ctx.TenantId, ct);
        }
        else
        {
            // Uninitialized — first-boot has not run, or unknown subdomain in multi mode.
            return NotFound();
        }

        if (result.retryAfter.HasValue)
        {
            Response.Headers.RetryAfter = result.retryAfter.Value.ToString();
            return StatusCode(429, new { detail = result.error });
        }

        if (result.token is null)
            return Unauthorized(new { detail = "Invalid credentials." });

        // Domain attribute intentionally omitted — host-only cookie scoping prevents
        // tenant cookies leaking across subdomains in multi mode (RFC 6265).
        Response.Cookies.Append("dependably_session", result.token, _urls.SessionCookieOptions(HttpContext));

        return Ok(new { message = "Logged in." });
    }

    /// <summary>POST /api/v1/invites/accept — set password and create account from an invite link</summary>
    [HttpPost("/api/v1/invites/accept")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> AcceptInvite([FromBody] AcceptInviteRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Token))
            return BadRequest(new { detail = "Invite token is required." });
        if (string.IsNullOrWhiteSpace(req.Password) || req.Password.Length < 12)
            return BadRequest(new { detail = "Password must be at least 12 characters." });

        var invite = await _invites.AcceptAsync(req.Token, ct);
        if (invite is null)
            return StatusCode(410, new { detail = "Invite token is invalid, expired, or already used." });

        var passwordHash = BCrypt.Net.BCrypt.HashPassword(req.Password, workFactor: 12);
        var userId = Guid.NewGuid().ToString("N");

        await using var conn = await _db.OpenAsync(ct);
        // 1:1 user:tenant — invite carries the tenant (org_id) the user is joining; insert
        // directly with that tenant_id and the invite's stored role (defaults to 'member').
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

        // Auto-login. Invite is tenant-scoped, so we know which tenant to authenticate against.
        var (token, _, _) = await _login.LoginTenantAsync(invite.Email, req.Password, invite.OrgId, ct);
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
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.CurrentPassword))
            return BadRequest(new { detail = "Current password is required." });
        if (string.IsNullOrWhiteSpace(req.NewPassword) || req.NewPassword.Length < 12)
            return BadRequest(new { detail = "New password must be at least 12 characters." });

        var sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null) return Unauthorized();

        await using var conn = await _db.OpenAsync(ct);
        var current = await conn.QueryFirstOrDefaultAsync<(string Email, string Hash)>(
            "SELECT email AS Email, password_hash AS Hash FROM users WHERE id = @id",
            new { id = sub });
        if (current.Hash is null) return Unauthorized();

        if (!BCrypt.Net.BCrypt.Verify(req.CurrentPassword, current.Hash))
            return Unauthorized(new { detail = "Current password is incorrect." });

        // Reject reusing the same password — users hitting forced rotation must actually rotate.
        if (BCrypt.Net.BCrypt.Verify(req.NewPassword, current.Hash))
            return BadRequest(new { detail = "New password must differ from current password." });

        var newHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword, workFactor: 12);
        await conn.ExecuteAsync(
            "UPDATE users SET password_hash = @hash, must_change_password = 0 WHERE id = @id",
            new { hash = newHash, id = sub });

        await _audit.LogAsync(action: "user.password_changed", actorId: sub, ct: ct);

        return Ok(new { message = "Password changed." });
    }

    /// <summary>POST /api/v1/auth/logout</summary>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        // Revoke the current session JWT before deleting the cookie
        var sessionCookie = Request.Cookies["dependably_session"];
        if (sessionCookie is not null)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                if (handler.CanReadToken(sessionCookie))
                {
                    var jwt = handler.ReadJwtToken(sessionCookie);
                    var jti = jwt.Id;
                    if (!string.IsNullOrEmpty(jti))
                        await _revocations.RevokeAsync(jti, jwt.ValidTo, ct);
                }
            }
            catch { /* malformed token — still delete the cookie */ }
        }

        Response.Cookies.Delete("dependably_session");
        return Ok(new { message = "Logged out." });
    }

    /// <summary>GET /api/v1/auth/me</summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        var sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        var orgId = User.FindFirst("org_id")?.Value;
        var role = User.FindFirst("role")?.Value;

        bool mustChangePassword = false;
        string? userLanguage = null;
        string? tenantDefaultLanguage = null;
        if (sub is not null)
        {
            await using var conn = await _db.OpenAsync(ct);
            var row = await conn.QuerySingleOrDefaultAsync<(int MustChangePassword, string? Language)>(
                "SELECT must_change_password AS MustChangePassword, language AS Language FROM users WHERE id = @id",
                new { id = sub });
            mustChangePassword = row.MustChangePassword == 1;
            userLanguage = string.IsNullOrEmpty(row.Language) ? null : row.Language;

            if (orgId is not null)
            {
                tenantDefaultLanguage = await conn.ExecuteScalarAsync<string?>(
                    "SELECT default_language FROM org_settings WHERE org_id = @orgId",
                    new { orgId });
            }
        }

        var resolvedLanguage = userLanguage
            ?? (string.IsNullOrEmpty(tenantDefaultLanguage) ? LanguageCodes.Default : tenantDefaultLanguage);
        var tenantDefault = string.IsNullOrEmpty(tenantDefaultLanguage) ? LanguageCodes.Default : tenantDefaultLanguage;

        return Ok(new
        {
            userId = sub,
            orgId,
            role,
            mustChangePassword,
            language = resolvedLanguage,
            tenantDefaultLanguage = tenantDefault,
        });
    }

    /// <summary>POST /api/v1/users/me/language — set the authenticated user's locale override.</summary>
    [HttpPost("/api/v1/users/me/language")]
    [Authorize]
    public async Task<IActionResult> UpdateLanguage([FromBody] UpdateLanguageRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Language) || !LanguageCodes.IsSupported(req.Language))
            return BadRequest(new { detail = $"Unsupported language code. Allowed: {string.Join(", ", LanguageCodes.Supported)}." });

        var sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null) return Unauthorized();
        var orgId = User.FindFirst("org_id")?.Value;

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE users SET language = @lang WHERE id = @id",
            new { lang = req.Language, id = sub });

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
