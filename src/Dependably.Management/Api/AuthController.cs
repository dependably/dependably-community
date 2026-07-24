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

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Dependency-injection constructor: the parameter list is the declared dependency set; grouping it into an aggregate would hide dependencies without adding cohesion.")]
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
        // email reaches LoginService which
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
            string trustedToken = await _login.IssueSystemTrustedDeviceSessionAsync(
                ff.AdminId!, ff.TokenVersion, "forms+trusted_device", sourceIp, ct);
            // System admins have no org, and activity.org_id is NOT NULL with an FK to orgs —
            // there is no activity plane for the system realm, so this stays in audit_log.
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
        // see HandleSystemLoginAsync — HashEmail
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
            // Skipping the second factor is a step of the login, not a configuration change —
            // it belongs in the activity feed alongside login.success, not in audit_log.
            await _audit.LogActivityAsync(
                ff.TenantId!, "auth", purl: null, MfaEvents.TypeTrustedDeviceUsed,
                actorId: ff.UserId, actorKind: ActorKinds.User,
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

        // ch.Eml/ch.Sub come from the HMAC-verified challenge and reach
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

        // ch.Eml/ch.Sub come from the HMAC-verified challenge and reach
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
            // Redeeming a recovery code is a step of the login — activity, not audit_log.
            await _audit.LogActivityAsync(
                ch.Tid!, "auth", purl: null, MfaEvents.TypeRecoveryCodeUsed,
                actorId: ch.Sub, actorKind: ActorKinds.User,
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
        [FromServices] InviteRepository invites, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Token))
        {
            return BadRequest(new { detail = "Invite token is required." });
        }

        // Peek (without consuming) so a failed policy check never burns the invite's single
        // use. The invite's email and tenant slug feed the context-dictionary check and the
        // zxcvbn user-inputs list — an empty context only ever blocks the literal product name.
        var pending = await invites.PeekPendingAsync(req.Token, ct);
        var pendingOrg = pending is not null ? await _orgs.GetByIdAsync(pending.OrgId, ct) : null;
        var verdict = PasswordPolicy.Evaluate(req.Password, new PasswordContext(pending?.Email, pendingOrg?.Slug));
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
        // invite.Email is hashed by
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

    /// <summary>
    /// POST /api/v1/auth/forgot-password — self-serve "forgot password" request. Always returns
    /// 202, whether or not the email resolves to an account in the request's tenant: the response
    /// shape carries no signal an attacker could use to enumerate registered emails, and the raw
    /// reset token is never included in the response body (it reaches the user only via the
    /// emailed link). Resolves the tenant from the same <see cref="TenantContext"/> fork
    /// <see cref="Login"/> uses; a system-admin apex host or an uninitialized installation has no
    /// tenant-user store to check against, so both fall through to <see cref="NotFound"/> exactly
    /// like the corresponding branch of <see cref="Login"/>. Every request that reaches a resolved
    /// tenant is audited under <c>user.password_reset_requested</c> — matched and unmatched emails
    /// alike, distinguished by the boolean <c>detail.matched</c> — since an unmatched request is
    /// itself a security-recon signal worth a per-tenant record even though no email is sent.
    /// </summary>
    [HttpPost("forgot-password")]
    [AllowAnonymous]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> ForgotPassword(
        [FromBody] ForgotPasswordRequest req,
        [FromServices] PasswordResetTokenRepository resetTokens,
        [FromServices] Dependably.Infrastructure.Mail.TransactionalEmailService mailer,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Email))
        {
            return BadRequest(new { detail = "Email is required." });
        }

        if (HttpContext.Items[TenantContext.HttpItemsKey] is not TenantContext ctx
            || !ctx.IsTenant || ctx.TenantId is null)
        {
            return NotFound();
        }

        string? userId = await _users.FindIdByEmailAsync(ctx.TenantId, req.Email, ct);
        if (userId is not null)
        {
            string raw = await resetTokens.IssueAsync(userId, ctx.TenantId, ct);
            string resetLink = _urls.Absolute(HttpContext, $"/reset?token={raw}");
            // 30 minutes — kept in lockstep with PasswordResetTokenRepository's own expiry window.
            var expiresAt = _time.GetUtcNow().AddMinutes(30);
            mailer.EnqueuePasswordReset(req.Email, resetLink, expiresAt);
        }

        // Single audit pseudonym, computed once, reused for both outcomes so the row stays
        // realm-joinable with login-failure rows without ever persisting the raw email.
        string emailHash = LoginService.HashEmail(req.Email);
        await _audit.LogAsync(action: "user.password_reset_requested", orgId: ctx.TenantId, actorId: userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                via = "self_serve_reset_link",
                matched = userId is not null,
                email_hash = emailHash,
                realm = "tenant",
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        // Identical response whether or not the email resolved to an account, and regardless of
        // whether instance SMTP is even configured — an unconfigured instance silently drops the
        // enqueued job (TransactionalEmailService/PasswordResetEmailJob), never surfacing here.
        return Accepted();
    }

    /// <summary>
    /// POST /api/v1/auth/reset-password — completes a self-serve reset. The token is the sole
    /// bearer credential (no session, no tenant header) — same shape as
    /// <see cref="AcceptInvite"/>. No auto-login: the user is sent to /login so MFA (if enrolled)
    /// is still enforced on the freshly reset account.
    /// </summary>
    [HttpPost("reset-password")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> ResetPassword(
        [FromBody] ResetPasswordRequest req,
        [FromServices] PasswordResetTokenRepository resetTokens,
        [FromServices] ILockoutStore lockoutStore,
        [FromServices] Dependably.Infrastructure.Mail.TransactionalEmailService mailer,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Token))
        {
            return BadRequest(new { detail = "Reset token is required." });
        }

        // Peek (without consuming) so a failed policy check never burns the link's single use.
        var pending = await resetTokens.PeekAsync(req.Token, ct);
        var pendingOrg = pending is not null ? await _orgs.GetByIdAsync(pending.OrgId, ct) : null;
        var verdict = PasswordPolicy.Evaluate(req.NewPassword, new PasswordContext(pending?.Email, pendingOrg?.Slug));
        if (!verdict.IsOk)
        {
            return BadRequest(new { detail = verdict.ToReason(), field = "newPassword" });
        }

        var consumed = await resetTokens.ConsumeAsync(req.Token, ct);
        if (consumed is null)
        {
            return StatusCode(StatusCodes.Status410Gone,
                new { detail = "Reset link is invalid, expired, or already used." });
        }

        await _users.ResetPasswordByRecoveryAsync(consumed.UserId, req.NewPassword, ct);
        await lockoutStore.ClearAsync(LoginService.HashLockoutKey("tenant", consumed.OrgId, consumed.Email), ct);

        var resetUserCtx = await _users.GetUserContextAsync(consumed.UserId, consumed.OrgId, ct);
        string resetLanguage = LanguageCodes.ResolveEffective(resetUserCtx?.Language, resetUserCtx?.TenantDefaultLanguage);
        mailer.EnqueuePasswordChanged(consumed.Email, resetLanguage, _time.GetUtcNow());

        await _audit.LogAsync(action: "user.password_reset", orgId: consumed.OrgId, actorId: consumed.UserId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { via = "self_serve_reset_link" },
                Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(new { message = "Password reset." });
    }

    /// <summary>POST /api/v1/users/me/password — change password for the authenticated user</summary>
    [HttpPost("/api/v1/users/me/password")]
    [Authorize]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req,
        [FromServices] Dependably.Infrastructure.Mail.TransactionalEmailService mailer,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.CurrentPassword))
        {
            return BadRequest(new { detail = "Current password is required." });
        }

        string? sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null)
        {
            return Unauthorized();
        }

        // The session JWT carries no email claim, so it's resolved live from the user's own
        // row; the tenant slug comes from the org the caller's own claims already name. Both
        // feed the context-dictionary check and the zxcvbn user-inputs list — an empty context
        // only ever blocks the literal product name, not the caller's own email or tenant.
        string? tenantIdForPolicy = User.FindFirst("tid")?.Value ?? User.FindFirst("org_id")?.Value;
        string? emailForPolicy = await _users.GetEmailAsync(sub, ct);
        string? tenantSlugForPolicy = tenantIdForPolicy is not null
            ? (await _orgs.GetByIdAsync(tenantIdForPolicy, ct))?.Slug
            : null;

        var verdict = PasswordPolicy.Evaluate(req.NewPassword, new PasswordContext(emailForPolicy, tenantSlugForPolicy));
        if (!verdict.IsOk)
        {
            return BadRequest(new { detail = verdict.ToReason(), field = "newPassword" });
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
        string? tenantId = tenantIdForPolicy;
        string role = User.FindFirst("role")?.Value ?? "member";
        if (!string.IsNullOrEmpty(tenantId) && result.NewTokenVersion is long newVersion)
        {
            string fresh = await _login.IssueTenantSessionAsync(sub, tenantId, role, newVersion, ct);
            Response.Cookies.Append("dependably_session", fresh, _urls.SessionCookieOptions(HttpContext));
        }

        if (!string.IsNullOrEmpty(emailForPolicy))
        {
            var changeUserCtx = await _users.GetUserContextAsync(sub, tenantId, ct);
            string changeLanguage = LanguageCodes.ResolveEffective(changeUserCtx?.Language, changeUserCtx?.TenantDefaultLanguage);
            mailer.EnqueuePasswordChanged(emailForPolicy, changeLanguage, _time.GetUtcNow());
        }

        await _audit.LogAsync(action: "user.password_changed", orgId: tenantId, actorId: sub,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                sessions_invalidated = true,
                api_tokens_revoked = result.RevokedApiTokens,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
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

    // Parses and revokes the session JWT embedded in the cookie. Only the parse step is
    // guarded — a corrupt or stale cookie never blocks the logout flow — so a revocation-store
    // failure (DB locked/unavailable) is never mistaken for "nothing to revoke" and swallowed.
    // It propagates out of Logout instead, so the caller cannot report success while the
    // session JWT remains valid and unrevoked.
    private async Task TryRevokeSessionCookieAsync(string sessionCookie, CancellationToken ct)
    {
        var handler = new JwtSecurityTokenHandler();
        string jti;
        DateTime validTo;
        try
        {
            if (!handler.CanReadToken(sessionCookie))
            {
                return;
            }
            var jwt = handler.ReadJwtToken(sessionCookie);
            jti = jwt.Id;
            validTo = jwt.ValidTo;
        }
        catch (ArgumentException)
        {
            // Malformed token — nothing to revoke; the cookie is still deleted by the caller.
            return;
        }

        if (!string.IsNullOrEmpty(jti))
        {
            await _revocations.RevokeAsync(jti, validTo, ct);
        }
    }

    /// <summary>
    /// GET /api/v1/auth/me — whoami. JWT/session callers keep their existing unconditional
    /// access (every tenant role already depends on this call to bootstrap the UI shell, so
    /// gating it behind a capability would break plain members on every login). A PAT/service
    /// token additionally reaches it, but only when it carries read:tenant — the response has
    /// no session-only state and sessionExpiresAt degrades to null without an exp claim.
    /// </summary>
    [HttpGet("me")]
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        // A service/CI token principal has no users-row role to fall back to, so its explicit
        // `cap` claims are read directly (never role-derived) — a legacy token with a NULL/
        // empty `capabilities` column carries zero `cap` claims and must be denied outright,
        // not upgraded to a role-based default.
        if (IsApiTokenPrincipal(User) &&
            !Capabilities.Grants(OrgAccessGuard.ResolveExplicitCapClaims(User), Capabilities.ReadTenant))
        {
            return new ObjectResult(new { detail = "read:tenant capability required." })
            { StatusCode = StatusCodes.Status403Forbidden };
        }

        string? sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        string? orgId = User.FindFirst("org_id")?.Value;
        string? role = User.FindFirst("role")?.Value;

        var ctx = sub is not null ? await _users.GetUserContextAsync(sub, orgId, ct) : null;
        string tenantDefault = string.IsNullOrEmpty(ctx?.TenantDefaultLanguage)
            ? LanguageCodes.Default : ctx.TenantDefaultLanguage;
        // Resolution chain: user override → negotiated request culture (query string /
        // culture cookie / Accept-Language, via RequestLocalization) → tenant default → en.
        // The request culture counts only when a provider actually matched (Provider is
        // null when the middleware fell back to its default), and it ranks above the
        // tenant default because it is a per-user signal — org_settings.default_language
        // is NOT NULL, so ordering it first would make browser language unreachable and
        // snap a French-browser user back to English right after login.
        var cultureFeature = HttpContext.Features
            .Get<Microsoft.AspNetCore.Localization.IRequestCultureFeature>();
        string? requestCulture = cultureFeature?.Provider is null
            ? null
            : cultureFeature.RequestCulture.UICulture.TwoLetterISOLanguageName;
        string resolvedLanguage = ctx?.Language
            ?? (requestCulture is not null && LanguageCodes.IsSupported(requestCulture) ? requestCulture : null)
            ?? (string.IsNullOrEmpty(ctx?.TenantDefaultLanguage) ? null : ctx.TenantDefaultLanguage)
            ?? LanguageCodes.Default;

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

    // True when the principal was authenticated by the opaque-API-token scheme rather than a
    // JWT session — the discriminator Me() uses to apply the read:tenant gate only to tokens.
    private static bool IsApiTokenPrincipal(System.Security.Claims.ClaimsPrincipal user) =>
        user.Identities.Any(i => i.AuthenticationType == TokenAuthenticationDefaults.Scheme);

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
            detail: System.Text.Json.JsonSerializer.Serialize(new { language = req.Language }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return NoContent();
    }
}

public sealed record LoginRequest(string Email, string Password);
public sealed record LoginTotpRequest(string Code, bool RememberDevice = false);
public sealed record AcceptInviteRequest(string Token, string Password);
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
public sealed record UpdateLanguageRequest(string Language);
public sealed record ForgotPasswordRequest(string Email);
public sealed record ResetPasswordRequest(string Token, string NewPassword);
