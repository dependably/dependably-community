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
    // authz-ok: pre-login probe — the login page must render before any credential exists.
    // Returns only the resolved tenant's configured auth methods, no tenant-identifying data.
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
    // authz-ok: first-factor login — the endpoint that mints the session, so it cannot require one.
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
    // authz-ok: second-factor step of login. The bearer credential is the short-lived MFA
    // challenge cookie issued by step 1, validated in the body; there is no session yet.
    // input-validation-ok: req.Code is verified against the stored TOTP/recovery secret two calls
    // deep (CompleteSystemTotpAsync/CompleteTenantTotpAsync → LoginService), rejecting with 401/429.
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
                actorKind: ActorKinds.User,
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
    // authz-ok: the invite token is the sole bearer credential — the account being created is
    // precisely what does not exist yet, so no session can be required.
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
        // directly with that tenant_id and the invite's stored role. A null result means the
        // tenant already holds an account for that address (in any casing): the invite is spent,
        // and the answer is "sign in", not a second account resolving to the same login.
        string? createdUserId = await _users.CreateFromInviteAsync(invite, req.Password, ct);
        if (createdUserId is null)
        {
            return Conflict(new { detail = "An account already exists for this email address. Sign in instead." });
        }

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
    ///
    /// <para>
    /// Two independent throttles guard the send. The endpoint's per-IP limiter bounds one caller
    /// (collapsed to a /64 for IPv6, so a routed prefix is one budget); <see cref="AccountSendThrottle"/>
    /// bounds sends to one TARGET account regardless of source, which is what stops a distributed
    /// attacker spread over many prefixes from mail-bombing a single mailbox. The account budget is
    /// consumed for every requested address, matched or not, so the work per request does not vary
    /// with whether the address resolves — and a throttled request returns the same 202 as any
    /// other, since a distinguishable rejection would be the enumeration oracle this whole endpoint
    /// is shaped to avoid.
    /// </para>
    /// </summary>
    [HttpPost("forgot-password")]
    // authz-ok: self-serve reset request — reached by a user who cannot authenticate. Responds
    // uniformly whether or not the email matched, so anonymity leaks no account existence.
    [AllowAnonymous]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> ForgotPassword(
        [FromBody] ForgotPasswordRequest req,
        [FromServices] PasswordResetTokenRepository resetTokens,
        [FromServices] AccountSendThrottle sendThrottle,
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

        // Consumed before the account lookup so every request does the same work in the same order.
        // The key is per (tenant, address), so one account running out of budget leaves every other
        // account's budget untouched.
        bool withinBudget = await sendThrottle.TryConsumeAsync(
            LoginService.HashLockoutKey("tenant", ctx.TenantId, req.Email),
            AccountSendThrottle.PurposePasswordReset, ct);

        string? userId = await _users.FindIdByEmailAsync(ctx.TenantId, req.Email, ct);
        bool linkIssued = false;
        if (userId is not null && withinBudget)
        {
            string raw = await resetTokens.IssueAsync(userId, ctx.TenantId, ct);
            string resetLink = _urls.Absolute(HttpContext, $"/reset?token={raw}");
            // 30 minutes — kept in lockstep with PasswordResetTokenRepository's own expiry window.
            var expiresAt = _time.GetUtcNow().AddMinutes(30);
            mailer.EnqueuePasswordReset(req.Email, resetLink, expiresAt);
            linkIssued = true;
        }

        // Single audit pseudonym, computed once, reused for both outcomes so the row stays
        // realm-joinable with login-failure rows without ever persisting the raw email.
        string emailHash = LoginService.HashEmail(req.Email);
        await _audit.LogAsync(action: "user.password_reset_requested", orgId: ctx.TenantId, actorId: userId,
            // The caller is unauthenticated (this is the pre-auth reset request); actorKind is only
            // meaningful once the email has resolved to a real account (actorId non-null).
            actorKind: userId is not null ? ActorKinds.User : null,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                via = "self_serve_reset_link",
                matched = userId is not null,
                throttled = !withinBudget,
                // Set inside the branch that actually mints and mails the link, so the row records
                // what happened rather than restating the conditions that led there.
                link_issued = linkIssued,
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
    // authz-ok: the single-use reset token is the sole bearer credential; the caller has no
    // session by construction. No auto-login, so MFA is still enforced afterwards.
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
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { via = "self_serve_reset_link" },
                Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(new { message = "Password reset." });
    }

    /// <summary>
    /// POST /api/v1/auth/confirm-email-change — redeems the link mailed to the NEW address and
    /// commits the rectification.
    ///
    /// The token is the sole credential, like <see cref="ResetPassword"/>: the caller is proving
    /// possession of the destination mailbox, which is precisely the fact the change turns on, and
    /// requiring a session as well would break the common case of confirming from a phone. The
    /// change is a credential-class event, so it bumps token_version and revokes the user's API
    /// tokens — every session issued to the old identity has to re-authenticate.
    ///
    /// The old mailbox is told after the fact. It just lost control of an account, and that is
    /// exactly the signal that surfaces a hostile change to the person who can still act on it.
    /// </summary>
    [HttpPost("confirm-email-change")]
    // authz-ok: the single-use change token is the sole bearer credential — the caller is proving
    // control of the new mailbox and has no session by construction.
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> ConfirmEmailChange(
        [FromBody] ConfirmEmailChangeRequest req,
        [FromServices] EmailChangeTokenRepository changeTokens,
        [FromServices] Dependably.Infrastructure.Mail.TransactionalEmailService mailer,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Token))
        {
            return BadRequest(new { detail = "Confirmation token is required." });
        }

        var consumed = await changeTokens.ConsumeAsync(req.Token, ct);
        if (consumed is null)
        {
            return StatusCode(StatusCodes.Status410Gone,
                new { detail = "Confirmation link is invalid, expired, or already used." });
        }

        long? newVersion = await _users.ApplyVerifiedEmailChangeAsync(consumed.UserId, consumed.NewEmail, ct);
        if (newVersion is null)
        {
            // Claimed by someone else between the request and this redemption. The token is spent
            // either way — the user asks again, against whatever the roster looks like now.
            return Conflict(new { detail = "That address is already in use in this organization." });
        }

        // Notify the address that just lost the account. Uses the user's resolved language; the
        // verification mail to the new address could not, since that mailbox had no account yet.
        var userCtx = await _users.GetUserContextAsync(consumed.UserId, consumed.OrgId, ct);
        string language = LanguageCodes.ResolveEffective(userCtx?.Language, userCtx?.TenantDefaultLanguage);
        mailer.EnqueueEmailChanged(consumed.CurrentEmail, language, _time.GetUtcNow());

        await _audit.LogAsync(action: "user.email_changed", orgId: consumed.OrgId, actorId: consumed.UserId,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                via = "verified_change_link",
                new_email = consumed.NewEmail,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(new { message = "Email address updated." });
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
            actorKind: ActorKinds.User,
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
    // authz-ok: no attribute by design. Acts only on the caller's own session cookie (revoke +
    // delete) and must still succeed when that cookie is expired, revoked, or corrupt, so
    // requiring authentication would strand a user holding a dead session. Omitting
    // [AllowAnonymous] rather than adding it keeps RouteScopeFilter and the rotation/MFA guards
    // live for callers who DO present a valid session.
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
            // The user's own override (null when inheriting) is reported separately from the
            // resolved zone, so the profile UI can show "use organization default" as selected
            // rather than pre-selecting the inherited zone by name and pinning it on next save.
            timezone = ctx?.Timezone,
            resolvedTimezone = TimeZoneCodes.ResolveEffective(ctx?.Timezone, ctx?.TenantDefaultTimezone),
            tenantDefaultTimezone = string.IsNullOrEmpty(ctx?.TenantDefaultTimezone)
                ? TimeZoneCodes.Default : ctx.TenantDefaultTimezone,
            // utcformat-ok: session-profile JSON wire field, not a DB write.
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
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { language = req.Language }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    /// <summary>
    /// POST /api/v1/users/me/timezone — set (or clear) the authenticated user's display-timezone
    /// override. An absent/empty value clears it, which is how "use the organization default" is
    /// expressed: storing the matching zone by name would pin the user and silently ignore a
    /// later change to that default.
    /// </summary>
    [HttpPost("/api/v1/users/me/timezone")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateTimezone([FromBody] UpdateTimezoneRequest req, CancellationToken ct)
    {
        string? requested = string.IsNullOrWhiteSpace(req.Timezone) ? null : req.Timezone;
        if (requested is not null && !TimeZoneCodes.IsSupported(requested))
        {
            return BadRequest(new { detail = $"Unrecognised timezone '{requested}'. Use an IANA zone name, e.g. 'America/Toronto'." });
        }

        string? sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        if (sub is null)
        {
            return Unauthorized();
        }

        string? orgId = User.FindFirst("org_id")?.Value;

        await _users.UpdateTimezoneAsync(sub, requested, ct);

        await _audit.LogAsync(
            action: "user.timezone_changed",
            orgId: orgId,
            actorId: sub,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { timezone = requested }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    /// <summary>
    /// GET /api/v1/users/me/export — GDPR Art. 15 (right of access) / Art. 20 (portability). Returns
    /// a structured, machine-readable JSON copy of the authenticated caller's own personal data,
    /// aggregated across every table classified in
    /// <see cref="Dependably.Infrastructure.Privacy.PersonalDataTables"/>.
    /// <para>
    /// Strictly self-scoped and BOLA-safe by construction: there is no user-id route parameter. The
    /// subject is the principal's own <c>sub</c> and <c>tid</c>, so the endpoint cannot be pointed
    /// at another user or another tenant. Every underlying query is filtered by that user id AND the
    /// subject's org where the table is tenant-scoped. The export is audited (counts only, never the
    /// exported PII) because obtaining a full copy of one's data is a security-relevant action.
    /// </para>
    /// </summary>
    [HttpGet("/api/v1/users/me/export")]
    [Authorize]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> ExportMyData(
        [FromServices] Dependably.Infrastructure.Privacy.PersonalDataExportRepository export,
        CancellationToken ct)
    {
        string? sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        string? orgId = User.FindFirst("tid")?.Value ?? User.FindFirst("org_id")?.Value;
        if (sub is null || orgId is null)
        {
            return Unauthorized();
        }

        // The subject's email lives on their own row, never in the session JWT — resolve it live.
        // It anchors the invite-by-recipient rows and the login-attempts lockout pseudonym.
        string? email = await _users.GetEmailAsync(sub, ct);
        if (email is null)
        {
            // A valid session whose user row is gone (deleted mid-session): nothing to export.
            return Unauthorized();
        }

        // login_attempts is keyed by the tenant-scoped lockout pseudonym, whose hash helper lives
        // here in Management; compute it and hand the opaque key to the Core aggregator.
        string loginAttemptKey = LoginService.HashLockoutKey("tenant", orgId, email);

        var data = await export.ExportAsync(sub, orgId, email, loginAttemptKey, ct);

        // Audit the export itself, recording only row COUNTS — never the exported personal data, so
        // the audit trail does not itself become a second copy of the subject's PII in audit_log.detail.
        await _audit.LogAsync(
            action: "user.data_exported",
            orgId: orgId,
            actorId: sub,
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                user_tokens = data.UserTokens.Count,
                password_reset_tokens = data.PasswordResetTokens.Count,
                email_change_tokens = data.EmailChangeTokens.Count,
                external_identities = data.ExternalIdentities.Count,
                mfa_trusted_devices = data.MfaTrustedDevices.Count,
                banner_dismissals = data.BannerDismissals.Count,
                invites_created = data.InvitesCreated.Count,
                invites_received = data.InvitesReceived.Count,
                audit_log = data.AuditLog.Count,
                activity = data.Activity.Count,
                audit_events = data.AuditEvents.Count,
                login_attempts = data.LoginAttempts is null ? 0 : 1,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);

        // MVC's System.Text.Json formatter serializes camelCase (JsonSerializerDefaults.Web), which
        // is the contract the SPA reads — the export DTO relies on that, no manual serialization.
        return Ok(data);
    }
}

public sealed record LoginRequest(string Email, string Password);
public sealed record LoginTotpRequest(string Code, bool RememberDevice = false);
public sealed record AcceptInviteRequest(string Token, string Password);
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
public sealed record UpdateLanguageRequest(string Language);
/// <summary>A null/empty Timezone clears the override, meaning "inherit the org default".</summary>
public sealed record UpdateTimezoneRequest(string? Timezone);
public sealed record ForgotPasswordRequest(string Email);
public sealed record ResetPasswordRequest(string Token, string NewPassword);

/// <summary>Body of POST /api/v1/auth/confirm-email-change — the one-shot token mailed to the
/// address being moved to.</summary>
public sealed record ConfirmEmailChangeRequest(string Token);
