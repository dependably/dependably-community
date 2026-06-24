using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure.Identity;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Infrastructure;

public sealed class LoginService
{
    private const int MaxFailedAttempts = 10;
    private const int LockoutMinutes = 15;

    /// <summary>
    /// Valid bcrypt (cost 12) hash of a random, unguessable, immediately-discarded value,
    /// computed once per process. Substituted as the stored hash when the user record is
    /// missing (or carries no usable hash) so <c>BCrypt.Verify</c> performs identical work for
    /// "unknown email" and "wrong password" — closing the timing oracle that would otherwise
    /// let a remote probe enumerate valid emails. It can never match any password because its
    /// preimage is 32 bytes of CSPRNG output that is never stored. Not a credential.
    /// </summary>
    internal static readonly string TimingSentinelHash = CreateTimingSentinelHash();

    private static string CreateTimingSentinelHash()
    {
        string preimage = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return BCrypt.Net.BCrypt.HashPassword(preimage, workFactor: 12);
    }

    /// <summary>
    /// Injected dependencies for <see cref="LoginService"/>. Bundles DI services
    /// so the constructor stays within the parameter-count gate (S107).
    /// </summary>
    public sealed record Dependencies(
        IMetadataStore Db,
        OrgRepository Orgs,
        SystemAdminRepository SystemAdmins,
        ILockoutStore Lockout,
        AuditRepository Audit,
        ExternalIdentityRepository ExternalIdentities,
        Audit.IAuditEmitter AuditEmitter,
        TimeProvider Time,
        IMfaEnrollmentService Mfa,
        ISystemMfaEnrollmentService SystemMfa);

    private readonly IMetadataStore _db;
    private readonly OrgRepository _orgs;
    private readonly SystemAdminRepository _systemAdmins;
    private readonly ILockoutStore _lockout;
    private readonly AuditRepository _audit;
    private readonly ExternalIdentityRepository _externalIdentities;
    private readonly Dependably.Infrastructure.Audit.IAuditEmitter _auditEmitter;
    private readonly TimeProvider _time;
    private readonly IMfaEnrollmentService _mfa;
    private readonly ISystemMfaEnrollmentService _systemMfa;

    public LoginService(Dependencies deps)
    {
        _db = deps.Db;
        _orgs = deps.Orgs;
        _systemAdmins = deps.SystemAdmins;
        _lockout = deps.Lockout;
        _audit = deps.Audit;
        _externalIdentities = deps.ExternalIdentities;
        _auditEmitter = deps.AuditEmitter;
        _time = deps.Time;
        _mfa = deps.Mfa;
        _systemMfa = deps.SystemMfa;
    }

    /// <summary>
    /// Result of a successful or failed tenant first-factor (password) check.
    /// <see cref="Token"/> is set (only) when MFA is not enabled — the completed-login path.
    /// When <see cref="MfaEnabled"/> is true the caller must proceed to the second factor.
    /// </summary>
    public sealed record TenantFirstFactorResult(
        string? UserId,
        string? TenantId,
        string? Role,
        long TokenVersion,
        bool MfaEnabled,
        string? Token,
        string? Error,
        int? RetryAfterSeconds);

    /// <summary>
    /// Result of a successful or failed tenant second-factor (TOTP or recovery-code) check.
    /// <see cref="Token"/> is set on success.
    /// </summary>
    public sealed record SecondFactorResult(
        string? Token,
        bool RecoveryCodeUsed,
        string? Error,
        int? RetryAfterSeconds);

    /// <summary>
    /// Request-side inputs shared by the tenant and system second-factor checks: the realm-scoped
    /// lockout key and audit email hash (both derived from the verified challenge), the submitted
    /// TOTP/recovery code, and the caller's source IP.
    /// </summary>
    public readonly record struct SecondFactorContext(
        string LockoutKey,
        string EmailHash,
        string Code,
        string? SourceIp);

    /// <summary>
    /// Result of a successful or failed system first-factor (password) check.
    /// <see cref="Token"/> is set (only) when MFA is not enabled — the completed-login path.
    /// When <see cref="MfaEnabled"/> is true the caller must proceed to the second factor.
    /// </summary>
    public sealed record SystemFirstFactorResult(
        string? AdminId,
        string? Email,
        long TokenVersion,
        bool MfaEnabled,
        string? Token,
        string? Error,
        int? RetryAfterSeconds);

    /// <summary>
    /// Verifies the first factor (password) for a tenant user and returns a result that tells the
    /// caller whether MFA is required. This is the timing-oracle-safe credential check: BCrypt.Verify
    /// runs unconditionally so unknown-email and wrong-password rejections take the same time.
    /// The MFA branch is only reachable when <c>valid == true</c>; an unknown user never receives a
    /// challenge token.
    /// </summary>
    public async Task<TenantFirstFactorResult> BeginTenantLoginAsync(
        string email, string password, string tenantId, string? sourceIp = null, CancellationToken ct = default)
    {
        var ff = await VerifyTenantFirstFactorAsync(email, password, tenantId, sourceIp, ct);
        if (ff.Error is not null)
        {
            return ff;
        }

        if (!ff.MfaEnabled)
        {
            string token = await CompleteTenantLoginAsync(
                ff.UserId!, ff.TenantId!, ff.Role!, ff.TokenVersion, "forms", sourceIp, ct);
            return ff with { Token = token };
        }

        return ff;
    }

    /// <summary>
    /// Authenticates a tenant user. The user must be a member of <paramref name="tenantId"/> —
    /// in single mode this is the one tenant; in multi mode it's the tenant whose subdomain
    /// the request hit. Returns a tenant-scoped JWT (<c>scope=tenant</c>) on success.
    /// Non-MFA path only; MFA-enrolled users go through <see cref="BeginTenantLoginAsync"/>
    /// and <see cref="CompleteTenantSecondFactorAsync"/>.
    /// </summary>
    public async Task<(string? Token, string? Error, int? RetryAfterSeconds)> LoginTenantAsync(
        string email, string password, string tenantId, string? sourceIp = null, CancellationToken ct = default)
    {
        var ff = await VerifyTenantFirstFactorAsync(email, password, tenantId, sourceIp, ct);
        if (ff.Error is not null)
        {
            return (null, ff.Error, ff.RetryAfterSeconds);
        }

        // MFA-enrolled users: auto-login path (invite accept) completes as non-MFA for simplicity.
        // The invite flow always creates a fresh user without MFA enrolled.
        string token = await CompleteTenantLoginAsync(
            ff.UserId!, ff.TenantId!, ff.Role!, ff.TokenVersion, "forms", sourceIp, ct);
        return (token, null, null);
    }

    /// <summary>
    /// Extracts the credential-check body shared by all tenant login entry points.
    /// Preserves the timing-oracle defense: BCrypt.Verify runs unconditionally on the first
    /// operand regardless of whether the email is known. Only returns a non-error result when
    /// the password matched a real stored hash (<c>valid == true</c>).
    /// </summary>
    private async Task<TenantFirstFactorResult> VerifyTenantFirstFactorAsync(
        string email, string password, string tenantId, string? sourceIp, CancellationToken ct)
    {
        // Lockout key is realm+tenant scoped so each (realm, tenant, email) identity gets an
        // independent counter. Tenant isolation lives in the key derivation — login_attempts
        // has no org_id column, so the OrgIdFilteringComplianceTests gate does not apply here.
        string lockoutKey = HashLockoutKey("tenant", tenantId, email);
        // Audit pseudonym remains the unsalted email hash so audit rows stay joinable across
        // realms without coupling them to the lockout key structure.
        string emailHash = HashEmail(email);

        var (failedCount, lockedUntil) = await _lockout.GetAsync(lockoutKey, ct);
        if (lockedUntil.HasValue && _time.GetUtcNow() < lockedUntil.Value)
        {
            int retryAfter = (int)(lockedUntil.Value - _time.GetUtcNow()).TotalSeconds + 1;
            await _audit.LogAsync("lockout.triggered",
                detail: System.Text.Json.JsonSerializer.Serialize(new { email_hash = emailHash, realm = "tenant" }),
                sourceIp: sourceIp, ct: ct);
            await _audit.LogActivityAsync(tenantId, "auth", purl: null, "login.locked",
                sourceIp: sourceIp, ct: ct);
            await _auditEmitter.EmitAsync(
                Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLockout,
                tenantId, "system", null, "rejected",
                new Dependably.Infrastructure.Audit.Events.AuthEvents.Lockout("tenant", emailHash).ToJson(), ct);
            return new TenantFirstFactorResult(null, null, null, 0, false, null, "Account locked due to too many failed attempts.", retryAfter);
        }

        await using var conn = await _db.OpenAsync(ct);
        var (Id, _, PasswordHash, DbTenantId, Role, AccountLocked, TokenVersion, MfaEnabled) =
            await conn.QuerySingleOrDefaultAsync<(string Id, string Email, string PasswordHash,
                string TenantId, string Role, int AccountLocked, long TokenVersion, int MfaEnabled)>(
            """
            SELECT id, email, password_hash, tenant_id AS TenantId, role,
                   CASE WHEN account_status IN ('locked','disabled') THEN 1 ELSE 0 END AS AccountLocked,
                   token_version AS TokenVersion,
                   mfa_enabled AS MfaEnabled
            FROM users
            WHERE lower(email) = lower(@email) AND tenant_id = @tenantId
            LIMIT 1
            """,
            new { email, tenantId });

        // BCrypt.Verify runs unconditionally (first operand) so unknown-email, locked, and
        // wrong-password rejections all pay the same hashing cost — no timing oracle.
        bool valid = VerifyPasswordConstantTime(password, PasswordHash)
            && Id is not null && AccountLocked == 0;

        if (!valid)
        {
            await RecordFailureAsync(new LoginFailureTarget(lockoutKey, emailHash, "tenant", tenantId), failedCount, sourceIp, "invalid_credentials", ct);
            return new TenantFirstFactorResult(null, null, null, 0, false, null, "Invalid credentials.", null);
        }

        // For non-MFA users the login is complete here — clear the failure counter.
        // For MFA users, clearing is deferred until the second factor succeeds (in
        // CompleteTenantSecondFactorAsync) so the budget accumulates across both steps and a
        // correct password cannot reset the TOTP brute-force counter.
        if (MfaEnabled == 0)
        {
            await _lockout.ClearAsync(lockoutKey, ct);
        }
        return new TenantFirstFactorResult(Id!, DbTenantId, Role, TokenVersion, MfaEnabled == 1, null, null, null);
    }

    /// <summary>
    /// Completes a tenant login after all factors have been verified: stamps last_login_at,
    /// emits the three audit calls with the supplied method string, and returns the session JWT.
    /// Calling this on a partial first-factor would falsely record the user as logged in —
    /// callers must only invoke it after all required factors succeed.
    /// </summary>
    private async Task<string> CompleteTenantLoginAsync(
        string userId, string tenantId, string role, long tokenVersion,
        string method, string? sourceIp, CancellationToken ct)
    {
        string loginDetail = System.Text.Json.JsonSerializer.Serialize(new { method });
        await _audit.LogAsync("login.success", actorId: userId, detail: loginDetail, sourceIp: sourceIp, ct: ct);
        await _audit.LogActivityAsync(tenantId, "auth", purl: null, "login.success", actorId: userId,
            detail: loginDetail,
            sourceIp: sourceIp, ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLoginSuccess,
            tenantId, "user", userId, "accepted",
            new Dependably.Infrastructure.Audit.Events.AuthEvents.LoginSuccess("tenant", method).ToJson(), ct);

        // Stamp last_login_at on the user row so the system_admin lookup endpoint can surface
        // it without a separate auth audit query.
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE users SET last_login_at = @now WHERE id = @id",
            new { id = userId, now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ") });

        string jwtSecret = await _orgs.GetInstanceSettingAsync("jwt_secret", ct)
            ?? throw new InvalidOperationException("JWT secret not found in instance_settings.");

        return IssueTenantJwt(userId, tenantId, role, jwtSecret, tokenVersion, _time);
    }

    /// <summary>
    /// Verifies the second factor (TOTP or recovery code) for a tenant MFA login. The lockout
    /// budget is shared with the first factor — the same key and counter carry failures from
    /// both steps so brute-forcing TOTP eats into the same budget as brute-forcing the password.
    /// </summary>
    public async Task<SecondFactorResult> CompleteTenantSecondFactorAsync(
        string userId, string tenantId, string role, long tokenVersion,
        SecondFactorContext context, CancellationToken ct = default)
    {
        var (lockoutKey, emailHash, code, sourceIp) = context;
        // Re-check the lockout at the top of step 2 so a burst of second-factor attempts cannot
        // exceed MaxFailedAttempts regardless of how they are interleaved with first-factor attempts.
        var (failedCount, lockedUntil) = await _lockout.GetAsync(lockoutKey, ct);
        if (lockedUntil.HasValue && _time.GetUtcNow() < lockedUntil.Value)
        {
            int retryAfter = (int)(lockedUntil.Value - _time.GetUtcNow()).TotalSeconds + 1;
            await _audit.LogAsync("lockout.triggered",
                detail: System.Text.Json.JsonSerializer.Serialize(new { email_hash = emailHash, realm = "tenant" }),
                sourceIp: sourceIp, ct: ct);
            await _auditEmitter.EmitAsync(
                Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLockout,
                tenantId, "system", null, "rejected",
                new Dependably.Infrastructure.Audit.Events.AuthEvents.Lockout("tenant", emailHash).ToJson(), ct);
            return new SecondFactorResult(null, false, "Account locked due to too many failed attempts.", retryAfter);
        }

        bool totpOk = await _mfa.VerifyTotpAsync(userId, code, ct);
        bool recoveryOk = false;
        if (!totpOk)
        {
            recoveryOk = await _mfa.RedeemRecoveryCodeAsync(userId, code, ct);
        }

        if (!totpOk && !recoveryOk)
        {
            await RecordFailureAsync(new LoginFailureTarget(lockoutKey, emailHash, "tenant", tenantId), failedCount, sourceIp, "mfa_invalid", ct);
            await _audit.LogAsync(
                Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLoginFailure,
                orgId: tenantId, sourceIp: sourceIp, ct: ct);
            return new SecondFactorResult(null, false, "Invalid credentials.", null);
        }

        await _lockout.ClearAsync(lockoutKey, ct);
        string method = recoveryOk ? "forms+recovery" : "forms+totp";
        string token = await CompleteTenantLoginAsync(userId, tenantId, role, tokenVersion, method, sourceIp, ct);
        return new SecondFactorResult(token, recoveryOk, null, null);
    }

    /// <summary>
    /// Issues a short-lived MFA challenge JWT (<c>scope=mfa_challenge</c>). The challenge
    /// is signed with the instance JWT secret and expires in 5 minutes. It is validated
    /// manually by <see cref="TryReadMfaChallenge"/>; it never flows through JwtBearer
    /// (which only reads <c>scope=tenant</c> tokens).
    /// </summary>
    internal static string IssueMfaChallengeJwt(
        string userId, string tenantId, string role, string email,
        long tokenVersion, string secret, TimeProvider time)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = time.GetUtcNow().UtcDateTime;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("tid", tenantId),
            new("org_id", tenantId),
            new("role", role),
            new("scope", "mfa_challenge"),
            new("tver", tokenVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("eml", email.ToLowerInvariant()),
            new("amr", "pwd"),
        };

        var token = new JwtSecurityToken(
            claims: claims,
            notBefore: now,
            expires: now.AddMinutes(5),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Async wrapper for <see cref="IssueMfaChallengeJwt"/> that resolves the JWT secret.
    /// </summary>
    public async Task<string> IssueMfaChallengeAsync(
        string userId, string tenantId, string role, string email,
        long tokenVersion, CancellationToken ct = default)
    {
        string secret = await JwtSecretAsync(ct);
        return IssueMfaChallengeJwt(userId, tenantId, role, email, tokenVersion, secret, _time);
    }

    /// <summary>
    /// Validates an MFA challenge token: checks the HMAC-SHA256 signature, lifetime, and
    /// <c>scope=mfa_challenge</c> claim. Populates the out parameters from the verified claims.
    /// <paramref name="realm"/> defaults to <c>"tenant"</c> when the claim is absent (back-compat
    /// with tenant challenges issued before the realm claim was added). For system challenges the
    /// realm claim is always present; tid/role are absent (system_admins live outside the tenant model).
    /// </summary>
    public (bool Valid, string? Sub, string? Tid, string? Role, string? Eml, long Tver, string? Jti, string Realm)
        TryReadMfaChallenge(string token, string secret)
    {
        try
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
            var validationParams = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
            };
            var principal = handler.ValidateToken(token, validationParams, out _);
            string? scope = principal.FindFirst("scope")?.Value;
            if (scope != "mfa_challenge")
            {
                return (false, null, null, null, null, 0, null, "tenant");
            }

            string? sub = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                ?? principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            string? tid = principal.FindFirst("tid")?.Value;
            string? role = principal.FindFirst("role")?.Value;
            string? eml = principal.FindFirst("eml")?.Value;
            string? jti = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            string? tverStr = principal.FindFirst("tver")?.Value;
            long tver = long.TryParse(tverStr, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out long tv) ? tv : 0;
            // Absent realm claim defaults to "tenant" for back-compat with existing challenge JWTs.
            string realm = principal.FindFirst("realm")?.Value ?? "tenant";

            // System challenge carries no tid/role — validate only the fields that are present;
            // a tenant challenge additionally requires tid and role.
            bool valid = realm == "system"
                ? sub is not null && eml is not null && jti is not null
                : sub is not null && tid is not null && role is not null && eml is not null && jti is not null;

            return (valid, sub, tid, role, eml, tver, jti, realm);
        }
        catch
        {
            return (false, null, null, null, null, 0, null, "tenant");
        }
    }

    /// <summary>
    /// Async wrapper that resolves the JWT secret and validates the MFA challenge token.
    /// Returns the realm alongside the other claims (absent realm defaults to "tenant").
    /// </summary>
    public async Task<(bool Valid, string? Sub, string? Tid, string? Role, string? Eml, long Tver, string? Jti, string Realm)>
        TryReadMfaChallengeAsync(string token, CancellationToken ct = default)
    {
        string secret = await JwtSecretAsync(ct);
        return TryReadMfaChallenge(token, secret);
    }

    /// <summary>
    /// Issues a trusted-device session JWT for a user who has presented a valid device cookie.
    /// Delegates to CompleteTenantLoginAsync so audit and last_login_at stamping fire identically.
    /// </summary>
    public async Task<string> IssueTrustedDeviceSessionAsync(
        string userId, string tenantId, string role, long tokenVersion,
        string method, string? sourceIp, CancellationToken ct = default) =>
        await CompleteTenantLoginAsync(userId, tenantId, role, tokenVersion, method, sourceIp, ct);

    /// <summary>
    /// Runs <c>BCrypt.Verify</c> against the stored hash, substituting the per-process
    /// <see cref="TimingSentinelHash"/> when no usable hash exists (unknown account, or a
    /// SAML-only user whose <c>password_hash</c> is empty). Verify always executes, so the
    /// caller's response time does not reveal whether the account exists. Returns true only
    /// when a real stored hash matched.
    /// </summary>
    internal static bool VerifyPasswordConstantTime(string password, string? storedHash)
    {
        bool usable = !string.IsNullOrEmpty(storedHash);
        bool hashOk = BCrypt.Net.BCrypt.Verify(password, usable ? storedHash : TimingSentinelHash);
        return hashOk && usable;
    }

    /// <summary>
    /// Verifies the first factor (password) for a system_admin and returns a result that tells
    /// the caller whether MFA is required. BCrypt.Verify runs unconditionally so unknown-email
    /// and wrong-password rejections take the same time (no timing oracle). The MFA branch is
    /// only reachable when <c>valid == true</c>; an unknown admin never receives a challenge token.
    /// </summary>
    private async Task<SystemFirstFactorResult> VerifySystemFirstFactorAsync(
        string email, string password, string? sourceIp, CancellationToken ct)
    {
        string lockoutKey = HashLockoutKey("system", null, email);
        string emailHash = HashEmail(email);

        var (failedCount, lockedUntil) = await _lockout.GetAsync(lockoutKey, ct);
        if (lockedUntil.HasValue && _time.GetUtcNow() < lockedUntil.Value)
        {
            int retryAfter = (int)(lockedUntil.Value - _time.GetUtcNow()).TotalSeconds + 1;
            await _audit.LogAsync("lockout.triggered",
                detail: System.Text.Json.JsonSerializer.Serialize(new { email_hash = emailHash, realm = "system" }),
                sourceIp: sourceIp, ct: ct);
            await _auditEmitter.EmitAsync(
                Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLockout,
                null, "system", null, "rejected",
                new Dependably.Infrastructure.Audit.Events.AuthEvents.Lockout("system", emailHash).ToJson(), ct);
            return new SystemFirstFactorResult(null, null, 0, false, null, "Account locked due to too many failed attempts.", retryAfter);
        }

        var creds = await _systemAdmins.GetCredentialsByEmailAsync(email, ct);
        // BCrypt.Verify runs unconditionally (first operand) so unknown-email, locked, and
        // wrong-password rejections all pay the same hashing cost — no timing oracle.
        bool hashOk = VerifyPasswordConstantTime(password, creds?.PasswordHash);
        bool valid = hashOk && creds is not null && creds.Value.AccountStatus == "active";

        if (!valid)
        {
            await RecordFailureAsync(new LoginFailureTarget(lockoutKey, emailHash, "system", null), failedCount, sourceIp, "invalid_credentials", ct);
            return new SystemFirstFactorResult(null, null, 0, false, null, "Invalid credentials.", null);
        }

        // For non-MFA admins the login is complete here — clear the failure counter.
        // For MFA admins, clearing is deferred until the second factor succeeds so the budget
        // accumulates across both steps and a correct password cannot reset the TOTP brute-force counter.
        if (!creds!.Value.MfaEnabled)
        {
            await _lockout.ClearAsync(lockoutKey, ct);
        }

        return new SystemFirstFactorResult(creds.Value.Id, creds.Value.Email, creds.Value.TokenVersion,
            creds.Value.MfaEnabled, null, null, null);
    }

    /// <summary>
    /// Begins a system_admin login: verifies the password and — when MFA is not enrolled —
    /// completes the login and returns a system-scoped session token. When MFA is enrolled
    /// the caller receives a partial result with <c>MfaEnabled=true</c> and must proceed
    /// to <see cref="CompleteSystemSecondFactorAsync"/>.
    /// </summary>
    public async Task<SystemFirstFactorResult> BeginSystemLoginAsync(
        string email, string password, string? sourceIp = null, CancellationToken ct = default)
    {
        var ff = await VerifySystemFirstFactorAsync(email, password, sourceIp, ct);
        if (ff.Error is not null)
        {
            return ff;
        }

        if (!ff.MfaEnabled)
        {
            string token = await CompleteSystemLoginAsync(ff.AdminId!, ff.TokenVersion, "forms", sourceIp, ct);
            return ff with { Token = token };
        }

        return ff;
    }

    /// <summary>
    /// Completes a system_admin login after all factors have been verified: stamps last_login_at,
    /// emits audit calls, and returns the system-scoped session JWT with the current token version.
    /// Callers must only invoke this after all required factors succeed.
    /// </summary>
    private async Task<string> CompleteSystemLoginAsync(
        string adminId, long tokenVersion, string method, string? sourceIp, CancellationToken ct)
    {
        await _audit.LogSystemAsync("login.success", actorId: adminId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { realm = "system", method }),
            sourceIp: sourceIp, ct: ct);
        // deepcode ignore PrivateInformationExposure: payload contains only the user UUID,
        // realm name, and method name — no email. The email arg was reduced to emailHash
        // (SHA-256) by HashEmail before any audit/log call in VerifySystemFirstFactorAsync.
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLoginSuccess,
            null, "user", adminId, "accepted",
            new Dependably.Infrastructure.Audit.Events.AuthEvents.LoginSuccess("system", method).ToJson(), ct);
        await _systemAdmins.UpdateLastLoginAsync(adminId, _time.GetUtcNow(), ct);

        string jwtSecret = await _orgs.GetInstanceSettingAsync("jwt_secret", ct)
            ?? throw new InvalidOperationException("JWT secret not found in instance_settings.");

        return IssueSystemJwt(adminId, jwtSecret, _time, tokenVersion);
    }

    /// <summary>
    /// Verifies the second factor (TOTP or recovery code) for a system_admin MFA login. The
    /// lockout budget is shared with the first factor so brute-forcing TOTP eats into the same
    /// budget as brute-forcing the password.
    /// </summary>
    public async Task<SecondFactorResult> CompleteSystemSecondFactorAsync(
        string adminId, string email, long tokenVersion,
        SecondFactorContext context, CancellationToken ct = default)
    {
        var (lockoutKey, emailHash, code, sourceIp) = context;
        var (failedCount, lockedUntil) = await _lockout.GetAsync(lockoutKey, ct);
        if (lockedUntil.HasValue && _time.GetUtcNow() < lockedUntil.Value)
        {
            int retryAfter = (int)(lockedUntil.Value - _time.GetUtcNow()).TotalSeconds + 1;
            await _audit.LogSystemAsync("lockout.triggered",
                detail: System.Text.Json.JsonSerializer.Serialize(new { email_hash = emailHash, realm = "system" }),
                sourceIp: sourceIp, ct: ct);
            await _auditEmitter.EmitAsync(
                Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLockout,
                null, "system", null, "rejected",
                new Dependably.Infrastructure.Audit.Events.AuthEvents.Lockout("system", emailHash).ToJson(), ct);
            return new SecondFactorResult(null, false, "Account locked due to too many failed attempts.", retryAfter);
        }

        bool totpOk = await _systemMfa.VerifyTotpAsync(adminId, code, ct);
        bool recoveryOk = false;
        if (!totpOk)
        {
            recoveryOk = await _systemMfa.RedeemRecoveryCodeAsync(adminId, code, ct);
        }

        if (!totpOk && !recoveryOk)
        {
            await RecordFailureAsync(new LoginFailureTarget(lockoutKey, emailHash, "system", null), failedCount, sourceIp, "mfa_invalid", ct);
            await _audit.LogSystemAsync(
                Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLoginFailure,
                sourceIp: sourceIp, ct: ct);
            return new SecondFactorResult(null, false, "Invalid credentials.", null);
        }

        await _lockout.ClearAsync(lockoutKey, ct);
        string method = recoveryOk ? "forms+recovery" : "forms+totp";
        string token = await CompleteSystemLoginAsync(adminId, tokenVersion, method, sourceIp, ct);
        return new SecondFactorResult(token, recoveryOk, null, null);
    }

    /// <summary>
    /// Mints a fresh system session JWT for an already-authenticated system_admin, resolving
    /// the signing secret internally. Used to re-issue the caller's own session cookie after
    /// MFA disable bumps <c>system_admins.token_version</c> and stales every outstanding JWT.
    /// </summary>
    public async Task<string> IssueSystemSessionAsync(
        string adminId, long tokenVersion, CancellationToken ct = default)
    {
        string secret = await JwtSecretAsync(ct);
        return IssueSystemJwt(adminId, secret, _time, tokenVersion);
    }

    /// <summary>
    /// Issues a short-lived system MFA challenge JWT (<c>scope=mfa_challenge</c>,
    /// <c>realm=system</c>). Does NOT carry tid/org_id/role — those are system-admin concepts
    /// outside the tenant model. Validated by <see cref="TryReadMfaChallenge"/>.
    /// </summary>
    internal static string IssueSystemMfaChallengeJwt(
        string adminId, string email, long tokenVersion, string secret, TimeProvider time)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = time.GetUtcNow().UtcDateTime;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, adminId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("scope", "mfa_challenge"),
            new("realm", "system"),
            new("tver", tokenVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("eml", email.ToLowerInvariant()),
        };

        var token = new JwtSecurityToken(
            claims: claims,
            notBefore: now,
            expires: now.AddMinutes(5),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Async wrapper for <see cref="IssueSystemMfaChallengeJwt"/> that resolves the JWT secret.
    /// </summary>
    public async Task<string> IssueSystemMfaChallengeAsync(
        string adminId, string email, long tokenVersion, CancellationToken ct = default)
    {
        string secret = await JwtSecretAsync(ct);
        return IssueSystemMfaChallengeJwt(adminId, email, tokenVersion, secret, _time);
    }

    /// <summary>
    /// Authenticates a system_admin when MFA is not enrolled. Returns a system-scoped JWT on
    /// success. MFA-enrolled admins must use <see cref="BeginSystemLoginAsync"/> and
    /// <see cref="CompleteSystemSecondFactorAsync"/> for the two-step flow.
    /// </summary>
    public async Task<(string? Token, string? Error, int? RetryAfterSeconds)> LoginSystemAsync(
        string email, string password, string? sourceIp = null, CancellationToken ct = default)
    {
        var ff = await BeginSystemLoginAsync(email, password, sourceIp, ct);
        return (ff.Token, ff.Error, ff.RetryAfterSeconds);
    }

    /// <summary>
    /// Outcome of a SAML SSO assertion. <see cref="Token"/> is set on success; <see cref="Error"/>
    /// is set on failure. <see cref="Provisioned"/> is true the first time we created a local
    /// user row from the assertion; <see cref="Linked"/> is true the first time we attached an
    /// IdP identity to a pre-existing forms user.
    /// </summary>
    public readonly record struct SamlLoginResult(
        string? Token, string? Error, string? UserId, string? Role, bool Provisioned, bool Linked);

    /// <summary>
    /// Authenticates an IdP-asserted user. Identity is the (idpEntityId, nameId) pair — never
    /// email. Email is only used as a one-time linking hint when an IdP-linked record doesn't
    /// yet exist. Returns a tenant-scoped JWT (<c>scope=tenant</c>) on success.
    ///
    /// The caller (SamlController) is responsible for validating the SAML response signature,
    /// audience, and timing constraints before invoking this method — this layer trusts the
    /// (entityId, nameId, email) tuple already.
    /// </summary>
    public async Task<SamlLoginResult> LoginSamlAsync(
        string tenantId,
        string idpEntityId,
        string nameId,
        string? assertionEmail,
        SamlLoginOptions options = default,
        CancellationToken ct = default)
    {
        var ctx = new SamlLoginContext(tenantId, idpEntityId, nameId, assertionEmail, options.MappedRole, options.IdpCanAssignAdmin, options.SourceIp);
        await using var conn = await _db.OpenAsync(ct);

        // 1. Primary lookup: by external identity. This is the stable path — if the IdP
        //    rotates the user's email, we still find them here.
        var existing = await _externalIdentities.FindAsync(tenantId, idpEntityId, nameId, ct);
        if (existing is not null)
        {
            return await LoginViaExternalIdentityAsync(conn, existing, ctx, ct);
        }

        // 2. No external identity yet. Try to link by email.
        if (!string.IsNullOrWhiteSpace(assertionEmail))
        {
            var linked = await TryLoginViaEmailLinkAsync(conn, ctx, ct);
            if (linked is not null)
            {
                return linked.Value;
            }
        }

        // 3. First-time JIT user.
        return await ProvisionJitUserAsync(conn, ctx, ct);
    }

    // The (entityId, nameId, email) tuple plus role/ceiling/source-IP that every SAML login
    // branch threads through. Bundled so branch helpers stay within a sane parameter count.
    private readonly record struct SamlLoginContext(
        string TenantId,
        string IdpEntityId,
        string NameId,
        string? AssertionEmail,
        string? MappedRole,
        bool IdpCanAssignAdmin,
        string? SourceIp);

    // ── IdP role ceiling ──────────────────────────────────────────────────────
    // The IdP may never auto-assign 'owner'; 'admin' requires the per-tenant
    // idp_can_assign_admin opt-in. member/auditor are always assignable.

    private const int RoleRankOwner = 3;
    private const int RoleRankAdmin = 2;
    private const int RoleRankMember = 1;

    private static int RoleRank(string role) => role switch
    {
        "owner" => RoleRankOwner,
        "admin" => RoleRankAdmin,
        _ => RoleRankMember,
    };

    private static string IdpRoleCeiling(in SamlLoginContext ctx) =>
        ctx.IdpCanAssignAdmin ? "admin" : "member";

    private static bool ExceedsIdpRoleCeiling(in SamlLoginContext ctx, string role) =>
        RoleRank(role) > RoleRank(IdpRoleCeiling(ctx));

    private Task AuditRoleMappingBlockedAsync(
        SamlLoginContext ctx, string? userId, string attemptedRole, string effectiveRole, CancellationToken ct) =>
        _audit.LogAsync("auth.saml.role_mapping_blocked", orgId: ctx.TenantId, actorId: userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                attempted_role = attemptedRole,
                effective_role = effectiveRole,
                ceiling = IdpRoleCeiling(ctx),
                idp_can_assign_admin = ctx.IdpCanAssignAdmin,
                idp_entity_id = ctx.IdpEntityId,
                nameid = ctx.NameId,
            }),
            sourceIp: ctx.SourceIp, ct: ct);

    // Branch 1: an external identity (idpEntityId, nameId) already maps to a local user.
    private async Task<SamlLoginResult> LoginViaExternalIdentityAsync(
        System.Data.Common.DbConnection conn, ExternalIdentity existing, SamlLoginContext ctx, CancellationToken ct)
    {
        var (Id, Role, AccountStatus, Email, TokenVersion) = await conn.QuerySingleOrDefaultAsync<(string Id, string Role, string AccountStatus, string Email, long TokenVersion)>(
            "SELECT id AS Id, role AS Role, account_status AS AccountStatus, email AS Email, token_version AS TokenVersion FROM users WHERE id = @id",
            new { id = existing.UserId });
        if (Id is null)
        {
            return new SamlLoginResult(null, "Linked user not found.", null, null, false, false);
        }

        if (AccountStatus is "locked" or "disabled")
        {
            return await RejectInactiveAccountAsync(Id, AccountStatus, ctx, ct);
        }

        await _externalIdentities.UpdateLastLoginAsync(existing.Id, ctx.AssertionEmail, ct);
        await StampUserLoginAsync(conn, Id, ctx.AssertionEmail, Email);

        await LogSamlSuccessAsync(ctx.TenantId, Id, ctx.IdpEntityId, ctx.NameId, "external_identity", ctx.SourceIp, ct);

        string effectiveRole = await ResyncRoleAsync(ctx, Id, Role, logRefusal: true, ct);

        return new SamlLoginResult(IssueJwt(Id, ctx.TenantId, effectiveRole, await JwtSecretAsync(ct), TokenVersion),
            null, Id, effectiveRole, false, false);
    }

    // Branch 2: no external identity, but a local user shares the asserted email — link them.
    // Returns null when no user matches the email, so the caller falls through to JIT provisioning.
    // Privileged accounts (owner, or admin without idp_can_assign_admin) are never silently linked:
    // the IdP ceiling that guards JIT provisioning must also guard the email-link path. Refusal is
    // audited and returns null-token so the ACS issues a 401; no external_identities row is created.
    private async Task<SamlLoginResult?> TryLoginViaEmailLinkAsync(
        System.Data.Common.DbConnection conn, SamlLoginContext ctx, CancellationToken ct)
    {
        var (Id, Role, AccountStatus, TokenVersion) = await conn.QuerySingleOrDefaultAsync<(string Id, string Role, string AccountStatus, long TokenVersion)>(
            """
            SELECT id AS Id, role AS Role, account_status AS AccountStatus, token_version AS TokenVersion
            FROM users
            WHERE lower(email) = lower(@email) AND tenant_id = @tenantId
            LIMIT 1
            """,
            new { email = ctx.AssertionEmail, tenantId = ctx.TenantId });
        if (Id is null)
        {
            return null;
        }

        if (AccountStatus is "locked" or "disabled")
        {
            return await RejectInactiveAccountAsync(Id, AccountStatus, ctx, ct);
        }

        // Guard: refuse to auto-link when the matched account is privileged beyond the IdP ceiling.
        // This mirrors the JIT ceiling in ProvisionJitUserAsync: owner is never linkable, admin only
        // when idp_can_assign_admin is set. On refusal, no external_identities row is created and a
        // login failure is audited so the caller returns 401. The block does not fall through to JIT
        // (that would create a duplicate user for the same email).
        if (ExceedsIdpRoleCeiling(ctx, Role))
        {
            await _audit.LogAsync("auth.saml.login.failure",
                orgId: ctx.TenantId, actorId: Id,
                detail: System.Text.Json.JsonSerializer.Serialize(new
                {
                    reason = "email_link_privileged_account_blocked",
                    existing_role = Role,
                    ceiling = IdpRoleCeiling(ctx),
                    idp_can_assign_admin = ctx.IdpCanAssignAdmin,
                    idp_entity_id = ctx.IdpEntityId,
                    nameid = ctx.NameId,
                }),
                sourceIp: ctx.SourceIp, ct: ct);
            await EmitSamlFailureAsync(ctx.TenantId, Id,
                "email_link_privileged_account_blocked", ctx.IdpEntityId, ctx.NameId, ct);
            return new SamlLoginResult(null, "SSO auto-link is not permitted for this account.", null, null, false, false);
        }

        await _externalIdentities.LinkAsync(ctx.TenantId, Id, ctx.IdpEntityId, ctx.NameId, ctx.AssertionEmail, ct);
        await StampUserLoginAsync(conn, Id, ctx.AssertionEmail, currentEmail: ctx.AssertionEmail);

        await _audit.LogAsync("auth.saml.user_linked",
            orgId: ctx.TenantId, actorId: Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new { idp_entity_id = ctx.IdpEntityId, nameid = ctx.NameId, email = ctx.AssertionEmail }),
            sourceIp: ctx.SourceIp, ct: ct);
        await LogSamlSuccessAsync(ctx.TenantId, Id, ctx.IdpEntityId, ctx.NameId, "email_link", ctx.SourceIp, ct);

        string finalRole = await ResyncRoleAsync(ctx, Id, Role, logRefusal: false, ct);

        return new SamlLoginResult(IssueJwt(Id, ctx.TenantId, finalRole, await JwtSecretAsync(ct), TokenVersion),
            null, Id, finalRole, false, true);
    }

    // Branch 3: first-time JIT user. Default role is 'member'. password_hash is empty (BCrypt
    // verify naturally rejects '' so this user can't accidentally use forms login).
    private async Task<SamlLoginResult> ProvisionJitUserAsync(
        System.Data.Common.DbConnection conn, SamlLoginContext ctx, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ctx.AssertionEmail))
        {
            await _audit.LogAsync("auth.saml.login.failure",
                orgId: ctx.TenantId,
                detail: System.Text.Json.JsonSerializer.Serialize(new { reason = "no_email_in_assertion", idp_entity_id = ctx.IdpEntityId, nameid = ctx.NameId }),
                sourceIp: ctx.SourceIp, ct: ct);
            await EmitSamlFailureAsync(ctx.TenantId, null, "no_email_in_assertion", ctx.IdpEntityId, ctx.NameId, ct);
            return new SamlLoginResult(null, "Assertion did not include an email and no existing user matches.", null, null, false, false);
        }

        // Apply the IdP role ceiling before the role is persisted: 'owner' is never
        // IdP-assignable, 'admin' only with the per-tenant opt-in.
        string requestedRole = ctx.MappedRole ?? "member";
        bool roleCapped = ExceedsIdpRoleCeiling(ctx, requestedRole);
        string jitRole = roleCapped ? IdpRoleCeiling(ctx) : requestedRole;
        string newUserId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role, account_type)
            VALUES (@id, @tenantId, @email, '', @role, 'saml')
            """,
            new { id = newUserId, tenantId = ctx.TenantId, email = ctx.AssertionEmail, role = jitRole });
        await _externalIdentities.LinkAsync(ctx.TenantId, newUserId, ctx.IdpEntityId, ctx.NameId, ctx.AssertionEmail, ct);
        await StampUserLoginAsync(conn, newUserId, ctx.AssertionEmail, currentEmail: ctx.AssertionEmail);

        if (roleCapped)
        {
            await AuditRoleMappingBlockedAsync(ctx, newUserId, requestedRole, jitRole, ct);
        }

        await _audit.LogAsync("auth.saml.user_provisioned",
            orgId: ctx.TenantId, actorId: newUserId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { idp_entity_id = ctx.IdpEntityId, nameid = ctx.NameId, email = ctx.AssertionEmail, role = jitRole }),
            sourceIp: ctx.SourceIp, ct: ct);

        if (ctx.MappedRole is not null)
        {
            await _audit.LogAsync("auth.saml.role_assigned", orgId: ctx.TenantId, actorId: newUserId,
                detail: System.Text.Json.JsonSerializer.Serialize(new { role = jitRole, idp_entity_id = ctx.IdpEntityId }),
                sourceIp: ctx.SourceIp, ct: ct);
        }

        await LogSamlSuccessAsync(ctx.TenantId, newUserId, ctx.IdpEntityId, ctx.NameId, "jit_provisioned", ctx.SourceIp, ct);

        // Freshly inserted users start at token_version 1 (schema default).
        return new SamlLoginResult(IssueJwt(newUserId, ctx.TenantId, jitRole, await JwtSecretAsync(ct), tokenVersion: 1),
            null, newUserId, jitRole, true, false);
    }

    // Re-syncs the user's role to the IdP-mapped role, with two guards: the IdP role ceiling
    // (an over-ceiling mapping never changes the role — a tenant-admin demotion must not be
    // silently re-promoted by the IdP) and last-owner protection (never demote the last owner).
    // Returns the role in effect after the attempt. When logRefusal is set, a blocked demotion
    // is audited as auth.saml.role_change_refused; over-ceiling attempts are always audited as
    // auth.saml.role_mapping_blocked.
    private async Task<string> ResyncRoleAsync(
        SamlLoginContext ctx, string userId, string currentRole, bool logRefusal, CancellationToken ct)
    {
        if (ctx.MappedRole is null || ctx.MappedRole == currentRole)
        {
            return currentRole;
        }

        if (ExceedsIdpRoleCeiling(ctx, ctx.MappedRole))
        {
            await AuditRoleMappingBlockedAsync(ctx, userId, ctx.MappedRole, currentRole, ct);
            return currentRole;
        }

        bool canResync = !(currentRole == "owner" && await _orgs.CountOwnersAsync(ctx.TenantId, ct) <= 1);
        if (canResync)
        {
            await _orgs.UpdateMemberRoleAsync(ctx.TenantId, userId, ctx.MappedRole, ct);
            await _audit.LogAsync("auth.saml.role_changed", orgId: ctx.TenantId, actorId: userId,
                detail: System.Text.Json.JsonSerializer.Serialize(new { old_role = currentRole, new_role = ctx.MappedRole, idp_entity_id = ctx.IdpEntityId }),
                sourceIp: ctx.SourceIp, ct: ct);
            return ctx.MappedRole;
        }

        if (logRefusal)
        {
            await _audit.LogAsync("auth.saml.role_change_refused", orgId: ctx.TenantId, actorId: userId,
                detail: System.Text.Json.JsonSerializer.Serialize(new { reason = "last_owner_protection", attempted_role = ctx.MappedRole }),
                sourceIp: ctx.SourceIp, ct: ct);
        }

        return currentRole;
    }

    private async Task<string> JwtSecretAsync(CancellationToken ct) =>
        await _orgs.GetInstanceSettingAsync("jwt_secret", ct)
        ?? throw new InvalidOperationException("JWT secret not found in instance_settings.");

    /// <summary>
    /// Updates <c>users.last_login_at</c> and refreshes <c>users.email</c> if the IdP has
    /// rotated it (we keep the local email in sync with the latest assertion so listings,
    /// audit, and invites surface the current address).
    /// </summary>
    private async Task StampUserLoginAsync(
        System.Data.Common.DbConnection conn, string userId, string? assertionEmail, string? currentEmail)
    {
        string nowStr = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        bool emailChanged = !string.IsNullOrWhiteSpace(assertionEmail)
            && !string.Equals(assertionEmail, currentEmail, StringComparison.OrdinalIgnoreCase);
        if (emailChanged)
        {
            await conn.ExecuteAsync(
                "UPDATE users SET last_login_at = @now, email = @email WHERE id = @id",
                new { id = userId, now = nowStr, email = assertionEmail });
        }
        else
        {
            await conn.ExecuteAsync(
                "UPDATE users SET last_login_at = @now WHERE id = @id",
                new { id = userId, now = nowStr });
        }
    }

    private async Task LogSamlSuccessAsync(
        string tenantId, string userId, string idpEntityId, string nameId, string path, string? sourceIp, CancellationToken ct)
    {
        await _audit.LogAsync("auth.saml.login.success",
            orgId: tenantId, actorId: userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { idp_entity_id = idpEntityId, nameid = nameId, path }),
            sourceIp: sourceIp, ct: ct);
        await _audit.LogActivityAsync(tenantId, "auth", purl: null, "login.success", actorId: userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { method = "saml" }),
            sourceIp: sourceIp, ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.AuthEvents.TypeSamlSuccess,
            tenantId, "user", userId, "accepted",
            new Dependably.Infrastructure.Audit.Events.AuthEvents.SamlSuccess(idpEntityId, nameId, path).ToJson(), ct);
    }

    // Writes the audit event and emitter call for a locked/disabled account, then returns the
    // inactive-account result. The audit action string and the "account_status_<status>" failure
    // code are part of the observable security event schema — they must not be changed.
    private async Task<SamlLoginResult> RejectInactiveAccountAsync(
        string userId, string accountStatus, SamlLoginContext ctx, CancellationToken ct)
    {
        await _audit.LogAsync("auth.saml.login.failure",
            orgId: ctx.TenantId, actorId: userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { reason = "account_status", account_status = accountStatus }),
            sourceIp: ctx.SourceIp, ct: ct);
        await EmitSamlFailureAsync(ctx.TenantId, userId, "account_status_" + accountStatus, ctx.IdpEntityId, ctx.NameId, ct);
        return new SamlLoginResult(null, "Account is not active.", null, null, false, false);
    }

    private Task EmitSamlFailureAsync(
        string tenantId, string? actorId, string reason, string? idpEntityId, string? nameId, CancellationToken ct) =>
        _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.AuthEvents.TypeSamlFailure,
            tenantId, actorId is null ? "system" : "user", actorId, "rejected",
            new Dependably.Infrastructure.Audit.Events.AuthEvents.SamlFailure(reason, idpEntityId, nameId).ToJson(), ct);

    /// <summary>Test-mode SAML run: writes audit record but does not provision a user or issue a JWT.</summary>
    public async Task RecordSamlTestAsync(
        string tenantId, string idpEntityId, string nameId, string? email, string? actorId, CancellationToken ct = default)
    {
        await _audit.LogAsync("auth.saml.test.success",
            orgId: tenantId, actorId: actorId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { idp_entity_id = idpEntityId, nameid = nameId, email }),
            ct: ct);
    }

    /// <summary>Issues a tenant JWT for a user that has already been authenticated by SAML.</summary>
    public string IssueTenantJwtForUser(string userId, string tenantId, string role, string secret, long tokenVersion = 1) =>
        IssueJwt(userId, tenantId, role, secret, tokenVersion);

    /// <summary>
    /// Mints a fresh tenant session JWT for an already-authenticated user, resolving the
    /// signing secret internally. Used to re-issue the caller's own session cookie after a
    /// password change bumps <c>users.token_version</c> and stales every outstanding JWT.
    /// </summary>
    public async Task<string> IssueTenantSessionAsync(
        string userId, string tenantId, string role, long tokenVersion, CancellationToken ct = default) =>
        IssueTenantJwt(userId, tenantId, role, await JwtSecretAsync(ct), tokenVersion, _time);

    private string IssueJwt(string userId, string tenantId, string role, string secret, long tokenVersion) =>
        IssueTenantJwt(userId, tenantId, role, secret, tokenVersion, _time);

    // Identifies the login attempt that failed: the realm-scoped lockout key, the audit email
    // hash, the realm, and (for tenant failures) the org the failure is pinned to.
    private readonly record struct LoginFailureTarget(
        string LockoutKey, string EmailHash, string Realm, string? OrgIdForActivity);

    private async Task RecordFailureAsync(
        LoginFailureTarget target, int currentFailedCount, string? sourceIp, string reason, CancellationToken ct)
    {
        var (lockoutKey, emailHash, realm, orgIdForActivity) = target;
        int newCount = currentFailedCount + 1;
        DateTimeOffset? lockExpiry = newCount >= MaxFailedAttempts
            ? _time.GetUtcNow().AddMinutes(LockoutMinutes)
            : null;
        // lockoutKey is realm+tenant scoped; emailHash is the unsalted audit pseudonym.
        await _lockout.RecordFailureAsync(lockoutKey, newCount, lockExpiry, ct);
        string failureDetail = System.Text.Json.JsonSerializer.Serialize(new { reason, realm });
        // Scope the audit row to the realm that rejected the login: a system/master failure is
        // visible only on the operator audit list (scope='system'); a tenant failure is pinned to
        // that one tenant's audit list (scope='tenant', org_id=<tenant>) so no other tenant — nor
        // the system realm — can see it.
        if (realm == "system" || orgIdForActivity is null)
        {
            await _audit.LogSystemAsync("login.failure",
                detail: failureDetail, sourceIp: sourceIp, ct: ct);
        }
        else
        {
            await _audit.LogAsync("login.failure",
                orgId: orgIdForActivity,
                detail: failureDetail, sourceIp: sourceIp, ct: ct);
        }
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLoginFailure,
            orgIdForActivity, "system", null, "rejected",
            new Dependably.Infrastructure.Audit.Events.AuthEvents.LoginFailure(realm, emailHash).ToJson(), ct);

        if (orgIdForActivity is not null)
        {
            await _audit.LogActivityAsync(orgIdForActivity, "auth", purl: null, "login.failure",
                sourceIp: sourceIp, ct: ct);
        }
    }

    internal static string IssueTenantJwt(string userId, string tenantId, string role, string secret, long tokenVersion = 1, TimeProvider? time = null)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = (time ?? TimeProvider.System).GetUtcNow().UtcDateTime;

        // Tenant-scoped JWT. `org_id` carries the same value as `tid` for compatibility with
        // controllers that read the legacy claim name directly. `tver` snapshots
        // users.token_version at issuance; JwtBearer OnTokenValidated rejects the session when
        // the stored version has moved on (password change).
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("org_id", tenantId ?? ""),
            new("tid", tenantId ?? ""),
            new("role", role ?? "member"),
            new("scope", "tenant"),
            new("tver", tokenVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };

        var token = new JwtSecurityToken(
            claims: claims,
            notBefore: now,
            expires: now.AddHours(8),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    internal static string IssueSystemJwt(string systemAdminId, string secret, TimeProvider? time = null, long tokenVersion = 1)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = (time ?? TimeProvider.System).GetUtcNow().UtcDateTime;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, systemAdminId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("role", "system_admin"),
            new("scope", "system"),
            new("tver", tokenVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };

        var token = new JwtSecurityToken(
            claims: claims,
            notBefore: now,
            expires: now.AddHours(8),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Computes the unsalted SHA-256 audit pseudonym for an email address. This value appears
    /// in audit and login-failure rows so cross-realm correlations are possible without
    /// storing the plaintext email. It is intentionally NOT the lockout key — see HashLockoutKey.
    /// </summary>
    public static string HashEmail(string email)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(email.ToLowerInvariant()));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Derives a lockout-store key that is unique per (realm, tenantId, email) identity.
    /// The canonical form uses a length-prefixed tenantId segment so that the construction
    /// is unambiguous regardless of what characters the tenantId contains:
    /// <c>"tenant|{len}|{tenantId}|{email}"</c> for tenant logins and
    /// <c>"system|0||{email}"</c> for system-admin logins. The tenantId length prefix makes
    /// different (tenantId, email) pairs that share the same bytes after naive concatenation
    /// hash to distinct values.
    /// This value is stored as the opaque PK in login_attempts; it is never used in audit
    /// payloads (use <see cref="HashEmail"/> for that so audit rows stay realm-joinable).
    /// </summary>
    public static string HashLockoutKey(string realm, string? tenantId, string email)
    {
        string tid = tenantId ?? "";
        // Length-prefix the tenantId so the boundary between tenantId and email is always
        // unambiguous: "tenant|1|a|b|c@x" (tenantId="a") differs from "tenant|3|a|b|c@x"
        // (tenantId="a|b") even though the suffixes share bytes.
        string canonical = $"{realm}|{tid.Length}|{tid}|{email.ToLowerInvariant()}";
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>
/// Policy options for <see cref="LoginService.LoginSamlAsync"/>: the IdP-assigned role, the
/// admin-assignment opt-in flag, and the caller's source IP for audit logging.
/// Grouped to keep the method within a sane parameter count.
/// </summary>
public readonly record struct SamlLoginOptions(
    string? MappedRole = null,
    bool IdpCanAssignAdmin = false,
    string? SourceIp = null);
