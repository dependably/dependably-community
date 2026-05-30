using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Infrastructure;

public sealed class LoginService
{
    private const int MaxFailedAttempts = 10;
    private const int LockoutMinutes = 15;

    /// <summary>
    /// Sentinel bcrypt-shaped string used to keep <c>BCrypt.Verify</c> work identical when
    /// the user record is missing — closes a timing oracle that would otherwise distinguish
    /// "unknown email" from "wrong password". Deliberately not a valid bcrypt hash, so it
    /// will never match any password. Not a credential.
    /// </summary>
    // deepcode ignore HardcodedNonCryptoSecret,NoHardcodedCredentials: sentinel for constant-time
    // verification, not a usable credential.
    private const string TimingSentinelHash = "$2a$12$invalidhashpaddingtomakebcryptrunfulltime000000000000000";

    private readonly IMetadataStore _db;
    private readonly OrgRepository _orgs;
    private readonly SystemAdminRepository _systemAdmins;
    private readonly ILockoutStore _lockout;
    private readonly AuditRepository _audit;
    private readonly ExternalIdentityRepository _externalIdentities;
    private readonly Dependably.Infrastructure.Audit.IAuditEmitter _auditEmitter;

    public LoginService(
        IMetadataStore db,
        OrgRepository orgs,
        SystemAdminRepository systemAdmins,
        ILockoutStore lockout,
        AuditRepository audit,
        ExternalIdentityRepository externalIdentities,
        Dependably.Infrastructure.Audit.IAuditEmitter auditEmitter)
    {
        _db = db;
        _orgs = orgs;
        _systemAdmins = systemAdmins;
        _lockout = lockout;
        _audit = audit;
        _externalIdentities = externalIdentities;
        _auditEmitter = auditEmitter;
    }

    /// <summary>
    /// Authenticates a tenant user. The user must be a member of <paramref name="tenantId"/> —
    /// in single mode this is the one tenant; in multi mode it's the tenant whose subdomain
    /// the request hit. Returns a tenant-scoped JWT (<c>scope=tenant</c>) on success.
    /// </summary>
    public async Task<(string? Token, string? Error, int? RetryAfterSeconds)> LoginTenantAsync(
        string email, string password, string tenantId, string? sourceIp = null, CancellationToken ct = default)
    {
        var emailHash = HashEmail(email);

        var (failedCount, lockedUntil) = await _lockout.GetAsync(emailHash, ct);
        if (lockedUntil.HasValue && DateTimeOffset.UtcNow < lockedUntil.Value)
        {
            var retryAfter = (int)(lockedUntil.Value - DateTimeOffset.UtcNow).TotalSeconds + 1;
            await _audit.LogAsync("lockout.triggered",
                detail: System.Text.Json.JsonSerializer.Serialize(new { email_hash = emailHash, realm = "tenant" }),
                sourceIp: sourceIp, ct: ct);
            await _audit.LogActivityAsync(tenantId, "auth", purl: null, "login.locked",
                sourceIp: sourceIp, ct: ct);
            await _auditEmitter.EmitAsync(
                Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLockout,
                tenantId, "system", null, "rejected",
                new Dependably.Infrastructure.Audit.Events.AuthEvents.Lockout("tenant", emailHash).ToJson(), ct);
            return (null, "Account locked due to too many failed attempts.", retryAfter);
        }

        await using var conn = await _db.OpenAsync(ct);
        var user = await conn.QuerySingleOrDefaultAsync<(string Id, string Email, string PasswordHash, string TenantId, string Role, int AccountLocked)>(
            """
            SELECT id, email, password_hash, tenant_id AS TenantId, role,
                   CASE WHEN account_status IN ('locked','disabled') THEN 1 ELSE 0 END AS AccountLocked
            FROM users
            WHERE lower(email) = lower(@email) AND tenant_id = @tenantId
            LIMIT 1
            """,
            new { email, tenantId });

        var passwordHash = user.PasswordHash ?? TimingSentinelHash;
        var valid = user.Id is not null && user.AccountLocked == 0
            && BCrypt.Net.BCrypt.Verify(password, passwordHash);

        if (!valid)
        {
            await RecordFailureAsync(emailHash, failedCount, "tenant", tenantId, sourceIp, ct);
            return (null, "Invalid credentials.", null);
        }

        await _lockout.ClearAsync(emailHash, ct);
        await _audit.LogAsync("login.success", actorId: user.Id, sourceIp: sourceIp, ct: ct);
        await _audit.LogActivityAsync(tenantId, "auth", purl: null, "login.success", actorId: user.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new { method = "forms" }),
            sourceIp: sourceIp, ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLoginSuccess,
            tenantId, "user", user.Id, "accepted",
            new Dependably.Infrastructure.Audit.Events.AuthEvents.LoginSuccess("tenant", "forms").ToJson(), ct);

        // Stamp last_login_at on the user row so the system_admin lookup endpoint can surface
        // it without a separate auth audit query.
        await conn.ExecuteAsync(
            "UPDATE users SET last_login_at = @now WHERE id = @id",
            new { id = user.Id, now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") });

        var jwtSecret = await _orgs.GetInstanceSettingAsync("jwt_secret", ct)
            ?? throw new InvalidOperationException("JWT secret not found in instance_settings.");

        var token = IssueTenantJwt(user.Id!, user.TenantId, user.Role, jwtSecret);
        return (token, null, null);
    }

    /// <summary>
    /// Authenticates a system_admin (apex login in multi mode). Issues a system-scoped JWT
    /// (<c>scope=system</c>, no <c>tid</c>). Returns null in single-mode installs because
    /// <c>system_admins</c> is empty there.
    /// </summary>
    public async Task<(string? Token, string? Error, int? RetryAfterSeconds)> LoginSystemAsync(
        string email, string password, string? sourceIp = null, CancellationToken ct = default)
    {
        var emailHash = HashEmail(email);

        var (failedCount, lockedUntil) = await _lockout.GetAsync(emailHash, ct);
        if (lockedUntil.HasValue && DateTimeOffset.UtcNow < lockedUntil.Value)
        {
            var retryAfter = (int)(lockedUntil.Value - DateTimeOffset.UtcNow).TotalSeconds + 1;
            await _audit.LogAsync("lockout.triggered",
                detail: System.Text.Json.JsonSerializer.Serialize(new { email_hash = emailHash, realm = "system" }),
                sourceIp: sourceIp, ct: ct);
            await _auditEmitter.EmitAsync(
                Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLockout,
                null, "system", null, "rejected",
                new Dependably.Infrastructure.Audit.Events.AuthEvents.Lockout("system", emailHash).ToJson(), ct);
            return (null, "Account locked due to too many failed attempts.", retryAfter);
        }

        var creds = await _systemAdmins.GetCredentialsByEmailAsync(email, ct);
        var passwordHash = creds?.PasswordHash ?? TimingSentinelHash;
        // Verify hash before checking account_status so the timing of "wrong password" and
        // "locked/disabled" responses is indistinguishable to a probe.
        var hashOk = creds is not null && BCrypt.Net.BCrypt.Verify(password, passwordHash);
        var valid = hashOk && creds!.Value.AccountStatus == "active";

        if (!valid)
        {
            await RecordFailureAsync(emailHash, failedCount, "system", orgIdForActivity: null, sourceIp, ct);
            return (null, "Invalid credentials.", null);
        }

        await _lockout.ClearAsync(emailHash, ct);
        await _audit.LogAsync("login.success", actorId: creds!.Value.Id,
            detail: System.Text.Json.JsonSerializer.Serialize(new { realm = "system" }),
            sourceIp: sourceIp, ct: ct);
        // deepcode ignore PrivateInformationExposure: payload contains only the user UUID,
        // realm name, and method name — no email. The `email` arg was reduced to emailHash
        // (SHA-256) by HashEmail before any audit/log call in this method.
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLoginSuccess,
            null, "user", creds.Value.Id, "accepted",
            new Dependably.Infrastructure.Audit.Events.AuthEvents.LoginSuccess("system", "forms").ToJson(), ct);
        await _systemAdmins.UpdateLastLoginAsync(creds.Value.Id, DateTimeOffset.UtcNow, ct);

        var jwtSecret = await _orgs.GetInstanceSettingAsync("jwt_secret", ct)
            ?? throw new InvalidOperationException("JWT secret not found in instance_settings.");

        var token = IssueSystemJwt(creds.Value.Id, jwtSecret);
        return (token, null, null);
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
        string? sourceIp = null,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // 1. Primary lookup: by external identity. This is the stable path — if the IdP
        //    rotates the user's email, we still find them here.
        var existing = await _externalIdentities.FindAsync(tenantId, idpEntityId, nameId, ct);
        if (existing is not null)
        {
            var user = await conn.QuerySingleOrDefaultAsync<(string Id, string Role, string AccountStatus, string Email)>(
                "SELECT id AS Id, role AS Role, account_status AS AccountStatus, email AS Email FROM users WHERE id = @id",
                new { id = existing.UserId });
            if (user.Id is null)
                return new SamlLoginResult(null, "Linked user not found.", null, null, false, false);
            if (user.AccountStatus is "locked" or "disabled")
            {
                await _audit.LogAsync("auth.saml.login.failure",
                    orgId: tenantId, actorId: user.Id,
                    detail: System.Text.Json.JsonSerializer.Serialize(new { reason = "account_status", account_status = user.AccountStatus }),
                    sourceIp: sourceIp, ct: ct);
                await EmitSamlFailureAsync(tenantId, user.Id, "account_status_" + user.AccountStatus, idpEntityId, nameId, ct);
                return new SamlLoginResult(null, "Account is not active.", null, null, false, false);
            }

            await _externalIdentities.UpdateLastLoginAsync(existing.Id, assertionEmail, ct);
            await StampUserLoginAsync(conn, user.Id, assertionEmail, user.Email);

            await LogSamlSuccessAsync(tenantId, user.Id, idpEntityId, nameId, "external_identity", sourceIp, ct);
            return new SamlLoginResult(IssueJwt(user.Id, tenantId, user.Role, await JwtSecretAsync(ct)),
                null, user.Id, user.Role, false, false);
        }

        // 2. No external identity yet. Try to link by email.
        if (!string.IsNullOrWhiteSpace(assertionEmail))
        {
            var existingByEmail = await conn.QuerySingleOrDefaultAsync<(string Id, string Role, string AccountStatus)>(
                """
                SELECT id AS Id, role AS Role, account_status AS AccountStatus
                FROM users
                WHERE lower(email) = lower(@email) AND tenant_id = @tenantId
                LIMIT 1
                """,
                new { email = assertionEmail, tenantId });
            if (existingByEmail.Id is not null)
            {
                if (existingByEmail.AccountStatus is "locked" or "disabled")
                {
                    await _audit.LogAsync("auth.saml.login.failure",
                        orgId: tenantId, actorId: existingByEmail.Id,
                        detail: System.Text.Json.JsonSerializer.Serialize(new { reason = "account_status", account_status = existingByEmail.AccountStatus }),
                        sourceIp: sourceIp, ct: ct);
                    await EmitSamlFailureAsync(tenantId, existingByEmail.Id,
                        "account_status_" + existingByEmail.AccountStatus, idpEntityId, nameId, ct);
                    return new SamlLoginResult(null, "Account is not active.", null, null, false, false);
                }

                await _externalIdentities.LinkAsync(tenantId, existingByEmail.Id, idpEntityId, nameId, assertionEmail, ct);
                await StampUserLoginAsync(conn, existingByEmail.Id, assertionEmail, currentEmail: assertionEmail);

                await _audit.LogAsync("auth.saml.user_linked",
                    orgId: tenantId, actorId: existingByEmail.Id,
                    detail: System.Text.Json.JsonSerializer.Serialize(new { idp_entity_id = idpEntityId, nameid = nameId, email = assertionEmail }),
                    sourceIp: sourceIp, ct: ct);
                await LogSamlSuccessAsync(tenantId, existingByEmail.Id, idpEntityId, nameId, "email_link", sourceIp, ct);

                return new SamlLoginResult(IssueJwt(existingByEmail.Id, tenantId, existingByEmail.Role, await JwtSecretAsync(ct)),
                    null, existingByEmail.Id, existingByEmail.Role, false, true);
            }
        }

        // 3. First-time JIT user. Default role is 'member'. password_hash is empty (BCrypt
        //    verify naturally rejects '' so this user can't accidentally use forms login).
        if (string.IsNullOrWhiteSpace(assertionEmail))
        {
            await _audit.LogAsync("auth.saml.login.failure",
                orgId: tenantId,
                detail: System.Text.Json.JsonSerializer.Serialize(new { reason = "no_email_in_assertion", idp_entity_id = idpEntityId, nameid = nameId }),
                sourceIp: sourceIp, ct: ct);
            await EmitSamlFailureAsync(tenantId, null, "no_email_in_assertion", idpEntityId, nameId, ct);
            return new SamlLoginResult(null, "Assertion did not include an email and no existing user matches.", null, null, false, false);
        }

        var newUserId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role, account_type)
            VALUES (@id, @tenantId, @email, '', 'member', 'saml')
            """,
            new { id = newUserId, tenantId, email = assertionEmail });
        await _externalIdentities.LinkAsync(tenantId, newUserId, idpEntityId, nameId, assertionEmail, ct);
        await StampUserLoginAsync(conn, newUserId, assertionEmail, currentEmail: assertionEmail);

        await _audit.LogAsync("auth.saml.user_provisioned",
            orgId: tenantId, actorId: newUserId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { idp_entity_id = idpEntityId, nameid = nameId, email = assertionEmail }),
            sourceIp: sourceIp, ct: ct);
        await LogSamlSuccessAsync(tenantId, newUserId, idpEntityId, nameId, "jit_provisioned", sourceIp, ct);

        return new SamlLoginResult(IssueJwt(newUserId, tenantId, "member", await JwtSecretAsync(ct)),
            null, newUserId, "member", true, false);
    }

    private async Task<string> JwtSecretAsync(CancellationToken ct) =>
        await _orgs.GetInstanceSettingAsync("jwt_secret", ct)
        ?? throw new InvalidOperationException("JWT secret not found in instance_settings.");

    /// <summary>
    /// Updates <c>users.last_login_at</c> and refreshes <c>users.email</c> if the IdP has
    /// rotated it (we keep the local email in sync with the latest assertion so listings,
    /// audit, and invites surface the current address).
    /// </summary>
    private static async Task StampUserLoginAsync(
        System.Data.Common.DbConnection conn, string userId, string? assertionEmail, string? currentEmail)
    {
        var nowStr = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var emailChanged = !string.IsNullOrWhiteSpace(assertionEmail)
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
    public string IssueTenantJwtForUser(string userId, string tenantId, string role, string secret) =>
        IssueJwt(userId, tenantId, role, secret);

    private static string IssueJwt(string userId, string tenantId, string role, string secret) =>
        IssueTenantJwt(userId, tenantId, role, secret);

    private async Task RecordFailureAsync(
        string emailHash, int currentFailedCount, string realm, string? orgIdForActivity, string? sourceIp, CancellationToken ct)
    {
        var newCount = currentFailedCount + 1;
        DateTimeOffset? lockExpiry = newCount >= MaxFailedAttempts
            ? DateTimeOffset.UtcNow.AddMinutes(LockoutMinutes)
            : null;
        await _lockout.RecordFailureAsync(emailHash, newCount, lockExpiry, ct);
        await _audit.LogAsync("login.failure",
            detail: System.Text.Json.JsonSerializer.Serialize(new { reason = "invalid_credentials", realm }),
            sourceIp: sourceIp, ct: ct);
        await _auditEmitter.EmitAsync(
            Dependably.Infrastructure.Audit.Events.AuthEvents.TypeLoginFailure,
            orgIdForActivity, "system", null, "rejected",
            new Dependably.Infrastructure.Audit.Events.AuthEvents.LoginFailure(realm, emailHash).ToJson(), ct);

        if (orgIdForActivity is not null)
            await _audit.LogActivityAsync(orgIdForActivity, "auth", purl: null, "login.failure",
                sourceIp: sourceIp, ct: ct);
    }

    internal static string IssueTenantJwt(string userId, string tenantId, string role, string secret)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = DateTime.UtcNow;

        // Tenant-scoped JWT. `org_id` carries the same value as `tid` for compatibility with
        // controllers that read the legacy claim name directly.
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("org_id", tenantId ?? ""),
            new("tid", tenantId ?? ""),
            new("role", role ?? "member"),
            new("scope", "tenant"),
        };

        var token = new JwtSecurityToken(
            claims: claims,
            notBefore: now,
            expires: now.AddHours(8),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    internal static string IssueSystemJwt(string systemAdminId, string secret)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, systemAdminId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("role", "system_admin"),
            new("scope", "system"),
        };

        var token = new JwtSecurityToken(
            claims: claims,
            notBefore: now,
            expires: now.AddHours(8),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string HashEmail(string email)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(email.ToLowerInvariant()));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
