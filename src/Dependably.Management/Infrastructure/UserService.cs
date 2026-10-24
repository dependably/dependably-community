using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-user lifecycle operations used by <see cref="Dependably.Api.AuthController"/>: create
/// from invite, password change, language preference, "me" projection. The controller calls
/// these methods directly so its actions stay HTTP-shape and the SQL surface lives here,
/// matching <see cref="LoginService"/>'s role for the authentication path.
/// </summary>
public sealed class UserService
{
    private readonly IMetadataStore _db;
    private readonly OrgRepository _orgs;
    private readonly UserTokenVersionStore? _tokenVersions;
    private readonly TrustedDeviceService? _trustedDevices;
    private readonly IRequireMfaMode? _requireMfa;

    public UserService(
        IMetadataStore db,
        OrgRepository orgs,
        UserTokenVersionStore? tokenVersions = null,
        TrustedDeviceService? trustedDevices = null,
        IRequireMfaMode? requireMfa = null)
    {
        _db = db;
        _orgs = orgs;
        _tokenVersions = tokenVersions;
        _trustedDevices = trustedDevices;
        _requireMfa = requireMfa;
    }

    /// <summary>
    /// Redeems an invite: consumes it and creates the tenant user it grants in one transaction
    /// (<see cref="InviteRepository.RedeemAsync{TResult}"/>), so a suspension cannot land between
    /// the two and leave an account the revoke never saw. Returns null when the invite is unknown,
    /// expired, or already accepted; throws <see cref="Dependably.Storage.TenantNotReadyException"/>
    /// when the tenant is locked out, with the invite left pending. The password is hashed before
    /// the transaction opens, so the BCrypt work never holds the write lock.
    ///
    /// <para>A null <see cref="InviteAcceptance.UserId"/> means the tenant already holds an
    /// account for that address: the invite is still spent, and the answer is "sign in", not a
    /// second account resolving to the same login.</para>
    /// </summary>
    public static async Task<InviteAcceptance?> AcceptInviteAsync(
        InviteRepository invites, string rawToken, string password, CancellationToken ct = default)
    {
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        var redeemed = await invites.RedeemAsync(
            rawToken, (invite, conn, tx) => InsertFromInviteAsync(conn, tx, invite, passwordHash, ct), ct);
        return redeemed is null ? null : new InviteAcceptance(redeemed.Credential, redeemed.Result);
    }

    /// <summary>
    /// Creates a tenant user from an invite the caller has already consumed. Returns null when the
    /// tenant already holds an account for that address. It neither consumes the invite nor runs
    /// the tenant-status gate, so it is internal: it exists for tests of the insert's address
    /// canonicalization, and every production redemption goes through
    /// <see cref="AcceptInviteAsync"/>, which does both in the same transaction.
    /// </summary>
    internal async Task<string?> CreateFromInviteAsync(InviteRecord invite, string password, CancellationToken ct = default)
    {
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        string? userId = await InsertFromInviteAsync(conn, tx, invite, passwordHash, ct);
        await tx.CommitAsync(ct);
        return userId;
    }

    // The address is stored canonically, so an invite addressed to a different casing of an
    // existing member's email resolves to the same account rather than minting a second one: two
    // rows satisfying every lower(email) lookup is what lets an invite silently take over the
    // login of an address that already belongs to someone. UNIQUE (tenant_id, email) is the
    // arbiter, not a prior SELECT, because an invite can be accepted concurrently with any other
    // account creation; DO NOTHING turns the collision into zero rows instead of an error that
    // would abort the surrounding transaction on Postgres and take the invite consumption with it.
    private static async Task<string?> InsertFromInviteAsync(
        DbConnection conn, DbTransaction tx, InviteRecord invite, string passwordHash, CancellationToken ct)
    {
        string userId = Guid.NewGuid().ToString("N");
        int inserted = await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role)
            VALUES (@id, @tenantId, @email, @hash, @role)
            ON CONFLICT DO NOTHING
            """,
            new
            {
                id = userId,
                tenantId = invite.OrgId,
                email = EmailNormalizer.Normalize(invite.Email),
                hash = passwordHash,
                role = invite.Role ?? "member",
            },
            transaction: tx, cancellationToken: ct));
        return inserted == 0 ? null : userId;
    }

    /// <summary>
    /// Changes the user's password and cuts off every credential minted under the old one:
    /// bumps <c>users.token_version</c> (staling all outstanding session JWTs, which snapshot
    /// the version as the <c>tver</c> claim) and revokes the user's API tokens
    /// (<c>user_tokens</c> rows are deleted). The caller re-issues the changing session's own
    /// cookie from <see cref="PasswordChangeResult.NewTokenVersion"/>.
    /// </summary>
    public async Task<PasswordChangeResult> ChangePasswordAsync(
        string userId, string currentPassword, string newPassword, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by users PK; userId is the authenticated session's own subject claim.
        string? hash = await conn.ExecuteScalarAsync<string?>(
            "SELECT password_hash FROM users WHERE id = @id",
            new { id = userId });
        if (hash is null)
        {
            return new PasswordChangeResult(PasswordChangeOutcome.UserNotFound);
        }

        if (!BCrypt.Net.BCrypt.Verify(currentPassword, hash))
        {
            return new PasswordChangeResult(PasswordChangeOutcome.CurrentPasswordIncorrect);
        }
        // Reject reusing the same password — users hitting forced rotation must actually rotate.
        if (BCrypt.Net.BCrypt.Verify(newPassword, hash))
        {
            return new PasswordChangeResult(PasswordChangeOutcome.NewPasswordSameAsOld);
        }

        string newHash = BCrypt.Net.BCrypt.HashPassword(newPassword, workFactor: 12);
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();

        // The password write, session cut-off, token revocation, and device drop commit together:
        // a fault between them must not leave a remembered device that skips the second factor
        // under the new password.
        await using var tx = await conn.BeginTransactionAsync(ct);
        // xtenant: self-service credential change keyed by the session subject's users PK.
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE users SET password_hash = @hash, must_change_password = 0, token_version = token_version + 1, security_stamp = @stamp WHERE id = @id",
            new { hash = newHash, stamp, id = userId }, transaction: tx, cancellationToken: ct));
        // xtenant: reads back the same session-subject users PK just written.
        long newVersion = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        // Revoke (delete) the user's API tokens — a rotated credential must cut off
        // everything minted under the old one. user_id is FK-bound to users.id, which is
        // already tenant-scoped.
        // xtenant: user_tokens.user_id is FK-bound to the session subject's users row.
        int revokedApiTokens = await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        // Revoke trusted-device records so remembered devices no longer bypass TOTP after
        // a password change. Optional dependency keeps existing test constructors working.
        if (_trustedDevices is not null)
        {
            await TrustedDeviceService.DeleteAllForUserAsync(conn, tx, userId, "tenant", ct);
        }

        // Any outstanding self-serve reset link is voided by any credential change — a password
        // change through one channel must never leave a still-valid reset link outstanding on
        // another.
        // xtenant: keyed by users PK; userId is the authenticated session's own subject claim.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM password_reset_tokens WHERE user_id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        await tx.CommitAsync(ct);

        // After the commit, so a cache fill cannot re-read the pre-change version.
        _tokenVersions?.Invalidate(userId);
        return new PasswordChangeResult(PasswordChangeOutcome.Success, newVersion, revokedApiTokens);
    }

    /// <summary>
    /// Verifies a user's current password without changing anything — the reauthentication gate in
    /// front of an identity-altering self-service action. Returns false for an unknown user, so a
    /// caller cannot distinguish "no such account" from "wrong password".
    /// </summary>
    public async Task<bool> VerifyCurrentPasswordAsync(
        string userId, string currentPassword, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by users PK; userId is the authenticated session's own subject claim.
        string? hash = await conn.ExecuteScalarAsync<string?>(
            "SELECT password_hash FROM users WHERE id = @id", new { id = userId });
        return hash is not null && BCrypt.Net.BCrypt.Verify(currentPassword, hash);
    }

    /// <summary>
    /// Redeems an email-change link (GDPR Art. 16 rectification): consumes it and applies the
    /// change in one transaction (<see cref="EmailChangeTokenRepository.RedeemAsync{TResult}"/>),
    /// so a suspension cannot land between the two and leave a moved address the revoke never saw.
    /// Returns null when the link is unknown, expired, or already used; throws
    /// <see cref="Dependably.Storage.TenantNotReadyException"/> when the tenant is locked out, with
    /// the link left pending. A null <see cref="EmailChangeConfirmation.NewTokenVersion"/> means
    /// the new address is already taken inside the tenant.
    ///
    /// <para>
    /// The change cuts off every session and token minted under the old address, because email is
    /// the account's login identifier and the delivery address for password resets and security
    /// notices: it is a credential-class event, so anything holding a session issued to the old
    /// identity must re-authenticate, exactly as it must after a password change.
    /// </para>
    ///
    /// <para>
    /// The address is checked when the change is requested, but hours can pass before the link is
    /// redeemed and another member may claim it meanwhile, so the UPDATE carries the collision
    /// check itself; a collision spends the link and changes nothing else. A concurrent claim that
    /// commits between that check and the write still trips <c>UNIQUE (tenant_id, email)</c>,
    /// which rolls the whole redemption back (the link stays redeemable) and reads as the same
    /// conflict.
    /// </para>
    /// </summary>
    public async Task<EmailChangeConfirmation?> ConfirmEmailChangeAsync(
        EmailChangeTokenRepository changeTokens, string rawToken, CancellationToken ct = default)
    {
        CredentialRedemption<EmailChangeTokenRecord, long?>? redeemed;
        try
        {
            redeemed = await changeTokens.RedeemAsync(
                rawToken, (consumed, conn, tx) => ApplyEmailChangeAsync(conn, tx, consumed, ct), ct);
        }
        catch (Exception ex) when (IsUniqueViolation(ex))
        {
            return new EmailChangeConfirmation(null, null);
        }

        if (redeemed is null)
        {
            return null;
        }

        if (redeemed.Result is not null)
        {
            _tokenVersions?.Invalidate(redeemed.Credential.UserId);
        }

        return new EmailChangeConfirmation(redeemed.Credential, redeemed.Result);
    }

    private async Task<long?> ApplyEmailChangeAsync(
        DbConnection conn, DbTransaction tx, EmailChangeTokenRecord consumed, CancellationToken ct)
    {
        string normalized = EmailNormalizer.Normalize(consumed.NewEmail);
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent; token_version remains the canonical per-request invalidation signal.
        string stamp = Guid.NewGuid().ToString();
        string userId = consumed.UserId;

        // The collision predicate compares against the same tenant's rows only, so the address
        // stays free to exist in another tenant.
        // xtenant: keyed by the users PK the change token was minted for; the subquery is
        // correlated to that row's own tenant_id.
        int updated = await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE users
            SET email = @email, token_version = token_version + 1, security_stamp = @stamp
            WHERE id = @id
              AND NOT EXISTS (
                  SELECT 1 FROM users other
                  WHERE other.tenant_id = users.tenant_id AND other.email = @email AND other.id <> @id)
            """,
            new { email = normalized, stamp, id = userId }, transaction: tx, cancellationToken: ct));
        if (updated == 0)
        {
            // Someone claimed the address between the request and the redemption.
            return null;
        }

        // xtenant: reads back the same users PK just written.
        long newVersion = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        // xtenant: user_tokens.user_id is FK-bound to the users row above.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        if (_trustedDevices is not null)
        {
            await TrustedDeviceService.DeleteAllForUserAsync(conn, tx, userId, "tenant", ct);
        }

        // Any reset link outstanding against the OLD address must die with it — otherwise a link
        // mailed to the previous mailbox still resets the account that mailbox no longer owns.
        // xtenant: keyed by the same users PK.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM password_reset_tokens WHERE user_id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        return newVersion;
    }

    // Both providers surface a UNIQUE violation as a provider-specific exception; matching on the
    // message keeps this free of a provider reference in a shared service.
    private static bool IsUniqueViolation(Exception ex) =>
        ex.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("duplicate key", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Completes a self-serve "forgot password" reset: consumes the link and sets the new
    /// credential in one transaction (<see cref="PasswordResetTokenRepository.RedeemAsync{TResult}"/>),
    /// so a suspension cannot land between the two and leave a password the revoke never saw.
    /// Returns the consumed link, or null when it is unknown, expired, or already used; throws
    /// <see cref="Dependably.Storage.TenantNotReadyException"/> when the tenant is locked out, with
    /// the link left pending. The password is hashed before the transaction opens.
    ///
    /// <para>
    /// The write cuts off every session and token minted under the old credential, exactly like
    /// <see cref="ChangePasswordAsync"/> but without a current-password check, since the one-shot
    /// link is what authenticated the request. It also voids every other outstanding reset link
    /// for the user (a stale second link must not be replayed after the credential has moved on)
    /// and clears <c>must_change_password</c> so the freshly reset account is not immediately
    /// forced to rotate again.
    /// </para>
    /// </summary>
    public async Task<PasswordResetTokenRecord?> ResetPasswordWithLinkAsync(
        PasswordResetTokenRepository resetTokens, string rawToken, string newPassword, CancellationToken ct = default)
    {
        string newHash = BCrypt.Net.BCrypt.HashPassword(newPassword, workFactor: 12);
        var redeemed = await resetTokens.RedeemAsync(
            rawToken, (consumed, conn, tx) => ApplyRecoveredPasswordAsync(conn, tx, consumed.UserId, newHash, ct), ct);
        if (redeemed is null)
        {
            return null;
        }

        _tokenVersions?.Invalidate(redeemed.Credential.UserId);
        return redeemed.Credential;
    }

    private async Task<long> ApplyRecoveredPasswordAsync(
        DbConnection conn, DbTransaction tx, string userId, string newHash, CancellationToken ct)
    {
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();

        // xtenant: keyed by the users PK the reset token was minted for.
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE users SET password_hash = @hash, must_change_password = 0, token_version = token_version + 1, security_stamp = @stamp WHERE id = @id",
            new { hash = newHash, stamp, id = userId }, transaction: tx, cancellationToken: ct));
        // xtenant: reads back the same users PK just written.
        long newVersion = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        // Revoke (delete) the user's API tokens — a rotated credential must cut off everything
        // minted under the old one. user_id is FK-bound to users.id, which is already tenant-scoped.
        // xtenant: user_tokens.user_id is FK-bound to the reset token's users row.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        if (_trustedDevices is not null)
        {
            await TrustedDeviceService.DeleteAllForUserAsync(conn, tx, userId, "tenant", ct);
        }

        // Void every outstanding reset link for the user (including the one just consumed, and
        // any stale link requested earlier) — replay defense.
        // xtenant: keyed by the users PK the reset token was minted for.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM password_reset_tokens WHERE user_id = @id", new { id = userId }, transaction: tx, cancellationToken: ct));

        return newVersion;
    }

    /// <summary>
    /// Lean check used by the request pipeline to force temp-password rotation: true when the
    /// user must change their password before continuing. Missing row → false.
    /// </summary>
    public async Task<bool> IsPasswordChangeRequiredAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by users PK from the request principal's subject claim.
        long? flag = await conn.ExecuteScalarAsync<long?>(
            "SELECT must_change_password FROM users WHERE id = @id", new { id = userId });
        return flag == 1;
    }

    /// <summary>
    /// Lean check used by <see cref="Dependably.Security.MfaEnrollmentGuard"/>: true when
    /// the user has completed MFA enrollment. Read live from the database (not from the JWT
    /// claim) so enrollment takes effect immediately. Missing row → false.
    /// </summary>
    public async Task<bool> IsMfaEnabledAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by users PK from the request principal's subject claim.
        long? flag = await conn.ExecuteScalarAsync<long?>(
            "SELECT mfa_enabled FROM users WHERE id = @id", new { id = userId });
        return flag == 1;
    }

    /// <summary>
    /// Resolves the authenticated user's own email so a self-service password change can
    /// feed it into <see cref="Dependably.Security.PasswordPolicy"/>'s context-dictionary
    /// check. Missing row → null (caller evaluates the policy with no email context).
    /// </summary>
    public async Task<string?> GetEmailAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by users PK from the request principal's subject claim.
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT email FROM users WHERE id = @id", new { id = userId });
    }

    /// <summary>
    /// Resolves a tenant user's id by (tenantId, email), case-insensitively — the lookup
    /// <c>AuthController.ForgotPassword</c> uses to decide whether to issue a reset token,
    /// without ever surfacing the distinction to the caller (a miss and a hit both continue
    /// through the same 202 response). Missing row → null.
    /// </summary>
    public async Task<string?> FindIdByEmailAsync(string tenantId, string email, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Same deterministic election as the login lookup, and deliberately the same order: a
        // legacy database can still hold two case-variant rows for one address, and a reset link
        // must bind to the account that address actually logs in as.
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT id FROM users
            WHERE tenant_id = @tenantId AND lower(email) = lower(@email)
            ORDER BY created_at, id
            LIMIT 1
            """,
            new { tenantId, email });
    }

    /// <summary>
    /// "Me" projection: per-user must_change_password + language/timezone overrides + the
    /// tenant's defaults for both. Returns null when the user row doesn't exist.
    /// </summary>
    public async Task<UserContext?> GetUserContextAsync(string userId, string? orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: "me" projection keyed by the session subject's own users PK.
        var row = await conn.QuerySingleOrDefaultAsync<UserRow>(
            """
            SELECT must_change_password AS MustChangePassword, language AS Language,
                   timezone AS Timezone, mfa_enabled AS MfaEnabled
            FROM users WHERE id = @id
            """,
            new { id = userId });
        if (row is null)
        {
            return null;
        }

        OrgSettings? orgSettings = null;
        if (orgId is not null)
        {
            orgSettings = await _orgs.GetSettingsAsync(orgId, ct);
        }

        bool mfaEnabled = row.MfaEnabled == 1;
        bool requireMfa = (_requireMfa?.IsEnabled ?? false) || (orgSettings?.RequireMfa ?? false);

        return new UserContext(
            MustChangePassword: row.MustChangePassword == 1,
            Language: string.IsNullOrEmpty(row.Language) ? null : row.Language,
            TenantDefaultLanguage: orgSettings?.DefaultLanguage,
            Timezone: string.IsNullOrEmpty(row.Timezone) ? null : row.Timezone,
            TenantDefaultTimezone: orgSettings?.DefaultTimezone,
            MfaEnabled: mfaEnabled,
            MfaEnrollmentRequired: requireMfa && !mfaEnabled);
    }

    public async Task UpdateLanguageAsync(string userId, string language, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: self-service preference write keyed by the session subject's users PK.
        await conn.ExecuteAsync(
            "UPDATE users SET language = @lang WHERE id = @id",
            new { lang = language, id = userId });
    }

    /// <summary>
    /// Sets the user's display-timezone override. A null <paramref name="timezone"/> clears it,
    /// which is how "use the organization default" is expressed — storing the matching zone by
    /// name instead would pin the user and silently ignore a later change to that default.
    /// </summary>
    public async Task UpdateTimezoneAsync(string userId, string? timezone, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: self-service preference write keyed by the session subject's users PK.
        await conn.ExecuteAsync(
            "UPDATE users SET timezone = @tz WHERE id = @id",
            new { tz = timezone, id = userId });
    }

    /// <summary>
    /// Bumps <c>users.token_version</c> and revokes all API tokens for the user, then
    /// invalidates the in-process token-version cache. Returns the new version so the caller
    /// can re-issue its own session cookie. Mirrors <see cref="ChangePasswordAsync"/> but
    /// without a credential check — the caller is responsible for verifying identity before
    /// invoking this method.
    /// </summary>
    public async Task<long> BumpTokenVersionAndRevokeTokensAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Rotating the Identity security_stamp alongside token_version keeps the Identity model
        // consistent with the credential change; token_version remains the canonical per-request
        // session-invalidation signal.
        string stamp = Guid.NewGuid().ToString();
        // xtenant: session-invalidation bump keyed by the session subject's own users PK.
        await conn.ExecuteAsync(
            "UPDATE users SET token_version = token_version + 1, security_stamp = @stamp WHERE id = @id",
            new { stamp, id = userId });
        // xtenant: reads back the same session-subject users PK just written.
        long newVersion = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });

        // xtenant: user_tokens.user_id is FK-bound to the session subject's users row.
        // user_id is FK-bound to users.id, which is already tenant-scoped.
        await conn.ExecuteAsync(
            "DELETE FROM user_tokens WHERE user_id = @id", new { id = userId });

        _tokenVersions?.Invalidate(userId);
        return newVersion;
    }

    // Integer columns bind as long, and [ExplicitConstructor] is what lets one signature serve
    // both providers — SQLite reports INTEGER as Int64, Postgres as Int32, and Dapper's default
    // positional-record binding demands an exact CLR match. See
    // DapperPositionalRecordComplianceTests. Converted to bool at the call site.
    [method: ExplicitConstructor]
    private sealed record UserRow(long MustChangePassword, string? Language, string? Timezone, long MfaEnabled);
}

public enum PasswordChangeOutcome
{
    Success,
    UserNotFound,
    CurrentPasswordIncorrect,
    NewPasswordSameAsOld,
}

/// <summary>
/// Outcome of a password change. On <see cref="PasswordChangeOutcome.Success"/>,
/// <see cref="NewTokenVersion"/> carries the bumped <c>users.token_version</c> (for re-issuing
/// the caller's own session) and <see cref="RevokedApiTokens"/> the number of API tokens revoked.
/// </summary>
public sealed record PasswordChangeResult(
    PasswordChangeOutcome Outcome, long? NewTokenVersion = null, int RevokedApiTokens = 0);

public sealed record UserContext(
    bool MustChangePassword,
    string? Language,
    string? TenantDefaultLanguage,
    string? Timezone = null,
    string? TenantDefaultTimezone = null,
    bool MfaEnabled = false,
    bool MfaEnrollmentRequired = false);

/// <summary>
/// A redeemed invite. <see cref="UserId"/> is the account it created, or null when the tenant
/// already held an account for the invite's address (the invite is spent either way).
/// </summary>
public sealed record InviteAcceptance(InviteRecord Invite, string? UserId);

/// <summary>
/// A redeemed email-change link. <see cref="NewTokenVersion"/> is the account's bumped
/// <c>token_version</c>, or null when the new address was already taken in the tenant.
/// <see cref="Token"/> is the consumed link; it is null only when a concurrent claim of the
/// address rolled the whole redemption back, which leaves the link unconsumed.
/// </summary>
public sealed record EmailChangeConfirmation(EmailChangeTokenRecord? Token, long? NewTokenVersion);
