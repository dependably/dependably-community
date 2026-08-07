using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure.Privacy;

/// <summary>
/// Aggregates a single data subject's personal data across every table classified as
/// <see cref="PersonalDataTables.Included"/> into one structured document, for the GDPR Art. 15
/// (access) / Art. 20 (portability) self-service export at <c>GET /api/v1/users/me/export</c>.
///
/// <para>
/// Every query is scoped to the subject on BOTH axes: the subject's user id (from the
/// authenticated principal, never a request parameter) AND — for tables that carry one — the
/// subject's <c>org_id</c>/<c>tenant_id</c>. That double scoping is what makes the surface
/// BOLA-safe: it can only ever return the caller's own rows, and never another tenant's.
/// </para>
///
/// <para>
/// Secret material is never selected: password/MFA secrets, token hashes, and the security stamp
/// are excluded from the projections so the export is a copy of the subject's personal data, not
/// a credential dump.
/// </para>
/// </summary>
public sealed class PersonalDataExportRepository
{
    private readonly IMetadataStore _db;

    public PersonalDataExportRepository(IMetadataStore db) => _db = db;

    /// <param name="userId">The subject's user id, resolved from the authenticated principal.</param>
    /// <param name="orgId">The subject's tenant id, resolved from the authenticated principal.</param>
    /// <param name="email">The subject's own email address (for invite-by-recipient rows).</param>
    /// <param name="loginAttemptKey">
    /// The subject's <c>login_attempts</c> primary key — the tenant-scoped lockout pseudonym
    /// computed by the caller (Management) from the subject's realm/tenant/email, since the hash
    /// helper lives in the Management assembly.
    /// </param>
    public async Task<PersonalDataExport> ExportAsync(
        string userId, string orgId, string email, string loginAttemptKey, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);

        var account = await LoadAccountDataAsync(conn, userId, orgId);
        var activityLog = await LoadActivityDataAsync(conn, userId, orgId, email);
        var lockout = await LoadLockoutDataAsync(conn, loginAttemptKey);

        return new PersonalDataExport(
            User: account.User,
            UserTokens: account.UserTokens.ToList(),
            PasswordResetTokens: account.PasswordResetTokens.ToList(),
            EmailChangeTokens: account.EmailChangeTokens.ToList(),
            ExternalIdentities: account.ExternalIdentities.ToList(),
            MfaTrustedDevices: account.TrustedDevices.ToList(),
            BannerDismissals: activityLog.BannerDismissals.ToList(),
            InvitesCreated: activityLog.InvitesCreated.ToList(),
            InvitesReceived: activityLog.InvitesReceived.ToList(),
            AuditLog: activityLog.AuditLog.ToList(),
            Activity: activityLog.Activity.ToList(),
            AuditEvents: activityLog.AuditEvents.ToList(),
            LoginAttempts: lockout.LoginAttempts,
            SendThrottles: lockout.SendThrottles.ToList());
    }

    // The subject's account/credential-adjacent rows: profile, tokens, and MFA/identity records.
    private static async Task<AccountData> LoadAccountDataAsync(
        DbConnection conn, string userId, string orgId)
    {
        var user = await conn.QuerySingleOrDefaultAsync<UserRow>(
            """
            SELECT id AS Id, tenant_id AS TenantId, email AS Email, role AS Role,
                   account_type AS AccountType, must_change_password AS MustChangePassword,
                   last_login_at AS LastLoginAt, account_status AS AccountStatus,
                   mfa_enabled AS MfaEnabled, password_reset_issued_at AS PasswordResetIssuedAt,
                   language AS Language, token_version AS TokenVersion, created_at AS CreatedAt
            FROM users
            WHERE id = @userId AND tenant_id = @orgId
            """,
            new { userId, orgId });

        var userTokens = await conn.QueryAsync<TokenRow>(
            """
            SELECT id AS Id, description AS Description, capabilities AS Capabilities,
                   created_at AS CreatedAt, expires_at AS ExpiresAt, last_used_at AS LastUsedAt
            FROM user_tokens
            WHERE user_id = @userId AND org_id = @orgId
            ORDER BY created_at
            """,
            new { userId, orgId });

        var passwordResetTokens = await conn.QueryAsync<ResetTokenRow>(
            """
            SELECT id AS Id, created_at AS CreatedAt, expires_at AS ExpiresAt, consumed_at AS ConsumedAt
            FROM password_reset_tokens
            WHERE user_id = @userId AND org_id = @orgId
            ORDER BY created_at
            """,
            new { userId, orgId });

        // The pending new address is the subject's own personal data and the most consequential
        // thing about an outstanding request — an export that omitted it would not tell them their
        // account is queued to move.
        var emailChangeTokens = await conn.QueryAsync<EmailChangeRow>(
            """
            SELECT id AS Id, new_email AS NewEmail, created_at AS CreatedAt,
                   expires_at AS ExpiresAt, consumed_at AS ConsumedAt
            FROM email_change_tokens
            WHERE user_id = @userId AND org_id = @orgId
            ORDER BY created_at
            """,
            new { userId, orgId });

        var externalIdentities = await conn.QueryAsync<ExternalIdentityRow>(
            """
            SELECT id AS Id, idp_entity_id AS IdpEntityId, nameid AS NameId,
                   email_snapshot AS EmailSnapshot, created_at AS CreatedAt, last_login_at AS LastLoginAt
            FROM external_identities
            WHERE user_id = @userId AND org_id = @orgId
            ORDER BY created_at
            """,
            new { userId, orgId });

        var trustedDevices = await conn.QueryAsync<TrustedDeviceRow>(
            """
            SELECT id AS Id, realm AS Realm, user_agent AS UserAgent, created_at AS CreatedAt,
                   last_seen_at AS LastSeenAt, expires_at AS ExpiresAt
            FROM mfa_trusted_devices
            WHERE user_id = @userId AND realm = 'tenant' AND tenant_id = @orgId
            ORDER BY created_at
            """,
            new { userId, orgId });

        return new AccountData(
            user, userTokens, passwordResetTokens, emailChangeTokens, externalIdentities, trustedDevices);
    }

    // The subject's activity/audit trail: dismissals, invites (both sent and received), and the
    // three audit-adjacent logs (audit_log, activity, audit_event) attributed to the subject.
    private static async Task<ActivityData> LoadActivityDataAsync(
        DbConnection conn, string userId, string orgId, string email)
    {
        var bannerDismissals = await conn.QueryAsync<BannerDismissalRow>(
            """
            SELECT banner_id AS BannerId, dismissed_at AS DismissedAt
            FROM banner_dismissals
            WHERE user_id = @userId
            ORDER BY dismissed_at
            """,
            new { userId });

        var invitesCreated = await conn.QueryAsync<InviteCreatedRow>(
            """
            SELECT id AS Id, email AS Email, role AS Role, created_at AS CreatedAt,
                   expires_at AS ExpiresAt, accepted_at AS AcceptedAt
            FROM invites
            WHERE org_id = @orgId AND created_by = @userId
            ORDER BY created_at
            """,
            new { userId, orgId });

        var invitesReceived = await conn.QueryAsync<InviteReceivedRow>(
            """
            SELECT id AS Id, role AS Role, created_by AS CreatedBy, created_at AS CreatedAt,
                   expires_at AS ExpiresAt, accepted_at AS AcceptedAt
            FROM invites
            WHERE org_id = @orgId AND email = @email
            ORDER BY created_at
            """,
            new { orgId, email });

        var auditLog = await conn.QueryAsync<AuditLogRow>(
            """
            SELECT id AS Id, action AS Action, ecosystem AS Ecosystem, purl AS Purl,
                   detail AS Detail, source_ip AS SourceIp, created_at AS CreatedAt
            FROM audit_log
            WHERE org_id = @orgId AND actor_id = @userId
              AND (actor_kind = 'user' OR actor_kind IS NULL)
            ORDER BY created_at
            """,
            new { userId, orgId });

        var activity = await conn.QueryAsync<ActivityRow>(
            """
            SELECT id AS Id, ecosystem AS Ecosystem, purl AS Purl, event_type AS EventType,
                   detail AS Detail, source_ip AS SourceIp, created_at AS CreatedAt
            FROM activity
            WHERE org_id = @orgId AND actor_id = @userId
              AND (actor_kind = 'user' OR actor_kind IS NULL)
            ORDER BY created_at
            """,
            new { userId, orgId });

        var auditEvents = await conn.QueryAsync<AuditEventRow>(
            """
            SELECT event_id AS EventId, event_type AS EventType, source_ip AS SourceIp,
                   user_agent AS UserAgent, outcome AS Outcome, payload AS Payload,
                   occurred_at AS OccurredAt
            FROM audit_event
            WHERE org_id = @orgId AND actor_type = 'user' AND actor_id = @userId
            ORDER BY occurred_at
            """,
            new { userId, orgId });

        return new ActivityData(
            bannerDismissals, invitesCreated, invitesReceived, auditLog, activity, auditEvents);
    }

    // The subject's pseudonymized lockout/throttle state — both tables key on the same
    // (realm, tenant, email) hash rather than user_id, so tenant scoping comes from the key
    // itself rather than an org_id column.
    private static async Task<LockoutData> LoadLockoutDataAsync(
        DbConnection conn, string loginAttemptKey)
    {
        // login_attempts has no org_id column; its primary key already encodes (realm, tenant,
        // email), so matching that pseudonym is inherently tenant-scoped.
        var loginAttempts = await conn.QuerySingleOrDefaultAsync<LoginAttemptRow>(
            """
            SELECT failed_count AS FailedCount, locked_until AS LockedUntil, last_attempt AS LastAttempt
            FROM login_attempts
            WHERE email_hash = @loginAttemptKey
            """,
            new { loginAttemptKey });

        // account_send_throttle shares login_attempts' pseudonymized key, so the same tenant-scoping
        // argument applies: the key already encodes (realm, tenant, email).
        var sendThrottles = await conn.QueryAsync<SendThrottleRow>(
            """
            SELECT purpose AS Purpose, send_count AS SendCount, window_start AS WindowStart
            FROM account_send_throttle
            WHERE email_hash = @loginAttemptKey
            ORDER BY purpose
            """,
            new { loginAttemptKey });

        return new LockoutData(loginAttempts, sendThrottles);
    }

    private sealed record AccountData(
        UserRow? User,
        IEnumerable<TokenRow> UserTokens,
        IEnumerable<ResetTokenRow> PasswordResetTokens,
        IEnumerable<EmailChangeRow> EmailChangeTokens,
        IEnumerable<ExternalIdentityRow> ExternalIdentities,
        IEnumerable<TrustedDeviceRow> TrustedDevices);

    private sealed record ActivityData(
        IEnumerable<BannerDismissalRow> BannerDismissals,
        IEnumerable<InviteCreatedRow> InvitesCreated,
        IEnumerable<InviteReceivedRow> InvitesReceived,
        IEnumerable<AuditLogRow> AuditLog,
        IEnumerable<ActivityRow> Activity,
        IEnumerable<AuditEventRow> AuditEvents);

    private sealed record LockoutData(LoginAttemptRow? LoginAttempts, IEnumerable<SendThrottleRow> SendThrottles);
}

/// <summary>
/// One data subject's personal data, keyed by source table. Serialized camelCase via the MVC Web
/// JSON defaults for the SPA. Structured, commonly-used, machine-readable JSON satisfies Art. 20.
/// </summary>
public sealed record PersonalDataExport(
    UserRow? User,
    IReadOnlyList<TokenRow> UserTokens,
    IReadOnlyList<ResetTokenRow> PasswordResetTokens,
    IReadOnlyList<EmailChangeRow> EmailChangeTokens,
    IReadOnlyList<ExternalIdentityRow> ExternalIdentities,
    IReadOnlyList<TrustedDeviceRow> MfaTrustedDevices,
    IReadOnlyList<BannerDismissalRow> BannerDismissals,
    IReadOnlyList<InviteCreatedRow> InvitesCreated,
    IReadOnlyList<InviteReceivedRow> InvitesReceived,
    IReadOnlyList<AuditLogRow> AuditLog,
    IReadOnlyList<ActivityRow> Activity,
    IReadOnlyList<AuditEventRow> AuditEvents,
    LoginAttemptRow? LoginAttempts,
    IReadOnlyList<SendThrottleRow> SendThrottles);

// SQLite stores boolean/int columns as INTEGER, which Dapper's positional-record materializer
// surfaces as Int64; the flag columns are therefore typed long (0/1) rather than bool so the
// constructor signature matches the reader exactly. 0/1 is unambiguous machine-readable JSON.
public sealed record UserRow(
    string Id, string TenantId, string Email, string Role, string AccountType,
    long MustChangePassword, string? LastLoginAt, string AccountStatus, long MfaEnabled,
    string? PasswordResetIssuedAt, string? Language, long TokenVersion, string CreatedAt);

public sealed record TokenRow(
    string Id, string? Description, string? Capabilities, string CreatedAt,
    string? ExpiresAt, string? LastUsedAt);

public sealed record ResetTokenRow(string Id, string CreatedAt, string ExpiresAt, string? ConsumedAt);

/// <summary>A pending or completed email rectification, including the address it moves to.</summary>
public sealed record EmailChangeRow(
    string Id, string NewEmail, string CreatedAt, string ExpiresAt, string? ConsumedAt);

public sealed record ExternalIdentityRow(
    string Id, string IdpEntityId, string NameId, string? EmailSnapshot,
    string CreatedAt, string? LastLoginAt);

public sealed record TrustedDeviceRow(
    string Id, string Realm, string? UserAgent, string CreatedAt, string? LastSeenAt, string ExpiresAt);

public sealed record BannerDismissalRow(string BannerId, string DismissedAt);

public sealed record InviteCreatedRow(
    string Id, string Email, string Role, string CreatedAt, string ExpiresAt, string? AcceptedAt);

public sealed record InviteReceivedRow(
    string Id, string Role, string CreatedBy, string CreatedAt, string ExpiresAt, string? AcceptedAt);

public sealed record AuditLogRow(
    string Id, string Action, string? Ecosystem, string? Purl, string? Detail,
    string? SourceIp, string CreatedAt);

public sealed record ActivityRow(
    string Id, string Ecosystem, string? Purl, string EventType, string? Detail,
    string? SourceIp, string CreatedAt);

public sealed record AuditEventRow(
    string EventId, string EventType, string? SourceIp, string? UserAgent,
    string Outcome, string Payload, string OccurredAt);

public sealed record LoginAttemptRow(long FailedCount, string? LockedUntil, string LastAttempt);

/// <summary>The subject's current per-account send budget for one account-targeted mail flow.</summary>
public sealed record SendThrottleRow(string Purpose, long SendCount, string WindowStart);
