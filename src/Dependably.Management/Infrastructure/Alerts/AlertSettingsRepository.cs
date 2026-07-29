using Dapper;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Dapper-backed store for the one-row-per-org <c>alert_settings</c> table — the write side (the
/// Core <see cref="AlertRepository.GetRaiseSettingsAsync"/> covers the read-only raise-gating
/// subset that must not depend on <see cref="EnvelopeProtector"/>). The Slack webhook URL is
/// envelope-encrypted at rest (<c>enc:v1:</c> prefix) and fails closed when no
/// <c>DEPENDABLY_MASTER_KEY</c> is configured — the API layer must check
/// <see cref="EnvelopeProtector.IsConfigured"/> before calling <see cref="UpdateSlackAsync"/> with a
/// non-empty <c>SlackWebhookUrl</c>. An absent row (no org has ever saved settings) is projected
/// as the documented defaults by <see cref="GetAsync"/>; there is no backfill migration.
/// </summary>
public sealed class AlertSettingsRepository
{
    private readonly IMetadataStore _db;
    private readonly EnvelopeProtector _envelope;
    private readonly TimeProvider _time;

    public AlertSettingsRepository(IMetadataStore db, EnvelopeProtector envelope, TimeProvider time)
    {
        _db = db;
        _envelope = envelope;
        _time = time;
    }

    private string NowIso() => _time.GetUtcNow().ToUtcIso();

    /// <summary>API-facing read: never returns the raw Slack webhook URL or SMTP password, only
    /// <c>HasSlackWebhook</c>/<c>HasEmailSmtpPassword</c>.</summary>
    public async Task<AlertSettings> GetAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<RawRow>(
            """
            SELECT quarantine_alerts_enabled AS QuarantineAlertsEnabled,
                   vuln_alerts_enabled AS VulnAlertsEnabled,
                   vuln_min_severity AS VulnMinSeverity,
                   slack_enabled AS SlackEnabled,
                   slack_webhook_url AS SlackWebhookUrlStored,
                   slack_last_delivery_at AS SlackLastDeliveryAt,
                   slack_last_status AS SlackLastStatus,
                   slack_consecutive_failures AS SlackConsecutiveFailures,
                   slack_failing_since AS SlackFailingSince,
                   slack_last_error AS SlackLastError,
                   email_enabled AS EmailEnabled,
                   email_inherit_instance AS EmailInheritInstance,
                   email_recipients AS EmailRecipients,
                   email_smtp_host AS EmailSmtpHost,
                   email_smtp_port AS EmailSmtpPort,
                   email_smtp_security AS EmailSmtpSecurity,
                   email_smtp_username AS EmailSmtpUsername,
                   email_smtp_password AS EmailSmtpPasswordStored,
                   email_smtp_from AS EmailSmtpFrom,
                   email_last_delivery_at AS EmailLastDeliveryAt,
                   email_last_status AS EmailLastStatus,
                   email_consecutive_failures AS EmailConsecutiveFailures,
                   email_failing_since AS EmailFailingSince,
                   email_last_error AS EmailLastError
            FROM alert_settings WHERE org_id = @orgId
            """,
            new { orgId });

        return row is null
            ? AlertSettings.Defaults(orgId)
            : new AlertSettings(
                orgId,
                row.QuarantineAlertsEnabled != 0,
                row.VulnAlertsEnabled != 0,
                row.VulnMinSeverity,
                row.SlackEnabled != 0,
                HasSlackWebhook: row.SlackWebhookUrlStored is not null,
                row.SlackLastDeliveryAt,
                row.SlackLastStatus,
                (int)row.SlackConsecutiveFailures,
                row.SlackFailingSince,
                row.SlackLastError,
                row.EmailEnabled != 0,
                row.EmailInheritInstance != 0,
                row.EmailRecipients,
                row.EmailSmtpHost,
                (int?)row.EmailSmtpPort,
                row.EmailSmtpSecurity,
                row.EmailSmtpUsername,
                HasEmailSmtpPassword: row.EmailSmtpPasswordStored is not null,
                row.EmailSmtpFrom,
                row.EmailLastDeliveryAt,
                row.EmailLastStatus,
                (int)row.EmailConsecutiveFailures,
                row.EmailFailingSince,
                row.EmailLastError);
    }

    /// <summary>
    /// Decrypted Slack webhook URL for delivery. Null when Slack is disabled, unset, or the org
    /// has no settings row. Called only by the delivery queue and the slack/test endpoint — never
    /// by a response-serializing path.
    /// </summary>
    public async Task<string?> GetDecryptedSlackWebhookUrlAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var (slackEnabled, stored) = await conn.QuerySingleOrDefaultAsync<(long SlackEnabled, string? Stored)>(
            "SELECT slack_enabled AS SlackEnabled, slack_webhook_url AS Stored FROM alert_settings WHERE org_id = @orgId",
            new { orgId });

        return slackEnabled == 0 || stored is null ? null : _envelope.Unprotect(stored);
    }

    /// <summary>
    /// Decrypted email delivery config for an org: the inherit flag, the parsed recipient list,
    /// and the org's own SMTP transport (decrypted password) for when it isn't inheriting. Null
    /// when the channel is disabled or has no recipients — called only by
    /// <see cref="EffectiveEmailConfigResolver"/> (delivery queue + test endpoint), never by a
    /// response-serializing path.
    /// </summary>
    public async Task<EmailDeliveryConfig?> GetDecryptedEmailDeliveryConfigAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<RawEmailDeliveryRow>(
            """
            SELECT email_enabled AS EmailEnabled, email_inherit_instance AS EmailInheritInstance,
                   email_recipients AS EmailRecipients, email_smtp_host AS EmailSmtpHost,
                   email_smtp_port AS EmailSmtpPort, email_smtp_security AS EmailSmtpSecurity,
                   email_smtp_username AS EmailSmtpUsername, email_smtp_password AS EmailSmtpPasswordStored,
                   email_smtp_from AS EmailSmtpFrom
            FROM alert_settings WHERE org_id = @orgId
            """,
            new { orgId });

        if (row is null || row.EmailEnabled == 0)
        {
            return null;
        }

        string[] recipients = EmailRecipients.Split(row.EmailRecipients);
        if (recipients.Length == 0)
        {
            return null;
        }

        var ownTransport = new SmtpTransportSettings(
            Host: row.EmailSmtpHost,
            Port: (int)(row.EmailSmtpPort ?? SmtpTransportSettings.DefaultPort),
            Security: string.IsNullOrWhiteSpace(row.EmailSmtpSecurity) ? SmtpTransportSettings.DefaultSecurity : row.EmailSmtpSecurity,
            Username: row.EmailSmtpUsername,
            Password: row.EmailSmtpPasswordStored is null ? null : _envelope.Unprotect(row.EmailSmtpPasswordStored),
            FromAddress: row.EmailSmtpFrom);

        return new EmailDeliveryConfig(row.EmailInheritInstance != 0, recipients, ownTransport);
    }

    /// <summary>
    /// Upserts only the Alerts-tab columns: the gates (quarantine/vuln toggles + severity floor)
    /// plus the email delivery gate (<c>email_enabled</c>) and its recipient list. Never touches
    /// the Slack or SMTP-transport columns, so a gates save can't clobber a
    /// concurrently-configured Slack channel or email transport — an insert triggered by this
    /// call takes the schema defaults for those columns.
    /// </summary>
    public async Task<AlertSettings> UpdateGatesAsync(string orgId, UpdateAlertGates req, CancellationToken ct = default)
    {
        string now = NowIso();

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, quarantine_alerts_enabled, vuln_alerts_enabled, vuln_min_severity,
                 email_enabled, email_recipients, created_at, updated_at)
            VALUES
                (@orgId, @quarantineAlertsEnabled, @vulnAlertsEnabled, @vulnMinSeverity,
                 @emailEnabled, @emailRecipients, @now, @now)
            ON CONFLICT (org_id) DO UPDATE SET
                quarantine_alerts_enabled = excluded.quarantine_alerts_enabled,
                vuln_alerts_enabled = excluded.vuln_alerts_enabled,
                vuln_min_severity = excluded.vuln_min_severity,
                email_enabled = excluded.email_enabled,
                email_recipients = excluded.email_recipients,
                updated_at = excluded.updated_at
            """,
            new
            {
                orgId,
                quarantineAlertsEnabled = req.QuarantineAlertsEnabled ? 1 : 0,
                vulnAlertsEnabled = req.VulnAlertsEnabled ? 1 : 0,
                vulnMinSeverity = req.VulnMinSeverity,
                emailEnabled = req.EmailEnabled ? 1 : 0,
                emailRecipients = req.EmailRecipients,
                now
            });

        return await GetAsync(orgId, ct);
    }

    /// <summary>
    /// Upserts only the Slack columns. <paramref name="req"/>.SlackWebhookUrl is write-only: a
    /// non-empty value rotates the encrypted URL (requires <see cref="EnvelopeProtector.IsConfigured"/>
    /// — the caller must check this before calling), null/empty leaves the stored value unchanged.
    /// Never touches the gate columns, so a Slack save can't clobber a concurrently-configured
    /// gate — an insert triggered by this call takes the schema defaults for the gate columns.
    /// </summary>
    public async Task<AlertSettings> UpdateSlackAsync(string orgId, UpdateAlertSlack req, CancellationToken ct = default)
    {
        string now = NowIso();
        string? encryptedUrl = string.IsNullOrEmpty(req.SlackWebhookUrl) ? null : _envelope.Protect(req.SlackWebhookUrl);

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, slack_enabled, slack_webhook_url, created_at, updated_at)
            VALUES
                (@orgId, @slackEnabled, @encryptedUrl, @now, @now)
            ON CONFLICT (org_id) DO UPDATE SET
                slack_enabled = excluded.slack_enabled,
                slack_webhook_url = COALESCE(excluded.slack_webhook_url, alert_settings.slack_webhook_url),
                updated_at = excluded.updated_at
            """,
            new
            {
                orgId,
                slackEnabled = req.SlackEnabled ? 1 : 0,
                encryptedUrl,
                now
            });

        return await GetAsync(orgId, ct);
    }

    /// <summary>
    /// Records a successful Slack delivery: resets the failure-health columns. Called by the
    /// management-plane Slack delivery queue after a confirmed 2xx response.
    /// </summary>
    public async Task RecordSlackSuccessAsync(string orgId, CancellationToken ct = default)
    {
        string now = NowIso();
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE alert_settings
            SET slack_last_delivery_at = @now, slack_last_status = 'ok',
                slack_consecutive_failures = 0, slack_failing_since = NULL, slack_last_error = NULL,
                updated_at = @now
            WHERE org_id = @orgId
            """,
            new { orgId, now });
    }

    /// <summary>
    /// Records a terminal Slack delivery failure and conditionally auto-disables Slack delivery
    /// (<c>slack_enabled = 0</c>) once <c>slack_consecutive_failures</c> reaches
    /// <paramref name="autoDisableAfterFailures"/> or the <c>slack_failing_since</c> window has
    /// exceeded <paramref name="autoDisableAfterDuration"/>, whichever comes first. Returns true
    /// when this call auto-disabled Slack so the caller can log it.
    /// </summary>
    public async Task<bool> RecordSlackFailureAsync(
        string orgId, string error,
        int autoDisableAfterFailures, TimeSpan autoDisableAfterDuration,
        CancellationToken ct = default)
    {
        string now = NowIso();
        await using var conn = await _db.OpenAsync(ct);

        var (currentFailures, currentFailingSince) = await conn.QuerySingleOrDefaultAsync<(long Failures, string? FailingSince)>(
            "SELECT slack_consecutive_failures AS Failures, slack_failing_since AS FailingSince FROM alert_settings WHERE org_id = @orgId",
            new { orgId });

        int newFailures = (int)currentFailures + 1;
        string? failingSince = currentFailingSince ?? now;

        bool autoDisable = newFailures >= autoDisableAfterFailures
            || (DateTimeOffset.TryParse(failingSince, out var since)
                && _time.GetUtcNow() - since >= autoDisableAfterDuration);

        string truncatedError = error.Length > 500 ? error[..500] : error;

        await conn.ExecuteAsync(
            """
            UPDATE alert_settings
            SET slack_last_delivery_at = @now, slack_last_status = 'failed',
                slack_consecutive_failures = @newFailures, slack_failing_since = @failingSince,
                slack_last_error = @truncatedError,
                slack_enabled = CASE WHEN @autoDisable = 1 THEN 0 ELSE slack_enabled END,
                updated_at = @now
            WHERE org_id = @orgId
            """,
            new
            {
                orgId,
                now,
                newFailures,
                failingSince,
                truncatedError,
                autoDisable = autoDisable ? 1 : 0
            });

        return autoDisable;
    }

    /// <summary>
    /// Upserts only the email SMTP-transport columns (inherit flag + own-transport fields).
    /// <paramref name="req"/>.EmailSmtpPassword is write-only: a non-empty value rotates the
    /// encrypted password (requires <see cref="EnvelopeProtector.IsConfigured"/> — the caller
    /// must check this before calling), null/empty leaves the stored value unchanged. Never
    /// touches the gate, Slack, or email delivery-gate columns (<c>email_enabled</c> and
    /// <c>email_recipients</c> belong to <see cref="UpdateGatesAsync"/>), so a transport save
    /// can't clobber a concurrently-saved Alerts tab or Slack channel — an insert triggered by
    /// this call takes the schema defaults for those columns.
    /// </summary>
    public async Task<AlertSettings> UpdateEmailAsync(string orgId, UpdateAlertEmail req, CancellationToken ct = default)
    {
        string now = NowIso();
        string? encryptedPassword = string.IsNullOrEmpty(req.EmailSmtpPassword)
            ? null
            : _envelope.Protect(req.EmailSmtpPassword);

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, email_inherit_instance,
                 email_smtp_host, email_smtp_port, email_smtp_security, email_smtp_username,
                 email_smtp_password, email_smtp_from, created_at, updated_at)
            VALUES
                (@orgId, @emailInheritInstance,
                 @emailSmtpHost, @emailSmtpPort, @emailSmtpSecurity, @emailSmtpUsername,
                 @encryptedPassword, @emailSmtpFrom, @now, @now)
            ON CONFLICT (org_id) DO UPDATE SET
                email_inherit_instance = excluded.email_inherit_instance,
                email_smtp_host = excluded.email_smtp_host,
                email_smtp_port = excluded.email_smtp_port,
                email_smtp_security = excluded.email_smtp_security,
                email_smtp_username = excluded.email_smtp_username,
                email_smtp_password = COALESCE(excluded.email_smtp_password, alert_settings.email_smtp_password),
                email_smtp_from = excluded.email_smtp_from,
                updated_at = excluded.updated_at
            """,
            new
            {
                orgId,
                emailInheritInstance = req.EmailInheritInstance ? 1 : 0,
                emailSmtpHost = req.EmailSmtpHost,
                emailSmtpPort = req.EmailSmtpPort,
                emailSmtpSecurity = req.EmailSmtpSecurity,
                emailSmtpUsername = req.EmailSmtpUsername,
                encryptedPassword,
                emailSmtpFrom = req.EmailSmtpFrom,
                now
            });

        return await GetAsync(orgId, ct);
    }

    /// <summary>
    /// Records a successful email delivery: resets the failure-health columns. Called by the
    /// management-plane email delivery queue after a confirmed send.
    /// </summary>
    public async Task RecordEmailSuccessAsync(string orgId, CancellationToken ct = default)
    {
        string now = NowIso();
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE alert_settings
            SET email_last_delivery_at = @now, email_last_status = 'ok',
                email_consecutive_failures = 0, email_failing_since = NULL, email_last_error = NULL,
                updated_at = @now
            WHERE org_id = @orgId
            """,
            new { orgId, now });
    }

    /// <summary>
    /// Records a terminal email delivery failure and conditionally auto-disables the email
    /// channel (<c>email_enabled = 0</c>) once <c>email_consecutive_failures</c> reaches
    /// <paramref name="autoDisableAfterFailures"/> or the <c>email_failing_since</c> window has
    /// exceeded <paramref name="autoDisableAfterDuration"/>, whichever comes first. Returns true
    /// when this call auto-disabled email delivery so the caller can log it.
    /// </summary>
    public async Task<bool> RecordEmailFailureAsync(
        string orgId, string error,
        int autoDisableAfterFailures, TimeSpan autoDisableAfterDuration,
        CancellationToken ct = default)
    {
        string now = NowIso();
        await using var conn = await _db.OpenAsync(ct);

        var (currentFailures, currentFailingSince) = await conn.QuerySingleOrDefaultAsync<(long Failures, string? FailingSince)>(
            "SELECT email_consecutive_failures AS Failures, email_failing_since AS FailingSince FROM alert_settings WHERE org_id = @orgId",
            new { orgId });

        int newFailures = (int)currentFailures + 1;
        string? failingSince = currentFailingSince ?? now;

        bool autoDisable = newFailures >= autoDisableAfterFailures
            || (DateTimeOffset.TryParse(failingSince, out var since)
                && _time.GetUtcNow() - since >= autoDisableAfterDuration);

        string truncatedError = error.Length > 500 ? error[..500] : error;

        await conn.ExecuteAsync(
            """
            UPDATE alert_settings
            SET email_last_delivery_at = @now, email_last_status = 'failed',
                email_consecutive_failures = @newFailures, email_failing_since = @failingSince,
                email_last_error = @truncatedError,
                email_enabled = CASE WHEN @autoDisable = 1 THEN 0 ELSE email_enabled END,
                updated_at = @now
            WHERE org_id = @orgId
            """,
            new
            {
                orgId,
                now,
                newFailures,
                failingSince,
                truncatedError,
                autoDisable = autoDisable ? 1 : 0
            });

        return autoDisable;
    }

    // SQLite returns INTEGER columns as Int64; use long here to avoid Dapper constructor-matching
    // errors, then convert to bool/int in the mapping call sites.
    private sealed record RawRow(
        long QuarantineAlertsEnabled, long VulnAlertsEnabled, string VulnMinSeverity,
        long SlackEnabled, string? SlackWebhookUrlStored,
        string? SlackLastDeliveryAt, string? SlackLastStatus,
        long SlackConsecutiveFailures, string? SlackFailingSince, string? SlackLastError,
        long EmailEnabled, long EmailInheritInstance, string? EmailRecipients,
        string? EmailSmtpHost, long? EmailSmtpPort, string? EmailSmtpSecurity, string? EmailSmtpUsername,
        string? EmailSmtpPasswordStored, string? EmailSmtpFrom,
        string? EmailLastDeliveryAt, string? EmailLastStatus,
        long EmailConsecutiveFailures, string? EmailFailingSince, string? EmailLastError);

    // Raw projection for GetDecryptedEmailDeliveryConfigAsync — a narrower column set than
    // RawRow, read separately so the delivery path never touches the health/audit columns.
    private sealed record RawEmailDeliveryRow(
        long EmailEnabled, long EmailInheritInstance, string? EmailRecipients,
        string? EmailSmtpHost, long? EmailSmtpPort, string? EmailSmtpSecurity, string? EmailSmtpUsername,
        string? EmailSmtpPasswordStored, string? EmailSmtpFrom);
}

/// <summary>API-facing projection of <c>alert_settings</c>. Never carries the raw webhook URL or
/// SMTP password. <see cref="SecretsAvailable"/> and <see cref="InstanceEmailConfigured"/> are not
/// stored on the row — the controller stamps them on from <see cref="EnvelopeProtector.IsConfigured"/>
/// and <see cref="Mail.InstanceSmtpConfig"/> respectively, so the UI can grey the secret inputs and
/// show the inherit-instance badge without ever seeing the instance's own SMTP details.</summary>
public sealed record AlertSettings(
    string OrgId,
    bool QuarantineAlertsEnabled,
    bool VulnAlertsEnabled,
    string VulnMinSeverity,
    bool SlackEnabled,
    bool HasSlackWebhook,
    string? SlackLastDeliveryAt,
    string? SlackLastStatus,
    int SlackConsecutiveFailures,
    string? SlackFailingSince,
    string? SlackLastError,
    bool EmailEnabled,
    bool EmailInheritInstance,
    string? EmailRecipients,
    string? EmailSmtpHost,
    int? EmailSmtpPort,
    string? EmailSmtpSecurity,
    string? EmailSmtpUsername,
    bool HasEmailSmtpPassword,
    string? EmailSmtpFrom,
    string? EmailLastDeliveryAt,
    string? EmailLastStatus,
    int EmailConsecutiveFailures,
    string? EmailFailingSince,
    string? EmailLastError,
    bool SecretsAvailable = false,
    bool InstanceEmailConfigured = false)
{
    /// <summary>
    /// True when this org's own SMTP transport would put its AUTH credentials on the wire in the
    /// clear (<c>security=none</c> with a username and a stored password). Reported on every read
    /// rather than only on the save that introduced it, because the config is DB-backed and an
    /// operator inheriting someone else's setting never sees that save. Always false while the org
    /// inherits the instance transport: those columns are then unused, and the instance surface
    /// reports its own transport separately.
    /// </summary>
    public bool EmailSmtpCleartextCredentials =>
        !EmailInheritInstance
        && Mail.SmtpTransportSettings.SendsCredentialsInCleartextWhen(
            EmailSmtpSecurity, EmailSmtpUsername, HasEmailSmtpPassword);

    /// <summary>The documented defaults for an org with no settings row: both alert types on, HIGH
    /// severity floor, Slack off, email off inheriting the instance transport.</summary>
    public static AlertSettings Defaults(string orgId) =>
        new(orgId, QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            SlackEnabled: false, HasSlackWebhook: false,
            SlackLastDeliveryAt: null, SlackLastStatus: null,
            SlackConsecutiveFailures: 0, SlackFailingSince: null, SlackLastError: null,
            EmailEnabled: false, EmailInheritInstance: true, EmailRecipients: null,
            EmailSmtpHost: null, EmailSmtpPort: null, EmailSmtpSecurity: null, EmailSmtpUsername: null,
            HasEmailSmtpPassword: false, EmailSmtpFrom: null,
            EmailLastDeliveryAt: null, EmailLastStatus: null, EmailConsecutiveFailures: 0,
            EmailFailingSince: null, EmailLastError: null);
}

/// <summary>Fields accepted by <see cref="AlertSettingsRepository.UpdateGatesAsync"/>.</summary>
public sealed record UpdateAlertGates(
    bool QuarantineAlertsEnabled,
    bool VulnAlertsEnabled,
    string VulnMinSeverity,
    bool EmailEnabled,
    string? EmailRecipients);

/// <summary>Fields accepted by <see cref="AlertSettingsRepository.UpdateSlackAsync"/>.</summary>
public sealed record UpdateAlertSlack(
    bool SlackEnabled,
    string? SlackWebhookUrl);

/// <summary>Fields accepted by <see cref="AlertSettingsRepository.UpdateEmailAsync"/>. Mirrors
/// <see cref="UpdateAlertSlack"/>'s write-only-secret convention: <see cref="EmailSmtpPassword"/>
/// is write-only, null/empty on update means "leave the stored password unchanged".</summary>
public sealed record UpdateAlertEmail(
    bool EmailInheritInstance,
    string? EmailSmtpHost,
    int? EmailSmtpPort,
    string? EmailSmtpSecurity,
    string? EmailSmtpUsername,
    string? EmailSmtpPassword,
    string? EmailSmtpFrom);

/// <summary>
/// Decrypted delivery-only view of an org's email channel, returned by
/// <see cref="AlertSettingsRepository.GetDecryptedEmailDeliveryConfigAsync"/>. Never serialized to
/// a client — <see cref="OwnTransport"/> carries the decrypted SMTP password.
/// </summary>
public sealed record EmailDeliveryConfig(
    bool InheritInstance,
    string[] Recipients,
    Mail.SmtpTransportSettings OwnTransport);
