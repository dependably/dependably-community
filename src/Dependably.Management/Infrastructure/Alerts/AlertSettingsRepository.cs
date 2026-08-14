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

    /// <summary>API-facing read: never returns the raw Slack webhook URL, only
    /// <c>HasSlackWebhook</c>.</summary>
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
                   email_recipients AS EmailRecipients,
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
                row.EmailRecipients,
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
    /// Delivery-only view of an org's email channel: the parsed recipient list. Null when the
    /// channel is disabled or has no recipients — called only by
    /// <see cref="EffectiveEmailConfigResolver"/> (delivery queue + test endpoint), never by a
    /// response-serializing path. The transport itself is instance-level and is resolved by the
    /// caller; an org configures who receives alert mail, never how it is carried.
    /// </summary>
    public async Task<EmailDeliveryConfig?> GetDecryptedEmailDeliveryConfigAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<RawEmailDeliveryRow>(
            """
            SELECT email_enabled AS EmailEnabled, email_recipients AS EmailRecipients
            FROM alert_settings WHERE org_id = @orgId
            """,
            new { orgId });

        if (row is null || row.EmailEnabled == 0)
        {
            return null;
        }

        string[] recipients = EmailRecipients.Split(row.EmailRecipients);
        return recipients.Length == 0 ? null : new EmailDeliveryConfig(recipients);
    }

    /// <summary>
    /// Upserts only the gate columns: the quarantine/vuln toggles and the severity floor. Never
    /// touches a delivery channel's columns, so a gates save can't clobber a concurrently-saved
    /// Slack or email channel — an insert triggered by this call takes the schema defaults for
    /// those columns.
    /// </summary>
    public async Task<AlertSettings> UpdateGatesAsync(string orgId, UpdateAlertGates req, CancellationToken ct = default)
    {
        string now = NowIso();

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, quarantine_alerts_enabled, vuln_alerts_enabled, vuln_min_severity,
                 created_at, updated_at)
            VALUES
                (@orgId, @quarantineAlertsEnabled, @vulnAlertsEnabled, @vulnMinSeverity,
                 @now, @now)
            ON CONFLICT (org_id) DO UPDATE SET
                quarantine_alerts_enabled = excluded.quarantine_alerts_enabled,
                vuln_alerts_enabled = excluded.vuln_alerts_enabled,
                vuln_min_severity = excluded.vuln_min_severity,
                updated_at = excluded.updated_at
            """,
            new
            {
                orgId,
                quarantineAlertsEnabled = req.QuarantineAlertsEnabled ? 1 : 0,
                vulnAlertsEnabled = req.VulnAlertsEnabled ? 1 : 0,
                vulnMinSeverity = req.VulnMinSeverity,
                now
            });

        return await GetAsync(orgId, ct);
    }

    /// <summary>
    /// Upserts only the email channel columns: the delivery gate (<c>email_enabled</c>) and the
    /// recipient list. Never touches the gate or Slack columns, so an email save can't clobber a
    /// concurrently-saved gate or Slack channel — an insert triggered by this call takes the
    /// schema defaults for those columns. Delivery health is owned by
    /// <see cref="RecordEmailSuccessAsync"/>/<see cref="RecordEmailFailureAsync"/> and is left
    /// alone here: configuration is intent, health is reality, and the two stay independent.
    /// </summary>
    public async Task<AlertSettings> UpdateEmailChannelAsync(string orgId, UpdateAlertEmailChannel req, CancellationToken ct = default)
    {
        string now = NowIso();

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, email_enabled, email_recipients, created_at, updated_at)
            VALUES
                (@orgId, @emailEnabled, @emailRecipients, @now, @now)
            ON CONFLICT (org_id) DO UPDATE SET
                email_enabled = excluded.email_enabled,
                email_recipients = excluded.email_recipients,
                updated_at = excluded.updated_at
            """,
            new
            {
                orgId,
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
    ///
    /// The count is incremented by the database and read back from the same statement rather than
    /// computed from a separately-read snapshot: a Postgres deployment runs one
    /// <see cref="AlertSlackQueue"/> per replica, so two failures for the same org can read the
    /// same value concurrently and both write the same +1, advancing the counter by one for two
    /// failures and delaying the auto-disable it drives.
    /// </summary>
    public async Task<bool> RecordSlackFailureAsync(
        string orgId, string error,
        int autoDisableAfterFailures, TimeSpan autoDisableAfterDuration,
        CancellationToken ct = default)
    {
        string now = NowIso();
        await using var conn = await _db.OpenAsync(ct);

        string truncatedError = error.Length > 500 ? error[..500] : error;

        // RETURNING yields the post-update row on both providers, so Failures is the authoritative
        // count this failure produced and FailingSince the first failure of the current streak.
        var (newFailures, failingSince) = await conn.QuerySingleOrDefaultAsync<(long Failures, string? FailingSince)>(
            """
            UPDATE alert_settings
            SET slack_last_delivery_at = @now, slack_last_status = 'failed',
                slack_consecutive_failures = slack_consecutive_failures + 1,
                slack_failing_since = COALESCE(slack_failing_since, @now),
                slack_last_error = @truncatedError,
                updated_at = @now
            WHERE org_id = @orgId
            RETURNING slack_consecutive_failures AS Failures, slack_failing_since AS FailingSince
            """,
            new { orgId, now, truncatedError });

        // An org with no settings row returns zero failures and a null streak start, which
        // disables nothing.
        bool autoDisable = newFailures > 0
            && (newFailures >= autoDisableAfterFailures
                || (DateTimeOffset.TryParse(failingSince, out var since)
                    && _time.GetUtcNow() - since >= autoDisableAfterDuration));

        if (autoDisable)
        {
            // Separate, idempotent statement so the disable condition is expressed once, in C#,
            // over the values the increment actually produced.
            await conn.ExecuteAsync(
                """
                UPDATE alert_settings
                SET slack_enabled = 0, updated_at = @now
                WHERE org_id = @orgId
                """,
                new { orgId, now });
        }

        return autoDisable;
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
    /// Records a terminal email delivery failure: updates the health columns only
    /// (<c>email_last_status</c>, <c>email_consecutive_failures</c>, <c>email_failing_since</c>,
    /// <c>email_last_error</c>) and deliberately leaves <c>email_enabled</c> alone.
    ///
    /// Email delivery runs over the instance-level SMTP transport, so a delivery failure is an
    /// operator infrastructure failure shared by every org — not a fault in this org's
    /// configuration. Auto-disabling each org's channel would turn one relay outage into dozens of
    /// independent tenant configuration failures, each needing a manual re-enable for a problem the
    /// tenant can neither see the cause of nor fix. Tenant configuration expresses intent, health
    /// reports reality, and failure never rewrites intent. The Slack arm
    /// (<see cref="RecordSlackFailureAsync"/>) still auto-disables, because a Slack webhook URL is
    /// genuinely tenant-owned and tenant-fixable.
    /// </summary>
    public async Task RecordEmailFailureAsync(string orgId, string error, CancellationToken ct = default)
    {
        string now = NowIso();
        await using var conn = await _db.OpenAsync(ct);

        string truncatedError = error.Length > 500 ? error[..500] : error;

        // Incremented by the database, like the Slack and webhook counters: the health figure an
        // operator reads has to be the number of failures that happened, not the number that
        // happened to serialize. Nothing here touches email_enabled — a shared-relay outage is not
        // a tenant configuration fault, so it never rewrites tenant configuration.
        await conn.ExecuteAsync(
            """
            UPDATE alert_settings
            SET email_last_delivery_at = @now, email_last_status = 'failed',
                email_consecutive_failures = email_consecutive_failures + 1,
                email_failing_since = COALESCE(email_failing_since, @now),
                email_last_error = @truncatedError,
                updated_at = @now
            WHERE org_id = @orgId
            """,
            new { orgId, now, truncatedError });
    }

    // Integer columns bind as long, and [ExplicitConstructor] is what lets one signature serve
    // both providers — SQLite reports INTEGER as Int64, Postgres as Int32, and Dapper's default
    // positional-record binding demands an exact CLR match. See
    // DapperPositionalRecordComplianceTests. Converted to bool/int at the mapping call sites.
    [method: ExplicitConstructor]
    private sealed record RawRow(
        long QuarantineAlertsEnabled, long VulnAlertsEnabled, string VulnMinSeverity,
        long SlackEnabled, string? SlackWebhookUrlStored,
        string? SlackLastDeliveryAt, string? SlackLastStatus,
        long SlackConsecutiveFailures, string? SlackFailingSince, string? SlackLastError,
        long EmailEnabled, string? EmailRecipients,
        string? EmailLastDeliveryAt, string? EmailLastStatus,
        long EmailConsecutiveFailures, string? EmailFailingSince, string? EmailLastError);

    // Raw projection for GetDecryptedEmailDeliveryConfigAsync — a narrower column set than
    // RawRow, read separately so the delivery path never touches the health/audit columns.
    [method: ExplicitConstructor]
    private sealed record RawEmailDeliveryRow(long EmailEnabled, string? EmailRecipients);
}

/// <summary>API-facing projection of <c>alert_settings</c>. Never carries the raw webhook URL.
/// <see cref="SecretsAvailable"/> and <see cref="InstanceEmailConfigured"/> are not stored on the
/// row — the controller stamps them on from <see cref="EnvelopeProtector.IsConfigured"/> and
/// <see cref="Mail.InstanceSmtpConfig"/> respectively, so the UI can grey the Slack secret input and
/// tell an admin their recipients will go nowhere, without ever seeing the instance's SMTP
/// details.</summary>
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
    string? EmailRecipients,
    string? EmailLastDeliveryAt,
    string? EmailLastStatus,
    int EmailConsecutiveFailures,
    string? EmailFailingSince,
    string? EmailLastError,
    bool SecretsAvailable = false,
    bool InstanceEmailConfigured = false)
{
    /// <summary>The documented defaults for an org with no settings row: both alert types on, HIGH
    /// severity floor, Slack off, email off with no recipients.</summary>
    public static AlertSettings Defaults(string orgId) =>
        new(orgId, QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            SlackEnabled: false, HasSlackWebhook: false,
            SlackLastDeliveryAt: null, SlackLastStatus: null,
            SlackConsecutiveFailures: 0, SlackFailingSince: null, SlackLastError: null,
            EmailEnabled: false, EmailRecipients: null,
            EmailLastDeliveryAt: null, EmailLastStatus: null, EmailConsecutiveFailures: 0,
            EmailFailingSince: null, EmailLastError: null);
}

/// <summary>Fields accepted by <see cref="AlertSettingsRepository.UpdateGatesAsync"/>.</summary>
public sealed record UpdateAlertGates(
    bool QuarantineAlertsEnabled,
    bool VulnAlertsEnabled,
    string VulnMinSeverity);

/// <summary>Fields accepted by <see cref="AlertSettingsRepository.UpdateEmailChannelAsync"/>.</summary>
public sealed record UpdateAlertEmailChannel(
    bool EmailEnabled,
    string? EmailRecipients);

/// <summary>Fields accepted by <see cref="AlertSettingsRepository.UpdateSlackAsync"/>.</summary>
public sealed record UpdateAlertSlack(
    bool SlackEnabled,
    string? SlackWebhookUrl);

/// <summary>
/// Delivery-only view of an org's email channel, returned by
/// <see cref="AlertSettingsRepository.GetDecryptedEmailDeliveryConfigAsync"/>. Carries only who the
/// mail goes to; the transport is instance-level and never varies per org.
/// </summary>
public sealed record EmailDeliveryConfig(string[] Recipients);
