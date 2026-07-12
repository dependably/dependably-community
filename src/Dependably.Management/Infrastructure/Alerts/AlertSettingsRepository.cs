using Dapper;
using Dependably.Infrastructure.Identity;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Dapper-backed store for the one-row-per-org <c>alert_settings</c> table — the write side (the
/// Core <see cref="AlertRepository.GetRaiseSettingsAsync"/> covers the read-only raise-gating
/// subset that must not depend on <see cref="EnvelopeProtector"/>). The Slack webhook URL is
/// envelope-encrypted at rest (<c>enc:v1:</c> prefix) and fails closed when no
/// <c>DEPENDABLY_MASTER_KEY</c> is configured — the API layer must check
/// <see cref="EnvelopeProtector.IsConfigured"/> before calling <see cref="UpdateAsync"/> with a
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

    private string NowIso() => _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");

    /// <summary>API-facing read: never returns the raw Slack webhook URL, only <c>HasSlackWebhook</c>.</summary>
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
                   slack_last_error AS SlackLastError
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
                row.SlackLastError);
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
    /// Upserts the settings row. <paramref name="req"/>.SlackWebhookUrl is write-only: a non-empty
    /// value rotates the encrypted URL (requires <see cref="EnvelopeProtector.IsConfigured"/> —
    /// the caller must check this before calling), null/empty leaves the stored value unchanged.
    /// </summary>
    public async Task<AlertSettings> UpdateAsync(string orgId, UpdateAlertSettings req, CancellationToken ct = default)
    {
        string now = NowIso();
        string? encryptedUrl = string.IsNullOrEmpty(req.SlackWebhookUrl) ? null : _envelope.Protect(req.SlackWebhookUrl);

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, quarantine_alerts_enabled, vuln_alerts_enabled, vuln_min_severity,
                 slack_enabled, slack_webhook_url, created_at, updated_at)
            VALUES
                (@orgId, @quarantineAlertsEnabled, @vulnAlertsEnabled, @vulnMinSeverity,
                 @slackEnabled, @encryptedUrl, @now, @now)
            ON CONFLICT (org_id) DO UPDATE SET
                quarantine_alerts_enabled = excluded.quarantine_alerts_enabled,
                vuln_alerts_enabled = excluded.vuln_alerts_enabled,
                vuln_min_severity = excluded.vuln_min_severity,
                slack_enabled = excluded.slack_enabled,
                slack_webhook_url = COALESCE(excluded.slack_webhook_url, alert_settings.slack_webhook_url),
                updated_at = excluded.updated_at
            """,
            new
            {
                orgId,
                quarantineAlertsEnabled = req.QuarantineAlertsEnabled ? 1 : 0,
                vulnAlertsEnabled = req.VulnAlertsEnabled ? 1 : 0,
                vulnMinSeverity = req.VulnMinSeverity,
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

    // SQLite returns INTEGER columns as Int64; use long here to avoid Dapper constructor-matching
    // errors, then convert to bool/int in the mapping call sites.
    private sealed record RawRow(
        long QuarantineAlertsEnabled, long VulnAlertsEnabled, string VulnMinSeverity,
        long SlackEnabled, string? SlackWebhookUrlStored,
        string? SlackLastDeliveryAt, string? SlackLastStatus,
        long SlackConsecutiveFailures, string? SlackFailingSince, string? SlackLastError);
}

/// <summary>API-facing projection of <c>alert_settings</c>. Never carries the raw webhook URL.</summary>
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
    string? SlackLastError)
{
    /// <summary>The documented defaults for an org with no settings row: both alert types on, HIGH
    /// severity floor, Slack off.</summary>
    public static AlertSettings Defaults(string orgId) =>
        new(orgId, QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            SlackEnabled: false, HasSlackWebhook: false,
            SlackLastDeliveryAt: null, SlackLastStatus: null,
            SlackConsecutiveFailures: 0, SlackFailingSince: null, SlackLastError: null);
}

/// <summary>Fields accepted by <see cref="AlertSettingsRepository.UpdateAsync"/>.</summary>
public sealed record UpdateAlertSettings(
    bool QuarantineAlertsEnabled,
    bool VulnAlertsEnabled,
    string VulnMinSeverity,
    bool SlackEnabled,
    string? SlackWebhookUrl);
