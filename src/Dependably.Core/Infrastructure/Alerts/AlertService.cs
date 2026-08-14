using Dependably.Protocol;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Raising entry point for both alert triggers. Reads the org's <c>alert_settings</c> gate,
/// deduplicates via <see cref="AlertRepository.TryInsertAsync"/>, and notifies
/// <see cref="IAlertNotifier"/> only on a fresh insert (never on a deduped repeat). Every failure
/// — a settings read, the insert, or the notifier — is logged and swallowed: raising an alert is
/// a best-effort side effect of the quarantine and vulnerability-scan pipelines, and must never
/// turn a successful block or scan into a failed request.
/// </summary>
public sealed class AlertService
{
    private readonly AlertRepository _alerts;
    private readonly IAlertNotifier _notifier;
    private readonly ILogger<AlertService> _logger;

    public AlertService(AlertRepository alerts, IAlertNotifier notifier, ILogger<AlertService> logger)
    {
        _alerts = alerts;
        _notifier = notifier;
        _logger = logger;
    }

    /// <summary>
    /// Raises a <see cref="AlertTypes.QuarantineNew"/> alert for a freshly-inserted quarantine
    /// row. Called only when <c>QuarantineRepository.UpsertPendingAsync</c> reports a fresh insert
    /// (not a conflict-refresh of an existing pending row) — a repeat block on the same purl must
    /// not re-alert. <paramref name="quarantineId"/> is the dedup key: one alert per quarantine row.
    /// </summary>
    public async Task RaiseQuarantineAlertAsync(
        string orgId, string quarantineId, string ecosystem, string purl, string gate,
        string? detail, CancellationToken ct = default)
    {
        try
        {
            var settings = await _alerts.GetRaiseSettingsAsync(orgId, ct);
            if (!settings.QuarantineAlertsEnabled)
            {
                return;
            }

            var alert = await _alerts.TryInsertAsync(
                new NewAlert(
                    OrgId: orgId,
                    Type: AlertTypes.QuarantineNew,
                    Severity: null,
                    SourceRef: quarantineId,
                    Ecosystem: ecosystem,
                    Purl: purl,
                    Title: $"New quarantine item: {purl}",
                    Detail: detail),
                ct);

            if (alert is not null)
            {
                await _notifier.NotifyAsync(alert, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Serilog structured parameter — the purl is encoded as
            // a property value, never spliced into the message text.
            _logger.LogWarning(ex,
                "Failed to raise quarantine alert for {Purl} (org {OrgId}, gate {Gate}); the block/review-queue write still succeeded.",
                purl, orgId, gate);
        }
    }

    /// <summary>
    /// Raises a <see cref="AlertTypes.VulnSeverity"/> alert when a scanned advisory's severity
    /// meets or exceeds the org's <c>vuln_min_severity</c> floor. Unscored advisories (empty/null
    /// severity) never alert regardless of the configured floor —
    /// <see cref="OsvScoring.MeetsSeverityThreshold"/> is the single source of truth for that rule.
    /// The dedup key is <c>vulnId:ecosystem:packageName</c> — one alert per advisory-per-package,
    /// not per version, so a fleet of versions sharing the same advisory raises once.
    /// </summary>
    public async Task RaiseVulnAlertAsync(
        string orgId, string ecosystem, string packageName, string purl,
        string vulnId, string? severity, CancellationToken ct = default)
    {
        try
        {
            var settings = await _alerts.GetRaiseSettingsAsync(orgId, ct);
            if (!settings.VulnAlertsEnabled || !OsvScoring.MeetsSeverityThreshold(severity, settings.VulnMinSeverity))
            {
                return;
            }

            string sourceRef = $"{vulnId}:{ecosystem}:{packageName}";
            var alert = await _alerts.TryInsertAsync(
                new NewAlert(
                    OrgId: orgId,
                    Type: AlertTypes.VulnSeverity,
                    Severity: severity,
                    SourceRef: sourceRef,
                    Ecosystem: ecosystem,
                    Purl: purl,
                    Title: $"{severity} vulnerability {vulnId} in {packageName}",
                    Detail: null),
                ct);

            if (alert is not null)
            {
                await _notifier.NotifyAsync(alert, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Failed to raise vuln alert for {VulnId} in {PackageName} (org {OrgId}); the scan result was still persisted.",
                vulnId, packageName, orgId);
        }
    }
}
