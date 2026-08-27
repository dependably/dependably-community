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

    /// <summary>
    /// Raises a <see cref="AlertTypes.VulnKev"/> alert for a scanned advisory that is listed in
    /// the CISA Known Exploited Vulnerabilities catalog — gated only on
    /// <c>settings.VulnAlertsEnabled</c>, deliberately with no severity check: exploitation
    /// evidence is the strongest signal held on an advisory and must not be silenced by a missing
    /// or below-floor CVSS score. <see cref="RaiseVulnAlertAsync"/> keeps its own
    /// <see cref="OsvScoring.MeetsSeverityThreshold"/> gate unchanged, so the two arms can fire
    /// independently for the same advisory (different types, different information content).
    /// The dedup key is the same <c>vulnId:ecosystem:packageName</c> shape as
    /// <see cref="RaiseVulnAlertAsync"/> — a different <see cref="AlertTypes.VulnKev"/>
    /// <c>Type</c> in the <c>(org_id, type, source_ref)</c> UNIQUE tuple is what lets the two
    /// alert types coexist as independent rows instead of colliding.
    ///
    /// <para>
    /// <b>Backlog posture:</b> this call site runs on every scan and every rescan of an
    /// already-linked advisory, not only on first link. A KEV catalog addition for a
    /// package already scanned before that addition does not alert immediately — it alerts on
    /// that package's next natural rescan, bounded by the existing scan/rescan cadence, not
    /// real-time. This is deliberate: there is no first-pass-burst or staged-rollout primitive in
    /// this codebase to build on, so the fix rides the periodic rescan cadence that already
    /// exists. It is safe to ride because <see cref="AlertRepository.TryInsertAsync"/>'s
    /// <c>ON CONFLICT DO NOTHING</c> makes every raise attempt idempotent forever — the backlog
    /// of already-KEV, never-alerted advisories drains gradually as each package's turn comes up
    /// in the rescan cycle, rather than firing as one synchronous burst against email/Slack on
    /// deploy day.
    /// </para>
    /// </summary>
    public async Task RaiseVulnKevAlertAsync(
        string orgId, string ecosystem, string packageName, string purl,
        string vulnId, string? severity, bool? knownRansomwareCampaignUse, CancellationToken ct = default)
    {
        try
        {
            var settings = await _alerts.GetRaiseSettingsAsync(orgId, ct);
            if (!settings.VulnAlertsEnabled)
            {
                return;
            }

            string sourceRef = $"{vulnId}:{ecosystem}:{packageName}";
            string severityLabel = string.IsNullOrEmpty(severity) ? "UNSCORED" : severity;

            // The tri-state must render as three distinct, legible sentences — true/false/null are
            // not "ransomware" vs "not ransomware": false is CISA's own explicit "no known use"
            // assertion, and null is CISA saying nothing at all. Collapsing false and null would
            // hide a real answer behind an absence.
            string ransomwareLine = knownRansomwareCampaignUse switch
            {
                true => "CISA marks this entry as used in ransomware campaigns.",
                false => "CISA has not recorded ransomware-campaign use for this entry.",
                null => "No ransomware-campaign assertion is recorded for this entry.",
            };

            var alert = await _alerts.TryInsertAsync(
                new NewAlert(
                    OrgId: orgId,
                    Type: AlertTypes.VulnKev,
                    Severity: severity,
                    SourceRef: sourceRef,
                    Ecosystem: ecosystem,
                    Purl: purl,
                    Title: $"Known-exploited vulnerability {vulnId} in {packageName} ({severityLabel})",
                    Detail: $"{vulnId} is listed in the CISA Known Exploited Vulnerabilities catalog. {ransomwareLine}"),
                ct);

            if (alert is not null)
            {
                await _notifier.NotifyAsync(alert, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Failed to raise KEV vuln alert for {VulnId} in {PackageName} (org {OrgId}); the scan result was still persisted.",
                vulnId, packageName, orgId);
        }
    }

    /// <summary>
    /// Raises a <see cref="AlertTypes.SbomPolicyViolation"/> alert the first time a project
    /// version's policy evaluation records at least one violation. The dedup key is the project
    /// version id alone (not per-component or per-arm): the findings table already carries every
    /// individual violation and a re-evaluation replaces that set wholesale, so the alert's job is
    /// only to tell the team once that this version has a problem, not to fan out one alert per
    /// violation. This also gives <c>EmailOutboxCoalescing.ForAlert</c> its coalescing key of
    /// exactly <c>sbom_policy_violation:{projectVersionId}</c> for free (no purl is set, so the
    /// coalesce key falls back to <paramref name="projectVersionId"/> — the same value as
    /// <see cref="NewAlert.SourceRef"/>).
    /// </summary>
    public async Task RaiseSbomPolicyViolationAlertAsync(
        string orgId, string projectVersionId, string projectName, string versionLabel,
        int violationCount, CancellationToken ct = default)
    {
        try
        {
            var settings = await _alerts.GetRaiseSettingsAsync(orgId, ct);
            if (!settings.SbomPolicyAlertsEnabled)
            {
                return;
            }

            var alert = await _alerts.TryInsertAsync(
                new NewAlert(
                    OrgId: orgId,
                    Type: AlertTypes.SbomPolicyViolation,
                    Severity: null,
                    SourceRef: projectVersionId,
                    Ecosystem: null,
                    Purl: null,
                    Title: $"SBOM policy violation: {projectName} {versionLabel} ({violationCount} finding(s))",
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
                "Failed to raise SBOM policy alert for project version {ProjectVersionId} (org {OrgId}); the findings were still persisted.",
                projectVersionId, orgId);
        }
    }
}
