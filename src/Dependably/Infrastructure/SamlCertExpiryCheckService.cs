using Cronos;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Daily background sweep that checks the effective IdP signing certificate expiry for every
/// tenant with SAML configured and emits <c>audit_log</c> events at configurable thresholds.
///
/// Alert stages (days-to-expiry): 30, 14, 7, 1, and "expired". Once a stage event has been
/// emitted, no duplicate is sent until the cert changes (which resets <c>cert_expiry_alert_stage</c>
/// to NULL) or a later stage is reached. Stage progression is strictly forward-only for the
/// same cert: a tenant that received a "30d" alert only gets "14d" when the window shrinks
/// past 14 — it never gets a second "30d" for the same cert.
///
/// Configured via:
///   SAML_CERT_EXPIRY_WARN_DAYS — comma-separated list of day thresholds (default "30,14,7,1")
///   SAML_CERT_EXPIRY_SCHEDULE  — cron expression in standard format (default "0 6 * * *", 06:00 UTC)
///   SAML_CERT_EXPIRY_JITTER_SECONDS — max random jitter added to the scheduled time (default 1800)
/// </summary>
public sealed class SamlCertExpiryCheckService : BackgroundService
{
    private readonly SamlConfigRepository _samlConfig;
    private readonly AuditRepository _audit;
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<SamlCertExpiryCheckService> _logger;

    public SamlCertExpiryCheckService(
        SamlConfigRepository samlConfig,
        AuditRepository audit,
        IConfiguration config,
        IAirGapMode airGap,
        ILogger<SamlCertExpiryCheckService> logger)
    {
        _samlConfig = samlConfig;
        _audit = audit;
        _config = config;
        _airGap = airGap;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Run an initial pass shortly after startup so freshly-configured certs are checked
        // without waiting for the next cron tick.
        try
        {
            await RunCheckPassAsync(stoppingToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SAML cert-expiry startup check pass failed.");
        }

        var schedule = CronExpression.Parse(
            _config["SAML_CERT_EXPIRY_SCHEDULE"] ?? "0 6 * * *",
            CronFormat.Standard);

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!await WaitForNextOccurrenceAsync(schedule, stoppingToken))
            {
                break;
            }

            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                await RunCheckPassAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SAML cert-expiry check pass failed.");
            }
        }
    }

    /// <summary>
    /// Sleeps until the next cron occurrence plus a random load-spreading jitter.
    /// Returns false when the schedule has no further occurrence or the host is stopping,
    /// which ends the scheduling loop.
    /// </summary>
    private async Task<bool> WaitForNextOccurrenceAsync(CronExpression schedule, CancellationToken stoppingToken)
    {
        var next = schedule.GetNextOccurrence(DateTimeOffset.UtcNow, TimeZoneInfo.Utc);
        if (next is null)
        {
            return false;
        }

        int jitterMaxSeconds = int.TryParse(_config["SAML_CERT_EXPIRY_JITTER_SECONDS"], out int j) && j >= 0
            ? j
            : 1800;

        // SCS0005: load-spreading jitter, not a security boundary — weak RNG is intentional.
#pragma warning disable SCS0005
        var jitter = jitterMaxSeconds > 0
            ? TimeSpan.FromSeconds(Random.Shared.Next(0, jitterMaxSeconds + 1))
            : TimeSpan.Zero;
#pragma warning restore SCS0005

        var delay = (next.Value - DateTimeOffset.UtcNow) + jitter;
        if (delay > TimeSpan.Zero)
        {
            try { await Task.Delay(delay, stoppingToken); }
            catch (OperationCanceledException) { return false; }
        }

        return true;
    }

    internal async Task RunCheckPassAsync(CancellationToken ct)
    {
        using var scope = Observability.BackgroundJobScope.Begin("saml-cert-expiry", "saml.cert_expiry_check");
        try
        {
            await RunCheckPassInnerAsync(ct);
            scope.Complete();
        }
        catch (Exception ex)
        {
            scope.Fail(ex);
            throw;
        }
    }

    private async Task RunCheckPassInnerAsync(CancellationToken ct)
    {
        if (_airGap.IsJobDisabled("saml-cert-expiry"))
        {
            _logger.LogInformation("SAML cert-expiry check pass skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return;
        }

        int[] warnDays = ParseWarnDays(_config["SAML_CERT_EXPIRY_WARN_DAYS"] ?? "30,14,7,1");

        _logger.LogInformation(
            "SAML cert-expiry check pass starting (thresholds: {Thresholds}d).",
            string.Join(",", warnDays));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var rows = await _samlConfig.GetAllCertRowsAsync(ct);

        int alerted = 0;
        int skipped = 0;
        int errors = 0;

        foreach (var row in rows)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            try
            {
                bool acted = await CheckOrgCertAsync(row, warnDays, ct);
                if (acted)
                {
                    alerted++;
                }
                else
                {
                    skipped++;
                }
            }
            catch (Exception ex)
            {
                errors++;
                _logger.LogWarning(ex, "SAML cert-expiry check failed for org {OrgId}; skipping.", row.OrgId);
            }
        }

        sw.Stop();
        _logger.LogInformation(
            "SAML cert-expiry check pass complete. Checked {Total} orgs: {Alerted} alerted, {Skipped} already-notified/no-cert, {Errors} error(s), took {ElapsedMs}ms.",
            rows.Count, alerted, skipped, errors, sw.ElapsedMilliseconds);
    }

    // Returns true if an audit event was emitted (stage advanced), false otherwise.
    private async Task<bool> CheckOrgCertAsync(TenantSamlCertRow row, int[] warnDays, CancellationToken ct)
    {
        // Override wins; fall back to metadata cert.
        string? effectiveCert = !string.IsNullOrWhiteSpace(row.IdpSigningCertOverride)
            ? row.IdpSigningCertOverride
            : row.IdpSigningCert;

        if (string.IsNullOrWhiteSpace(effectiveCert))
        {
            return false;
        }

        // Parse failure is a per-org skip, not a fatal error — the sweep continues.
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
        string thumbprint;
        DateTimeOffset notAfter;
        try
        {
            byte[] bytes = Convert.FromBase64String(
                effectiveCert.Replace("\n", "").Replace("\r", "").Replace(" ", ""));
            cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(bytes);
            thumbprint = cert.Thumbprint;
            notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not parse SAML IdP cert for org {OrgId}; skipping cert-expiry check.", row.OrgId);
            return false;
        }

        double daysRemaining = (notAfter - DateTimeOffset.UtcNow).TotalDays;
        string targetStage = ComputeTargetStage(daysRemaining, warnDays);

        // No alert warranted yet (beyond the longest warn window and not expired).
        if (targetStage == "none")
        {
            return false;
        }

        // Already emitted this stage for the current cert — nothing new to do.
        if (!IsStageAdvancement(row.CertExpiryAlertStage, targetStage))
        {
            return false;
        }

        string action = targetStage == "expired"
            ? "saml.signing_cert_expired"
            : "saml.signing_cert_expiring";

        string detail = System.Text.Json.JsonSerializer.Serialize(new
        {
            thumbprint,
            days_remaining = (int)Math.Floor(daysRemaining),
            not_after = notAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            stage = targetStage,
        });

        await _audit.LogAsync(action, orgId: row.OrgId, detail: detail, ct: ct);
        await _samlConfig.SetCertExpiryAlertStageAsync(row.OrgId, targetStage, ct);

        _logger.LogWarning(
            "SAML signing cert for org {OrgId} is {Stage}: thumbprint={Thumbprint}, " +
            "daysRemaining={Days}, notAfter={NotAfter}.",
            row.OrgId, targetStage, thumbprint, (int)Math.Floor(daysRemaining),
            notAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"));

        return true;
    }

    // Determines the alert stage for a given days-to-expiry value.
    // Returns "none" when no threshold is met (cert is healthy and outside all warn windows).
    // Returns "expired" when daysRemaining < 0.
    // Returns the highest triggered threshold as a string ("30", "14", "7", "1") otherwise.
    internal static string ComputeTargetStage(double daysRemaining, int[] warnDays)
    {
        if (daysRemaining < 0)
        {
            return "expired";
        }

        // Find the tightest (smallest) threshold the cert has already entered.
        // A cert with 5 days left and thresholds [30,14,7,1] is in stage "7" because 5 <= 7
        // is the smallest satisfied threshold — it has crossed the 7d boundary (and also the
        // 14d and 30d ones), but the most recent crossing is the 7d threshold.
        // Iterate ascending so the first match is the smallest satisfied threshold.
        int[] sorted = warnDays.OrderBy(d => d).ToArray();
        foreach (int threshold in sorted)
        {
            if (daysRemaining <= threshold)
            {
                return threshold.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
        }
        return "none";
    }

    // Returns true when moving from currentStage to targetStage represents an advancement
    // (i.e., a new event should be emitted). "expired" > "1" > "7" > "14" > "30" > null.
    // Stage values that are not recognized default to the lowest priority (null behaviour).
    internal static bool IsStageAdvancement(string? currentStage, string targetStage)
    {
        if (currentStage == targetStage)
        {
            return false;
        }
        int currentPriority = StagePriority(currentStage);
        int targetPriority = StagePriority(targetStage);
        return targetPriority > currentPriority;
    }

    private static int StagePriority(string? stage) => stage switch
    {
        "30" => 1,
        "14" => 2,
        "7" => 3,
        "1" => 4,
        "expired" => 5,
        _ => 0,
    };

    private static int[] ParseWarnDays(string raw)
    {
        return raw
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => int.TryParse(s, out int d) && d > 0 ? d : 0)
            .Where(d => d > 0)
            .Distinct()
            .OrderByDescending(d => d)
            .ToArray();
    }
}
