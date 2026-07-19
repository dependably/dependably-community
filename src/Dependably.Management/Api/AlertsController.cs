using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Localization;

namespace Dependably.Api;

/// <summary>
/// Per-tenant alert center, surfaced as the topbar bell (admin/owner only — <c>read:tenant</c>
/// and <c>tenant:configure</c> are not granted to member/auditor). GET routes list/summarize
/// alert rows; dismiss records a shared active/dismissed flag all admins in the org see the same
/// way. Settings live under <c>/api/v1/alert-settings</c>: the base GET/PUT own the Alerts-tab
/// columns — the gates (severity floor, per-type toggles) plus the email delivery gate and its
/// recipient list; <c>/alert-settings/slack</c> owns the optional Slack delivery channel,
/// write-only for the webhook URL — GET/PUT never echo the raw URL, only a computed
/// <c>hasSlackWebhook</c> boolean, mirroring <see cref="WebhookController"/>'s secret-handling
/// convention. <c>/alert-settings/email</c> owns the email SMTP transport: the password is
/// write-only (<c>hasEmailSmtpPassword</c>) and <c>instanceEmailConfigured</c> tells the UI
/// whether inheriting the instance transport would actually resolve to something, without ever
/// exposing the instance's own host/username/etc. Splitting the write surface this way means an
/// Alerts-tab save and an Integrations-tab save can never clobber each other's columns.
/// </summary>
[ApiController]
[Authorize]
public sealed class AlertsController : OrgScopedControllerBase
{
    // Audit-detail-only options: the shared camelCase Web contract with the relaxed encoder so a
    // purl's query-string-shaped characters don't render with literal \uXXXX escapes in the audit UI.
    private static readonly JsonSerializerOptions WebJson = new(JsonContracts.Web)
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly HashSet<string> ValidSeverities = new(StringComparer.OrdinalIgnoreCase)
    {
        "LOW", "MEDIUM", "HIGH", "CRITICAL"
    };

    private const int MaxAlertPageSize = 200;

    private readonly AlertRepository _alerts;
    private readonly AlertSettingsRepository _settings;
    private readonly SlackWebhookClient _slackClient;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly EnvelopeProtector _envelope;
    private readonly IConfiguration _config;
    private readonly ILogger<AlertsController> _logger;

#pragma warning disable S107 // constructor injection of independently-registered DI services
    public AlertsController(
        AlertRepository alerts,
        AlertSettingsRepository settings,
        SlackWebhookClient slackClient,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems,
        EnvelopeProtector envelope,
        IConfiguration config,
        ILogger<AlertsController> logger)
#pragma warning restore S107
    {
        _alerts = alerts;
        _settings = settings;
        _slackClient = slackClient;
        _guard = guard;
        _audit = audit;
        _problems = problems;
        _envelope = envelope;
        _config = config;
        _logger = logger;
    }

    /// <summary>GET /api/v1/alerts?state=active&amp;limit=50&amp;offset=0</summary>
    [HttpGet("api/v1/alerts")]
    public async Task<IActionResult> List(
        [FromQuery] string? state, [FromQuery] int limit = 50, [FromQuery] int offset = 0,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        if (state is not (null or "active" or "dismissed"))
        {
            return _problems.ValidationErrorActionKey("state", "error.alert.stateInvalid");
        }

        limit = Math.Clamp(limit, 1, MaxAlertPageSize);
        offset = Math.Max(offset, 0);

        var (items, total) = await _alerts.ListAsync(CurrentTenantId(), state, limit, offset, ct);
        return Ok(new { total, items });
    }

    /// <summary>GET /api/v1/alerts/summary — backs the topbar bell badge.</summary>
    [HttpGet("api/v1/alerts/summary")]
    public async Task<IActionResult> Summary(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        int activeCount = await _alerts.CountActiveAsync(CurrentTenantId(), ct);
        return Ok(new { activeCount });
    }

    /// <summary>
    /// POST /api/v1/alerts/{id}/dismiss — idempotent; a repeat dismiss returns 200 without
    /// re-auditing. Unknown or cross-tenant id is 404 (BOLA guard, same convention as
    /// <see cref="QuarantineController"/>).
    /// </summary>
    [HttpPost("api/v1/alerts/{id}/dismiss")]
    public async Task<IActionResult> Dismiss(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var alert = await _alerts.GetByIdAsync(orgId, id, ct);
        if (alert is null)
        {
            return NotFound();
        }

        if (alert.State == "dismissed")
        {
            // Idempotent repeat — no state change, no audit row.
            return Ok(new { id = alert.Id, state = alert.State });
        }

        string? userId = GetUserId();
        bool changed = await _alerts.DismissAsync(orgId, id, userId, ct);
        if (!changed)
        {
            // Raced with another admin's dismiss between the read and the guarded update.
            return Ok(new { id = alert.Id, state = "dismissed" });
        }

        await _audit.LogAsync("alert_dismissed", orgId, userId,
            detail: JsonSerializer.Serialize(new { id = alert.Id, type = alert.Type, purl = alert.Purl }, WebJson),
            ct: ct);

        return Ok(new { id = alert.Id, state = "dismissed" });
    }

    /// <summary>
    /// GET /api/v1/alert-settings — the full projection (gates + Slack + email), plus
    /// <c>secretsAvailable</c> (whether a master key is configured) so the Integrations tab can
    /// grey the Slack/email secret inputs with an explanatory hint when they can't be saved, and
    /// <c>instanceEmailConfigured</c> (boolean only — never the instance's own SMTP details) so
    /// the email inherit-instance checkbox can show whether inheriting would resolve to anything.
    /// </summary>
    [HttpGet("api/v1/alert-settings")]
    public async Task<IActionResult> GetSettings(
        [FromServices] InstanceSmtpConfig instanceSmtp, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        var settings = await _settings.GetAsync(CurrentTenantId(), ct);
        var instance = await instanceSmtp.ResolveAsync(ct);
        return Ok(settings with
        {
            SecretsAvailable = _envelope.IsConfigured,
            InstanceEmailConfigured = instance.Enabled && instance.Configured,
        });
    }

    /// <summary>
    /// PUT /api/v1/alert-settings — the Alerts-tab columns: the gates (quarantine/vuln toggles,
    /// severity floor) plus the email delivery gate (<c>emailEnabled</c>) and its recipient list.
    /// <c>emailRecipients</c> is comma-separated and validated (each entry must parse as an email
    /// address, capped at <see cref="EmailRecipients.MaxRecipients"/>). Never touches the Slack or
    /// SMTP-transport columns; use <see cref="UpdateSlackSettings"/> /
    /// <see cref="UpdateEmailSettings"/> for those. Audits alert_settings_updated with the gate
    /// fields, the email toggle, and the recipient count.
    /// </summary>
    [HttpPut("api/v1/alert-settings")]
    public async Task<IActionResult> UpdateSettings(
        [FromBody] AlertSettingsRequest req,
        [FromServices] InstanceSmtpConfig instanceSmtp,
        CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (!string.IsNullOrEmpty(req.VulnMinSeverity) && !ValidSeverities.Contains(req.VulnMinSeverity))
        {
            return _problems.ValidationErrorActionKey("vulnMinSeverity", "error.alert.severityInvalid");
        }

        var (recipients, recipientsErrorKey) = EmailRecipients.Validate(req.EmailRecipients);
        if (recipientsErrorKey is not null)
        {
            return _problems.ValidationErrorActionKey("emailRecipients", recipientsErrorKey);
        }

        string orgId = CurrentTenantId();
        string? recipientsStored = recipients is { Length: > 0 } ? string.Join(",", recipients) : null;

        var updated = await _settings.UpdateGatesAsync(orgId, new UpdateAlertGates(
            req.QuarantineAlertsEnabled, req.VulnAlertsEnabled,
            string.IsNullOrEmpty(req.VulnMinSeverity) ? "HIGH" : req.VulnMinSeverity.ToUpperInvariant(),
            req.EmailEnabled, recipientsStored), ct);

        await _audit.LogAsync("alert_settings_updated", orgId, GetUserId(),
            detail: JsonSerializer.Serialize(new
            {
                quarantineAlertsEnabled = updated.QuarantineAlertsEnabled,
                vulnAlertsEnabled = updated.VulnAlertsEnabled,
                vulnMinSeverity = updated.VulnMinSeverity,
                emailEnabled = updated.EmailEnabled,
                recipientCount = recipients?.Length ?? 0,
            }, WebJson),
            ct: ct);

        var instance = await instanceSmtp.ResolveAsync(ct);
        return Ok(updated with
        {
            SecretsAvailable = _envelope.IsConfigured,
            InstanceEmailConfigured = instance.Enabled && instance.Configured,
        });
    }

    /// <summary>
    /// PUT /api/v1/alert-settings/slack — <c>slackWebhookUrl</c> is write-only: a non-empty value
    /// rotates the encrypted URL (requires DEPENDABLY_MASTER_KEY), null/absent leaves it
    /// unchanged. Never touches the gate columns. Audits alert_settings_updated with
    /// <c>slackEnabled</c> only — never the URL.
    /// </summary>
    [HttpPut("api/v1/alert-settings/slack")]
    public async Task<IActionResult> UpdateSlackSettings(
        [FromBody] AlertSlackSettingsRequest req,
        [FromServices] InstanceSmtpConfig instanceSmtp,
        CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (!string.IsNullOrEmpty(req.SlackWebhookUrl))
        {
            if (!_envelope.IsConfigured)
            {
                return _problems.ValidationErrorActionKey("slackWebhookUrl", "error.alert.masterKeyRequired");
            }

            bool allowPrivate = string.Equals(
                _config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);
            string? urlError = Dependably.Infrastructure.Webhooks.WebhookDeliveryClient.ValidateWebhookUrl(
                req.SlackWebhookUrl, allowPrivate);
            if (urlError is not null)
            {
                return _problems.ValidationErrorAction("slackWebhookUrl", urlError);
            }
        }

        string orgId = CurrentTenantId();
        var updated = await _settings.UpdateSlackAsync(orgId, new UpdateAlertSlack(
            req.SlackEnabled, req.SlackWebhookUrl), ct);

        await _audit.LogAsync("alert_settings_updated", orgId, GetUserId(),
            detail: JsonSerializer.Serialize(new
            {
                slackEnabled = updated.SlackEnabled,
            }, WebJson),
            ct: ct);

        var instance = await instanceSmtp.ResolveAsync(ct);
        return Ok(updated with
        {
            SecretsAvailable = _envelope.IsConfigured,
            InstanceEmailConfigured = instance.Enabled && instance.Configured,
        });
    }

    /// <summary>
    /// POST /api/v1/alert-settings/slack/test — sends a synchronous test message via the
    /// currently-configured Slack webhook (not through the async delivery queue) so the operator
    /// gets an immediate success/failure result.
    /// </summary>
    [HttpPost("api/v1/alert-settings/slack/test")]
    public async Task<IActionResult> TestSlack(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        string? webhookUrl = await _settings.GetDecryptedSlackWebhookUrlAsync(orgId, ct);
        if (webhookUrl is null)
        {
            return _problems.ValidationErrorActionKey("slackWebhookUrl", "error.alert.slackNotConfigured");
        }

        try
        {
            await _slackClient.SendAsync(webhookUrl, ":white_check_mark: Dependably alert test — Slack delivery is working.", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                ex,
                "Alert Slack test send failed: {ExceptionType} org={OrgId} trace={TraceId}",
                ex.GetType().Name,
                orgId,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
            return _problems.ValidationErrorActionKey("slackWebhookUrl", "error.alert.slackTestFailedGeneric");
        }

        return NoContent();
    }

    /// <summary>
    /// PUT /api/v1/alert-settings/email — full-form replacement of the email SMTP transport
    /// (inherit flag + own-transport fields); never touches the gate, Slack, or email
    /// delivery-gate columns (the email toggle and recipients belong to
    /// <see cref="UpdateSettings"/>). <c>emailSmtpPassword</c> is write-only (empty/absent
    /// preserves the stored value, non-empty rotates it and requires
    /// <see cref="EnvelopeProtector.IsConfigured"/>). An IP-literal <c>emailSmtpHost</c> in a
    /// blocked SSRF range is rejected unless <c>WEBHOOK_ALLOW_PRIVATE=true</c> (via
    /// <see cref="HostSsrfValidator"/>), reusing the same posture as the Slack webhook URL check
    /// above — a hostname is not resolved at save time (DNS can change between save and send, and
    /// a resolution failure here would reject a value the operator has not tried to use yet); the
    /// authoritative, DNS-rebinding-aware gate is the connect-time guard
    /// <see cref="SmtpMailSender"/> runs on every send. Audits alert_email_settings_updated with
    /// the non-secret fields only (inherit flag, host).
    /// </summary>
    [HttpPut("api/v1/alert-settings/email")]
    public async Task<IActionResult> UpdateEmailSettings(
        [FromBody] AlertEmailSettingsRequest req,
        [FromServices] InstanceSmtpConfig instanceSmtp,
        CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        // An explicit JSON null bypasses the property initializer; coalesce to "" so it fails
        // Validate's security-mode check as a 422 instead of dereferencing null further down.
        string requestedSecurity = req.EmailSmtpSecurity ?? "";
        var (field, resourceKey) = SmtpTransportSettings.Validate(req.EmailSmtpPort, requestedSecurity, req.EmailSmtpFrom);
        if (field is not null)
        {
            string apiFieldName = field switch
            {
                "port" => "emailSmtpPort",
                "security" => "emailSmtpSecurity",
                "fromAddress" => "emailSmtpFrom",
                _ => field,
            };
            return _problems.ValidationErrorActionKey(apiFieldName, resourceKey!);
        }

        if (!string.IsNullOrEmpty(req.EmailSmtpPassword) && !_envelope.IsConfigured)
        {
            return _problems.ValidationErrorActionKey("emailSmtpPassword", "error.email.masterKeyRequired");
        }

        if (!string.IsNullOrWhiteSpace(req.EmailSmtpHost))
        {
            bool allowPrivate = string.Equals(
                _config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);
            Func<System.Net.IPAddress, bool> isBlocked = allowPrivate
                ? SsrfGuard.IsBlockedIpExcludingPrivate
                : SsrfGuard.IsBlockedIp;
            if (HostSsrfValidator.IsHostBlocked(req.EmailSmtpHost, isBlocked))
            {
                return _problems.ValidationErrorActionKey("emailSmtpHost", "error.email.hostBlocked");
            }
        }

        string orgId = CurrentTenantId();

        var updated = await _settings.UpdateEmailAsync(orgId, new UpdateAlertEmail(
            req.EmailInheritInstance,
            req.EmailSmtpHost,
            req.EmailSmtpPort,
            requestedSecurity.ToLowerInvariant(),
            req.EmailSmtpUsername,
            req.EmailSmtpPassword,
            req.EmailSmtpFrom), ct);

        await _audit.LogAsync("alert_email_settings_updated", orgId, GetUserId(),
            detail: JsonSerializer.Serialize(new
            {
                emailInheritInstance = updated.EmailInheritInstance,
                emailSmtpHost = updated.EmailSmtpHost,
            }, WebJson),
            ct: ct);

        var instance = await instanceSmtp.ResolveAsync(ct);
        return Ok(updated with
        {
            SecretsAvailable = _envelope.IsConfigured,
            InstanceEmailConfigured = instance.Enabled && instance.Configured,
        });
    }

    /// <summary>
    /// POST /api/v1/alert-settings/email/test — resolves the effective transport through
    /// <see cref="EffectiveEmailConfigResolver"/> (so an inherit-instance org genuinely exercises
    /// the inherit path, not just its own columns) and sends a test message to the org's
    /// configured recipients. Rate-limited like the other test-send endpoints.
    /// </summary>
    [HttpPost("api/v1/alert-settings/email/test")]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> TestEmail(
        [FromServices] EffectiveEmailConfigResolver resolver,
        [FromServices] SmtpMailSender sender,
        [FromServices] IStringLocalizer<SharedResource> localizer,
        CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var resolved = await resolver.ResolveAsync(orgId, ct);
        if (resolved is null)
        {
            return _problems.ValidationErrorActionKey("email", "error.email.notConfigured");
        }

        try
        {
            await sender.SendAsync(
                resolved.Transport,
                resolved.Recipients,
                localizer["email.test.subject"],
                localizer["email.test.body"],
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                ex,
                "Alert email test send failed: {ExceptionType} org={OrgId} host={Host} port={Port} trace={TraceId}",
                ex.GetType().Name,
                orgId,
                resolved.Transport.Host,
                resolved.Transport.Port,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
            return _problems.ValidationErrorActionKey("email", "error.email.testFailedGeneric");
        }

        return NoContent();
    }
}

/// <summary>Request body for PUT /api/v1/alert-settings — the Alerts-tab columns: gates plus the
/// email delivery gate and recipient list.</summary>
public sealed class AlertSettingsRequest
{
    public bool QuarantineAlertsEnabled { get; set; } = true;
    public bool VulnAlertsEnabled { get; set; } = true;
    public string? VulnMinSeverity { get; set; }
    public bool EmailEnabled { get; set; }
    /// <summary>Comma-separated. Empty/absent means the email channel has no recipients (nothing sends).</summary>
    public string? EmailRecipients { get; set; }
}

/// <summary>Request body for PUT /api/v1/alert-settings/slack.</summary>
public sealed class AlertSlackSettingsRequest
{
    public bool SlackEnabled { get; set; }
    /// <summary>Write-only. Null/empty on update means "leave the stored URL unchanged".</summary>
    public string? SlackWebhookUrl { get; set; }
}

/// <summary>
/// Request body for PUT /api/v1/alert-settings/email — a full-form replacement of the SMTP
/// transport the caller always supplies in full, mirroring
/// <see cref="Dependably.Infrastructure.Mail.EmailConfigRequest"/>'s write-only-secret
/// convention: every field except <see cref="EmailSmtpPassword"/> replaces the stored value
/// outright. The email delivery gate and recipients belong to <see cref="AlertSettingsRequest"/>.
/// </summary>
public sealed class AlertEmailSettingsRequest
{
    public bool EmailInheritInstance { get; set; } = true;
    public string? EmailSmtpHost { get; set; }
    public int EmailSmtpPort { get; set; } = Dependably.Infrastructure.Mail.SmtpTransportSettings.DefaultPort;
    public string EmailSmtpSecurity { get; set; } = Dependably.Infrastructure.Mail.SmtpTransportSettings.DefaultSecurity;
    public string? EmailSmtpUsername { get; set; }
    /// <summary>Write-only. Null/empty on update means "leave the stored password unchanged".</summary>
    public string? EmailSmtpPassword { get; set; }
    public string? EmailSmtpFrom { get; set; }
}
