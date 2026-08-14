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
/// way. Settings live under <c>/api/v1/alert-settings</c>, whose write surface is split one
/// endpoint per editing surface: the base GET/PUT own the Alerts-tab gates (severity floor,
/// per-type toggles); <c>/alert-settings/email</c> owns the email delivery channel (the gate and
/// its recipient list); <c>/alert-settings/slack</c> owns the optional Slack delivery channel,
/// write-only for the webhook URL — GET/PUT never echo the raw URL, only a computed
/// <c>hasSlackWebhook</c> boolean, mirroring <see cref="WebhookController"/>'s secret-handling
/// convention. Both delivery channels are edited on the Integrations tab. There is no per-org SMTP transport: SMTP is an instance-level transport, and an org
/// configures only whether alert mail is sent and to whom. <c>instanceEmailConfigured</c> tells the
/// UI whether that transport currently resolves — a boolean only, never the instance's own
/// host/username/etc — so an admin can be told their recipients would go nowhere. Splitting the
/// write surface this way means a gates save and either channel's save can never clobber each
/// other's columns.
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
            actorKind: ActorKinds.User,
            detail: JsonSerializer.Serialize(new { id = alert.Id, type = alert.Type, purl = alert.Purl }, WebJson),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(new { id = alert.Id, state = "dismissed" });
    }

    /// <summary>
    /// POST /api/v1/alerts/dismiss-all — dismisses every active alert in the caller's org and
    /// returns how many were dismissed. Server-side rather than a client loop over the rendered
    /// page: the list is paged, so the caller can only see part of what it is asking to clear.
    /// Idempotent — a repeat call dismisses nothing, returns <c>dismissed: 0</c>, and writes no
    /// audit row, matching the single-alert dismiss.
    /// </summary>
    [HttpPost("api/v1/alerts/dismiss-all")]
    public async Task<IActionResult> DismissAll(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        string? userId = GetUserId();
        int dismissed = await _alerts.DismissAllActiveAsync(orgId, userId, ct);

        if (dismissed > 0)
        {
            // One audit row carrying the count, not one per alert: the operator action being
            // recorded is the bulk clear, and the per-alert rows are recoverable from the alert
            // table's own dismissed_by/dismissed_at stamps.
            await _audit.LogAsync("alert_dismissed_all", orgId, userId,
                actorKind: ActorKinds.User,
                detail: JsonSerializer.Serialize(new { dismissed }, WebJson),
                sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        }

        return Ok(new { dismissed });
    }

    /// <summary>
    /// GET /api/v1/alert-settings — the full projection (gates + Slack + email), plus
    /// <c>secretsAvailable</c> (whether a master key is configured) so the Integrations tab can
    /// grey the Slack webhook input with an explanatory hint when it can't be saved, and
    /// <c>instanceEmailConfigured</c> (boolean only — never the instance's own SMTP details) so
    /// the Integrations tab can tell an admin their recipients would go nowhere.
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
    /// PUT /api/v1/alert-settings — the Alerts-tab gates: the quarantine/vuln toggles and the
    /// severity floor. Never touches a delivery channel's columns; use
    /// <see cref="UpdateEmailChannel"/> and <see cref="UpdateSlackSettings"/> for those. Audits
    /// alert_settings_updated with the gate fields.
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

        string orgId = CurrentTenantId();

        var updated = await _settings.UpdateGatesAsync(orgId, new UpdateAlertGates(
            req.QuarantineAlertsEnabled, req.VulnAlertsEnabled,
            string.IsNullOrEmpty(req.VulnMinSeverity) ? "HIGH" : req.VulnMinSeverity.ToUpperInvariant()), ct);

        await _audit.LogAsync("alert_settings_updated", orgId, GetUserId(),
            detail: JsonSerializer.Serialize(new
            {
                quarantineAlertsEnabled = updated.QuarantineAlertsEnabled,
                vulnAlertsEnabled = updated.VulnAlertsEnabled,
                vulnMinSeverity = updated.VulnMinSeverity,
            }, WebJson),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        var instance = await instanceSmtp.ResolveAsync(ct);
        return Ok(updated with
        {
            SecretsAvailable = _envelope.IsConfigured,
            InstanceEmailConfigured = instance.Enabled && instance.Configured,
        });
    }

    /// <summary>
    /// PUT /api/v1/alert-settings/email — the email delivery channel: the gate
    /// (<c>emailEnabled</c>) and the recipient list. <c>emailRecipients</c> is comma-separated and
    /// validated (each entry must parse as an email address, capped at
    /// <see cref="EmailRecipients.MaxRecipients"/>). Never touches the gate or Slack columns, so
    /// an Integrations-tab email save can't clobber an Alerts-tab or Slack save. There is no SMTP
    /// transport here — that is instance-level. Audits alert_settings_updated with the email
    /// toggle and the recipient count, never the addresses.
    /// </summary>
    [HttpPut("api/v1/alert-settings/email")]
    public async Task<IActionResult> UpdateEmailChannel(
        [FromBody] AlertEmailChannelRequest req,
        [FromServices] InstanceSmtpConfig instanceSmtp,
        CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        var (recipients, recipientsErrorKey) = EmailRecipients.Validate(req.EmailRecipients);
        if (recipientsErrorKey is not null)
        {
            return _problems.ValidationErrorActionKey("emailRecipients", recipientsErrorKey);
        }

        string orgId = CurrentTenantId();
        string? recipientsStored = recipients is { Length: > 0 } ? string.Join(",", recipients) : null;

        var updated = await _settings.UpdateEmailChannelAsync(
            orgId, new UpdateAlertEmailChannel(req.EmailEnabled, recipientsStored), ct);

        await _audit.LogAsync("alert_settings_updated", orgId, GetUserId(),
            detail: JsonSerializer.Serialize(new
            {
                emailEnabled = updated.EmailEnabled,
                recipientCount = recipients?.Length ?? 0,
            }, WebJson),
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

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
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

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
    /// POST /api/v1/alert-settings/email/test — resolves the channel through
    /// <see cref="EffectiveEmailConfigResolver"/> (the same gate/recipients/instance-transport path
    /// the delivery queue takes) and sends a test message to the org's configured recipients. The
    /// only way a tenant admin can verify email works at all, since the transport is not theirs to
    /// inspect. Rate-limited like the other test-send endpoints.
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

/// <summary>Request body for PUT /api/v1/alert-settings — the Alerts-tab gates.</summary>
public sealed class AlertSettingsRequest
{
    public bool QuarantineAlertsEnabled { get; set; } = true;
    public bool VulnAlertsEnabled { get; set; } = true;
    public string? VulnMinSeverity { get; set; }
}

/// <summary>Request body for PUT /api/v1/alert-settings/email — the email delivery channel.</summary>
public sealed class AlertEmailChannelRequest
{
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
