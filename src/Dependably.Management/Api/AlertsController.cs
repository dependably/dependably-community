using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Identity;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Per-tenant alert center, surfaced as the topbar bell (admin/owner only — <c>read:tenant</c>
/// and <c>tenant:configure</c> are not granted to member/auditor). GET routes list/summarize
/// alert rows; dismiss records a shared active/dismissed flag all admins in the org see the same
/// way. Settings (severity floor, per-type toggles, optional Slack delivery) live under
/// <c>/api/v1/alert-settings</c>, write-only for the Slack webhook URL — GET/PUT never echo the
/// raw URL, only a computed <c>hasSlackWebhook</c> boolean, mirroring
/// <see cref="WebhookController"/>'s secret-handling convention.
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

#pragma warning disable S107 // constructor injection of independently-registered DI services
    public AlertsController(
        AlertRepository alerts,
        AlertSettingsRepository settings,
        SlackWebhookClient slackClient,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems,
        EnvelopeProtector envelope,
        IConfiguration config)
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

    /// <summary>GET /api/v1/alert-settings</summary>
    [HttpGet("api/v1/alert-settings")]
    public async Task<IActionResult> GetSettings(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        return result ?? Ok(await _settings.GetAsync(CurrentTenantId(), ct));
    }

    /// <summary>
    /// PUT /api/v1/alert-settings — <c>slackWebhookUrl</c> is write-only: a non-empty value
    /// rotates the encrypted URL (requires DEPENDABLY_MASTER_KEY), null/absent leaves it
    /// unchanged. Audits alert_settings_updated with the toggles/severity only — never the URL.
    /// </summary>
    [HttpPut("api/v1/alert-settings")]
    public async Task<IActionResult> UpdateSettings([FromBody] AlertSettingsRequest req, CancellationToken ct)
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
        var updated = await _settings.UpdateAsync(orgId, new UpdateAlertSettings(
            req.QuarantineAlertsEnabled, req.VulnAlertsEnabled,
            string.IsNullOrEmpty(req.VulnMinSeverity) ? "HIGH" : req.VulnMinSeverity.ToUpperInvariant(),
            req.SlackEnabled, req.SlackWebhookUrl), ct);

        await _audit.LogAsync("alert_settings_updated", orgId, GetUserId(),
            detail: JsonSerializer.Serialize(new
            {
                quarantineAlertsEnabled = updated.QuarantineAlertsEnabled,
                vulnAlertsEnabled = updated.VulnAlertsEnabled,
                vulnMinSeverity = updated.VulnMinSeverity,
                slackEnabled = updated.SlackEnabled,
            }, WebJson),
            ct: ct);

        return Ok(updated);
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
            return _problems.ValidationErrorActionKey("slackWebhookUrl", "error.alert.slackTestFailed", ex.Message);
        }

        return NoContent();
    }
}

/// <summary>Request body for PUT /api/v1/alert-settings.</summary>
public sealed class AlertSettingsRequest
{
    public bool QuarantineAlertsEnabled { get; set; } = true;
    public bool VulnAlertsEnabled { get; set; } = true;
    public string? VulnMinSeverity { get; set; }
    public bool SlackEnabled { get; set; }
    /// <summary>Write-only. Null/empty on update means "leave the stored URL unchanged".</summary>
    public string? SlackWebhookUrl { get; set; }
}
