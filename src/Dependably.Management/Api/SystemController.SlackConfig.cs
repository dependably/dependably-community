using System.Security.Claims;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Webhooks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Apex-only operator Slack config surface (multi-tenant deployments). Every route requires
/// <c>scope=system</c> + apex context, enforced by <see cref="Dependably.Security.RouteScopeFilter"/>
/// on every <c>/api/v1/system/</c> route. Not surfaced in single mode — there is no
/// <c>/api/v1/instance/slack-config</c> counterpart, because the operator Slack channel is a
/// control-plane concept that only exists once tenants are apex-managed.
///
/// The webhook URL is write-only, mirroring the per-org alert-Slack and instance-email-config
/// conventions: GET/PUT never echo the stored URL, only a computed <c>hasWebhook</c> boolean.
/// <c>system_slack_enabled</c>/<c>system_slack_webhook_url</c>/<c>system_slack_last_*</c> are flat
/// <c>instance_settings</c> keys (no dedicated table) read and written through
/// <see cref="OrgRepository.GetInstanceSettingAsync"/>/<see cref="OrgRepository.SetInstanceSettingAsync"/>,
/// which already handle envelope encryption/decryption for the webhook URL.
/// </summary>
public sealed partial class SystemController
{
    /// <summary>
    /// GET /api/v1/system/slack-config — the resolved operator Slack config plus its last
    /// delivery outcome. The webhook URL itself is never returned.
    /// </summary>
    [HttpGet("slack-config")]
    public async Task<IActionResult> GetSlackConfig(CancellationToken ct)
        => Ok(await BuildSlackConfigViewAsync(ct));

    /// <summary>
    /// PUT /api/v1/system/slack-config — <c>webhookUrl</c> is write-only: a non-empty value
    /// rotates the encrypted URL (requires <c>DEPENDABLY_MASTER_KEY</c>) and is SSRF-validated via
    /// <see cref="WebhookDeliveryClient.ValidateWebhookUrl"/> (<c>WEBHOOK_ALLOW_PRIVATE</c>
    /// honoured); empty/absent leaves the stored URL unchanged. Audits
    /// <c>system_admin.slack_config_updated</c> with the enabled flag and a rotation flag only —
    /// never the URL.
    /// </summary>
    [HttpPut("slack-config")]
    public async Task<IActionResult> UpdateSlackConfig(
        [FromBody] SlackConfigRequest req, CancellationToken ct)
    {
        if (req is null)
        {
            return _problems.ValidationErrorActionKey("body", "error.common.requestBodyRequired");
        }

        if (!string.IsNullOrEmpty(req.WebhookUrl))
        {
            if (!_envelope.IsConfigured)
            {
                return _problems.ValidationErrorActionKey("webhookUrl", "error.system.slackMasterKeyRequired");
            }

            bool allowPrivate = string.Equals(
                _config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);
            string? urlError = WebhookDeliveryClient.ValidateWebhookUrl(req.WebhookUrl, allowPrivate);
            if (urlError is not null)
            {
                return _problems.ValidationErrorAction("webhookUrl", urlError);
            }
        }

        await _orgs.SetInstanceSettingAsync("system_slack_enabled", req.Enabled ? "1" : "0", ct);
        if (!string.IsNullOrEmpty(req.WebhookUrl))
        {
            await _orgs.SetInstanceSettingAsync("system_slack_webhook_url", req.WebhookUrl, ct);
        }

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.slack_config_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                webhookRotated = !string.IsNullOrEmpty(req.WebhookUrl),
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        return Ok(await BuildSlackConfigViewAsync(ct));
    }

    /// <summary>
    /// POST /api/v1/system/slack-config/test — sends a synchronous test message via the
    /// currently-configured webhook (not through the async delivery queue) so the operator gets
    /// an immediate success/failure result. Rate-limited like the other test-send endpoints.
    /// </summary>
    [HttpPost("slack-config/test")]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> TestSlackConfig(
        [FromServices] SlackWebhookClient client, CancellationToken ct)
    {
        string? enabledRaw = await _orgs.GetInstanceSettingAsync("system_slack_enabled", ct);
        bool enabled = enabledRaw is "1" or "true";
        string? webhookUrl = enabled ? await _orgs.GetInstanceSettingAsync("system_slack_webhook_url", ct) : null;
        if (string.IsNullOrEmpty(webhookUrl))
        {
            return _problems.ValidationErrorActionKey("webhookUrl", "error.system.slackNotConfigured");
        }

        try
        {
            await client.SendAsync(
                webhookUrl,
                ":white_check_mark: Dependably [system]: operator Slack delivery is working.",
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                ex,
                "System Slack test send failed: {ExceptionType} trace={TraceId}",
                ex.GetType().Name,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
            return _problems.ValidationErrorActionKey("webhookUrl", "error.system.slackTestFailedGeneric");
        }

        return NoContent();
    }

    private async Task<object> BuildSlackConfigViewAsync(CancellationToken ct)
    {
        string? enabledRaw = await _orgs.GetInstanceSettingAsync("system_slack_enabled", ct);
        string? webhookUrl = await _orgs.GetInstanceSettingAsync("system_slack_webhook_url", ct);
        string? lastDeliveryAt = await _orgs.GetInstanceSettingAsync("system_slack_last_delivery_at", ct);
        string? lastStatus = await _orgs.GetInstanceSettingAsync("system_slack_last_status", ct);
        string? lastError = await _orgs.GetInstanceSettingAsync("system_slack_last_error", ct);

        return new
        {
            enabled = enabledRaw is "1" or "true",
            hasWebhook = !string.IsNullOrEmpty(webhookUrl),
            lastDeliveryAt,
            lastStatus,
            lastError = string.IsNullOrEmpty(lastError) ? null : lastError,
            secretsAvailable = _envelope.IsConfigured,
        };
    }
}

/// <summary>Request body for PUT /api/v1/system/slack-config.</summary>
public sealed class SlackConfigRequest
{
    public bool Enabled { get; set; }

    /// <summary>Write-only. Null/empty on update means "leave the stored URL unchanged".</summary>
    public string? WebhookUrl { get; set; }
}
