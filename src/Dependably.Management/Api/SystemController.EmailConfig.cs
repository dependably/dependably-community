using System.Security.Claims;
using Dependably.Infrastructure.Mail;
using Dependably.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Localization;

namespace Dependably.Api;

/// <summary>
/// Apex-only instance SMTP config surface. Multi-mode counterpart of
/// <c>InstanceController</c>'s single-mode <c>/api/v1/instance/email-config</c> routes; both
/// share validation and response-shaping via <see cref="EmailConfigEditing"/> so the two
/// surfaces can't drift. Every route requires <c>scope=system</c> + apex context, enforced by
/// <see cref="Dependably.Security.RouteScopeFilter"/> on every <c>/api/v1/system/</c> route.
/// </summary>
public sealed partial class SystemController
{
    /// <summary>
    /// GET /api/v1/system/email-config — the resolved instance SMTP transport. The password is
    /// never echoed, only a computed <c>hasPassword</c> boolean.
    /// </summary>
    [HttpGet("email-config")]
    public async Task<IActionResult> GetEmailConfig(
        [FromServices] InstanceSmtpConfig smtp,
        CancellationToken ct)
    {
        var resolved = await smtp.ResolveAsync(ct);
        return Ok(EmailConfigEditing.BuildView(resolved, _envelope.IsConfigured));
    }

    /// <summary>
    /// PUT /api/v1/system/email-config — updates the instance SMTP transport in
    /// <c>instance_settings</c>. A non-empty <c>password</c> requires
    /// <see cref="Dependably.Infrastructure.Identity.EnvelopeProtector.IsConfigured"/> (otherwise
    /// <c>SetInstanceSettingAsync</c> would silently store it in plaintext) — 400 when absent. An
    /// IP-literal <c>host</c> in a blocked SSRF range is rejected unless
    /// <c>WEBHOOK_ALLOW_PRIVATE=true</c> (via <see cref="HostSsrfValidator"/>) — the same
    /// save-time posture as the per-org alert email transport; the authoritative,
    /// DNS-rebinding-aware gate is the connect-time guard <see cref="SmtpMailSender"/> runs on
    /// every send. Audits the non-secret fields only.
    /// </summary>
    [HttpPut("email-config")]
    public async Task<IActionResult> UpdateEmailConfig(
        [FromBody] EmailConfigRequest req,
        [FromServices] InstanceSmtpConfig smtp,
        CancellationToken ct)
    {
        if (req is null)
        {
            return _problems.ValidationErrorActionKey("body", "error.common.requestBodyRequired");
        }

        var (field, resourceKey) = EmailConfigEditing.Validate(req);
        if (field is not null)
        {
            return _problems.ValidationErrorActionKey(field, resourceKey!);
        }

        if (!string.IsNullOrEmpty(req.Password) && !_envelope.IsConfigured)
        {
            return _problems.ValidationErrorActionKey("password", "error.email.masterKeyRequired");
        }

        bool allowPrivate = string.Equals(
            _config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);
        Func<System.Net.IPAddress, bool> isBlocked = allowPrivate
            ? SsrfGuard.IsBlockedIpExcludingPrivate
            : SsrfGuard.IsBlockedIp;
        if (HostSsrfValidator.IsHostBlocked(req.Host, isBlocked))
        {
            return _problems.ValidationErrorActionKey("host", "error.email.hostBlocked");
        }

        await EmailConfigEditing.ApplyAsync(_orgs, req, ct);
        smtp.Invalidate();

        string? actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await _audit.LogSystemAsync(
            action: "system_admin.email_config_updated",
            actorId: actor,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                host = req.Host,
                port = req.Port,
                security = req.Security,
                username = req.Username,
                fromAddress = req.FromAddress,
                passwordRotated = !string.IsNullOrEmpty(req.Password),
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            ct: ct);

        var resolved = await smtp.ResolveAsync(ct);
        return Ok(EmailConfigEditing.BuildView(resolved, _envelope.IsConfigured));
    }

    /// <summary>
    /// POST /api/v1/system/email-config/test — sends a synchronous test message to the
    /// configured from-address (never a caller-supplied target) so an operator gets an
    /// immediate success/failure result. Rate-limited like the invite send path.
    /// </summary>
    [HttpPost("email-config/test")]
    [EnableRateLimiting("invite")]
    public async Task<IActionResult> TestEmailConfig(
        [FromServices] InstanceSmtpConfig smtp,
        [FromServices] SmtpMailSender sender,
        [FromServices] IStringLocalizer<SharedResource> localizer,
        CancellationToken ct)
    {
        var resolved = await smtp.ResolveAsync(ct);
        if (!resolved.Configured || string.IsNullOrWhiteSpace(resolved.Transport.FromAddress))
        {
            return _problems.ValidationErrorActionKey("email", "error.email.notConfigured");
        }

        try
        {
            await sender.SendAsync(
                resolved.Transport,
                [resolved.Transport.FromAddress],
                localizer["email.test.subject"],
                localizer["email.test.body"],
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                ex,
                "System email test send failed: {ExceptionType} host={Host} port={Port} trace={TraceId}",
                ex.GetType().Name,
                resolved.Transport.Host,
                resolved.Transport.Port,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
            return _problems.ValidationErrorActionKey("email", "error.email.testFailedGeneric");
        }

        return NoContent();
    }
}
