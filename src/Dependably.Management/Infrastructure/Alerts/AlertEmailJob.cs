using System.Diagnostics;
using Dependably.Infrastructure.Mail;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Wraps a freshly-raised <see cref="AlertRecord"/> as an <see cref="IEmailDeliveryJob"/> for the
/// shared <see cref="EmailDeliveryQueue"/>. Resolves the org's effective email transport via
/// <see cref="EffectiveEmailConfigResolver"/>, renders through <see cref="AlertEmailQueue.BuildMessage"/>,
/// and records the terminal outcome on the alert row plus the org's <c>alert_settings</c>
/// failure-health columns — auto-disabling email after
/// <see cref="AlertDeliveryPolicy.AutoDisableAfterFailures"/> consecutive failures OR the
/// <see cref="AlertDeliveryPolicy.AutoDisableAfterDuration"/> window, whichever comes first.
/// </summary>
internal sealed class AlertEmailJob : IEmailDeliveryJob
{
    private readonly AlertRecord _alert;
    private readonly EffectiveEmailConfigResolver _resolver;
    private readonly AlertRepository _alerts;
    private readonly AlertSettingsRepository _settings;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger _logger;

    public AlertEmailJob(
        AlertRecord alert,
        EffectiveEmailConfigResolver resolver,
        AlertRepository alerts,
        AlertSettingsRepository settings,
        IStringLocalizer<SharedResource> localizer,
        ILogger logger)
    {
        _alert = alert;
        _resolver = resolver;
        _alerts = alerts;
        _settings = settings;
        _localizer = localizer;
        _logger = logger;
    }

    public async Task<(SmtpTransportSettings Transport, IReadOnlyList<string> Recipients)?> ResolveAsync(CancellationToken ct)
    {
        try
        {
            var resolved = await _resolver.ResolveAsync(_alert.OrgId, ct);
            return resolved is null ? null : (resolved.Transport, resolved.Recipients);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} loading email settings for org {OrgId}; skipping delivery for alert {AlertId}.",
                ex.GetType().Name, _alert.OrgId, _alert.Id);
            return null;
        }
    }

    public (string Subject, string Body) Render() => AlertEmailQueue.BuildMessage(_localizer, _alert);

    public async Task RecordSuccessAsync()
    {
        try
        {
            // A durable-write failure here must survive host shutdown cancelling the delivery
            // attempt that triggered it — run on an independent token.
            await _alerts.RecordEmailOutcomeAsync(_alert.OrgId, _alert.Id, "sent", null, CancellationToken.None);
            await _settings.RecordEmailSuccessAsync(_alert.OrgId, CancellationToken.None);
        }
        catch (Exception ex)
        {
            // The send happened but was not durably recorded — this must stand out from the
            // routine transient-failure logging elsewhere in this class.
            _logger.LogWarning(ex,
                "{ExceptionType} recording email delivery success for alert {AlertId} (org {OrgId}); " +
                "delivery happened but was not durably recorded. TraceId={TraceId}",
                ex.GetType().Name, _alert.Id, _alert.OrgId, Activity.Current?.TraceId.ToString());
        }
    }

    public async Task RecordFailureAsync(string error)
    {
        try
        {
            await _alerts.RecordEmailOutcomeAsync(_alert.OrgId, _alert.Id, "failed", error, CancellationToken.None);

            bool autoDisabled = await _settings.RecordEmailFailureAsync(
                _alert.OrgId, error,
                AlertDeliveryPolicy.AutoDisableAfterFailures, AlertDeliveryPolicy.AutoDisableAfterDuration,
                CancellationToken.None);

            if (autoDisabled)
            {
                _logger.LogWarning(
                    "Email delivery for org {OrgId} auto-disabled after consecutive or sustained " +
                    "failures. Re-enable via Settings → Integrations.",
                    _alert.OrgId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} recording email delivery failure for alert {AlertId} (org {OrgId}); " +
                "failure count for auto-disable was not durably recorded. TraceId={TraceId}",
                ex.GetType().Name, _alert.Id, _alert.OrgId, Activity.Current?.TraceId.ToString());
        }
    }
}
