using System.Globalization;
using Dependably.Infrastructure.Mail;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Per-org email delivery for freshly-raised alerts. Thin adapter over the shared
/// <see cref="EmailDeliveryQueue"/>: <see cref="Notify"/> wraps the alert as an
/// <see cref="AlertEmailJob"/> (carrying the org's <see cref="EffectiveEmailConfigResolver"/>,
/// <see cref="AlertRepository"/>, <see cref="AlertSettingsRepository"/>, and localized content)
/// and enqueues it — the queue itself owns the channel, worker loop, retry backoff, and
/// shutdown drain, all shared with every other outbound-email delivery channel.
/// </summary>
public sealed class AlertEmailQueue : IAlertNotifier
{
    private readonly EmailDeliveryQueue _queue;
    private readonly EffectiveEmailConfigResolver _resolver;
    private readonly AlertSettingsRepository _settings;
    private readonly AlertRepository _alerts;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger<AlertEmailQueue> _logger;

    public AlertEmailQueue(
        EmailDeliveryQueue queue,
        EffectiveEmailConfigResolver resolver,
        AlertSettingsRepository settings,
        AlertRepository alerts,
        IStringLocalizer<SharedResource> localizer,
        ILogger<AlertEmailQueue> logger)
    {
        _queue = queue;
        _resolver = resolver;
        _settings = settings;
        _alerts = alerts;
        _localizer = localizer;
        _logger = logger;
    }

    /// <summary>Non-blocking: wraps the alert as a job and enqueues it onto the shared delivery queue.</summary>
    public void Notify(AlertRecord alert) =>
        _queue.Enqueue(new AlertEmailJob(alert, _resolver, _alerts, _settings, _localizer, _logger));

    /// <summary>
    /// Renders the alert subject/body from the resx <c>email.alert.*</c> keys. Alert email is
    /// English-only (there is no per-org language on <see cref="AlertRecord"/> to key a culture
    /// off), so the ambient <see cref="CultureInfo.CurrentUICulture"/> is pinned to English for
    /// the duration of the lookups regardless of what a request thread left it at, then restored.
    /// The title is CR/LF-stripped defensively before formatting — <see cref="Mail.SmtpMailSender"/>
    /// strips the final joined subject too, but stripping the raw title here keeps the two
    /// placeholder substitutions from ever reintroducing a header-injection vector.
    /// </summary>
    internal static (string Subject, string Body) BuildMessage(
        IStringLocalizer<SharedResource> localizer, AlertRecord alert)
    {
        string safeTitle = StripCrLf(alert.Title);
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = new CultureInfo(LanguageCodes.Default);
            string subject = StripCrLf(localizer["email.alert.subject", safeTitle]);
            string body = localizer["email.alert.body", safeTitle, alert.Detail ?? string.Empty];
            return (subject, body);
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    private static string StripCrLf(string value) => value.Replace("\r", "").Replace("\n", "");
}
