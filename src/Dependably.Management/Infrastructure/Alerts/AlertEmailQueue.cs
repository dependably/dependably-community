using System.Diagnostics;
using System.Globalization;
using System.Threading.Channels;
using Dependably.Infrastructure.Mail;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Bounded in-memory queue + background worker for email delivery of freshly-raised alerts.
/// Structural copy of <see cref="AlertSlackQueue"/>: <see cref="Notify"/> is non-blocking and
/// drops on overflow with a log warning so the raising path never blocks on SMTP reachability.
/// On each dequeued alert the worker resolves the org's effective email transport via
/// <see cref="EffectiveEmailConfigResolver"/> (own SMTP or instance inheritance); a disabled,
/// unconfigured, or unresolvable channel is a silent no-op (no failure recorded — there was
/// nothing to attempt, mirroring the Slack queue's null-URL branch). A resolvable channel gets 1
/// initial attempt + 3 retries at 1s / 5s / 30s (<see cref="AlertDeliveryPolicy.BackoffSchedule"/>),
/// the same schedule as every other delivery queue. After a terminal outcome the alert row's
/// <c>email_status</c>/<c>email_error</c> are updated and the org's <c>alert_settings</c>
/// failure-health columns are recorded; email is auto-disabled after
/// <see cref="AlertDeliveryPolicy.AutoDisableAfterFailures"/> consecutive failures OR the
/// <see cref="AlertDeliveryPolicy.AutoDisableAfterDuration"/> window, whichever comes first.
/// </summary>
public sealed class AlertEmailQueue : BackgroundService, IAlertNotifier
{
    private const int DefaultCapacity = 1024;

    /// <summary>
    /// Upper bound on how long the shutdown drain (see <see cref="ExecuteAsync"/>) spends
    /// delivering alerts still buffered in the channel once the host's stopping token has
    /// already fired. Bounded independently of the host's own shutdown timeout so one slow,
    /// retrying alert cannot consume the entire grace period at the expense of every other
    /// alert waiting behind it in the channel.
    /// </summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(25);

    private readonly Channel<AlertRecord> _channel;
    private readonly EffectiveEmailConfigResolver _resolver;
    private readonly AlertSettingsRepository _settings;
    private readonly AlertRepository _alerts;
    private readonly SmtpMailSender _sender;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly TimeProvider _time;
    private readonly ILogger<AlertEmailQueue> _logger;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;

    // DI constructor: 8 dependencies are required by the delivery pipeline stages (transport
    // resolution, settings/alert repositories, the mail sender, localized content, time, queue
    // capacity config, and logging) — one more than AlertSlackQueue's because email routing needs
    // both a per-org transport resolver and localized content that Slack's single webhook does
    // not. No cleaner grouping exists without artificially diverging from AlertSlackQueue's
    // parallel structure.
#pragma warning disable S107 // DI constructor — see comment above
    public AlertEmailQueue(
        EffectiveEmailConfigResolver resolver,
        AlertSettingsRepository settings,
        AlertRepository alerts,
        SmtpMailSender sender,
        IStringLocalizer<SharedResource> localizer,
        TimeProvider time,
        IConfiguration config,
        ILogger<AlertEmailQueue> logger)
#pragma warning restore S107
    {
        _resolver = resolver;
        _settings = settings;
        _alerts = alerts;
        _sender = sender;
        _localizer = localizer;
        _time = time;
        _logger = logger;

        int capacity = int.TryParse(config["ALERT_EMAIL_QUEUE_CAPACITY"], out int c) && c > 0
            ? c : DefaultCapacity;
        _channel = Channel.CreateBounded<AlertRecord>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    }

    /// <summary>Non-blocking enqueue. Drops on overflow (logged, never thrown back to the caller).</summary>
    public void Notify(AlertRecord alert)
    {
        if (!_channel.Writer.TryWrite(alert))
        {
            Interlocked.Increment(ref _droppedCount);
            _logger.LogWarning(
                "Alert email queue full; dropping notification for alert {AlertId} (org {OrgId}).",
                alert.Id, alert.OrgId);
        }
    }

    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long FailedCount => Interlocked.Read(ref _failedCount);

    /// <summary>
    /// Test-only direct invocation of <see cref="ExecuteAsync"/>. <see cref="BackgroundService.StartAsync"/>
    /// short-circuits and never invokes <c>ExecuteAsync</c> at all when handed an already-cancelled
    /// token, so it cannot exercise the shutdown-drain race this method covers (a stopping token
    /// cancelled while the read loop is genuinely running, with alerts still buffered).
    /// </summary>
    internal Task ExecuteAsyncForTests(CancellationToken stoppingToken) => ExecuteAsync(stoppingToken);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Alert email queue starting.");

        try
        {
            await foreach (var alert in _channel.Reader.ReadAllAsync(stoppingToken))
            {
                await DeliverAsync(alert, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // ReadAllAsync's WaitToReadAsync checks the stopping token before it checks whether
            // the channel has buffered items, so cancellation can fire here with alerts still
            // sitting in the channel — fall through to drain them instead of dropping them.
        }

        await DrainOnShutdownAsync();
    }

    /// <summary>
    /// Runs whatever is still buffered in the channel through the normal delivery path when
    /// shutdown cancels the main read loop above. The host's own stopping token is already
    /// cancelled by this point, so drained deliveries run on a fresh, time-bounded token
    /// (<see cref="DrainTimeout"/>) instead — otherwise every delivery attempt would see
    /// cancellation immediately and skip straight to "failed" without ever trying.
    /// </summary>
    private async Task DrainOnShutdownAsync()
    {
        using var drainCts = new CancellationTokenSource(DrainTimeout);
        int drained = 0;
        int abandoned = 0;

        while (_channel.Reader.TryRead(out var alert))
        {
            if (drainCts.IsCancellationRequested)
            {
                // Drain window exhausted — stop attempting deliveries but keep draining the
                // channel itself so the abandoned count is accurate.
                abandoned++;
                continue;
            }

            await DeliverAsync(alert, drainCts.Token);
            drained++;
        }

        if (abandoned > 0)
        {
            _logger.LogWarning(
                "Alert email queue shutdown drain timed out after {Timeout}s; " +
                "{Count} alert(s) still buffered were not attempted.",
                DrainTimeout.TotalSeconds, abandoned);
        }

        if (drained > 0)
        {
            _logger.LogInformation(
                "Alert email queue drained {Count} alert(s) still buffered at shutdown.", drained);
        }
    }

    internal async Task DeliverAsync(AlertRecord alert, CancellationToken ct)
    {
        EffectiveEmailConfigResolver.ResolvedEmailConfig? resolved;
        try
        {
            resolved = await _resolver.ResolveAsync(alert.OrgId, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} loading email settings for org {OrgId}; skipping delivery for alert {AlertId}.",
                ex.GetType().Name, alert.OrgId, alert.Id);
            return;
        }

        if (resolved is null)
        {
            // Email disabled, unconfigured, or unresolvable for this org — nothing to attempt.
            return;
        }

        (string subject, string body) = BuildMessage(_localizer, alert);
        Exception? lastEx = null;

        for (int attempt = 0; attempt <= AlertDeliveryPolicy.BackoffSchedule.Length; attempt++)
        {
            if (ct.IsCancellationRequested)
            {
                return;
            }

            try
            {
                await _sender.SendAsync(resolved.Transport, resolved.Recipients, subject, body, ct);

                // The send already landed at the SMTP relay — this is an irreversible external
                // side effect. If host shutdown cancels `ct` in the window between the send
                // returning and the bookkeeping write, the write must still happen: run it on an
                // independent token so it survives the stopping token being cancelled.
                // DeliveredCount is bumped only after the durable write succeeds, so the
                // observable completion signal implies durable state.
                await RecordSuccessAsync(alert, CancellationToken.None);
                Interlocked.Increment(ref _deliveredCount);
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                lastEx = ex;
                if (attempt == AlertDeliveryPolicy.BackoffSchedule.Length)
                {
                    break;
                }

                _logger.LogDebug(ex,
                    "Email delivery attempt {Attempt} failed for alert {AlertId} (org {OrgId}); retrying in {Backoff}.",
                    attempt + 1, alert.Id, alert.OrgId, AlertDeliveryPolicy.BackoffSchedule[attempt]);
                try
                {
                    await Task.Delay(AlertDeliveryPolicy.BackoffSchedule[attempt], _time, ct);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }

        // The retry budget is exhausted — this is also a terminal, durable outcome (it drives
        // auto-disable), so it gets the same independent-token treatment as success.
        string errorMsg = lastEx?.Message ?? "Unknown error";
        _logger.LogWarning(lastEx,
            "Email delivery failed after {Attempts} attempts for alert {AlertId} (org {OrgId}); recording failure.",
            AlertDeliveryPolicy.BackoffSchedule.Length + 1, alert.Id, alert.OrgId);

        await RecordFailureAsync(alert, errorMsg, CancellationToken.None);
        Interlocked.Increment(ref _failedCount);
    }

    /// <summary>
    /// Renders the alert subject/body from the resx <c>email.alert.*</c> keys. Alert email is
    /// English-only (there is no per-org language on <see cref="AlertRecord"/> to key a culture
    /// off), so the ambient <see cref="CultureInfo.CurrentUICulture"/> is pinned to English for
    /// the duration of the lookups regardless of what a request thread left it at, then restored.
    /// The title is CR/LF-stripped defensively before formatting — <see cref="SmtpMailSender"/>
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

    internal async Task RecordSuccessAsync(AlertRecord alert, CancellationToken ct)
    {
        try
        {
            await _alerts.RecordEmailOutcomeAsync(alert.OrgId, alert.Id, "sent", null, ct);
            await _settings.RecordEmailSuccessAsync(alert.OrgId, ct);
        }
        catch (Exception ex)
        {
            // Callers pass CancellationToken.None here once the send has succeeded, so an
            // OperationCanceledException reaching this catch is not host-shutdown noise — it
            // means the durable write itself was lost and needs to stand out from the routine
            // transient-failure logging elsewhere in this class.
            _logger.LogWarning(ex,
                "{ExceptionType} recording email delivery success for alert {AlertId} (org {OrgId}); " +
                "delivery happened but was not durably recorded. TraceId={TraceId}",
                ex.GetType().Name, alert.Id, alert.OrgId, Activity.Current?.TraceId.ToString());
        }
    }

    internal async Task RecordFailureAsync(AlertRecord alert, string errorMsg, CancellationToken ct)
    {
        try
        {
            await _alerts.RecordEmailOutcomeAsync(alert.OrgId, alert.Id, "failed", errorMsg, ct);

            bool autoDisabled = await _settings.RecordEmailFailureAsync(
                alert.OrgId, errorMsg,
                AlertDeliveryPolicy.AutoDisableAfterFailures, AlertDeliveryPolicy.AutoDisableAfterDuration, ct);

            if (autoDisabled)
            {
                _logger.LogWarning(
                    "Email delivery for org {OrgId} auto-disabled after consecutive or sustained " +
                    "failures. Re-enable via Settings → Integrations.",
                    alert.OrgId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} recording email delivery failure for alert {AlertId} (org {OrgId}); " +
                "failure count for auto-disable was not durably recorded. TraceId={TraceId}",
                ex.GetType().Name, alert.Id, alert.OrgId, Activity.Current?.TraceId.ToString());
        }
    }
}
