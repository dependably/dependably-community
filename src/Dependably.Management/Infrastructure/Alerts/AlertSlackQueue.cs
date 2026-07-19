using System.Diagnostics;
using System.Threading.Channels;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Bounded in-memory queue + background worker for Slack delivery of freshly-raised alerts.
/// Mirrors <see cref="Webhooks.WebhookDispatchQueue"/>: <see cref="Notify"/> is non-blocking and
/// drops on overflow with a log warning so the raising path (a supply-chain block or vuln scan)
/// never blocks on Slack reachability. On each dequeued alert the worker looks up the org's
/// decrypted Slack webhook URL; a disabled or unconfigured org is a silent no-op (no failure
/// recorded — there was nothing to attempt). A configured org gets 1 initial attempt + 3 retries
/// at 1s / 5s / 30s (4 total), the same backoff schedule as
/// <see cref="Webhooks.WebhookDispatchQueue"/> and the SIEM forwarder. After a terminal outcome
/// the alert row's <c>slack_status</c>/<c>slack_error</c> are updated and the org's
/// <c>alert_settings</c> failure-health columns are recorded; Slack is auto-disabled after
/// <see cref="AutoDisableAfterFailures"/> consecutive failures OR the
/// <see cref="AutoDisableAfterDuration"/> window, whichever comes first — identical arithmetic to
/// the webhook subscription auto-disable.
/// </summary>
public sealed class AlertSlackQueue : BackgroundService, IAlertNotifier
{
    private const int DefaultCapacity = 1024;

    /// <summary>Auto-disable Slack delivery for an org after this many consecutive terminal failures.</summary>
    internal const int AutoDisableAfterFailures = AlertDeliveryPolicy.AutoDisableAfterFailures;

    /// <summary>Auto-disable Slack delivery for an org failing continuously for this long.</summary>
    internal static readonly TimeSpan AutoDisableAfterDuration = AlertDeliveryPolicy.AutoDisableAfterDuration;

    /// <summary>
    /// Upper bound on how long the shutdown drain (see <see cref="ExecuteAsync"/>) spends
    /// delivering alerts still buffered in the channel once the host's stopping token has
    /// already fired. Bounded independently of the host's own shutdown timeout so one slow,
    /// retrying alert cannot consume the entire grace period at the expense of every other
    /// alert waiting behind it in the channel.
    /// </summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(25);

    private static readonly TimeSpan[] BackoffSchedule = AlertDeliveryPolicy.BackoffSchedule;

    private readonly Channel<AlertRecord> _channel;
    private readonly AlertSettingsRepository _settings;
    private readonly AlertRepository _alerts;
    private readonly SlackWebhookClient _client;
    private readonly TimeProvider _time;
    private readonly ILogger<AlertSlackQueue> _logger;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;

    public AlertSlackQueue(
        AlertSettingsRepository settings,
        AlertRepository alerts,
        SlackWebhookClient client,
        TimeProvider time,
        IConfiguration config,
        ILogger<AlertSlackQueue> logger)
    {
        _settings = settings;
        _alerts = alerts;
        _client = client;
        _time = time;
        _logger = logger;

        int capacity = int.TryParse(config["ALERT_SLACK_QUEUE_CAPACITY"], out int c) && c > 0
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
                "Alert Slack queue full; dropping notification for alert {AlertId} (org {OrgId}).",
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
        _logger.LogInformation("Alert Slack queue starting.");

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
                "Alert Slack queue shutdown drain timed out after {Timeout}s; " +
                "{Count} alert(s) still buffered were not attempted.",
                DrainTimeout.TotalSeconds, abandoned);
        }

        if (drained > 0)
        {
            _logger.LogInformation(
                "Alert Slack queue drained {Count} alert(s) still buffered at shutdown.", drained);
        }
    }

    internal async Task DeliverAsync(AlertRecord alert, CancellationToken ct)
    {
        string? webhookUrl;
        try
        {
            webhookUrl = await _settings.GetDecryptedSlackWebhookUrlAsync(alert.OrgId, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to load Slack settings for org {OrgId}; skipping delivery for alert {AlertId}.",
                alert.OrgId, alert.Id);
            return;
        }

        if (webhookUrl is null)
        {
            // Slack disabled or never configured for this org — nothing to attempt.
            return;
        }

        string text = BuildMessage(alert);
        Exception? lastEx = null;

        for (int attempt = 0; attempt <= BackoffSchedule.Length; attempt++)
        {
            if (ct.IsCancellationRequested)
            {
                return;
            }

            try
            {
                await _client.SendAsync(webhookUrl, text, ct);

                // The POST already landed at Slack — this is an irreversible external side
                // effect. If host shutdown cancels `ct` in the window between the send
                // returning and the bookkeeping write, the write must still happen: run it
                // on an independent token so it survives the stopping token being cancelled.
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
                if (attempt == BackoffSchedule.Length)
                {
                    break;
                }

                _logger.LogDebug(ex,
                    "Slack delivery attempt {Attempt} failed for alert {AlertId} (org {OrgId}); retrying in {Backoff}.",
                    attempt + 1, alert.Id, alert.OrgId, BackoffSchedule[attempt]);
                try
                {
                    await Task.Delay(BackoffSchedule[attempt], _time, ct);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }

        // The retry budget is exhausted — this is also a terminal, durable outcome (it
        // drives auto-disable), so it gets the same independent-token treatment as success.
        string errorMsg = lastEx?.Message ?? "Unknown error";
        _logger.LogWarning(lastEx,
            "Slack delivery failed after {Attempts} attempts for alert {AlertId} (org {OrgId}); recording failure.",
            BackoffSchedule.Length + 1, alert.Id, alert.OrgId);

        await RecordFailureAsync(alert, errorMsg, CancellationToken.None);
        Interlocked.Increment(ref _failedCount);
    }

    // Slack incoming-webhook messages are plain text; the title carries the human summary and
    // detail (when present) is appended as a second line for extra context.
    private static string BuildMessage(AlertRecord alert)
    {
        string prefix = alert.Type == AlertTypes.VulnSeverity ? ":rotating_light:" : ":package:";
        return string.IsNullOrEmpty(alert.Detail)
            ? $"{prefix} Dependably alert: {alert.Title}"
            : $"{prefix} Dependably alert: {alert.Title}\n{alert.Detail}";
    }

    internal async Task RecordSuccessAsync(AlertRecord alert, CancellationToken ct)
    {
        try
        {
            await _alerts.RecordSlackOutcomeAsync(alert.OrgId, alert.Id, "sent", null, ct);
            await _settings.RecordSlackSuccessAsync(alert.OrgId, ct);
        }
        catch (Exception ex)
        {
            // Callers pass CancellationToken.None here once the Slack send has succeeded, so
            // an OperationCanceledException reaching this catch is not host-shutdown noise —
            // it means the durable write itself was lost and needs to stand out from the
            // routine transient-failure logging elsewhere in this class.
            _logger.LogWarning(ex,
                "{ExceptionType} recording Slack delivery success for alert {AlertId} (org {OrgId}); " +
                "delivery happened but was not durably recorded. TraceId={TraceId}",
                ex.GetType().Name, alert.Id, alert.OrgId, Activity.Current?.TraceId.ToString());
        }
    }

    internal async Task RecordFailureAsync(AlertRecord alert, string errorMsg, CancellationToken ct)
    {
        try
        {
            await _alerts.RecordSlackOutcomeAsync(alert.OrgId, alert.Id, "failed", errorMsg, ct);

            bool autoDisabled = await _settings.RecordSlackFailureAsync(
                alert.OrgId, errorMsg, AutoDisableAfterFailures, AutoDisableAfterDuration, ct);

            if (autoDisabled)
            {
                _logger.LogWarning(
                    "Slack delivery for org {OrgId} auto-disabled after consecutive or sustained " +
                    "failures. Re-enable via Settings → Alerts.",
                    alert.OrgId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} recording Slack delivery failure for alert {AlertId} (org {OrgId}); " +
                "failure count for auto-disable was not durably recorded. TraceId={TraceId}",
                ex.GetType().Name, alert.Id, alert.OrgId, Activity.Current?.TraceId.ToString());
        }
    }
}
