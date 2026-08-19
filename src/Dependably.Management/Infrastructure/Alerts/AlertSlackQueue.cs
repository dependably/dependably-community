using System.Diagnostics;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Per-org queue + background worker pool for Slack delivery of freshly-raised alerts.
/// Mirrors <see cref="Webhooks.WebhookDispatchQueue"/>: <see cref="Notify"/> is non-blocking and
/// drops on overflow with a log warning so the raising path (a supply-chain block or vuln scan)
/// never blocks on Slack reachability. Queuing is partitioned by org and served round-robin by an
/// <see cref="OrgFairDispatcher{TItem}"/> for the same reason as the webhook queue: the Slack
/// webhook URL is tenant-supplied, so how long an org's delivery takes must decide only when that
/// org's own next alert is delivered — security and compliance alerts for every other tenant on
/// the instance cannot queue behind it. On each dequeued alert the worker looks up the org's
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
    /// <summary>Queued alerts held per org before that org's own alerts are shed.</summary>
    private const int DefaultCapacity = 1024;

    /// <summary>How many orgs' alerts are delivered concurrently (<c>ALERT_SLACK_WORKERS</c>).</summary>
    private const int DefaultWorkers = 4;

    /// <summary>
    /// Default hard deadline on one alert's delivery, retries included
    /// (<c>ALERT_SLACK_BUDGET_SECONDS</c>). The full retry budget is 4 attempts at the Slack
    /// client's 10-second per-attempt timeout plus 36 seconds of backoff, so this leaves a
    /// legitimately slow Slack endpoint room to finish while bounding how long an org holds a
    /// worker.
    /// </summary>
    private const int DefaultBudgetSeconds = 90;

    /// <summary>Auto-disable Slack delivery for an org after this many consecutive terminal failures.</summary>
    internal const int AutoDisableAfterFailures = AlertDeliveryPolicy.AutoDisableAfterFailures;

    /// <summary>Auto-disable Slack delivery for an org failing continuously for this long.</summary>
    internal static readonly TimeSpan AutoDisableAfterDuration = AlertDeliveryPolicy.AutoDisableAfterDuration;

    /// <summary>
    /// Upper bound on how long the shutdown drain (see <see cref="ExecuteAsync"/>) spends
    /// delivering alerts still queued once the host's stopping token has already fired. Bounded
    /// independently of the host's own shutdown timeout so one slow, retrying alert cannot
    /// consume the entire grace period at the expense of every other org's queued alerts.
    /// </summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(25);

    private static readonly TimeSpan[] DefaultBackoffSchedule = AlertDeliveryPolicy.BackoffSchedule;

    private readonly OrgFairDispatcher<AlertRecord> _dispatcher;
    private readonly AlertSettingsRepository _settings;
    private readonly AlertRepository _alerts;
    private readonly SlackWebhookClient _client;
    private readonly TimeProvider _time;
    private readonly ILogger<AlertSlackQueue> _logger;
    private readonly TimeSpan[] _backoffSchedule;
    private readonly int _workers;
    private readonly TimeSpan _alertBudget;
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
        : this(settings, alerts, client, time, config, logger, backoffSchedule: null)
    {
    }

    /// <summary>
    /// Test seam over the retry backoff. <paramref name="backoffSchedule"/> replaces
    /// <see cref="DefaultBackoffSchedule"/> (<see cref="AlertDeliveryPolicy.BackoffSchedule"/>); null keeps it, which is what every production caller gets. It is not
    /// configuration — an operator has no way to reach it, so no deployment can shorten the
    /// interval a failing org's Slack webhook is retried on.
    ///
    /// It exists because the alternative is worse. A test that only needs the retry chain to
    /// reach its terminal outcome, and asserts nothing about the intervals, otherwise has to
    /// hand-drive a <c>FakeTimeProvider</c> from outside while the loop registers its next
    /// timer from inside — and the two race. Every advance the pump spends before that timer
    /// exists is wasted, so the wait passes or fails on how heavily loaded the machine is.
    /// Injecting a zero schedule removes the clock from those tests entirely: a zero delay
    /// completes without any time, real or virtual, having to pass. Tests that assert on the
    /// intervals, or on the per-item budget that runs on the same injected clock, keep the real
    /// schedule and drive the clock.
    /// </summary>
    internal AlertSlackQueue(
        AlertSettingsRepository settings,
        AlertRepository alerts,
        SlackWebhookClient client,
        TimeProvider time,
        IConfiguration config,
        ILogger<AlertSlackQueue> logger,
        TimeSpan[]? backoffSchedule)
    {
        _backoffSchedule = backoffSchedule ?? DefaultBackoffSchedule;
        _settings = settings;
        _alerts = alerts;
        _client = client;
        _time = time;
        _logger = logger;

        int capacity = int.TryParse(config["ALERT_SLACK_QUEUE_CAPACITY"], out int c) && c > 0
            ? c : DefaultCapacity;
        _workers = int.TryParse(config["ALERT_SLACK_WORKERS"], out int w) && w > 0
            ? w : DefaultWorkers;
        _alertBudget = OrgFairDispatcher.ResolveItemBudget(
            config, "ALERT_SLACK_BUDGET_SECONDS", DefaultBudgetSeconds, logger);

        _dispatcher = new OrgFairDispatcher<AlertRecord>(
            capacity, _workers, _alertBudget, time, logger, "Slack alert");
    }

    /// <summary>
    /// Non-blocking enqueue onto the alert's own org lane. Drops on overflow (logged, never thrown
    /// back to the caller), and the lane is per-org so a backlog only ever sheds the alerts of the
    /// org that created it. Returns a completed task: Slack delivery is in-memory and best-effort,
    /// so there is nothing to await — the seam is asynchronous for the durable email channel's
    /// sake, not this one's.
    /// </summary>
    public Task NotifyAsync(AlertRecord alert, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(alert);

        if (!_dispatcher.TryEnqueue(alert.OrgId, alert))
        {
            Interlocked.Increment(ref _droppedCount);
            _logger.LogWarning(
                "Alert Slack queue full; dropping notification for alert {AlertId} (org {OrgId}).",
                alert.Id, alert.OrgId);
        }

        return Task.CompletedTask;
    }

    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long FailedCount => Interlocked.Read(ref _failedCount);

    /// <summary>
    /// Test-only direct invocation of <see cref="ExecuteAsync"/>. <see cref="BackgroundService.StartAsync"/>
    /// short-circuits and never invokes <c>ExecuteAsync</c> at all when handed an already-cancelled
    /// token, so it cannot exercise the shutdown-drain race this method covers (a stopping token
    /// cancelled while the worker pool is genuinely running, with alerts still queued).
    /// </summary>
    internal Task ExecuteAsyncForTests(CancellationToken stoppingToken) => ExecuteAsync(stoppingToken);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Alert Slack queue starting with {Workers} worker(s) serving per-org lanes.", _workers);

        // Completes normally on shutdown: the dispatcher's workers treat a cancelled stopping
        // token as an expected end and leave whatever is still queued for the drain below.
        await _dispatcher.RunAsync(DeliverAsync, stoppingToken);

        await DrainOnShutdownAsync();
    }

    /// <summary>
    /// Runs whatever is still queued through the normal delivery path when shutdown cancels the
    /// worker pool above, taking alerts in the same per-org round-robin order and running each
    /// through the dispatcher's own per-alert budget. Both matter, and the budget is the one that
    /// carries the cross-tenant property: rotation alone still lets the first org drained decide,
    /// from its own endpoint, how much of a bounded drain window every other org's security alerts
    /// get. The host's own stopping token is already cancelled by this point, so drained
    /// deliveries run on a fresh, time-bounded token (<see cref="DrainTimeout"/>) instead —
    /// otherwise every delivery attempt would see cancellation immediately and skip straight to
    /// "failed" without ever trying.
    /// </summary>
    private async Task DrainOnShutdownAsync()
    {
        using var drainCts = new CancellationTokenSource(DrainTimeout);
        int drained = 0;
        int abandoned = 0;

        while (_dispatcher.TryTakeForDrain(out var alert, out string orgId))
        {
            if (drainCts.IsCancellationRequested)
            {
                // Drain window exhausted — stop attempting deliveries but keep emptying the
                // lanes so the abandoned count is accurate.
                abandoned++;
                continue;
            }

            if (await _dispatcher.RunOneAsync(DeliverAsync, alert, orgId, drainCts.Token))
            {
                drained++;
            }
            else
            {
                // Cut short by this alert's own budget or by the drain window closing under it.
                // Counted as abandoned rather than drained: the next org's alert is what that
                // budget exists to protect, and the operator needs the count to be honest.
                abandoned++;
            }
        }

        if (abandoned > 0)
        {
            _logger.LogWarning(
                "Alert Slack queue shutdown drain gave up on {Count} alert(s) within its {Timeout}s " +
                "window: each alert gets at most {Budget}s so no one org's endpoint can consume " +
                "another org's share of the drain.",
                abandoned, DrainTimeout.TotalSeconds, _alertBudget.TotalSeconds);
        }

        if (drained > 0)
        {
            _logger.LogInformation(
                "Alert Slack queue drained {Count} alert(s) still queued at shutdown.", drained);
        }
    }

    /// <summary>
    /// Delivers one alert to the org's Slack webhook. Returns whether the alert reached a
    /// conclusion: false means cancellation ended it early, which is what tells the dispatcher to
    /// hand it back for the shutdown drain rather than lose it. An org with Slack off, or a
    /// settings read that failed for its own reasons, is a conclusion — there is nothing pending.
    /// </summary>
    internal async Task<bool> DeliverAsync(AlertRecord alert, CancellationToken ct)
    {
        string? webhookUrl;
        try
        {
            webhookUrl = await _settings.GetDecryptedSlackWebhookUrlAsync(alert.OrgId, ct);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to load Slack settings for org {OrgId}; skipping delivery for alert {AlertId}.",
                alert.OrgId, alert.Id);
            return true;
        }

        if (webhookUrl is null)
        {
            // Slack disabled or never configured for this org — nothing to attempt.
            return true;
        }

        string text = BuildMessage(alert);
        Exception? lastEx = null;

        for (int attempt = 0; attempt <= _backoffSchedule.Length; attempt++)
        {
            if (ct.IsCancellationRequested)
            {
                return false;
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
                return true;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return false;
            }
            catch (Exception ex)
            {
                lastEx = ex;
                if (attempt == _backoffSchedule.Length)
                {
                    break;
                }

                _logger.LogDebug(ex,
                    "Slack delivery attempt {Attempt} failed for alert {AlertId} (org {OrgId}); retrying in {Backoff}.",
                    attempt + 1, alert.Id, alert.OrgId, _backoffSchedule[attempt]);
                try
                {
                    await Task.Delay(_backoffSchedule[attempt], _time, ct);
                }
                catch (OperationCanceledException)
                {
                    return false;
                }
            }
        }

        // The retry budget is exhausted — this is also a terminal, durable outcome (it
        // drives auto-disable), so it gets the same independent-token treatment as success.
        string errorMsg = lastEx?.Message ?? "Unknown error";
        _logger.LogWarning(lastEx,
            "Slack delivery failed after {Attempts} attempts for alert {AlertId} (org {OrgId}); recording failure.",
            _backoffSchedule.Length + 1, alert.Id, alert.OrgId);

        await RecordFailureAsync(alert, errorMsg, CancellationToken.None);
        Interlocked.Increment(ref _failedCount);
        return true;
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
