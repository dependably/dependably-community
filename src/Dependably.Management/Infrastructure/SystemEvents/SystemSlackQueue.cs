using System.Threading.Channels;
using Dependably.Infrastructure.Alerts;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.SystemEvents;

/// <summary>
/// Bounded in-memory queue + background worker delivering operator-realm control-plane events to
/// a single instance-wide Slack webhook. Structural sibling of
/// <see cref="Dependably.Infrastructure.Alerts.AlertSlackQueue"/> — same bounded-channel
/// drop-on-overflow, same 1s/5s/30s retry schedule via the injected <see cref="TimeProvider"/> —
/// but reads <c>system_slack_enabled</c>/<c>system_slack_webhook_url</c> from
/// <c>instance_settings</c> (not tenant-scoped) instead of per-org <c>alert_settings</c>, and
/// writes its terminal outcome to <c>system_slack_last_delivery_at</c>/<c>_status</c>/<c>_error</c>
/// instance keys. Unlike the per-org queue there is no auto-disable in v1 — a sustained failure is
/// only logged, since silently turning off the sole operator notification channel would remove the
/// only signal an operator has that it's failing.
///
/// This queue is the sole production implementation of <see cref="ISystemEventNotifier"/>. It is
/// never constructed from, or passed into, anything that also touches
/// <see cref="Dependably.Infrastructure.Alerts.IAlertNotifier"/> — see that interface's doc
/// comment for the isolation invariant this enforces.
/// </summary>
public sealed class SystemSlackQueue : BackgroundService, ISystemEventNotifier
{
    private const int DefaultCapacity = 256;

    /// <summary>
    /// Upper bound on how long the shutdown drain (see <see cref="ExecuteAsync"/>) spends
    /// delivering events still buffered in the channel once the host's stopping token has
    /// already fired. Bounded independently of the host's own shutdown timeout so one slow,
    /// retrying event cannot consume the entire grace period at the expense of every other
    /// event waiting behind it in the channel.
    /// </summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(25);

    private static readonly TimeSpan[] BackoffSchedule =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(30)
    ];

    private readonly Channel<SystemEventRecord> _channel;
    private readonly OrgRepository _orgs;
    private readonly SlackWebhookClient _client;
    private readonly TimeProvider _time;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger<SystemSlackQueue> _logger;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;

    public SystemSlackQueue(
        OrgRepository orgs,
        SlackWebhookClient client,
        TimeProvider time,
        IStringLocalizer<SharedResource> localizer,
        IConfiguration config,
        ILogger<SystemSlackQueue> logger)
    {
        _orgs = orgs;
        _client = client;
        _time = time;
        _localizer = localizer;
        _logger = logger;

        int capacity = int.TryParse(config["SYSTEM_SLACK_QUEUE_CAPACITY"], out int c) && c > 0
            ? c : DefaultCapacity;
        _channel = Channel.CreateBounded<SystemEventRecord>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    }

    /// <summary>Non-blocking enqueue. Drops on overflow (logged, never thrown back to the caller).</summary>
    public void Notify(SystemEventRecord record)
    {
        if (!_channel.Writer.TryWrite(record))
        {
            Interlocked.Increment(ref _droppedCount);
            _logger.LogWarning(
                "System Slack queue full; dropping notification for action {Action}.", record.Action);
        }
    }

    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long FailedCount => Interlocked.Read(ref _failedCount);

    /// <summary>
    /// Test-only direct invocation of <see cref="ExecuteAsync"/>. <see cref="BackgroundService.StartAsync"/>
    /// short-circuits and never invokes <c>ExecuteAsync</c> at all when handed an already-cancelled
    /// token, so it cannot exercise the shutdown-drain race this method covers (a stopping token
    /// cancelled while the read loop is genuinely running, with events still buffered).
    /// </summary>
    internal Task ExecuteAsyncForTests(CancellationToken stoppingToken) => ExecuteAsync(stoppingToken);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("System Slack queue starting.");

        try
        {
            await foreach (var record in _channel.Reader.ReadAllAsync(stoppingToken))
            {
                await DeliverAsync(record, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // ReadAllAsync's WaitToReadAsync checks the stopping token before it checks whether
            // the channel has buffered items, so cancellation can fire here with events still
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

        while (_channel.Reader.TryRead(out var record))
        {
            if (drainCts.IsCancellationRequested)
            {
                // Drain window exhausted — stop attempting deliveries but keep draining the
                // channel itself so the abandoned count is accurate.
                abandoned++;
                continue;
            }

            await DeliverAsync(record, drainCts.Token);
            drained++;
        }

        if (abandoned > 0)
        {
            _logger.LogWarning(
                "System Slack queue shutdown drain timed out after {Timeout}s; " +
                "{Count} event(s) still buffered were not attempted.",
                DrainTimeout.TotalSeconds, abandoned);
        }

        if (drained > 0)
        {
            _logger.LogInformation(
                "System Slack queue drained {Count} event(s) still buffered at shutdown.", drained);
        }
    }

    private async Task DeliverAsync(SystemEventRecord record, CancellationToken ct)
    {
        string? webhookUrl;
        try
        {
            webhookUrl = await ResolveWebhookUrlAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to load system Slack settings; skipping delivery for action {Action}.",
                record.Action);
            return;
        }

        if (webhookUrl is null)
        {
            // Disabled or never configured — nothing to attempt.
            return;
        }

        string text = SystemEventMessages.Build(record, _localizer);
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

                Interlocked.Increment(ref _deliveredCount);
                await RecordOutcomeAsync("sent", null, ct);
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
                    "System Slack delivery attempt {Attempt} failed for action {Action}; retrying in {Backoff}.",
                    attempt + 1, record.Action, BackoffSchedule[attempt]);
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

        Interlocked.Increment(ref _failedCount);
        string errorMsg = lastEx?.Message ?? "Unknown error";
        _logger.LogWarning(lastEx,
            "System Slack delivery failed after {Attempts} attempts for action {Action}; recording failure.",
            BackoffSchedule.Length + 1, record.Action);

        await RecordOutcomeAsync("failed", errorMsg, ct);
    }

    private async Task<string?> ResolveWebhookUrlAsync(CancellationToken ct)
    {
        string? enabledRaw = await _orgs.GetInstanceSettingAsync("system_slack_enabled", ct);
        bool enabled = enabledRaw is "1" or "true";
        if (!enabled)
        {
            return null;
        }

        string? url = await _orgs.GetInstanceSettingAsync("system_slack_webhook_url", ct);
        return string.IsNullOrEmpty(url) ? null : url;
    }

    private async Task RecordOutcomeAsync(string status, string? error, CancellationToken ct)
    {
        try
        {
            await _orgs.SetInstanceSettingAsync(
                "system_slack_last_delivery_at", _time.GetUtcNow().ToString("O"), ct);
            await _orgs.SetInstanceSettingAsync("system_slack_last_status", status, ct);
            await _orgs.SetInstanceSettingAsync("system_slack_last_error", error ?? "", ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to record system Slack delivery outcome for action.");
        }
    }
}
