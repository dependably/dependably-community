using System.Threading.Channels;

namespace Dependably.Infrastructure.Webhooks;

/// <summary>
/// Bounded in-memory queue + background worker for outbound webhook delivery.
/// Producers call <see cref="Dispatch"/> (via <see cref="IPackageEventSink"/>), which
/// is non-blocking and drops on overflow with a metric so the originating request path
/// never blocks.
///
/// On each dequeued envelope the worker looks up all matching enabled subscriptions for
/// the event's org and event type, then fans out one delivery per subscription. Each
/// subscription's delivery is retried independently with the same backoff schedule as the
/// SIEM forwarder (initial + 3 retries at 1s / 5s / 30s = 4 total attempts). Failure
/// counters are per-subscription and do not cross-contaminate when some succeed and others
/// fail in the same fan-out.
///
/// After a terminal outcome (success or all retries exhausted) the subscription's
/// <c>consecutive_failures</c> and <c>last_status</c> fields are updated. The subscription
/// is auto-disabled when <c>consecutive_failures</c> reaches
/// <see cref="AutoDisableAfterFailures"/> OR the <c>failing_since</c> window has exceeded
/// <see cref="AutoDisableAfterDuration"/>, whichever comes first.
/// </summary>
public sealed class WebhookDispatchQueue : BackgroundService, IPackageEventSink
{
    private const int DefaultCapacity = 1024;

    /// <summary>Auto-disable a subscription after this many consecutive terminal failures.</summary>
    internal const int AutoDisableAfterFailures = 20;

    /// <summary>Auto-disable a subscription that has been failing continuously for this long.</summary>
    internal static readonly TimeSpan AutoDisableAfterDuration = TimeSpan.FromHours(48);

    private static readonly TimeSpan[] BackoffSchedule =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(30)
    ];

    private readonly Channel<PackageEventEnvelope> _channel;
    private readonly WebhookSubscriptionRepository _subscriptions;
    private readonly WebhookDeliveryClient _client;
    private readonly ILogger<WebhookDispatchQueue> _logger;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;

    public WebhookDispatchQueue(
        WebhookSubscriptionRepository subscriptions,
        WebhookDeliveryClient client,
        IConfiguration config,
        ILogger<WebhookDispatchQueue> logger)
    {
        _subscriptions = subscriptions;
        _client = client;
        _logger = logger;

        int capacity = int.TryParse(config["WEBHOOK_QUEUE_CAPACITY"], out int c) && c > 0
            ? c : DefaultCapacity;
        // FullMode.Wait is the default for BoundedChannel. With this mode, TryWrite returns
        // false immediately when the channel is at capacity — enabling the Dispatch method
        // to detect and count the drop. DropWrite is not used because TryWrite returns true
        // even when the item was dropped, making overflow tracking impossible.
        _channel = Channel.CreateBounded<PackageEventEnvelope>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    }

    /// <summary>
    /// Non-blocking enqueue. Drops the event when the channel is full (overflow is recorded
    /// with a log warning; no exception propagated to the caller).
    /// </summary>
    public void Dispatch(PackageEventEnvelope envelope)
    {
        if (!_channel.Writer.TryWrite(envelope))
        {
            Interlocked.Increment(ref _droppedCount);
            _logger.LogWarning(
                "Webhook dispatch queue full; dropping event {EventType} for org {OrgId}.",
                envelope.EventType, envelope.OrgId);
        }
    }

    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long FailedCount => Interlocked.Read(ref _failedCount);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Webhook dispatch queue starting.");

        await foreach (var envelope in _channel.Reader.ReadAllAsync(stoppingToken))
        {
            await FanOutAsync(envelope, stoppingToken);
        }
    }

    private async Task FanOutAsync(PackageEventEnvelope envelope, CancellationToken ct)
    {
        IReadOnlyList<WebhookSubscriptionDelivery> subs;
        try
        {
            subs = await _subscriptions.ListEnabledForEventAsync(
                envelope.OrgId, envelope.EventType, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to load subscriptions for event {EventType} org {OrgId}; skipping fan-out.",
                envelope.EventType, envelope.OrgId);
            return;
        }

        foreach (var sub in subs)
        {
            if (ct.IsCancellationRequested)
            {
                return;
            }

            await DeliverToSubscriptionAsync(envelope, sub, ct);
        }
    }

    private async Task DeliverToSubscriptionAsync(
        PackageEventEnvelope envelope,
        WebhookSubscriptionDelivery sub,
        CancellationToken ct)
    {
        string deliveryId = Guid.NewGuid().ToString("D");
        Exception? lastEx = null;

        for (int attempt = 0; attempt <= BackoffSchedule.Length; attempt++)
        {
            if (ct.IsCancellationRequested)
            {
                return;
            }

            try
            {
                await _client.SendAsync(sub.Url, sub.Secret, envelope, deliveryId, ct);

                Interlocked.Increment(ref _deliveredCount);
                await RecordSuccessAsync(sub, ct);
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
                    "Webhook delivery attempt {Attempt} failed for subscription {SubId}; retrying in {Backoff}.",
                    attempt + 1, sub.Id, BackoffSchedule[attempt]);
                try
                {
                    await Task.Delay(BackoffSchedule[attempt], ct);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }

        // All attempts exhausted.
        Interlocked.Increment(ref _failedCount);
        string errorMsg = lastEx?.Message ?? "Unknown error";
        _logger.LogWarning(lastEx,
            "Webhook delivery failed after {Attempts} attempts for subscription {SubId} ({Url}); recording failure.",
            BackoffSchedule.Length + 1, sub.Id, sub.Url);

        await RecordFailureAsync(sub, errorMsg, ct);
    }

    private async Task RecordSuccessAsync(WebhookSubscriptionDelivery sub, CancellationToken ct)
    {
        try
        {
            await _subscriptions.RecordSuccessAsync(sub.OrgId, sub.Id, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to record webhook delivery success for subscription {SubId}.", sub.Id);
        }
    }

    private async Task RecordFailureAsync(
        WebhookSubscriptionDelivery sub, string errorMsg, CancellationToken ct)
    {
        try
        {
            bool autoDisabled = await _subscriptions.RecordFailureAsync(
                sub.OrgId, sub.Id, errorMsg,
                AutoDisableAfterFailures, AutoDisableAfterDuration, ct);

            if (autoDisabled)
            {
                _logger.LogWarning(
                    "Webhook subscription {SubId} (org {OrgId}, url {Url}) auto-disabled " +
                    "after consecutive or sustained failures. Re-enable via Settings → Webhooks.",
                    sub.Id, sub.OrgId, sub.Url);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to record webhook delivery failure for subscription {SubId}.", sub.Id);
        }
    }
}
