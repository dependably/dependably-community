using System.Diagnostics;

namespace Dependably.Infrastructure.Webhooks;

/// <summary>
/// Per-org queue + background worker pool for outbound webhook delivery.
/// Producers call <see cref="Dispatch"/> (via <see cref="IPackageEventSink"/>), which
/// is non-blocking and drops on overflow with a metric so the originating request path
/// never blocks.
///
/// Queuing is partitioned by org and served round-robin by an
/// <see cref="OrgFairDispatcher{TItem}"/> (see that type for the fairness bound and why a
/// single shared queue cannot provide it). Subscription URLs are tenant-supplied and may
/// point at an endpoint that accepts a connection and never answers, so "how long this org's
/// deliveries take" is a tenant-controlled quantity: it decides only when that org's own next
/// event is delivered and which of that org's own events are shed on overflow.
///
/// On each dequeued envelope the worker looks up all matching enabled subscriptions for
/// the event's org and event type, then fans out the deliveries concurrently, bounded by
/// <see cref="DefaultFanOutConcurrency"/> (<c>WEBHOOK_FANOUT_CONCURRENCY</c>). Each
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
    /// <summary>Queued envelopes held per org before that org's own events are shed.</summary>
    private const int DefaultCapacity = 1024;

    /// <summary>How many orgs' envelopes are served concurrently (<c>WEBHOOK_DISPATCH_WORKERS</c>).</summary>
    private const int DefaultWorkers = 4;

    /// <summary>
    /// Default bound on how many of one envelope's subscriptions are delivered to concurrently
    /// (<c>WEBHOOK_FANOUT_CONCURRENCY</c>). Bounded rather than unbounded so an org with many
    /// subscriptions cannot open an arbitrary number of simultaneous outbound connections.
    /// </summary>
    private const int DefaultFanOutConcurrency = 8;

    /// <summary>
    /// Default hard deadline on one envelope's whole fan-out (<c>WEBHOOK_ENVELOPE_BUDGET_SECONDS</c>).
    /// One subscription's full retry budget is 4 attempts at the delivery client's 15-second
    /// per-attempt timeout plus 36 seconds of backoff, so this leaves a single legitimately slow
    /// subscriber room to finish its retries while still bounding how long an org holds a worker.
    /// </summary>
    private const int DefaultEnvelopeBudgetSeconds = 120;

    /// <summary>
    /// Upper bound on how long the shutdown drain (see <see cref="ExecuteAsync"/>) spends
    /// delivering envelopes still queued once the host's stopping token has already fired.
    /// Bounded independently of the host's own shutdown timeout so one slow, retrying
    /// subscription cannot consume the entire grace period at the expense of every other org's
    /// queued envelopes.
    /// </summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(25);

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

    private readonly OrgFairDispatcher<PackageEventEnvelope> _dispatcher;
    private readonly WebhookSubscriptionRepository _subscriptions;
    private readonly WebhookDeliveryClient _client;
    private readonly TimeProvider _time;
    private readonly ILogger<WebhookDispatchQueue> _logger;
    private readonly int _workers;
    private readonly int _fanOutConcurrency;
    private readonly TimeSpan _envelopeBudget;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;

    public WebhookDispatchQueue(
        WebhookSubscriptionRepository subscriptions,
        WebhookDeliveryClient client,
        TimeProvider time,
        IConfiguration config,
        ILogger<WebhookDispatchQueue> logger)
    {
        _subscriptions = subscriptions;
        _client = client;
        _time = time;
        _logger = logger;

        int capacity = int.TryParse(config["WEBHOOK_QUEUE_CAPACITY"], out int c) && c > 0
            ? c : DefaultCapacity;
        _workers = int.TryParse(config["WEBHOOK_DISPATCH_WORKERS"], out int w) && w > 0
            ? w : DefaultWorkers;
        _fanOutConcurrency = int.TryParse(config["WEBHOOK_FANOUT_CONCURRENCY"], out int fc) && fc > 0
            ? fc : DefaultFanOutConcurrency;
        _envelopeBudget = OrgFairDispatcher.ResolveItemBudget(
            config, "WEBHOOK_ENVELOPE_BUDGET_SECONDS", DefaultEnvelopeBudgetSeconds, logger);

        _dispatcher = new OrgFairDispatcher<PackageEventEnvelope>(
            capacity, _workers, _envelopeBudget, time, logger, "webhook envelope");
    }

    /// <summary>
    /// Non-blocking enqueue onto the event's own org lane. Drops the event when that org's lane
    /// is full (overflow is recorded with a log warning; no exception propagated to the caller).
    /// The lane is per-org, so a backlog only ever sheds the events of the org that created it.
    /// </summary>
    public void Dispatch(PackageEventEnvelope envelope)
    {
        if (!_dispatcher.TryEnqueue(envelope.OrgId, envelope))
        {
            Interlocked.Increment(ref _droppedCount);
            _logger.LogWarning(
                "Webhook dispatch queue full for org {OrgId}; dropping event {EventType}.",
                envelope.OrgId, envelope.EventType);
        }
    }

    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long FailedCount => Interlocked.Read(ref _failedCount);

    /// <summary>
    /// Test-only direct invocation of <see cref="ExecuteAsync"/>. <see cref="BackgroundService.StartAsync"/>
    /// short-circuits and never invokes <c>ExecuteAsync</c> at all when handed an already-cancelled
    /// token, so it cannot exercise the shutdown-drain race this method covers (a stopping token
    /// cancelled while the worker pool is genuinely running, with envelopes still queued).
    /// </summary>
    internal Task ExecuteAsyncForTests(CancellationToken stoppingToken) => ExecuteAsync(stoppingToken);

    /// <summary>
    /// Test-only direct invocation of the fan-out. Exists to assert the contract the worker pool
    /// depends on: cancellation — a stopping token, or an exhausted per-envelope budget — is a
    /// return, never a thrown <see cref="OperationCanceledException"/>. A fan-out that threw on
    /// cancellation would escape the shutdown drain, which has no handler of its own, and would
    /// take a worker out of the pool during normal running.
    /// </summary>
    internal Task<bool> FanOutAsyncForTests(PackageEventEnvelope envelope, CancellationToken ct) =>
        FanOutAsync(envelope, ct);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Webhook dispatch queue starting with {Workers} worker(s) serving per-org lanes.", _workers);

        // Completes normally on shutdown: the dispatcher's workers treat a cancelled stopping
        // token as an expected end and leave whatever is still queued for the drain below.
        await _dispatcher.RunAsync(FanOutAsync, stoppingToken);

        await DrainOnShutdownAsync();
    }

    /// <summary>
    /// Runs whatever is still queued through the normal fan-out path when shutdown cancels the
    /// worker pool above, taking envelopes in the same per-org round-robin order and running each
    /// through the dispatcher's own per-envelope budget. Both matter, and the budget is the one
    /// that carries the cross-tenant property: rotation alone still lets the first org drained
    /// decide, from its own endpoint, how much of a bounded drain window every other org gets.
    /// The host's own stopping token is already cancelled by this point, so drained deliveries run
    /// on a fresh, time-bounded token (<see cref="DrainTimeout"/>) instead — otherwise every
    /// delivery attempt would see cancellation immediately and skip straight to "failed" without
    /// ever trying.
    /// </summary>
    private async Task DrainOnShutdownAsync()
    {
        using var drainCts = new CancellationTokenSource(DrainTimeout);
        int drained = 0;
        int abandoned = 0;

        while (_dispatcher.TryTakeForDrain(out var envelope, out string orgId))
        {
            if (drainCts.IsCancellationRequested)
            {
                // Drain window exhausted — stop attempting deliveries but keep emptying the
                // lanes so the abandoned count is accurate.
                abandoned++;
                continue;
            }

            if (await _dispatcher.RunOneAsync(FanOutAsync, envelope, orgId, drainCts.Token))
            {
                drained++;
            }
            else
            {
                // Cut short by this envelope's own budget or by the drain window closing under
                // it. Counted as abandoned rather than drained: the next org's envelope is what
                // that budget exists to protect, and the operator needs the count to be honest.
                abandoned++;
            }
        }

        if (abandoned > 0)
        {
            _logger.LogWarning(
                "Webhook dispatch queue shutdown drain gave up on {Count} envelope(s) within its " +
                "{Timeout}s window: each envelope gets at most {Budget}s so no one org's endpoints " +
                "can consume another org's share of the drain.",
                abandoned, DrainTimeout.TotalSeconds, _envelopeBudget.TotalSeconds);
        }

        if (drained > 0)
        {
            _logger.LogInformation(
                "Webhook dispatch queue drained {Count} envelope(s) still queued at shutdown.", drained);
        }
    }

    /// <summary>
    /// Delivers one envelope to every matching subscription. Returns whether the envelope was
    /// carried to a conclusion: false means cancellation stopped it part-way, which is what tells
    /// the dispatcher to hand it back for the shutdown drain rather than lose it. A subscription
    /// load that fails for its own reasons is a conclusion — there is nothing to retry later.
    /// </summary>
    private async Task<bool> FanOutAsync(PackageEventEnvelope envelope, CancellationToken ct)
    {
        IReadOnlyList<WebhookSubscriptionDelivery> subs;
        try
        {
            subs = await _subscriptions.ListEnabledForEventAsync(
                envelope.OrgId, envelope.EventType, ct);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to load subscriptions for event {EventType} org {OrgId}; skipping fan-out.",
                envelope.EventType, envelope.OrgId);
            return true;
        }

        if (ct.IsCancellationRequested)
        {
            return false;
        }

        if (subs.Count == 0)
        {
            return true;
        }

        // Deliver to this org's subscriptions concurrently rather than one after another: the
        // envelope's whole fan-out runs under one budget, so a sequential loop would spend that
        // budget on the first few subscriptions and leave the rest of the org's own endpoints
        // unattempted whenever one of them is slow.
        using var gate = new SemaphoreSlim(Math.Min(subs.Count, _fanOutConcurrency));
        bool[] outcomes = await Task.WhenAll(subs.Select(sub => DeliverGatedAsync(envelope, sub, gate, ct)));
        return Array.TrueForAll(outcomes, reachedConclusion => reachedConclusion);
    }

    // Every path here completes rather than throws — including both of SemaphoreSlim.WaitAsync's
    // cancellation paths, which raise OperationCanceledException on an already-cancelled token
    // even when a slot is free. A thrown task would surface out of Task.WhenAll above and escape
    // the caller: the shutdown drain has no handler, and the worker pool would lose a worker.
    private async Task<bool> DeliverGatedAsync(
        PackageEventEnvelope envelope,
        WebhookSubscriptionDelivery sub,
        SemaphoreSlim gate,
        CancellationToken ct)
    {
        try
        {
            await gate.WaitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            return false;
        }

        try
        {
            return await DeliverToSubscriptionAsync(envelope, sub, ct);
        }
        catch (OperationCanceledException)
        {
            // The delivery path already returns on cancellation; this is the belt to that brace.
            return false;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>
    /// Delivers to one subscription, retrying on the shared backoff schedule. Returns whether the
    /// subscription reached a terminal outcome — a recorded success or a recorded exhaustion of
    /// the retry budget. False means cancellation ended it early and nothing terminal was written.
    /// </summary>
    internal async Task<bool> DeliverToSubscriptionAsync(
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
                return false;
            }

            try
            {
                await _client.SendAsync(sub.Url, sub.Secret, envelope, deliveryId, ct);

                // The POST already landed at the subscriber — this is an irreversible external
                // side effect. If host shutdown cancels `ct` in the window between the send
                // returning and the bookkeeping write, the write must still happen: run it on
                // an independent token so it survives the stopping token being cancelled.
                // DeliveredCount is bumped only after the durable write succeeds, so the
                // observable completion signal implies durable state.
                await RecordSuccessAsync(sub, CancellationToken.None);
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
                if (attempt == BackoffSchedule.Length)
                {
                    break;
                }

                _logger.LogDebug(ex,
                    "Webhook delivery attempt {Attempt} failed for subscription {SubId}; retrying in {Backoff}.",
                    attempt + 1, sub.Id, BackoffSchedule[attempt]);
                try
                {
                    await Task.Delay(BackoffSchedule[attempt], _time, ct);
                }
                catch (OperationCanceledException)
                {
                    return false;
                }
            }
        }

        // All attempts exhausted — also a terminal, durable outcome (it drives auto-disable),
        // so it gets the same independent-token treatment as success.
        string errorMsg = lastEx?.Message ?? "Unknown error";
        _logger.LogWarning(lastEx,
            "Webhook delivery failed after {Attempts} attempts for subscription {SubId} ({Url}); recording failure.",
            BackoffSchedule.Length + 1, sub.Id, sub.Url);

        await RecordFailureAsync(sub, errorMsg, CancellationToken.None);
        Interlocked.Increment(ref _failedCount);
        return true;
    }

    internal async Task RecordSuccessAsync(WebhookSubscriptionDelivery sub, CancellationToken ct)
    {
        try
        {
            await _subscriptions.RecordSuccessAsync(sub.OrgId, sub.Id, ct);
        }
        catch (Exception ex)
        {
            // Callers pass CancellationToken.None here once the delivery has succeeded, so an
            // OperationCanceledException reaching this catch means the durable write itself was
            // lost, not routine shutdown noise — it needs to stand out from the transient
            // per-attempt failures logged at Debug above.
            _logger.LogWarning(ex,
                "{ExceptionType} recording webhook delivery success for subscription {SubId}; " +
                "delivery happened but was not durably recorded. TraceId={TraceId}",
                ex.GetType().Name, sub.Id, Activity.Current?.TraceId.ToString());
        }
    }

    internal async Task RecordFailureAsync(
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
            _logger.LogWarning(ex,
                "{ExceptionType} recording webhook delivery failure for subscription {SubId}; " +
                "failure count for auto-disable was not durably recorded. TraceId={TraceId}",
                ex.GetType().Name, sub.Id, Activity.Current?.TraceId.ToString());
        }
    }
}
