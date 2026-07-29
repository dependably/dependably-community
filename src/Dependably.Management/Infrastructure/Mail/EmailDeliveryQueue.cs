using System.Threading.Channels;
using Dependably.Infrastructure.Alerts;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Bounded in-memory queue + background worker shared by every outbound-email delivery channel
/// (per-org alert email via <see cref="Alerts.AlertEmailQueue"/>, transactional account email via
/// <see cref="TransactionalEmailService"/>, …). Each channel wraps its own domain object in an
/// <see cref="IEmailDeliveryJob"/> and calls <see cref="Enqueue"/>; this class owns the one
/// channel, worker loop, retry backoff, shutdown drain, and delivery counters — no delivery
/// channel implements any of that machinery itself.
///
/// A job resolving to null (channel disabled, unconfigured, or unresolvable) is a silent no-op —
/// nothing sent, nothing recorded. A resolvable job gets 1 initial attempt + 3 retries at
/// 1s / 5s / 30s (<see cref="AlertDeliveryPolicy.BackoffSchedule"/>), the schedule every delivery
/// queue in this codebase shares. Terminal success/failure bookkeeping is the job's own
/// responsibility (<see cref="IEmailDeliveryJob.RecordSuccessAsync"/> /
/// <see cref="IEmailDeliveryJob.RecordFailureAsync"/>) — this queue only decides when to call them.
/// </summary>
public sealed class EmailDeliveryQueue : BackgroundService
{
    private const int DefaultCapacity = 1024;

    /// <summary>
    /// Upper bound on how long the shutdown drain (see <see cref="ExecuteAsync"/>) spends
    /// delivering jobs still buffered in the channel once the host's stopping token has already
    /// fired. Bounded independently of the host's own shutdown timeout so one slow, retrying job
    /// cannot consume the entire grace period at the expense of every other job waiting behind it.
    /// </summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(25);

    private readonly Channel<IEmailDeliveryJob> _channel;
    private readonly SmtpMailSender _sender;
    private readonly TimeProvider _time;
    private readonly ILogger<EmailDeliveryQueue> _logger;
    private long _droppedCount;
    private long _deliveredCount;
    private long _failedCount;
    private long _processedCount;

    public EmailDeliveryQueue(
        SmtpMailSender sender,
        TimeProvider time,
        ILogger<EmailDeliveryQueue> logger)
        : this(sender, time, logger, DefaultCapacity)
    {
    }

    /// <summary>
    /// Test-only overload accepting an explicit channel capacity so
    /// <c>EmailDeliveryQueueTests</c> can exercise the overflow/drop path with a small bound.
    /// Not configurable in production — the channel capacity is a process-internal backpressure
    /// bound, not an operator-tunable setting.
    /// </summary>
    internal EmailDeliveryQueue(
        SmtpMailSender sender,
        TimeProvider time,
        ILogger<EmailDeliveryQueue> logger,
        int capacity)
    {
        _sender = sender;
        _time = time;
        _logger = logger;

        _channel = Channel.CreateBounded<IEmailDeliveryJob>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    }

    /// <summary>Non-blocking enqueue. Drops on overflow (logged, never thrown back to the caller).</summary>
    public void Enqueue(IEmailDeliveryJob job)
    {
        if (!_channel.Writer.TryWrite(job))
        {
            Interlocked.Increment(ref _droppedCount);
            _logger.LogWarning(
                "Email delivery queue full; dropping a {JobType} job.", job.GetType().Name);
        }
    }

    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long FailedCount => Interlocked.Read(ref _failedCount);

    /// <summary>
    /// Total jobs that have left the channel and run through <see cref="DeliverAsync"/> to a
    /// terminal outcome (delivered, failed, or dropped because the transport resolved to null) —
    /// distinct from <see cref="DroppedCount"/>, which counts only channel-overflow drops that
    /// never reach delivery. Lets a caller observe that a specific enqueued job has been fully
    /// handled; tests use it to wait out a setup email (enqueued while SMTP was unconfigured, so
    /// resolved to null and dropped) before mutating SMTP config, closing the enqueue-vs-drain
    /// race that delivery-time transport resolution otherwise leaves open.
    /// </summary>
    public long ProcessedCount => Interlocked.Read(ref _processedCount);

    /// <summary>
    /// Test-only direct invocation of <see cref="ExecuteAsync"/>. <see cref="BackgroundService.StartAsync"/>
    /// short-circuits and never invokes <c>ExecuteAsync</c> at all when handed an already-cancelled
    /// token, so it cannot exercise the shutdown-drain race this method covers (a stopping token
    /// cancelled while the read loop is genuinely running, with jobs still buffered).
    /// </summary>
    internal Task ExecuteAsyncForTests(CancellationToken stoppingToken) => ExecuteAsync(stoppingToken);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Email delivery queue starting.");

        try
        {
            await foreach (var job in _channel.Reader.ReadAllAsync(stoppingToken))
            {
                await DeliverAsync(job, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // ReadAllAsync's WaitToReadAsync checks the stopping token before it checks whether
            // the channel has buffered items, so cancellation can fire here with jobs still
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

        while (_channel.Reader.TryRead(out var job))
        {
            if (drainCts.IsCancellationRequested)
            {
                // Drain window exhausted — stop attempting deliveries but keep draining the
                // channel itself so the abandoned count is accurate.
                abandoned++;
                continue;
            }

            await DeliverAsync(job, drainCts.Token);
            drained++;
        }

        if (abandoned > 0)
        {
            _logger.LogWarning(
                "Email delivery queue shutdown drain timed out after {Timeout}s; " +
                "{Count} job(s) still buffered were not attempted.",
                DrainTimeout.TotalSeconds, abandoned);
        }

        if (drained > 0)
        {
            _logger.LogInformation(
                "Email delivery queue drained {Count} job(s) still buffered at shutdown.", drained);
        }
    }

    internal async Task DeliverAsync(IEmailDeliveryJob job, CancellationToken ct)
    {
        try
        {
            await DeliverCoreAsync(job, ct);
        }
        finally
        {
            // Count every job exactly once, whatever its terminal outcome (delivered, failed, or
            // dropped on a null transport). A caller can then wait for a specific enqueued job to
            // have been handled — see ProcessedCount.
            Interlocked.Increment(ref _processedCount);
        }
    }

    private async Task DeliverCoreAsync(IEmailDeliveryJob job, CancellationToken ct)
    {
        (SmtpTransportSettings Transport, IReadOnlyList<string> Recipients)? resolved;
        try
        {
            resolved = await job.ResolveAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} resolving transport for a {JobType} job; skipping delivery.",
                ex.GetType().Name, job.GetType().Name);
            return;
        }

        if (resolved is null)
        {
            // Disabled, unconfigured, or unresolvable — nothing to attempt. Logged at
            // Information rather than Warning: an instance may deliberately run without SMTP.
            _logger.LogInformation(
                "Email transport unavailable (SMTP disabled or unconfigured); dropping a {JobType} job without delivery.",
                job.GetType().Name);
            return;
        }

        (string subject, string body) = job.Render();
        Exception? lastEx = null;

        for (int attempt = 0; attempt <= AlertDeliveryPolicy.BackoffSchedule.Length; attempt++)
        {
            if (ct.IsCancellationRequested)
            {
                return;
            }

            try
            {
                await _sender.SendAsync(resolved.Value.Transport, resolved.Value.Recipients, subject, body, ct);

                // The send already landed at the SMTP relay — this is an irreversible external
                // side effect. The job's own RecordSuccessAsync is responsible for durably
                // recording it on a token that survives host shutdown cancelling this method's
                // own ct; DeliveredCount is bumped only after that durable write returns, so the
                // observable completion signal implies durable state.
                await job.RecordSuccessAsync();
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
                    "Email delivery attempt {Attempt} failed for a {JobType} job; retrying in {Backoff}.",
                    attempt + 1, job.GetType().Name, AlertDeliveryPolicy.BackoffSchedule[attempt]);
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

        // The retry budget is exhausted — this is also a terminal, durable outcome, so the job
        // records it the same way it records success.
        string errorMsg = lastEx?.Message ?? "Unknown error";
        _logger.LogWarning(lastEx,
            "Email delivery failed after {Attempts} attempts for a {JobType} job; recording failure.",
            AlertDeliveryPolicy.BackoffSchedule.Length + 1, job.GetType().Name);

        await job.RecordFailureAsync(errorMsg);
        Interlocked.Increment(ref _failedCount);
    }
}
