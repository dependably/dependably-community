using System.Threading.Channels;
using Dependably.Infrastructure.Alerts;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// The delivery worker behind the durable outbox. Each pass retires rows that have passed a
/// ceiling, claims the due ones under a lease, and attempts each over the instance-level SMTP
/// transport — resolved fresh on every pass, so an operator fixing the relay mid-outage is picked
/// up without a restart and without the queue having been drained into the void meanwhile.
///
/// <para>
/// The state machine this worker implements:
/// <c>pending → sending → delivered</c> on success;
/// <c>sending → pending</c> (backoff) on a transient or unrecognised failure;
/// <c>sending → dead_letter</c> on a permanent one;
/// <c>pending|sending → expired</c> when the retry ceiling, the retry-duration ceiling, or the
/// retention ceiling is reached. <c>delivered</c>, <c>dead_letter</c> and <c>expired</c> are
/// terminal and this worker never leaves them.
/// </para>
///
/// <para>
/// An unavailable transport (SMTP disabled or unconfigured) is <b>not</b> a delivery attempt: the
/// pass claims nothing, so no row consumes an attempt against a relay that was never dialed. Such a
/// row waits, durably, until the transport exists or until its retention ceiling retires it. That is
/// the case the old in-memory queue turned into a silent drop.
/// </para>
///
/// <para>
/// Claiming also goes through <see cref="EmailTransportBreaker"/>, which circuit-breaks the shared
/// transport itself rather than any tenant's channel: a run of transport-scope failures (connection
/// refused, timeout, an SMTP 4xx — never a permanent, message-specific one) stops this worker from
/// claiming new rows until a self-issued probe confirms the relay again, so a down relay is not
/// hammered by the whole backlog on every 5-second poll. The four bounds below are unaffected by the
/// breaker's state: <see cref="RunPassAsync"/> always retires overdue rows first, breaker open or not.
/// </para>
///
/// <para>
/// Deliberately absent, and deliberately not simulated here: burst coalescing at delivery time (it
/// happens at enqueue, in <see cref="AlertEmailQueue"/>) and an operator aggregate health surface.
/// What this worker does carry in the interim is a backlog-depth warning on threshold crossing, so
/// an outage is visible in the logs rather than only in the table.
/// </para>
/// </summary>
public sealed class EmailOutboxDeliveryService : BackgroundService
{
    private readonly EmailOutboxRepository _outbox;
    private readonly EmailOutboxPolicy _policy;
    private readonly EmailTransportBreaker _breaker;
    private readonly InstanceSmtpConfig _instanceConfig;
    private readonly SmtpMailSender _sender;
    private readonly AlertRepository _alerts;
    private readonly AlertSettingsRepository _alertSettings;
    private readonly TimeProvider _time;
    private readonly ILogger<EmailOutboxDeliveryService> _logger;

    // Capacity-1 drop-on-full wake signal: an enqueue nudges the worker so a freshly-raised alert
    // does not wait out the poll interval, and N enqueues collapse into one nudge. A Channel rather
    // than a SemaphoreSlim because a cancelled channel wait cannot consume the pending signal.
    private readonly Channel<byte> _wake = Channel.CreateBounded<byte>(
        new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
            SingleWriter = false,
        });

    private bool _backlogWarned;
    private long _deliveredCount;
    private long _deadLetteredCount;
    private long _expiredCount;
    private long _retriedCount;

    public EmailOutboxDeliveryService(
        EmailOutboxRepository outbox,
        EmailOutboxPolicy policy,
        EmailTransportBreaker breaker,
        InstanceSmtpConfig instanceConfig,
        SmtpMailSender sender,
        AlertRepository alerts,
        AlertSettingsRepository alertSettings,
        TimeProvider time,
        ILogger<EmailOutboxDeliveryService> logger)
    {
        _outbox = outbox;
        _policy = policy;
        _breaker = breaker;
        _instanceConfig = instanceConfig;
        _sender = sender;
        _alerts = alerts;
        _alertSettings = alertSettings;
        _time = time;
        _logger = logger;
    }

    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long DeadLetteredCount => Interlocked.Read(ref _deadLetteredCount);
    public long ExpiredCount => Interlocked.Read(ref _expiredCount);
    public long RetriedCount => Interlocked.Read(ref _retriedCount);

    /// <summary>
    /// Nudges the worker to run a pass now instead of at the next poll tick. Non-blocking, and a
    /// no-op when a nudge is already queued.
    /// </summary>
    public void Wake() => _wake.Writer.TryWrite(0);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Email outbox delivery worker starting.");

        while (!stoppingToken.IsCancellationRequested)
        {
            // Collapse any nudges that arrived while the previous pass ran — the pass about to run
            // already covers them.
            while (_wake.Reader.TryRead(out _))
            {
            }

            try
            {
                await RunPassAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // A failed pass must never fault the hosted service — under the default
                // BackgroundServiceExceptionBehavior that stops the whole host. The next pass
                // retries, and every row it did not reach is still durably queued.
                _logger.LogError(ex,
                    "{ExceptionType} in the email outbox delivery pass; the queue is unchanged and the next pass retries.",
                    ex.GetType().Name);
            }

            await WaitForWorkAsync(stoppingToken);
        }

        // No shutdown drain: the queue is the database. Whatever is still pending is picked up by
        // this replica's next start or by another replica's next pass — which is the whole point.
        _logger.LogInformation("Email outbox delivery worker stopping; queued messages remain durably persisted.");
    }

    /// <summary>
    /// One delivery pass: retire overdue rows, report the backlog, then claim and attempt the due
    /// batch. Internal so tests drive the semantics directly rather than through the timing loop.
    /// </summary>
    internal async Task RunPassAsync(CancellationToken ct)
    {
        int expired = await _outbox.ExpireOverdueAsync(ct);
        if (expired > 0)
        {
            Interlocked.Add(ref _expiredCount, expired);
            _logger.LogWarning(
                "Email outbox: {Count} message(s) expired without delivery — the retry or retention ceiling was reached.",
                expired);
        }

        await ReportBacklogAsync(ct);

        var instance = await _instanceConfig.ResolveAsync(ct);
        if (!instance.Enabled || !instance.Configured)
        {
            // Claim nothing: an unresolvable transport is not a failed attempt, and charging the
            // retry budget for it would retire mail the operator has not had a chance to carry yet.
            _logger.LogDebug(
                "Email outbox: instance SMTP transport is not enabled/configured; no delivery attempted this pass.");
            return;
        }

        int budget = _breaker.BeginPassBudget(EmailOutboxPolicy.DrainBatchSize);
        if (budget <= 0)
        {
            _logger.LogDebug("Email outbox: transport breaker is open; no delivery attempted this pass.");
            return;
        }

        var due = await _outbox.ClaimDueAsync(budget, ct);
        if (due.Count == 0)
        {
            // A probe budget with nothing due proves nothing about the relay — release it rather
            // than counting it as a failed (or successful) probe.
            _breaker.AbandonUnusedProbe();
            return;
        }

        foreach (var message in due)
        {
            if (ct.IsCancellationRequested)
            {
                // The lease lapses on its own; the row returns to the drain set untouched.
                return;
            }

            await AttemptAsync(instance.Transport, message, ct);
        }
    }

    private async Task AttemptAsync(
        SmtpTransportSettings transport, ClaimedEmailOutboxMessage message, CancellationToken ct)
    {
        try
        {
            await _sender.SendAsync(transport, message.Recipients, message.Subject, message.Body, ct);
        }
        catch (Exception ex)
        {
            await RecordFailedAttemptAsync(message, ex);
            return;
        }

        // The message has left for the relay — an irreversible external side effect. The terminal
        // write and the domain bookkeeping therefore run on an independent token, so host shutdown
        // cancelling this attempt cannot leave the row claimed for a send that already happened.
        _breaker.RecordDelivered();
        await _outbox.MarkDeliveredAsync(message.Id, CancellationToken.None);
        Interlocked.Increment(ref _deliveredCount);
        await RecordDomainOutcomeAsync(message, delivered: true, error: null);
    }

    private async Task RecordFailedAttemptAsync(ClaimedEmailOutboxMessage message, Exception ex)
    {
        string failureClass = EmailOutboxFailureClassifier.Classify(ex);
        string error = $"{ex.GetType().Name}: {ex.Message}";

        if (failureClass == EmailOutboxFailureClasses.Permanent)
        {
            // A single bad recipient is not a relay outage: the transport answered with a
            // definitive protocol verdict about this one message, which never trips the breaker.
            _breaker.RecordPermanentFailure();
            await _outbox.MarkDeadLetterAsync(message.Id, failureClass, error, CancellationToken.None);
            Interlocked.Increment(ref _deadLetteredCount);
            _logger.LogWarning(ex,
                "{ExceptionType} delivering outbox message {MessageId} (org {OrgId}): permanent failure, dead-lettered without retry.",
                ex.GetType().Name, message.Id, message.OrgId);
            await RecordDomainOutcomeAsync(message, delivered: false, error);
            return;
        }

        // Transient or unrecognised: the two classes the classifier could not pin on the message
        // itself, so they are the ones that can mean the relay is the problem.
        _breaker.RecordTransportFailure();

        var nextAttemptAt = _time.GetUtcNow().Add(EmailOutboxPolicy.BackoffAfter(message.Attempts));
        string nextAttemptIso = nextAttemptAt.ToUtcIso();

        // Three ceilings retire the message here rather than scheduling an attempt that could never
        // run: the attempt count, the retry-duration deadline, and the retention deadline. The
        // deadline comparisons are ordinal over canonical ISO-8601 UTC text — the same comparison
        // the database performs on the same columns.
        bool attemptsExhausted = message.Attempts >= _policy.MaxAttempts;
        bool pastRetryDeadline = string.CompareOrdinal(nextAttemptIso, message.RetryDeadlineAt) >= 0;
        bool pastRetention = string.CompareOrdinal(nextAttemptIso, message.ExpiresAt) >= 0;

        if (attemptsExhausted || pastRetryDeadline || pastRetention)
        {
            await _outbox.MarkExpiredAsync(message.Id, failureClass, error, CancellationToken.None);
            Interlocked.Increment(ref _expiredCount);
            _logger.LogWarning(ex,
                "{ExceptionType} delivering outbox message {MessageId} (org {OrgId}) after {Attempts} attempt(s): "
                + "expired ({Ceiling}) — the message was never delivered.",
                ex.GetType().Name, message.Id, message.OrgId, message.Attempts,
                attemptsExhausted ? "retry ceiling"
                    : pastRetryDeadline ? "maximum retry duration" : "maximum retention");
            await RecordDomainOutcomeAsync(message, delivered: false, error);
            return;
        }

        await _outbox.ScheduleRetryAsync(
            message.Id, nextAttemptAt, failureClass, error, CancellationToken.None);
        Interlocked.Increment(ref _retriedCount);
        _logger.LogDebug(ex,
            "{ExceptionType} delivering outbox message {MessageId} (org {OrgId}) on attempt {Attempts}: "
            + "{FailureClass} failure, retrying at {NextAttemptAt}.",
            ex.GetType().Name, message.Id, message.OrgId, message.Attempts, failureClass, nextAttemptIso);
    }

    /// <summary>
    /// Writes the terminal outcome back onto the domain row the message reports on.
    /// <c>message_kind</c> is the discriminator: alert mail stamps <c>alert.email_status</c> and the
    /// org's <c>alert_settings</c> delivery-health columns, exactly as the in-memory path did.
    /// Failure is recorded, never acted on — the transport is instance-level, so a delivery failure
    /// is shared operator infrastructure and must not disable this org's channel.
    /// </summary>
    private async Task RecordDomainOutcomeAsync(
        ClaimedEmailOutboxMessage message, bool delivered, string? error)
    {
        if (message.MessageKind != EmailOutboxMessageKinds.Alert
            || message.OrgId is null
            || message.CorrelationId is null)
        {
            return;
        }

        try
        {
            await _alerts.RecordEmailOutcomeAsync(
                message.OrgId, message.CorrelationId, delivered ? "sent" : "failed", error,
                CancellationToken.None);

            if (delivered)
            {
                await _alertSettings.RecordEmailSuccessAsync(message.OrgId, CancellationToken.None);
            }
            else
            {
                await _alertSettings.RecordEmailFailureAsync(
                    message.OrgId, error ?? "Unknown error", CancellationToken.None);
            }
        }
        catch (Exception ex)
        {
            // The outbox row already holds the authoritative terminal state; only the domain
            // read-model write failed. Log loudly and move on rather than re-queueing a message
            // that was already handed to the relay.
            _logger.LogWarning(ex,
                "{ExceptionType} recording the {Outcome} outcome of outbox message {MessageId} on alert "
                + "{AlertId} (org {OrgId}); the outbox row is correct but the alert row was not updated.",
                ex.GetType().Name, delivered ? "delivered" : "failed", message.Id,
                message.CorrelationId, message.OrgId);
        }
    }

    /// <summary>
    /// Logs a warning the first time the non-terminal backlog crosses
    /// <see cref="EmailOutboxPolicy.BacklogWarnDepth"/>, and an informational line when it recovers.
    /// Edge-triggered on purpose: a per-pass warning at a 5-second poll would emit thousands of
    /// identical lines across one outage and bury the transition that matters.
    /// </summary>
    private async Task ReportBacklogAsync(CancellationToken ct)
    {
        var backlog = await _outbox.GetBacklogAsync(ct);

        if (backlog.Depth >= _policy.BacklogWarnDepth && !_backlogWarned)
        {
            _backlogWarned = true;
            _logger.LogWarning(
                "Email outbox backlog is {Depth} message(s) (threshold {Threshold}); oldest queued at "
                + "{OldestCreatedAt}. Dead-lettered: {DeadLettered}, expired: {Expired}.",
                backlog.Depth, _policy.BacklogWarnDepth, backlog.OldestCreatedAt,
                backlog.DeadLettered, backlog.Expired);
        }
        else if (backlog.Depth < _policy.BacklogWarnDepth && _backlogWarned)
        {
            _backlogWarned = false;
            _logger.LogInformation(
                "Email outbox backlog recovered to {Depth} message(s), below the {Threshold} threshold.",
                backlog.Depth, _policy.BacklogWarnDepth);
        }
    }

    /// <summary>
    /// Waits for the poll interval or for an enqueue nudge, whichever lands first, then cancels and
    /// observes the loser so neither a timer registration nor a queued channel waiter accumulates.
    /// </summary>
    private async Task WaitForWorkAsync(CancellationToken stoppingToken)
    {
        using var iteration = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var tick = Task.Delay(EmailOutboxPolicy.PollInterval, _time, iteration.Token);
        var nudge = _wake.Reader.WaitToReadAsync(iteration.Token).AsTask();

        try
        {
            await Task.WhenAny(tick, nudge);
        }
        finally
        {
            await iteration.CancelAsync();
            await ObserveAsync(tick);
            await ObserveAsync(nudge);
        }
    }

    // Awaits a task purely to consume its outcome, so a cancelled loser of the race above never
    // surfaces as an unobserved task exception.
    private static async Task ObserveAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (Exception)
        {
            // Intentionally swallowed: the only outcomes here are completion and cancellation, and
            // neither is actionable.
        }
    }
}
