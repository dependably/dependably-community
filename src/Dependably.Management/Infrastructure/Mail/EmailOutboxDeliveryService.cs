using System.Threading.Channels;
using Dependably.Infrastructure.Alerts;

namespace Dependably.Infrastructure.Mail;

/// <summary>Injected dependencies, bundled so the constructor stays within S107.</summary>
public sealed record EmailOutboxDeliveryServices(
    EmailOutboxRepository Outbox,
    EmailOutboxPolicy Policy,
    EmailTransportBreaker Breaker,
    InstanceSmtpConfig InstanceConfig,
    SmtpMailSender Sender,
    AlertRepository Alerts,
    AlertSettingsRepository AlertSettings,
    OrgRepository Orgs,
    TimeProvider Time,
    ILogger<EmailOutboxDeliveryService> Logger);

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
/// Each pass also reconciles the alert-side projection of terminal rows —
/// <see cref="ReconcileAlertProjectionsAsync"/>. The terminal outbox write and the write onto
/// <c>alert.email_status</c> are not one transaction, so a projection that does not land leaves a
/// permanent divergence rather than a lag; the sweep re-derives that state from the outbox row,
/// which stays authoritative. It re-projects the idempotent state only, never the accumulative
/// delivery-health counters.
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
    private readonly OrgRepository _orgs;
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
    private long _reconciledCount;

    public EmailOutboxDeliveryService(EmailOutboxDeliveryServices services)
    {
        _outbox = services.Outbox;
        _policy = services.Policy;
        _breaker = services.Breaker;
        _instanceConfig = services.InstanceConfig;
        _sender = services.Sender;
        _alerts = services.Alerts;
        _alertSettings = services.AlertSettings;
        _orgs = services.Orgs;
        _time = services.Time;
        _logger = services.Logger;
    }

    public long DeliveredCount => Interlocked.Read(ref _deliveredCount);
    public long DeadLetteredCount => Interlocked.Read(ref _deadLetteredCount);
    public long ExpiredCount => Interlocked.Read(ref _expiredCount);
    public long RetriedCount => Interlocked.Read(ref _retriedCount);

    /// <summary>
    /// Stale alert projections this worker has repaired — see
    /// <see cref="ReconcileAlertProjectionsAsync"/>. A non-zero value is a signal in its own right:
    /// it counts terminal outcomes the inline projection did not land, which is the condition an
    /// operator would otherwise have no way to see.
    /// </summary>
    public long ReconciledCount => Interlocked.Read(ref _reconciledCount);

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
                // Draining is the whole body — TryRead already consumed the nudge.
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

        // Immediately after the ceiling sweep, and before anything that can return early: the
        // sweep above just retired rows set-based with no per-row projection, and reconciliation
        // is independent of the transport and of the breaker, exactly as ExpireOverdueAsync is.
        await ReconcileAlertProjectionsAsync(ct);

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

        // Tracks whether this pass ever reached a REAL delivery attempt (AttemptAsync). A pass
        // whose entire claimed batch is skipped (suspension or a lookup failure) must still
        // resolve the breaker's probe below — see the AbandonUnusedProbe call after the loop for
        // why leaving it unresolved is a whole-instance outage, not a per-org one.
        bool anyRealAttempt = false;

        foreach (var message in due)
        {
            if (ct.IsCancellationRequested)
            {
                // The lease lapses on its own; the row returns to the drain set untouched.
                break;
            }

            switch (await ClassifySkipAsync(message, ct))
            {
                case SkipReason.None:
                    anyRealAttempt = true;
                    await AttemptAsync(instance.Transport, message, ct);
                    break;

                case SkipReason.NonActiveOrg:
                    // Not a failure, not a success: defer the row forward by the same ceiling a
                    // real transient failure ultimately backs off to, releasing its lease so it
                    // does not occupy this org's spot in every subsequent pass's claim query.
                    // `failureClass: null` deliberately does not reuse
                    // "transient"/"permanent"/"unknown": no delivery attempt happened, so no
                    // delivery failure occurred to classify. This deferral is deliberately NOT
                    // applied to a lookup failure (see SkipReason.LookupFailed below) — a
                    // suspended org should back off hard, a possibly-active org whose status this
                    // pass simply failed to resolve should not.
                    await _outbox.ScheduleRetryAsync(
                        message.Id,
                        _time.GetUtcNow() + EmailOutboxPolicy.MaxBackoff,
                        failureClass: null,
                        error: "Suspended/archived/deleting org - delivery deferred, not attempted.",
                        ct);
                    break;

                case SkipReason.LookupFailed:
                    // Deliberately not deferred: this org may be perfectly active, and a one-off
                    // lookup failure (e.g. a transient SQLITE_BUSY) is not evidence it should back
                    // off for MaxBackoff (30 min). The row stays claimed and its lease simply
                    // lapses (EmailOutboxPolicy.LeaseDuration, 2 min), so it is retried promptly
                    // on a later pass rather than losing most of a half-hour to a
                    // suspension-strength backoff it never earned.
                    break;
            }
        }

        // This pass claimed at least one row (the branch above already handled zero) but never
        // reached a real attempt — every claimed row was skipped, whether for suspension or a
        // lookup failure. That is exactly the shape a probe budget (BeginPassBudget granting
        // exactly 1 while HalfOpen) can hit: ClaimDueAsync orders by (next_attempt_at,
        // created_at), so a long-idle row can keep winning the single probe slot pass after pass.
        // Leaving the probe unresolved here freezes EmailTransportBreaker in HalfOpen forever —
        // BeginPassBudget returns 0 for every state but Closed/cooled-down-Open, so no later pass
        // would ever call ClaimDueAsync again, for ANY org, including operator-scope
        // (org_id IS NULL) mail. The NonActiveOrg deferral above already moves that row out of
        // the immediate claim order for its own reason (see the case above); this call is what
        // stops the current pass's probe from wedging the breaker regardless of which skip
        // reason emptied the pass.
        if (!anyRealAttempt)
        {
            _breaker.AbandonUnusedProbe();
        }
    }

    /// <summary>Why <see cref="ClassifySkipAsync"/> declined to attempt a message this pass.</summary>
    private enum SkipReason
    {
        /// <summary>No skip — attempt delivery normally.</summary>
        None,

        /// <summary>The org is suspended/archived/deleting (or soft-deleted). Back off hard.</summary>
        NonActiveOrg,

        /// <summary>
        /// The org lookup itself failed. Not a suspension signal — the org may be perfectly
        /// active — so the caller must not apply the suspension-strength deferral to it.
        /// </summary>
        LookupFailed,
    }

    // A suspended/archived/deleting org (see TenantLifecycle) never receives fresh alert email at
    // its own configured recipients — those addresses are tenant-owned, exactly the kind of
    // egress-on-the-org's-behalf the suspension is meant to stop. A null OrgId is operator-scope
    // mail (no tenant owner to suspend) and is never skipped.
    private async Task<SkipReason> ClassifySkipAsync(ClaimedEmailOutboxMessage message, CancellationToken ct)
    {
        if (message.OrgId is null)
        {
            return SkipReason.None;
        }

        Org? org;
        try
        {
            org = await _orgs.GetByIdAsync(message.OrgId, ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Fail closed, matching WebhookDispatchQueue.FanOutAsync and AlertSlackQueue.DeliverAsync:
            // an org lookup that failed for its own reasons must not read as "active" and let
            // delivery through. This is a lookup failure, not evidence of suspension — the caller
            // leaves the row's lease to lapse naturally rather than applying the
            // suspension-strength MaxBackoff deferral, so a perfectly active org's mail is
            // retried promptly rather than delayed by up to half an hour.
            _logger.LogWarning(ex,
                "Failed to resolve org {OrgId} while draining the email outbox; skipping message {MessageId} this pass.",
                message.OrgId, message.Id);
            return SkipReason.LookupFailed;
        }

        if (TenantLifecycle.IsActive(org))
        {
            return SkipReason.None;
        }

        _logger.LogInformation(
            "Email outbox delivery skipped for message {MessageId}: org {OrgId} is {Status} (deleted={Deleted}).",
            message.Id, message.OrgId, org?.Status ?? "unknown", org?.DeletedAt is not null);
        return SkipReason.NonActiveOrg;
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
                message.OrgId, message.CorrelationId,
                delivered ? AlertEmailStatuses.Sent : AlertEmailStatuses.Failed, error,
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
            // read-model write failed. Log and move on rather than re-queueing a message that was
            // already handed to the relay — an inline retry here has no natural bound, because the
            // outbox row is terminal and so nothing else would ever stop retrying it.
            // ReconcileAlertProjectionsAsync is what closes the divergence instead, on a later
            // pass, from the outbox row that is still authoritative.
            _logger.LogWarning(ex,
                "{ExceptionType} recording the {Outcome} outcome of outbox message {MessageId} on alert "
                + "{AlertId} (org {OrgId}); the outbox row is correct but the alert row was not updated. "
                + "A later pass reconciles it.",
                ex.GetType().Name, delivered ? "delivered" : "failed", message.Id,
                message.CorrelationId, message.OrgId);
        }
    }

    /// <summary>
    /// Re-projects terminal outbox rows whose alert row disagrees with them, and only those.
    ///
    /// <para>
    /// The terminal outbox write and the projection onto the alert are separate statements with no
    /// transaction around them. When the second fails — or the process dies between them — the
    /// divergence is permanent rather than a lag: the outbox row is already terminal, so
    /// <see cref="EmailOutboxRepository.ClaimDueAsync"/> never returns the message again and
    /// nothing else writes that <c>email_status</c>. The alert then reads as NULL, indistinguishable
    /// from mail that was never attempted, on the surface where a drop is supposed to become
    /// visible. The same sweep also covers the rows
    /// <see cref="EmailOutboxRepository.ExpireOverdueAsync"/> retires set-based, which have never
    /// had a per-row projection at all.
    /// </para>
    ///
    /// <para>
    /// <b>Only the idempotent state is re-projected. The accumulative health columns deliberately
    /// are not.</b> <c>alert.email_status</c> is a state: writing <c>sent</c> or <c>failed</c> onto
    /// a row that already holds it changes nothing, so re-deriving it from the authoritative outbox
    /// row is safe however many times it runs. <c>alert_settings.email_consecutive_failures</c> is
    /// a counter and <c>email_failing_since</c> is a first-seen instant, so replaying
    /// <c>RecordEmailFailureAsync</c> here would invent failures that never happened — and could
    /// cross a threshold on replay. Three reasons make that not merely risky but unfixable in this
    /// shape. This repair is itself best-effort and retried on the next pass, so an accumulative
    /// replay double-counts by construction whenever a repair partially lands. The health columns
    /// are a running summary of *now* with no event time and no idempotency key, so folding a
    /// historical failure into them stamps a current timestamp on an old event and can reopen
    /// <c>email_failing_since</c> for a relay that recovered hours ago — reporting an outage that
    /// is over is worse than reporting one increment short. And exactly-once is unreachable here
    /// without an idempotency ledger: a replay and the status write are themselves two statements
    /// with no transaction around them, so replaying before the status write double-counts when the
    /// status write throws and the row is selected again, while replaying after it loses the
    /// increment for good when the replay throws and the row has already left the predicate.
    /// (It is tempting to reason that a selected row must have failed at the alert write, which
    /// runs first in the same <c>try</c>, so its health write cannot have run — true of this one
    /// path, but it makes correctness rest on statement order inside a <c>catch</c>, which is not
    /// an invariant a repair loop should depend on.) The honest operator signal is this sweep's own
    /// count, logged below: it is the number of divergences actually found, where a replayed
    /// counter would be fiction.
    /// </para>
    ///
    /// <para>
    /// Nothing here writes tenant configuration — no <c>email_enabled</c>, no recipients — for the
    /// same reason <c>RecordEmailFailureAsync</c> does not: the component that failed is the
    /// operator's, and configuration is intent while health is reality.
    /// </para>
    /// </summary>
    private async Task ReconcileAlertProjectionsAsync(CancellationToken ct)
    {
        IReadOnlyList<DivergentAlertProjection> divergent;
        try
        {
            divergent = await _outbox.FindDivergentAlertProjectionsAsync(
                EmailOutboxPolicy.ReconcileBatchSize, ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Reconciliation is repair work; a failure to even read the divergence set must not
            // stop this pass from draining the queue. The next pass reads it again.
            _logger.LogWarning(ex,
                "{ExceptionType} reading the email outbox reconciliation set; delivery continues and "
                + "the next pass retries the reconciliation.",
                ex.GetType().Name);
            return;
        }

        if (divergent.Count == 0)
        {
            return;
        }

        var (repaired, failed, lastFailure) = await RepairProjectionsAsync(divergent, ct);

        if (repaired > 0)
        {
            Interlocked.Add(ref _reconciledCount, repaired);
            _logger.LogWarning(
                "Email outbox: reconciled {Count} alert(s) whose email outcome had not been projected "
                + "from their terminal outbox row. Delivery-health counters are deliberately not "
                + "replayed. Divergences older than the terminal-retention window are unrecoverable — "
                + "the outbox row carrying the outcome is already gone.",
                repaired);
        }

        if (failed > 0)
        {
            _logger.LogWarning(lastFailure,
                "{ExceptionType} reconciling {Count} alert email projection(s); the outbox rows remain "
                + "authoritative and the next pass retries them.",
                lastFailure?.GetType().Name ?? "Error", failed);
        }
    }

    /// <summary>
    /// Re-projects each divergent row's outcome onto its alert. Failures are counted and the last
    /// one kept rather than logged per row: a database refusing writes would otherwise emit one
    /// line per row in the batch. Cancellation stops the batch — whatever is left stays divergent
    /// and is selected again next pass, since the outbox row it derives from is untouched.
    /// </summary>
    private async Task<(int Repaired, int Failed, Exception? LastFailure)> RepairProjectionsAsync(
        IReadOnlyList<DivergentAlertProjection> divergent, CancellationToken ct)
    {
        int repaired = 0;
        int failed = 0;
        Exception? lastFailure = null;

        foreach (var row in divergent)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            bool delivered = row.State == EmailOutboxStates.Delivered;

            try
            {
                // The error text comes from the outbox row itself, so the repaired projection
                // carries the same diagnostic the inline one would have. A delivered row records
                // no error, matching RecordDomainOutcomeAsync: last_error on a delivered row can
                // still hold a prior attempt's transient failure, which is not this outcome.
                await _alerts.RecordEmailOutcomeAsync(
                    row.OrgId, row.CorrelationId,
                    delivered ? AlertEmailStatuses.Sent : AlertEmailStatuses.Failed,
                    delivered ? null : row.LastError,
                    ct);
                repaired++;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                failed++;
                lastFailure = ex;
            }
        }

        return (repaired, failed, lastFailure);
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
