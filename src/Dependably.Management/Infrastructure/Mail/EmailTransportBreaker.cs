namespace Dependably.Infrastructure.Mail;

/// <summary>The breaker's three states over the one shared SMTP transport.</summary>
public enum EmailTransportState
{
    /// <summary>Attempting normally.</summary>
    Closed,

    /// <summary>Tripped: no claims until the cooldown elapses, except a single probe attempt.</summary>
    Open,

    /// <summary>One probe message is in flight; no further claims until it resolves.</summary>
    HalfOpen,
}

/// <summary>
/// Read-only snapshot of the breaker's state, for logging and for a future operator surface that
/// reads the same underlying fact about relay health this breaker gates delivery on.
/// </summary>
public sealed record EmailTransportBreakerSnapshot(
    EmailTransportState State,
    int ConsecutiveTransportFailures,
    DateTimeOffset? OpenedAt,
    DateTimeOffset? NextProbeAt);

/// <summary>
/// Circuit-breaks the ONE shared SMTP transport that every org's alert mail flows over — not any
/// tenant's channel. <c>email_enabled</c> is never read or written here: the breaker decides whether
/// <see cref="EmailOutboxDeliveryService"/> claims work this pass, exactly the same posture a
/// disabled/unconfigured instance transport already gets, and every bound the outbox establishes
/// (retry duration, retention, depth, backoff) keeps governing rows regardless of the breaker's
/// state — the breaker only ever narrows how many rows get <em>claimed</em>, never how they age or
/// expire.
///
/// <para>
/// <b>State: process-local, in-memory, deliberately not persisted.</b> A file-backed SQLite
/// deployment already runs exactly one live process — <see cref="InstanceLock"/> refuses a second
/// writer on the same database — so a process-local breaker there IS instance-wide, by construction.
/// A Postgres deployment can run multiple replicas, and each replica then holds its own view of relay
/// health: one replica's breaker can be open while another's is still closed. That is a deliberate,
/// bounded trade rather than an oversight. Persisting the state onto a shared row would make the
/// state instance-wide again, at the cost of write contention on every attempt and a distributed lock
/// to keep the probe from firing once per replica (a synchronized "one probe, ever" needs its own
/// coordination primitive, not a bare row read). The unsynchronized cost is small and self-correcting:
/// each replica's message-claim already goes through
/// <see cref="EmailOutboxRepository.ClaimDueAsync"/>'s per-row lease, so no message is ever attempted
/// twice; the only redundancy is a handful of replicas independently re-discovering an outage (bounded
/// by the failure threshold per replica) and independently probing recovery (bounded by one probe
/// message per replica, never by the size of the backlog). Both are far short of "stampede the relay
/// with the whole queue", which is the failure this breaker exists to prevent.
/// </para>
///
/// <para>
/// <b>What trips it, and what deliberately does not.</b> Only <see cref="RecordTransportFailure"/> —
/// fed a <see cref="EmailOutboxFailureClasses.Transient"/> or <see cref="EmailOutboxFailureClasses.Unknown"/>
/// classification — counts toward the trip threshold: those are exactly the classes
/// <see cref="EmailOutboxFailureClassifier"/> could not pin on the message itself. A
/// <see cref="EmailOutboxFailureClasses.Permanent"/> failure (a bad recipient, a rejected credential,
/// an <c>SsrfBlockedException</c>) is message- or configuration-specific and reported through
/// <see cref="RecordPermanentFailure"/> instead, which never trips the breaker — a bad recipient is not
/// a relay outage, and a relay that answers with a definitive protocol verdict has, by that fact,
/// proven itself reachable.
/// </para>
///
/// <para>
/// <b>Half-open/probe behaviour.</b> An open breaker admits nothing until its cooldown elapses, then
/// admits exactly one message — a probe, via <see cref="BeginPassBudget"/> returning 1 instead of the
/// full batch size — and admits nothing else until that probe resolves. A delivered probe (or a
/// permanent failure on it, which still proves the relay reachable) closes the breaker outright; a
/// transport failure on the probe reopens it with a doubled cooldown, capped, so a relay that is still
/// down settles into a slow, steady poll rather than a tight retry loop. This is what keeps recovery
/// self-service — no operator action closes the breaker — and keeps the recovering relay from being
/// stampeded by the whole backlog at once: at most one message is in flight against a breaker that is
/// anything other than fully closed, on any one replica.
/// </para>
/// </summary>
public sealed class EmailTransportBreaker
{
    /// <summary>Default for <see cref="_failureThreshold"/>.</summary>
    public const int DefaultFailureThreshold = 3;

    /// <summary>Default first cooldown, in seconds, before the first recovery probe.</summary>
    public const int DefaultInitialCooldownSeconds = 30;

    /// <summary>Default ceiling on the cooldown, in minutes, after repeated failed probes.</summary>
    public const int DefaultMaxCooldownMinutes = 10;

    private readonly object _gate = new();
    private readonly TimeProvider _time;
    private readonly ILogger<EmailTransportBreaker> _logger;
    private readonly int _failureThreshold;
    private readonly TimeSpan _initialCooldown;
    private readonly TimeSpan _maxCooldown;

    private EmailTransportState _state = EmailTransportState.Closed;
    private int _consecutiveFailures;
    private DateTimeOffset? _openedAt;
    private DateTimeOffset _nextProbeAt;
    private TimeSpan _cooldown;

    public EmailTransportBreaker(IConfiguration config, TimeProvider time, ILogger<EmailTransportBreaker> logger)
    {
        _time = time;
        _logger = logger;
        _failureThreshold = ReadPositiveInt(
            config, "EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD", DefaultFailureThreshold);
        _initialCooldown = TimeSpan.FromSeconds(ReadPositiveInt(
            config, "EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS", DefaultInitialCooldownSeconds));
        _maxCooldown = TimeSpan.FromMinutes(ReadPositiveInt(
            config, "EMAIL_TRANSPORT_BREAKER_MAX_COOLDOWN_MINUTES", DefaultMaxCooldownMinutes));
        _cooldown = _initialCooldown;
    }

    /// <summary>The current state, for logging and for a future operator health surface.</summary>
    public EmailTransportBreakerSnapshot Snapshot()
    {
        lock (_gate)
        {
            return new EmailTransportBreakerSnapshot(
                _state,
                _consecutiveFailures,
                _openedAt,
                _state == EmailTransportState.Open ? _nextProbeAt : null);
        }
    }

    /// <summary>
    /// How many due rows this delivery pass may claim: <paramref name="fullBatchSize"/> while closed;
    /// exactly one (a probe) once an open breaker's cooldown has elapsed; zero otherwise, including
    /// while a probe is already in flight — the case that keeps a recovering relay from being
    /// stampeded by the rest of the backlog landing on it at once.
    /// </summary>
    public int BeginPassBudget(int fullBatchSize)
    {
        lock (_gate)
        {
            switch (_state)
            {
                case EmailTransportState.Closed:
                    return fullBatchSize;

                case EmailTransportState.Open:
                    if (_time.GetUtcNow() < _nextProbeAt)
                    {
                        return 0;
                    }

                    _state = EmailTransportState.HalfOpen;
                    _logger.LogInformation(
                        "Email transport breaker probing after a {CooldownSeconds:F0}s cooldown.",
                        _cooldown.TotalSeconds);
                    return 1;

                default: // HalfOpen: a probe is already in flight on this replica.
                    return 0;
            }
        }
    }

    /// <summary>
    /// The pass was granted a probe budget but claimed nothing to attempt (every row's own
    /// message-level backoff was still in the future). Releases the in-flight probe without touching
    /// the failure count or the cooldown clock — an empty pass proves nothing about the relay, so the
    /// next pass gets to try again once the original cooldown deadline arrives.
    /// </summary>
    public void AbandonUnusedProbe()
    {
        lock (_gate)
        {
            if (_state == EmailTransportState.HalfOpen)
            {
                _state = EmailTransportState.Open;
            }
        }
    }

    /// <summary>
    /// The relay accepted a message. Closes the breaker outright regardless of prior state — a live
    /// send is the strongest possible evidence the transport works, whether it was an ordinary attempt
    /// or the probe.
    /// </summary>
    public void RecordDelivered()
    {
        lock (_gate)
        {
            bool wasOpen = _state != EmailTransportState.Closed;
            CloseInternal();
            if (wasOpen)
            {
                _logger.LogWarning("Email transport breaker closed: the relay accepted a message.");
            }
        }
    }

    /// <summary>
    /// A permanent, message- or configuration-specific failure. Never trips the breaker: the relay
    /// answered with a definitive protocol verdict about this one message, which is itself proof the
    /// relay is reachable. During a probe this closes the breaker exactly like a delivered probe would
    /// — the transport works, this particular message did not go through. Outside a probe it resets
    /// the consecutive-failure streak, since a reachable relay is no longer evidence of an outage.
    /// </summary>
    public void RecordPermanentFailure()
    {
        lock (_gate)
        {
            if (_state == EmailTransportState.HalfOpen)
            {
                CloseInternal();
                _logger.LogWarning(
                    "Email transport breaker closed: the probe reached the relay (message itself was refused).");
                return;
            }

            _consecutiveFailures = 0;
        }
    }

    /// <summary>
    /// A transient or unrecognised failure — the two classes that can mean the relay itself is the
    /// problem. Trips the breaker after <see cref="_failureThreshold"/> consecutive occurrences while
    /// closed, or reopens immediately with a doubled (capped) cooldown when it happens to the probe.
    /// </summary>
    public void RecordTransportFailure()
    {
        lock (_gate)
        {
            _consecutiveFailures++;

            if (_state == EmailTransportState.HalfOpen)
            {
                OpenInternal(extendCooldown: true);
                return;
            }

            if (_state == EmailTransportState.Closed && _consecutiveFailures >= _failureThreshold)
            {
                OpenInternal(extendCooldown: false);
            }
        }
    }

    private void CloseInternal()
    {
        _state = EmailTransportState.Closed;
        _consecutiveFailures = 0;
        _openedAt = null;
        _cooldown = _initialCooldown;
    }

    private void OpenInternal(bool extendCooldown)
    {
        _state = EmailTransportState.Open;
        _openedAt ??= _time.GetUtcNow();
        if (extendCooldown)
        {
            var doubled = _cooldown * 2;
            _cooldown = doubled > _maxCooldown ? _maxCooldown : doubled;
        }

        _nextProbeAt = _time.GetUtcNow().Add(_cooldown);
        _logger.LogWarning(
            "Email transport breaker opened after {Failures} consecutive transport-scope failure(s); "
            + "next probe at {NextProbeAt}.",
            _consecutiveFailures, _nextProbeAt);
    }

    private static int ReadPositiveInt(IConfiguration config, string key, int fallback) =>
        int.TryParse(config[key], out int value) && value > 0 ? value : fallback;
}
