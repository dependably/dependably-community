namespace Dependably.Infrastructure.Mail;

/// <summary>
/// The four bounds on the durable email outbox, plus the retry backoff between them. Every bound
/// is explicit and operator-tunable, because the guarantee the outbox makes is deliberately not
/// "every message is eventually sent":
///
/// <list type="number">
///   <item><b>Maximum retry duration</b> (<see cref="MaxRetryDuration"/>) — how long a message may
///     keep being retried. An alert delivered three days late can be worse than one never sent.</item>
///   <item><b>Maximum queue retention</b> (<see cref="MaxRetention"/>) — how long a row may sit at
///     all, independent of the retry budget. A row parked because the relay was never configured
///     consumes no attempts, so the retry ceiling alone would never retire it.</item>
///   <item><b>Maximum queue size</b> (<see cref="MaxDepth"/>) — the cap on non-terminal rows, with
///     an explicit shed policy: at the cap the <i>newest</i> message is refused, counted, and
///     recorded against the alert that raised it. See <see cref="MaxDepth"/>.</item>
///   <item><b>Dead-letter / permanently-failed terminal state</b> — <c>dead_letter</c> and
///     <c>expired</c> rows stay in the table, inspectable. Nothing in the delivery path deletes
///     them; only the retention sweep does, past
///     <see cref="TerminalRetentionDays"/>, and it logs the count it removed.</item>
/// </list>
/// </summary>
public sealed class EmailOutboxPolicy
{
    /// <summary>Retry ceiling: total delivery attempts a message may consume before it expires.</summary>
    public const int DefaultMaxAttempts = 12;

    /// <summary>Default for <see cref="MaxRetryDuration"/>, in hours.</summary>
    public const int DefaultMaxRetryHours = 6;

    /// <summary>Default for <see cref="MaxRetention"/>, in hours.</summary>
    public const int DefaultMaxRetentionHours = 72;

    /// <summary>Default for <see cref="MaxDepth"/>.</summary>
    public const int DefaultMaxDepth = 10_000;

    /// <summary>Default for <see cref="BacklogWarnDepth"/>.</summary>
    public const int DefaultBacklogWarnDepth = 100;

    /// <summary>Default for <see cref="TerminalRetentionDays"/>.</summary>
    public const int DefaultTerminalRetentionDays = 30;

    /// <summary>First retry delay; each subsequent attempt doubles it up to <see cref="MaxBackoff"/>.</summary>
    public static readonly TimeSpan FirstBackoff = TimeSpan.FromSeconds(30);

    /// <summary>Ceiling on a single backoff step, so a long outage polls at a steady, cheap rate.</summary>
    public static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(30);

    /// <summary>
    /// How long a claimed (<c>sending</c>) row stays leased. A replica that dies mid-attempt leaves
    /// the row in <c>sending</c> forever otherwise; once the lease lapses the row re-enters the
    /// drain set. Comfortably longer than the SMTP client's own 15s timeout so a live attempt is
    /// never stolen from underneath itself.
    /// </summary>
    public static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);

    /// <summary>How many due rows one drain pass claims and attempts.</summary>
    public const int DrainBatchSize = 50;

    /// <summary>How often the delivery worker polls for due rows when nothing wakes it sooner.</summary>
    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    public EmailOutboxPolicy(IConfiguration config)
    {
        MaxAttempts = ReadPositiveInt(config, "EMAIL_OUTBOX_MAX_ATTEMPTS", DefaultMaxAttempts);
        MaxRetryDuration = TimeSpan.FromHours(
            ReadPositiveInt(config, "EMAIL_OUTBOX_MAX_RETRY_HOURS", DefaultMaxRetryHours));
        MaxRetention = TimeSpan.FromHours(
            ReadPositiveInt(config, "EMAIL_OUTBOX_RETENTION_HOURS", DefaultMaxRetentionHours));
        MaxDepth = ReadPositiveInt(config, "EMAIL_OUTBOX_MAX_DEPTH", DefaultMaxDepth);
        BacklogWarnDepth = ReadPositiveInt(config, "EMAIL_OUTBOX_BACKLOG_WARN_DEPTH", DefaultBacklogWarnDepth);
        TerminalRetentionDays = ReadPositiveInt(
            config, "EMAIL_OUTBOX_TERMINAL_RETENTION_DAYS", DefaultTerminalRetentionDays);
    }

    /// <summary>Retry ceiling: total attempts before the message is <c>expired</c>.</summary>
    public int MaxAttempts { get; }

    /// <summary>Bound 1 — the retry window measured from when the message was enqueued.</summary>
    public TimeSpan MaxRetryDuration { get; }

    /// <summary>
    /// Bound 2 — how long a row may exist at all, whether or not it has consumed any attempt.
    /// Independent of <see cref="MaxRetryDuration"/> because the two retire different failures: the
    /// retry ceiling retires a message the relay keeps rejecting, the retention ceiling retires one
    /// nothing ever tried to send.
    /// </summary>
    public TimeSpan MaxRetention { get; }

    /// <summary>
    /// Bound 3 — the cap on non-terminal (<c>pending</c> + <c>sending</c>) rows.
    ///
    /// <para>
    /// <b>Shed policy: refuse the newest.</b> At the cap the enqueue fails; the alert's
    /// <c>email_status</c> is set to <c>failed</c> with the reason and the org's delivery-health
    /// columns record it, so the drop is visible in the tenant's alert list rather than only in a
    /// log line. Evicting the oldest instead was rejected: the oldest rows are the ones nearest
    /// their retention ceiling and the ones that already survived a restart, so dropping them to
    /// admit newer mail discards the start of the outage — the part an operator most needs — and
    /// makes the durability guarantee unstateable, since any persisted row could still vanish.
    /// </para>
    /// </summary>
    public int MaxDepth { get; }

    /// <summary>
    /// Backlog depth at which the delivery worker logs a warning naming the depth and the oldest
    /// queued row, so a relay outage is not invisible until the operator aggregate health surface
    /// exists. Logged on the crossing, not on every pass.
    /// </summary>
    public int BacklogWarnDepth { get; }

    /// <summary>
    /// Bound 4's disposal half — how long terminal rows (<c>delivered</c>, <c>dead_letter</c>,
    /// <c>expired</c>) are kept for inspection before the retention sweep removes them. The
    /// delivery path never deletes a row; this window is what keeps recipient addresses from being
    /// retained indefinitely (GDPR Art. 5(1)(e)), and the sweep logs what it removed.
    /// </summary>
    public int TerminalRetentionDays { get; }

    /// <summary>
    /// Delay before the next attempt after <paramref name="attemptsMade"/> failed attempts:
    /// <see cref="FirstBackoff"/> doubling per attempt, capped at <see cref="MaxBackoff"/>.
    /// </summary>
    public static TimeSpan BackoffAfter(int attemptsMade)
    {
        if (attemptsMade <= 1)
        {
            return FirstBackoff;
        }

        // Shift rather than Math.Pow, and clamp the exponent first: 2^attemptsMade overflows long
        // past ~63 attempts, and a configured MaxAttempts is not bounded to less than that.
        int exponent = Math.Min(attemptsMade - 1, 20);
        var scaled = FirstBackoff * (1L << exponent);
        return scaled > MaxBackoff ? MaxBackoff : scaled;
    }

    private static int ReadPositiveInt(IConfiguration config, string key, int fallback) =>
        int.TryParse(config[key], out int value) && value > 0 ? value : fallback;
}
