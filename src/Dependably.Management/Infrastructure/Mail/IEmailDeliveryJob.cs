namespace Dependably.Infrastructure.Mail;

/// <summary>
/// A single piece of outbound email work queued onto <see cref="EmailDeliveryQueue"/>. Every
/// delivery channel (per-org alert email, transactional account email, …) implements this rather
/// than owning its own channel/worker/retry machinery — the queue is the one place that
/// schedules sends, retries transient failures on the shared backoff, and durably records the
/// terminal outcome.
/// </summary>
public interface IEmailDeliveryJob
{
    /// <summary>
    /// Resolves the transport and recipient list this job actually sends through. Returns null
    /// when there is nothing to send (channel disabled, unconfigured, or otherwise
    /// unresolvable) — the queue treats null as a silent no-op, never a fallback to some other
    /// transport, and never a recorded failure.
    /// </summary>
    Task<(SmtpTransportSettings Transport, IReadOnlyList<string> Recipients)?> ResolveAsync(CancellationToken ct);

    /// <summary>Renders the subject and body to send. Called once <see cref="ResolveAsync"/> has
    /// returned a usable transport.</summary>
    (string Subject, string Body) Render();

    /// <summary>
    /// Durably records that the send succeeded. Called after the message has already left for
    /// the SMTP relay — an irreversible side effect — so implementations run this write on an
    /// independent cancellation token rather than the caller's, the same way the DB write must
    /// survive host shutdown cancelling the delivery attempt that triggered it.
    /// </summary>
    Task RecordSuccessAsync();

    /// <summary>
    /// Durably records that every attempt in the retry budget failed. Same independent-token
    /// rationale as <see cref="RecordSuccessAsync"/>: the retry budget being exhausted is also a
    /// terminal, durable outcome.
    /// </summary>
    Task RecordFailureAsync(string error);
}
