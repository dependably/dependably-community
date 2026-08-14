namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Dispatch seam for delivering a freshly-raised alert to an external channel (Slack, email).
///
/// <para>
/// Awaited rather than fire-and-forget, because one channel is now durable: alert email persists
/// the message to the outbox inside this call, and the durability guarantee starts where that write
/// commits. A void enqueue would leave a window between "the alert was raised" and "the mail exists
/// anywhere" that a crash silently swallows — the exact failure the outbox exists to remove. The
/// awaited call is still non-blocking on <i>delivery</i>: implementations queue, they never dial a
/// relay here.
/// </para>
///
/// <para>
/// A delivery failure never propagates back into the alert-raising path; implementations record it
/// on the alert row instead.
/// </para>
/// </summary>
public interface IAlertNotifier
{
    /// <summary>
    /// Notifies the configured delivery channel that <paramref name="alert"/> was just raised
    /// (fresh insert, not a deduped repeat). Returns once the notification is queued — durably, for
    /// channels that persist. Failures are recorded by the implementation, never thrown back.
    /// </summary>
    Task NotifyAsync(AlertRecord alert, CancellationToken ct = default);
}
