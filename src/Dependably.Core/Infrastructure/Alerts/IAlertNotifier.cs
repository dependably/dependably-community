namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Dispatch seam for delivering a freshly-raised alert to an external channel (Slack). Mirrors
/// <see cref="Webhooks.IPackageEventSink"/>: implementations are fire-and-forget from the
/// caller's perspective — <see cref="Notify"/> enqueues and returns immediately, and a delivery
/// failure never propagates back into the alert-raising path.
/// </summary>
public interface IAlertNotifier
{
    /// <summary>
    /// Notifies the configured delivery channel that <paramref name="alert"/> was just raised
    /// (fresh insert, not a deduped repeat). Non-blocking; failures are recorded on the alert row
    /// by the implementation, never thrown back to the caller.
    /// </summary>
    void Notify(AlertRecord alert);
}
