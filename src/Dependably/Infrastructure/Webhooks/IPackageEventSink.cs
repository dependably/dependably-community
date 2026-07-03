namespace Dependably.Infrastructure.Webhooks;

/// <summary>
/// Dispatch seam for package-level events that trigger outbound webhooks.
/// Implementations are fire-and-forget from the caller's perspective: the sink
/// enqueues the envelope non-blocking and returns immediately. Failures are
/// recorded by the sink, not propagated to the caller.
/// </summary>
public interface IPackageEventSink
{
    /// <summary>
    /// Enqueues a package event for delivery to all matching enabled webhook subscriptions
    /// for the org. Non-blocking: drops on overflow with a metric, never throws.
    /// </summary>
    void Dispatch(PackageEventEnvelope envelope);
}
