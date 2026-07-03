namespace Dependably.Infrastructure.Webhooks;

/// <summary>
/// <see cref="IPackageEventSink"/> that discards every event. Registered only by the headless edge
/// composition root: outbound webhook delivery is a management-plane feature (the dispatch queue,
/// the subscription table, and the SSRF-guarded delivery worker all live in
/// <c>Dependably.Management</c>), and an edge node manages no subscriptions. The no-op keeps the
/// Core services that take the sink as a hard dependency (the vulnerability-scan pipeline) resolvable
/// without pulling the webhook plane into the edge closure. Dispatch is already fire-and-forget and
/// best-effort by contract, so discarding is a valid — and honest — implementation.
/// </summary>
public sealed class NoOpPackageEventSink : IPackageEventSink
{
    public void Dispatch(PackageEventEnvelope envelope)
    {
        // Intentionally empty: an edge node has no webhook subscriptions to deliver to.
    }
}
