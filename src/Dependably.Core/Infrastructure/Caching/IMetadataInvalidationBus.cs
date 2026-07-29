namespace Dependably.Infrastructure.Caching;

/// <summary>
/// Fan-out transport for rendered-metadata invalidations. The mutation path always evicts its own
/// replica's entries first and then hands the coordinates here; this interface's only job is to
/// tell the <em>other</em> replicas.
///
/// <para><b>Never throws.</b> A missed invalidation is a staleness bug bounded by the entry's TTL,
/// not an outage — an unreachable broker must not fail a push. Implementations swallow, log, and
/// count their own failures; <see cref="Publish"/> returns <see langword="void"/> precisely so a
/// caller has nothing to await or to fault on.</para>
///
/// <para>Standalone (single-replica) deployments bind <see cref="NullMetadataInvalidationBus"/>,
/// which is a no-op: the in-process eviction the mutation path already performed is complete, and
/// no broker dependency is introduced.</para>
/// </summary>
public interface IMetadataInvalidationBus
{
    /// <summary>
    /// Best-effort broadcast of <paramref name="invalidation"/> to the other replicas. Returns
    /// immediately; delivery is not awaited and failure is not surfaced to the caller.
    /// </summary>
    void Publish(MetadataInvalidation invalidation);
}

/// <summary>
/// The standalone-mode bus: does nothing. Registered whenever no fan-out transport is configured,
/// so the mutation path has an unconditional non-null dependency and single-replica deployments
/// take on no broker dependency at all.
/// </summary>
public sealed class NullMetadataInvalidationBus : IMetadataInvalidationBus
{
    public void Publish(MetadataInvalidation invalidation)
    {
        // No peers to notify: the caller's in-process eviction is the whole invalidation.
    }
}
