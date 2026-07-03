namespace Dependably.Protocol;

/// <summary>
/// Source of OSV vulnerability advisories. Two implementations: <see cref="OsvClient"/>
/// (remote, calls api.osv.dev) and <c>LocalOsvSource</c> (offline, reads a sideloaded
/// directory of OSV JSON dumps for air-gapped deployments).
///
/// Selected by <c>OSV_MODE=remote|local</c>; the consumer (<c>VulnerabilityScanService</c>)
/// is unaware of which is in use.
/// </summary>
public interface IOsvSource
{
    /// <summary>Single-PURL query. Returns hydrated advisories (<see cref="OsvAdvisory.IsHydrated"/> = true).</summary>
    Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default);

    /// <summary>
    /// Batch query, parallel results to inputs. The remote implementation deduplicates
    /// hydration across the batch; the local implementation answers each purl from its
    /// in-memory index.
    /// </summary>
    Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default);
}
