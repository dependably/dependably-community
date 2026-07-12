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

    /// <summary>
    /// Same single-PURL query as <see cref="QueryAsync"/>, but also reports whether the source
    /// was actually reached this call. <see cref="QueryAsync"/>'s contract is swallow-and-return-
    /// empty on every failure mode (network error, 5xx, non-2xx, rate limit) — callers that only
    /// need "did anything come back" keep using it. <see cref="PackageLookupService"/> needs to
    /// tell a genuine "no known advisories" result apart from an outage that would otherwise be
    /// indistinguishable from one, so it uses this instead.
    ///
    /// The default implementation assumes the source was reached whenever <see cref="QueryAsync"/>
    /// does not throw — correct for any <see cref="IOsvSource"/> whose <see cref="QueryAsync"/>
    /// contract is "throw on failure, return data on success". <see cref="OsvClient"/> and
    /// <c>LocalOsvSource</c> override this with their own reachability signal because both
    /// swallow their respective failure modes inside <see cref="QueryAsync"/> itself.
    /// </summary>
    async Task<OsvQueryResult> TryQueryAsync(string purl, CancellationToken ct = default)
    {
        var advisories = await QueryAsync(purl, ct);
        return new OsvQueryResult(advisories, Reached: true);
    }
}

/// <summary>
/// Result of <see cref="IOsvSource.TryQueryAsync"/>: the advisories found (empty on both a
/// genuine no-hits answer and an unreached source) plus <see cref="Reached"/>, which
/// distinguishes the two. <see cref="Reached"/> false means the caller must not treat
/// <see cref="Advisories"/> as authoritative.
/// </summary>
public sealed record OsvQueryResult(List<OsvAdvisory> Advisories, bool Reached);
