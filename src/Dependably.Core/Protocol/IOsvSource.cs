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
    ///
    /// Same swallow-and-return-empty contract as <see cref="QueryAsync"/>: every failure mode
    /// yields a full-length list of empty results, indistinguishable from a genuine all-clean
    /// answer. Callers that must not read an outage as "no advisories" use
    /// <see cref="TryQueryBatchAsync"/> instead.
    /// </summary>
    Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default);

    /// <summary>
    /// Batch counterpart to <see cref="TryQueryAsync"/>: the same query as
    /// <see cref="QueryBatchAsync"/>, plus whether the source was actually reached this call.
    /// <see cref="OsvBatchQueryResult.Reached"/> false means <see cref="OsvBatchQueryResult.Results"/>
    /// must not be treated as authoritative — it is the empty list every failure mode produces,
    /// not an all-clean answer.
    ///
    /// The default implementation assumes the source was reached whenever
    /// <see cref="QueryBatchAsync"/> does not throw — correct for any <see cref="IOsvSource"/>
    /// whose batch contract is "throw on failure, return data on success". <see cref="OsvClient"/>
    /// and <c>LocalOsvSource</c> override it with their own reachability signal because both
    /// swallow their respective failure modes inside <see cref="QueryBatchAsync"/> itself.
    /// </summary>
    async Task<OsvBatchQueryResult> TryQueryBatchAsync(
        IReadOnlyList<string> purls, CancellationToken ct = default)
    {
        var results = await QueryBatchAsync(purls, ct);
        return new OsvBatchQueryResult(results, Reached: true);
    }

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

    /// <summary>
    /// One advisory by its OSV id, read from this source. <see cref="OsvIdLookupResult.Reached"/>
    /// false means the source could not answer (outage, rate limit, missing dump directory), so
    /// a null advisory says nothing; Reached true with a null advisory means the source does not
    /// know the id. The default answers unreached, so a source that cannot look an advisory up
    /// by id never reads as "unknown" and never lets a caller fall back to another record.
    /// </summary>
    Task<OsvIdLookupResult> TryGetAdvisoryAsync(string id, CancellationToken ct = default) =>
        Task.FromResult(new OsvIdLookupResult(null, Reached: false));

    /// <summary>
    /// True when this source's currently loaded/reachable state actually carries advisory
    /// coverage for <paramref name="ecosystem"/> — a dynamic, source-aware refinement of
    /// <see cref="OsvFeedCoverage.HasAdvisoryFeed"/>. The static gate is the hard,
    /// source-independent fact ("OSV structurally publishes no feed an artefact of this
    /// ecosystem could ever match" — OCI, Terraform); this member only ever narrows further,
    /// never widens what the static gate already excludes, for a source whose own loaded state
    /// can fall short of what the static gate allows. <c>LocalOsvSource</c> overrides it: a
    /// sideloaded dump may carry no feed for an ecosystem the static gate still allows (a dump
    /// without the PyPI feed, or with none of the distro feeds like "Rocky Linux" that RPM, having
    /// no single OSV ecosystem, resolves through), and it then queries empty for every purl of that
    /// ecosystem, which is indistinguishable from a genuine clean scan unless this member says so.
    ///
    /// The default implementation defers entirely to the static gate, which is correct for any
    /// source (like <see cref="OsvClient"/>) whose reachability is not ecosystem-dependent — a
    /// live upstream either has a feed for an ecosystem or it does not, and that fact is exactly
    /// what <see cref="OsvFeedCoverage.HasAdvisoryFeed"/> already encodes.
    /// </summary>
    Task<bool> HasCoverageFor(string? ecosystem) =>
        Task.FromResult(OsvFeedCoverage.HasAdvisoryFeed(ecosystem));

    /// <summary>
    /// Release-scoped package query for distro feeds (Alpine, the RPM distros): the advisories
    /// filed under <paramref name="scope"/>'s OSV ecosystem that affect <paramref name="version"/>
    /// of <paramref name="name"/>, ordered by the distro's own version scheme. A bare PURL cannot
    /// carry the release, so the PURL queries cannot answer this.
    ///
    /// The default implementation answers <see cref="OsvScopedQueryResult.Reached"/> false: a
    /// source that has not implemented the scoped query must read as "not consulted", never as an
    /// empty, clean answer.
    /// </summary>
    Task<OsvScopedQueryResult> TryQueryDistroPackageAsync(
        DistroScope scope, string name, string version, CancellationToken ct = default) =>
        Task.FromResult(new OsvScopedQueryResult([], Reached: false, Covered: false));
}

/// <summary>
/// Result of <see cref="IOsvSource.TryQueryDistroPackageAsync"/>. <see cref="Reached"/> false means
/// the source was not consulted (outage, or no scoped query). <see cref="Covered"/> false with
/// <see cref="Reached"/> true means the source was consulted but holds no feed for the requested
/// release, which an offline dump can lack; in both cases an empty <see cref="Advisories"/> is not
/// a clean answer.
/// </summary>
public sealed record OsvScopedQueryResult(List<OsvAdvisory> Advisories, bool Reached, bool Covered = true);

/// <summary>
/// Result of <see cref="IOsvSource.TryQueryAsync"/>: the advisories found (empty on both a
/// genuine no-hits answer and an unreached source) plus <see cref="Reached"/>, which
/// distinguishes the two. <see cref="Reached"/> false means the caller must not treat
/// <see cref="Advisories"/> as authoritative.
/// </summary>
public sealed record OsvQueryResult(List<OsvAdvisory> Advisories, bool Reached);

public sealed record OsvIdLookupResult(OsvAdvisory? Advisory, bool Reached);

/// <summary>
/// Result of <see cref="IOsvSource.TryQueryBatchAsync"/>: the per-purl advisory lists (parallel to
/// the input purls) plus <see cref="Reached"/>. On an unreached source <see cref="Results"/> is the
/// full-length all-empty list every failure mode produces — <see cref="Reached"/> is the only thing
/// distinguishing that from a genuinely clean batch.
/// </summary>
public sealed record OsvBatchQueryResult(List<List<OsvAdvisory>> Results, bool Reached);
