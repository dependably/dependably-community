using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Advisory-shaped output of <see cref="PackageLookupService"/>: the alias and fixed-version
/// fields on each lookup advisory, and the single-advisory detail read the vulnerability detail
/// endpoint falls back to when an advisory is not stored for the org. Split from the lookup
/// orchestration to stay under the file-length compliance gate — both halves are one service.
/// </summary>
public sealed partial class PackageLookupService
{
    // The ids other databases publish the same flaw under. The advisory's own id is dropped (a
    // source may list it among its aliases) so a client folding duplicates by id-or-alias never
    // sees a self-reference.
    private static IReadOnlyList<string> AdvisoryAliases(OsvAdvisory advisory) =>
        (advisory.Aliases ?? [])
            .Where(a => !string.IsNullOrWhiteSpace(a)
                && !string.Equals(a, advisory.Id, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    // The fix for the affected range containing the queried version, resolved by the same
    // release-line-aware FixedVersionResolver the vulnerability detail endpoint applies. Null
    // when the advisory carries no raw JSON, no range contains the version, the containing range
    // has no fix, or the ecosystem has no version ordering — never a guess.
    // An apk or rpm advisory is resolved within the release the lookup was scoped to
    // (<paramref name="distroScope"/>) using the distro's own version ordering. An OCI advisory
    // comes from a stored scan row with no ranges, so it has no fixed version.
    private static string? AdvisoryFixedVersion(
        OsvAdvisory advisory, string ecosystem, string name, string version, string? distroScope = null)
    {
        var detail = NpmAdvisoryProjection.TryParseDetail(advisory.RawJson);
        return detail is null
            ? null
            : FixedVersionResolver.Resolve(detail.Affected, ecosystem, name, version, distroScope);
    }

    /// <summary>
    /// Finds <paramref name="osvId"/> (matched against each advisory's id and aliases) among the
    /// advisories OSV holds for the (ecosystem, name, version) coordinate, for an advisory no
    /// stored row exposes to the org. The record is public OSV data; nothing org-specific is
    /// read except the reserved-namespace gate. A name the org has reserved is never looked up
    /// here: this response has no reserved flag to warn that a public advisory may describe a
    /// lookalike of the org's internal package. Returns null for an unsupported ecosystem, an
    /// invalid coordinate, a reserved name, an unreached OSV source, or an id the coordinate has
    /// no advisory for.
    /// </summary>
    public async Task<UpstreamAdvisoryDetail?> FindAdvisoryDetailAsync(
        string orgId, string ecosystem, string name, string version, string osvId, CancellationToken ct = default)
    {
        string eco = (ecosystem ?? string.Empty).Trim().ToLowerInvariant();
        string pkg = (name ?? string.Empty).Trim();
        string ver = (version ?? string.Empty).Trim();
        if (!PurlQueryEcosystems.Contains(eco)
            || ValidateName(eco, pkg) is not null
            || string.IsNullOrWhiteSpace(osvId)
            || !PathSafeValidator.ValidateUpstreamSegment(ver, "version").IsValid)
        {
            return null;
        }

        if (await _reservedNamespaces.IsUpstreamNameReservedAsync(orgId, eco, pkg, ct))
        {
            return null;
        }

        // The OSV answer for a purl is public data, so it is cached across orgs; the reserved
        // check above runs on every call and never reads the cache.
        string purl = BuildPurl(eco, pkg, ver);
        var query = await _osvCache.GetOrComputeAsync(
            OsvQueryCache.PurlKey(purl),
            async () =>
            {
                var fresh = await QueryAdvisoriesAsync(eco, purl, ct);
                return (fresh, fresh.Available, OsvQueryCache.EstimateBytes(fresh.Advisories));
            },
            ct);
        if (!query.Available)
        {
            return null;
        }

        var matches = query.Advisories
            .Where(a => string.Equals(a.Id, osvId, StringComparison.OrdinalIgnoreCase)
                || (a.Aliases ?? []).Contains(osvId, StringComparer.OrdinalIgnoreCase))
            .ToList();
        if (matches.Count == 0)
        {
            return null;
        }

        // An exact id match is the advisory; an alias-only match falls back to the first copy.
        var advisory = MergeDuplicateAdvisories(matches)
            .OrderByDescending(a => string.Equals(a.Id, osvId, StringComparison.OrdinalIgnoreCase))
            .First();
        var enrichment = await ResolveKevEpssAsync([advisory], ct);
        var intel = enrichment.TryGetValue(advisory.Id, out var e) ? new ThreatIntel(e.IsKev, e.EpssScore) : null;

        var parsed = NpmAdvisoryProjection.TryParseDetail(advisory.RawJson);
        var detail = parsed is not null ? parsed with { Id = advisory.Id } : new OsvDetail(
            Id: advisory.Id, SchemaVersion: null, Published: advisory.Published, Modified: advisory.Modified,
            Withdrawn: null, Summary: advisory.Summary, Details: null, Aliases: AdvisoryAliases(advisory).ToArray(),
            Related: null, References: null, Severity: null, Affected: null, Credits: null, DatabaseSpecific: null);
        return new UpstreamAdvisoryDetail(detail, intel);
    }
}

/// <summary>
/// An advisory read from OSV for a coordinate the org has no stored row for. <see cref="Intel"/>
/// is the threat-feed enrichment across the advisory's id and aliases, null when no feed knows it.
/// </summary>
public sealed record UpstreamAdvisoryDetail(OsvDetail Detail, ThreatIntel? Intel);
