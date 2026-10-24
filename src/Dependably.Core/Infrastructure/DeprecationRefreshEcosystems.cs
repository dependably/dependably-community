namespace Dependably.Infrastructure;

/// <summary>
/// The ecosystems the daily deprecation refresh processes: those with an upstream fetcher for
/// deprecation and/or upstream-latest facts. <c>DeprecationRefreshService</c> skips any group
/// outside this set, and both group-enumeration queries
/// (<see cref="CacheArtifactRepository.ListGroupsNeedingDeprecationRefreshAsync"/> and
/// <see cref="PackageRepository.ListHostedGroupsNeedingUpstreamRefreshAsync"/>) list the same
/// ecosystems as SQL literals, because a parameterized list does not bind the same way on SQLite
/// and Postgres. <c>DeprecationRefreshEcosystemSelectionTests</c> runs both queries against a
/// stale group for each member and fails if either query does not return it, so the set and the
/// SQL cannot drift apart.
/// </summary>
public static class DeprecationRefreshEcosystems
{
    public static readonly IReadOnlyList<string> All = ["npm", "pypi", "nuget", "maven", "hex"];

    public static bool Contains(string ecosystem) => All.Contains(ecosystem, StringComparer.Ordinal);
}
