using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Builds a parenthesized, individually-parameterized substitute for Dapper's own <c>IN @list</c>
/// (and <c>NOT IN @list</c>) auto-expansion.
///
/// Dapper special-cases any connection whose runtime type name is <c>"npgsqlconnection"</c>
/// (<c>Dapper.FeatureSupport.Get</c>): for that one provider it skips the SQL-text rewrite
/// entirely and binds the whole <c>IEnumerable</c> as a single native array parameter instead —
/// which is only valid syntax after <c>= ANY(...)</c>, never after <c>IN</c> or <c>NOT IN</c>.
/// The identical C# call that expands correctly on SQLite therefore sends Postgres a bound array
/// where it expects a parenthesized list, and the query fails with a syntax error at the bind
/// site. <c>= ANY(...)</c> is not an option either — SQLite has no such operator, and negating it
/// (<c>!= ALL(...)</c>) is a second per-provider branch, not a fix — so the one construct both
/// engines accept without a per-provider branch is a literal <c>(@p0, @p1, ...)</c> list of
/// ordinary scalar parameters, which this builds. Dapper's own special-case is purely
/// connection-type-based — it does not distinguish the SQL keyword the list follows — so the
/// mechanism, and this fix, apply identically to <c>IN</c> and <c>NOT IN</c>; both were confirmed
/// broken on live Postgres, not merely reasoned about.
///
/// <para>Call sites: <c>PackageAnalyticsRepository.QueryCoverageStatsAsync</c> (<c>IN</c>, the
/// dashboard no-feed coverage classifier); <c>VulnerabilityScanService.RunScanPassInnerAsync</c>,
/// <c>RunRescanPassInnerAsync</c>, and <c>RunSbomScanPassInnerAsync</c>, plus
/// <c>SbomComponentVulnRepository.GetScannableComponentsForVersionAsync</c> via the shared
/// <c>SbomScannableComponents.BuildPredicate</c> fragment (all <c>NOT IN</c>, the vulnerability
/// scan pass's no-feed-ecosystem exclusions). Each of the five <c>NOT IN</c> sites is pinned by a
/// live-Postgres regression test in <c>VulnerabilityScanNotInPostgresTests</c>, the way the
/// <c>IN</c> site is pinned by <c>PostgresQuerySmokeTests</c>.</para>
/// </summary>
internal static class DapperInClause
{
    /// <summary>
    /// Returns the <c>(@prefix0, @prefix1, ...)</c> SQL fragment for <paramref name="values"/> and
    /// a <see cref="DynamicParameters"/> bag already carrying one bound parameter per value.
    /// Merge additional parameters onto the returned bag with <see cref="DynamicParameters.AddDynamicParams"/>.
    /// Callers must guard the empty-list case themselves — an empty <c>IN ()</c> is invalid SQL on
    /// both engines — by returning their empty-input default or omitting the clause before the
    /// fragment reaches SQL.
    /// </summary>
    public static (string Sql, DynamicParameters Parameters) Expand<T>(string paramPrefix, IReadOnlyList<T> values)
    {
        var parameters = new DynamicParameters();
        string[] names = new string[values.Count];
        for (int i = 0; i < values.Count; i++)
        {
            string name = paramPrefix + i;
            names[i] = "@" + name;
            parameters.Add(name, values[i]);
        }

        return ("(" + string.Join(", ", names) + ")", parameters);
    }
}
