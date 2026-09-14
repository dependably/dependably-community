using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Builds parenthesized, individually-parameterized SQL fragments from a value list: a substitute
/// for Dapper's own <c>IN @list</c> (and <c>NOT IN @list</c>) auto-expansion (<see cref="Expand"/>),
/// and the <c>LIKE</c> disjunction for prefix matching (<see cref="ExpandLikeAny"/>).
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
/// dashboard no-feed coverage classifier); <c>AuditRepository.ListActivityEventsAsync</c>
/// (<c>IN</c>, the SIEM activity feed's exact event-type allowlist);
/// <c>VulnerabilityScanService.RunScanPassInnerAsync</c>, <c>RunRescanPassInnerAsync</c>, and
/// <c>RunSbomScanPassInnerAsync</c>, plus
/// <c>SbomComponentVulnRepository.GetScannableComponentsForVersionAsync</c> via the shared
/// <c>SbomScannableComponents.BuildPredicate</c> fragment (all <c>NOT IN</c>, the vulnerability
/// scan pass's no-feed-ecosystem exclusions). Every site is pinned by a live-Postgres regression
/// test — the five <c>NOT IN</c> sites by <c>VulnerabilityScanNotInPostgresTests</c>, the two
/// <c>IN</c> sites by <c>PostgresQuerySmokeTests</c> and
/// <c>SiemActivityEventsPostgresTests</c>.</para>
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

    /// <summary>
    /// Returns the <c>(&lt;expr&gt; LIKE @prefix0 OR &lt;expr&gt; LIKE @prefix1 ...)</c> disjunction for
    /// <paramref name="patterns"/> and a <see cref="DynamicParameters"/> bag already carrying one
    /// bound parameter per pattern. The <c>IN</c>-list sibling of <see cref="Expand"/> for the case
    /// a set of values has to be matched by <c>LIKE</c> rather than by equality, where there is no
    /// <c>IN</c> form to reach for at all.
    ///
    /// <para>The hazard it exists to remove is the same one, in a different dress: unfolding the
    /// list inside SQL instead (<c>json_each(@json)</c> on SQLite, <c>unnest(@array)</c> on
    /// Postgres) binds the query to one engine's dialect, and the SQLite-backed test suite cannot
    /// see the breakage. A literal disjunction of ordinary scalar parameters is what both engines
    /// accept unchanged. A row satisfying several patterns still matches once — the fragment is a
    /// predicate on the row, not a join — so it is a drop-in for an <c>EXISTS (SELECT 1 FROM
    /// json_each(...))</c> unfold.</para>
    ///
    /// <para><paramref name="columnExpression"/> is spliced into SQL verbatim and must therefore be
    /// a compile-time constant at the call site (a column or qualified column name), never a
    /// caller-supplied string; only the patterns are bound. The fragment declares no <c>ESCAPE</c>
    /// clause, so <c>%</c> and <c>_</c> inside a pattern keep their LIKE-metacharacter meaning: a
    /// caller that needs them matched literally has to escape them itself (<c>LikePattern</c>) and
    /// declare the escape character per term. As with <see cref="Expand"/>, the
    /// empty-list case is the caller's to guard — an empty <c>()</c> is invalid SQL on both
    /// engines — and callers are responsible for keeping the pattern count under the provider's
    /// bind-parameter ceiling.</para>
    /// </summary>
    public static (string Sql, DynamicParameters Parameters) ExpandLikeAny(
        string paramPrefix, string columnExpression, IReadOnlyList<string> patterns)
    {
        var parameters = new DynamicParameters();
        string[] terms = new string[patterns.Count];
        for (int i = 0; i < patterns.Count; i++)
        {
            string name = paramPrefix + i;
            terms[i] = columnExpression + " LIKE @" + name;
            parameters.Add(name, patterns[i]);
        }

        return ("(" + string.Join(" OR ", terms) + ")", parameters);
    }
}
