using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Builds a parenthesized, individually-parameterized substitute for Dapper's own <c>IN @list</c>
/// auto-expansion.
///
/// Dapper special-cases any connection whose runtime type name is <c>"npgsqlconnection"</c>
/// (<c>Dapper.FeatureSupport.Get</c>): for that one provider it skips the SQL-text rewrite
/// entirely and binds the whole <c>IEnumerable</c> as a single native array parameter instead —
/// which is only valid syntax after <c>= ANY(...)</c>, never after <c>IN</c>. The identical C#
/// call that expands correctly on SQLite therefore sends Postgres a bound array where it expects
/// a parenthesized list, and the query fails with a syntax error at the bind site. <c>= ANY(...)</c>
/// is not an option either — SQLite has no such operator — so the one construct both engines
/// accept without a per-provider branch is a literal <c>(@p0, @p1, ...)</c> list of ordinary
/// scalar parameters, which this builds.
/// </summary>
internal static class DapperInClause
{
    /// <summary>
    /// Returns the <c>(@prefix0, @prefix1, ...)</c> SQL fragment for <paramref name="values"/> and
    /// a <see cref="DynamicParameters"/> bag already carrying one bound parameter per value.
    /// Merge additional parameters onto the returned bag with <see cref="DynamicParameters.AddDynamicParams"/>.
    /// Callers must guard the empty-list case themselves — an empty <c>IN ()</c> is invalid SQL on
    /// both engines, and every call site here already returns its empty-input default before
    /// reaching SQL.
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
