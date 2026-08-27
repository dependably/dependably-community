using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// The one definition of which <c>sbom_components</c> rows the OSV scan queue covers, shared by
/// every reader of that queue so the answer cannot differ by which path happened to run.
///
/// <para>Two writers stamp <c>vuln_checked_at</c>: the upload/rescan-triggered
/// <c>SbomScanWorker</c> and the nightly safety net in <c>VulnerabilityScanService</c>. When they
/// disagree on the predicate, a component's terminal state becomes a function of scheduling luck
/// — stamped when one path covered it, NULL forever when only the other did — and a NULL stamp is
/// what the policy evaluator reads. Both queries therefore splice the SQL fragment
/// <see cref="BuildPredicate"/> returns rather than spelling the condition out, and every
/// in-memory reader asks <see cref="IsScannable"/>.</para>
///
/// <para>Scannable means all three of: a parseable purl, a parsed ecosystem, and an ecosystem OSV
/// publishes a feed for (<see cref="OsvFeedCoverage"/>). A row failing any of them is
/// <b>unscannable</b> — no query could ever answer for it — which is a different statement from
/// a scan that was deferred because the source was unreachable.</para>
/// </summary>
public static class SbomScannableComponents
{
    /// <summary>
    /// Builds the SQL fragment selecting the scannable set, aliasing <c>sbom_components</c> as
    /// <paramref name="alias"/>, plus the individually-parameterized list of bound values the
    /// fragment references.
    ///
    /// <para>Dapper's own <c>IN @list</c>/<c>NOT IN @list</c> auto-expansion binds an Npgsql
    /// connection's <c>IEnumerable</c> parameter as one native Postgres array — valid only after
    /// <c>= ANY(...)</c>, never after <c>NOT IN</c> — so this can no longer be a plain constant
    /// string plus a bound-list parameter the way it shipped originally; see
    /// <see cref="DapperInClause"/>'s own doc comment. Being a shared fragment consumed by two
    /// call sites (<c>VulnerabilityScanService.RunSbomScanPassInnerAsync</c> and
    /// <c>SbomComponentVulnRepository.GetScannableComponentsForVersionAsync</c>) rules out binding
    /// the parameters here too — the caller owns the <see cref="DynamicParameters"/> bag it
    /// eventually executes with, so <see cref="DapperInClause.Expand{T}"/>'s own
    /// <c>(Sql, Parameters)</c> shape is returned unmodified for the caller to merge onto its own
    /// other bound parameters via <see cref="DynamicParameters.AddDynamicParams"/>.</para>
    /// </summary>
    public static (string Sql, DynamicParameters Parameters) BuildPredicate(string alias = "sc")
    {
        var (noFeedClause, parameters) = DapperInClause.Expand(
            "sbomNoFeed", OsvFeedCoverage.NoFeedEcosystems);

        // An empty no-feed set (every ecosystem gained a feed) degrades the exclusion to a no-op
        // — "NOT IN ()" is invalid SQL on both engines, and nothing is no-feed when the list is
        // empty, so every otherwise-scannable row correctly stays in the scannable set.
        string sql = OsvFeedCoverage.NoFeedEcosystems.Count == 0
            ? $"{alias}.ecosystem IS NOT NULL AND {alias}.purl IS NOT NULL"
            : $"{alias}.ecosystem IS NOT NULL AND {alias}.purl IS NOT NULL AND {alias}.ecosystem NOT IN {noFeedClause}";

        return (sql, parameters);
    }

    /// <summary>
    /// In-memory twin of <see cref="BuildPredicate"/>: true when an OSV lookup for this component
    /// could produce a meaningful answer, and so when a NULL <c>vuln_checked_at</c> means "not
    /// scanned yet" rather than "never scannable".
    /// </summary>
    public static bool IsScannable(string? ecosystem, string? purl) =>
        !string.IsNullOrEmpty(ecosystem)
        && !string.IsNullOrEmpty(purl)
        && OsvFeedCoverage.HasAdvisoryFeed(ecosystem);
}
