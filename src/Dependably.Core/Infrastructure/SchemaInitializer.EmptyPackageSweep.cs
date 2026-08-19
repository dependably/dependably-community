using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

// One-shot reclamation of packages rows left with no version on either plane.
public sealed partial class SchemaInitializer
{
    /// <summary>
    /// Deletes <c>packages</c> rows that catalogue nothing: no <c>package_versions</c> row and no
    /// cache-plane version reachable through this org's <c>tenant_artifact_access</c>. Same
    /// emptiness predicate as <see cref="PackageRepository.DeletePackageIfEmptyAsync"/>, which the
    /// interactive delete paths call but the two background reclaimers do not — proxy-cache
    /// eviction and the retention version limit both remove the last version of a package and
    /// leave the parent row behind, so it lingers reading as "0 versions" on the Packages page
    /// with nothing servable under it.
    ///
    /// Two rows are deliberately spared:
    /// <list type="bullet">
    ///   <item>Anything created within <see cref="EmptyPackageSweepMinAgeHours"/>. A publish
    ///   creates the <c>packages</c> row before it writes the version row, so a row that is empty
    ///   right now may be an in-flight publish on a replica still serving through a blue-green
    ///   cutover — deleting it would fail that publish on the version row's foreign key. Genuine
    ///   residue is at minimum as old as the eviction that produced it, so an age floor costs
    ///   nothing.</item>
    ///   <item>Anything carrying a <c>same_version_push_override</c>. That column is deliberate
    ///   per-package operator policy which survives the package having no versions today, and it
    ///   is not reconstructible from anything else.</item>
    /// </list>
    ///
    /// Ledgered, so it clears the accumulated backlog once. Rows that fall empty afterwards are
    /// prevented at the source rather than swept again: with no cache cap configured the eviction
    /// pass evicts nothing (<c>CacheEvictionService</c>), and a configured cap or a configured
    /// <c>keep_versions</c> is an explicit operator decision to expire versions.
    /// </summary>
    private async Task DeleteEmptyPackageRowsAsync(DbConnection conn)
    {
        string cutoff = _time.GetUtcNow().AddHours(-EmptyPackageSweepMinAgeHours).ToUtcIso();

        // xtenant: one-shot instance-wide reclamation. Both NOT EXISTS sub-selects correlate back
        // to the row being deleted (package_id = packages.id, or its own org_id/ecosystem/
        // purl_name), so the cache-plane check is per tenant and never a cross-tenant scan.
        int deleted = await conn.ExecuteAsync(
            """
            DELETE FROM packages
            WHERE created_at < @cutoff
              AND same_version_push_override IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM package_versions pv WHERE pv.package_id = packages.id)
              AND NOT EXISTS (
                  SELECT 1 FROM tenant_artifact_access taa
                  JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                  WHERE taa.org_id = packages.org_id
                    AND ca.ecosystem = packages.ecosystem
                    AND ca.name = packages.purl_name)
            """,
            new { cutoff });

        if (deleted > 0)
        {
            _logger.LogInformation(
                "Schema migration: reclaimed {Count} packages row(s) that catalogued no version on either plane.",
                deleted);
        }
    }

    // Age floor for the sweep above. A day is far longer than any publish's window between
    // creating the packages row and writing its version row, and far shorter than the age of any
    // row the sweep exists to reclaim.
    private const int EmptyPackageSweepMinAgeHours = 24;
}
