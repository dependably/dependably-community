using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// The canonical read model: one definition of an org's artifacts, and one definition of its stored
/// bytes, that every read surface can share.
///
/// An artifact reaches an org through either catalogue — a hosted push writes a
/// <c>package_versions</c> row, a proxy fetch writes a <c>cache_artifact</c> row the org reaches
/// through <c>tenant_artifact_access</c> — and until now every surface re-derived the union of the
/// two by hand, each with a slightly different filter set. That is what let a surface be blind to
/// half an org's inventory without anyone noticing.
///
/// The sharpest edge it removes is OCI. An image casts a shadow into BOTH catalogues — a tag push
/// into <c>package_versions</c>, a proxy pull into <c>cache_artifact</c> — but every "exclude OCI"
/// guard in the codebase was written as <c>ecosystem != 'oci'</c> against <c>cache_artifact</c>
/// alone, so each one was only half-enforced. Over <c>artifact_inventory</c> there is a single
/// <c>ecosystem</c> column spanning both shadows, so that predicate finally means what every author
/// already believes it means.
///
/// Views are stateless, so they are dropped and recreated unconditionally on every boot rather than
/// migrated. That is also why the drop runs early and the create runs last: a view holding a
/// dependency on a table blocks a Postgres <c>ALTER COLUMN</c> and dangles across a SQLite
/// DROP+RENAME, and several recreate-table migrations do exactly that. Dropping first means no view
/// is ever in the way; creating last means every column and table shape the bodies reference is
/// guaranteed to exist, including those added by the additive migrations that run after the schema
/// file.
///
/// Both providers share one body per view, so there is no SQLite/Postgres pair to drift. The bodies
/// are therefore held to the portability rules the schema files follow: timestamps are ISO-8601 TEXT
/// on both and are never passed through <c>strftime</c> / <c>NOW()</c> / <c>to_char</c>; booleans are
/// INTEGER 0/1 and are compared with <c>= 1</c>, never <c>IS TRUE</c>.
/// </summary>
public sealed partial class SchemaInitializer
{
    private static readonly string[] ViewNames =
        ["artifact_inventory", "artifact_license", "org_storage_bytes"];

    /// <summary>
    /// One row per (org, artifact), across both catalogues.
    ///
    /// <c>owner_kind</c> + <c>owner_id</c> key a row back to its physical table — the same
    /// polymorphic discriminator <c>package_version_licenses</c> and <c>package_version_vulns</c>
    /// already use — so a writer dispatches on the kind and targets the id. Views carry no
    /// constraints and cannot be written through; every UPDATE and DELETE still goes to the table.
    ///
    /// <c>package_id</c> is nullable on purpose. An org reaches a <c>cache_artifact</c> through
    /// <c>tenant_artifact_access</c> alone and can hold one with no <c>packages</c> row at all, so
    /// the proxy arm LEFT JOINs. Making this an INNER JOIN silently drops those artifacts, which is
    /// precisely the bug this model exists to make impossible.
    ///
    /// <c>size_bytes</c> is the bytes of THIS row's blob. For an OCI image that is the manifest — a
    /// few KB — never the layers. Never SUM it for storage; that is what <c>org_storage_bytes</c> is
    /// for.
    /// </summary>
    private const string ArtifactInventoryView =
        """
        CREATE VIEW artifact_inventory AS
        SELECT p.org_id                        AS org_id,
               'package_version'               AS owner_kind,
               pv.id                           AS owner_id,
               p.id                            AS package_id,
               p.ecosystem                     AS ecosystem,
               p.purl_name                     AS name,
               p.name                          AS display_name,
               pv.version                      AS version,
               pv.filename                     AS filename,
               pv.purl                         AS purl,
               pv.blob_key                     AS blob_key,
               pv.size_bytes                   AS size_bytes,
               'uploaded'                      AS origin,
               pv.created_at                   AS created_at,
               pv.published_at                 AS published_at,
               pv.last_used                    AS last_used,
               pv.download_count               AS download_count,
               pv.yanked                       AS yanked,
               pv.manual_block_state           AS manual_block_state,
               pv.deprecated                   AS deprecated,
               pv.deprecation_checked_at       AS deprecation_checked_at,
               pv.revoked_at                   AS revoked_at,
               pv.versions_behind              AS versions_behind,
               pv.vuln_checked_at              AS vuln_checked_at,
               pv.has_install_script           AS has_install_script,
               pv.provenance_status            AS provenance_status,
               CASE WHEN p.ecosystem = 'oci' THEN pv.version ELSE NULL END AS oci_digest
        FROM package_versions pv
        JOIN packages p ON p.id = pv.package_id
        WHERE pv.origin = 'uploaded'
        UNION ALL
        SELECT taa.org_id                      AS org_id,
               'cache_artifact'                AS owner_kind,
               ca.id                           AS owner_id,
               p.id                            AS package_id,
               ca.ecosystem                    AS ecosystem,
               ca.name                         AS name,
               COALESCE(p.name, ca.name)       AS display_name,
               ca.version                      AS version,
               ca.filename                     AS filename,
               ca.purl                         AS purl,
               ca.blob_key                     AS blob_key,
               ca.size_bytes                   AS size_bytes,
               'proxy'                         AS origin,
               ca.first_cached_at              AS created_at,
               ca.published_at                 AS published_at,
               taa.last_used                   AS last_used,
               taa.download_count              AS download_count,
               taa.yanked                      AS yanked,
               taa.manual_block_state          AS manual_block_state,
               ca.deprecated                   AS deprecated,
               ca.deprecation_checked_at       AS deprecation_checked_at,
               ca.revoked_at                   AS revoked_at,
               ca.versions_behind              AS versions_behind,
               ca.vuln_checked_at              AS vuln_checked_at,
               ca.has_install_script           AS has_install_script,
               ca.provenance_status            AS provenance_status,
               CASE WHEN ca.ecosystem = 'oci' THEN ca.version ELSE NULL END AS oci_digest
        FROM cache_artifact ca
        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
        LEFT JOIN packages p
               ON p.org_id = taa.org_id AND p.ecosystem = ca.ecosystem AND p.purl_name = ca.name
        """;

    /// <summary>
    /// One row per (artifact, SPDX identifier), joinable to <see cref="ArtifactInventoryView"/> on
    /// (org_id, owner_kind, owner_id). Two arms, not three: an OCI image's license is projected onto
    /// whichever catalogue row it cast, so it needs no plane of its own.
    ///
    /// <c>license_spdx</c> holds the raw captured value, which may be an expression
    /// ("MIT OR Apache-2.0"). Callers that need leaves parse it — <c>SpdxLicenseExpression</c>.
    ///
    /// <c>created_at</c> is the license fact's own timestamp (when this SPDX id was captured for
    /// this artifact), not the artifact's — a license attached by a later backfill can postdate the
    /// artifact's own <c>artifact_inventory.created_at</c>. The license review queue's first-seen
    /// column depends on this distinction.
    /// </summary>
    private const string ArtifactLicenseView =
        """
        CREATE VIEW artifact_license AS
        SELECT p.org_id               AS org_id,
               'package_version'      AS owner_kind,
               pvl.package_version_id AS owner_id,
               pvl.license_spdx       AS license_spdx,
               pvl.source             AS source,
               pvl.created_at         AS created_at
        FROM package_version_licenses pvl
        JOIN package_versions pv ON pv.id = pvl.package_version_id
        JOIN packages         p  ON p.id  = pv.package_id
        WHERE pvl.owner_kind = 'package_version'
        UNION ALL
        SELECT taa.org_id             AS org_id,
               'cache_artifact'       AS owner_kind,
               pvl.cache_artifact_id  AS owner_id,
               pvl.license_spdx       AS license_spdx,
               pvl.source             AS source,
               pvl.created_at         AS created_at
        FROM package_version_licenses pvl
        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = pvl.cache_artifact_id
        WHERE pvl.owner_kind = 'cache_artifact'
        """;

    /// <summary>
    /// An org's stored bytes. Deliberately NOT derived from <see cref="ArtifactInventoryView"/>:
    /// a catalogue row for an OCI image sizes its manifest, never its layers, and an image pushed by
    /// digest casts no catalogue row at all. So OCI is excluded from both catalogue arms and summed
    /// whole from <c>oci_blobs</c>, which is the only table that sees an image's real bytes.
    /// </summary>
    private const string OrgStorageBytesView =
        """
        CREATE VIEW org_storage_bytes AS
        SELECT sb.org_id AS org_id, SUM(sb.bytes) AS total_bytes
        FROM (
            SELECT p.org_id AS org_id, pv.size_bytes AS bytes
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem != 'oci' AND pv.origin = 'uploaded'
            UNION ALL
            SELECT taa.org_id AS org_id, ca.size_bytes AS bytes
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
            WHERE ca.ecosystem != 'oci'
            UNION ALL
            SELECT ob.org_id AS org_id, ob.size_bytes AS bytes
            FROM oci_blobs ob
        ) sb
        GROUP BY sb.org_id
        """;

    // Runs before the schema pass and before every recreate-table migration, so no view is ever
    // holding a dependency on a table one of them is about to reshape.
    private static async Task DropViewsAsync(DbConnection conn)
    {
        foreach (string view in ViewNames)
        {
            // rawsql: the name comes from ViewNames, a private compile-time constant array.
            await conn.ExecuteAsync($"DROP VIEW IF EXISTS {view}");
        }
    }

    // Runs last, once every table and column the bodies reference is guaranteed present — including
    // the columns added by the additive migrations, which run after the schema file.
    private static async Task CreateViewsAsync(DbConnection conn)
    {
        await conn.ExecuteAsync(ArtifactInventoryView);
        await conn.ExecuteAsync(ArtifactLicenseView);
        await conn.ExecuteAsync(OrgStorageBytesView);
    }
}
