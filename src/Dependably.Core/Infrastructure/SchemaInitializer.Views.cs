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
/// View creation is idempotent, because a replica boot is not a schema change. A rolling restart,
/// a scale-out event, and a blue-green cutover all start replicas against a database other replicas
/// are already querying, so an unconditional DROP+CREATE would remove a live object once per task
/// start — and <c>org_storage_bytes</c> is on the quota read path. A boot that changes nothing
/// therefore touches nothing: Postgres issues <c>CREATE OR REPLACE VIEW</c>, which swaps the
/// definition in place and never leaves the name unresolvable; SQLite, which has no
/// <c>CREATE OR REPLACE VIEW</c>, compares the desired statement against the one stored in
/// <c>sqlite_master</c> and only drops when they genuinely differ.
///
/// The drop that recreate-table migrations need is taken lazily instead of unconditionally. A view
/// holding a dependency on a table blocks a Postgres <c>ALTER COLUMN</c> and dangles across a SQLite
/// DROP+RENAME, and several one-time migrations do exactly that — so <c>RunOnceAsync</c> drops the
/// views once, immediately before the first migration body it actually runs. A boot with nothing
/// pending runs no migration body and so takes no drop at all. Creation still runs last, once every
/// column and table shape the bodies reference is guaranteed to exist, including those added by the
/// additive migrations that run after the schema file.
///
/// A view's shape is under the same blue-green rule as a table's: blue reads the view while green
/// replaces it, so a view may gain columns but may not drop, rename, or retype them in one release
/// — that is an expand/migrate/contract sequence. Postgres enforces the rule mechanically, because
/// <c>CREATE OR REPLACE VIEW</c> refuses any of those three changes; the guarded drop+create
/// fallback below is the deliberate escape hatch for the contract step, and is the only path that
/// makes a view briefly absent.
///
/// Both providers share one body per view, so there is no SQLite/Postgres pair to drift. The bodies
/// are therefore held to the portability rules the schema files follow: timestamps are ISO-8601 TEXT
/// on both and are never passed through <c>strftime</c> / <c>NOW()</c> / <c>to_char</c>; booleans are
/// INTEGER 0/1 and are compared with <c>= 1</c>, never <c>IS TRUE</c>.
/// </summary>
public sealed partial class SchemaInitializer
{
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
    ///
    /// The hosted arm filters <c>pv.origin = 'uploaded'</c> to match
    /// <see cref="ArtifactInventoryView"/>'s hosted arm exactly. Without it a licence row hanging
    /// off a non-uploaded <c>package_versions</c> row would project a licence fact whose
    /// (org_id, owner_kind, owner_id) key has no <c>artifact_inventory</c> counterpart, so every
    /// consumer that joins the two would drop it.
    /// </summary>
    // xtenant: view DDL. The view projects org_id as its own column so that every consumer can
    // filter on it; the definition itself necessarily spans all tenants.
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
          AND pv.origin = 'uploaded'
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
    // xtenant: view DDL. The view groups by org_id and projects it as its own column so that every
    // consumer can filter on it; the definition itself necessarily spans all tenants.
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

    // Name paired with the statement that declares it. The statement text is also the comparison key
    // on SQLite, so it is stored verbatim rather than rebuilt per provider.
    private static readonly (string Name, string Sql)[] ViewDefinitions =
    [
        ("artifact_inventory", ArtifactInventoryView),
        ("artifact_license", ArtifactLicenseView),
        ("org_storage_bytes", OrgStorageBytesView),
    ];

    // Set once per boot, the first time a one-time migration is about to run a body that may reshape
    // a table a view depends on. A boot with no pending migration never sets it and never drops.
    private bool _viewsDropped;

    // Called by RunOnceAsync immediately before it executes a pending migration body. Idempotent
    // within a boot, so every subsequent pending migration in the same run reuses the first drop.
    private async Task EnsureViewsDroppedAsync(DbConnection conn)
    {
        if (_viewsDropped)
        {
            return;
        }

        _viewsDropped = true;
        foreach ((string view, _) in ViewDefinitions)
        {
            // rawsql: the name comes from ViewDefinitions, a private compile-time constant array.
            await conn.ExecuteAsync($"DROP VIEW IF EXISTS {view}");
        }
    }

    // Runs last, once every table and column the bodies reference is guaranteed present — including
    // the columns added by the additive migrations, which run after the schema file.
    private async Task EnsureViewsAsync(DbConnection conn)
    {
        foreach ((string name, string sql) in ViewDefinitions)
        {
            if (_db.Provider == DbProvider.Postgres)
            {
                await EnsurePostgresViewAsync(conn, name, sql);
            }
            else
            {
                await EnsureSqliteViewAsync(conn, name, sql);
            }
        }
    }

    // CREATE OR REPLACE VIEW swaps the definition atomically: the name is never unresolvable, so a
    // concurrent reader on another replica cannot observe the view missing. It refuses to remove,
    // rename, or retype an existing output column, which is exactly the blue-green rule for view
    // shape — so that refusal is honoured as a signal, not worked around: the fallback drops and
    // recreates, which is the contract step of an expand/migrate/contract sequence and the only path
    // that leaves a window. If the body is simply invalid, the CREATE in the fallback throws the real
    // error rather than the replace's.
    private static async Task EnsurePostgresViewAsync(DbConnection conn, string name, string sql)
    {
        try
        {
            // rawsql: `sql` is a private compile-time constant; only the CREATE keyword is rewritten.
            await conn.ExecuteAsync(string.Concat("CREATE OR REPLACE ", sql.AsSpan("CREATE ".Length)));
            return;
        }
        catch (DbException)
        {
            // Output column list changed. Fall through to the guarded drop+create below.
        }

        // rawsql: the name comes from ViewDefinitions, a private compile-time constant array.
        await conn.ExecuteAsync($"DROP VIEW IF EXISTS {name}");
        await conn.ExecuteAsync(sql);
    }

    // SQLite has no CREATE OR REPLACE VIEW, and stores each view's CREATE statement verbatim in
    // sqlite_master. Comparing the stored text against the desired text — with whitespace runs
    // collapsed, so reindenting a body is not mistaken for a definition change — makes the common
    // case (nothing changed) a pure read, and confines the drop to a boot that genuinely changes
    // the definition.
    private static async Task EnsureSqliteViewAsync(DbConnection conn, string name, string sql)
    {
        string? stored = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = @name", new { name });

        if (stored is not null)
        {
            if (string.Equals(CollapseWhitespace(stored), CollapseWhitespace(sql), StringComparison.Ordinal))
            {
                return;
            }

            // rawsql: the name comes from ViewDefinitions, a private compile-time constant array.
            await conn.ExecuteAsync($"DROP VIEW IF EXISTS {name}");
        }

        await conn.ExecuteAsync(sql);
    }

    private static string CollapseWhitespace(string sql) =>
        string.Join(' ', sql.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
}
