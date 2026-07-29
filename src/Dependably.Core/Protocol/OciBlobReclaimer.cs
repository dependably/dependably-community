using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Decides whether an <c>oci_blobs</c> row may be reclaimed for one org, and performs the reclaim.
///
/// This is the mark-and-sweep half of OCI eviction. Retention and the cache LRU evict *images* —
/// they release a manifest's claim and drop its catalogue rows — and never touch layers. The layers
/// that image was holding up become unreferenced, and this reclaims them on a later pass. Splitting
/// it that way avoids a cascading delete, where the order in which a manifest's closure is walked
/// determines whether a concurrently-pushed image loses its bytes; here every delete is justified by
/// the graph as it stands at the moment of the check, not by a traversal begun earlier.
///
/// <para><b>The four claims.</b> A digest is reclaimable for an org only when none of these hold:
/// another manifest references it (<see cref="OciReferenceGraph"/>), a tag points at it, an
/// uploaded <c>package_versions</c> row carries it as its version, or a cache-plane
/// <c>cache_artifact</c> row this org retains access to does. The last two are what stop a proxy
/// eviction from destroying bytes a hosted image serves from — the hazard that makes
/// <c>oci_blobs.origin</c> useless for this decision, since the upsert never rewrites it and a
/// pull-then-push round trip leaves a hosted image's row reading <c>origin='proxy'</c> forever.</para>
///
/// <para><b>The precondition.</b> None of this is sound while any manifest in the org has an unknown
/// closure: a manifest whose references were never recorded may well reference the layer being
/// examined, and the graph would report it unreferenced. <see cref="IsOrgClosureCompleteAsync"/> is
/// therefore checked per org before any reclaim, and a single un-backfilled manifest disables the
/// sweep for that org rather than allowing a delete on partial evidence.</para>
/// </summary>
public sealed class OciBlobReclaimer
{
    private readonly IMetadataStore _db;
    private readonly OciReferenceGraph _graph;
    private readonly OciOrphanBlobDeleter _orphanBlobs;
    private readonly ILogger<OciBlobReclaimer> _logger;

    public OciBlobReclaimer(
        IMetadataStore db,
        OciReferenceGraph graph,
        OciOrphanBlobDeleter orphanBlobs,
        ILogger<OciBlobReclaimer> logger)
    {
        _db = db;
        _graph = graph;
        _orphanBlobs = orphanBlobs;
        _logger = logger;
    }

    /// <summary>
    /// True when every manifest this org holds has a recorded closure, which is the precondition for
    /// trusting an "unreferenced" answer from the graph. False while
    /// <see cref="OciReferenceGraphBackfillService"/> still has work to do for the org, or when a
    /// manifest's bytes are unreadable so its closure can never be recorded.
    /// </summary>
    public async Task<bool> IsOrgClosureCompleteAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: org_id filter scopes the completeness check to the caller's tenant.
        bool anyUnknown = await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS(
                SELECT 1 FROM oci_blobs b
                WHERE b.org_id = @orgId
                  AND b.media_type IN @mediaTypes
                  AND NOT EXISTS (
                      SELECT 1 FROM oci_manifest_blobs g
                      WHERE g.org_id = b.org_id AND g.manifest_digest = b.digest))
            """,
            new { orgId, mediaTypes = OciManifestParser.AcceptedMediaTypes.ToArray() });

        return !anyUnknown;
    }

    /// <summary>
    /// True when any of the four claims still holds for <paramref name="digest"/> in this org, so the
    /// row must stay. Callers drop the evicted image's edges and catalogue rows first; a true answer
    /// afterwards means something else genuinely still needs the bytes.
    /// </summary>
    public async Task<bool> IsClaimedAsync(string orgId, string digest, CancellationToken ct = default)
    {
        if (await _graph.IsReferencedAsync(orgId, digest, ct))
        {
            return true;
        }

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: every arm is org_id-filtered — this asks only about the caller's tenant, which is
        // the right scope for removing that tenant's oci_blobs row. The cross-org question governing
        // the physical file is OciOrphanBlobDeleter's blob_key count.
        return await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS(SELECT 1 FROM oci_tags WHERE org_id = @orgId AND digest = @digest)
                OR EXISTS(
                    SELECT 1 FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.org_id = @orgId AND p.ecosystem = 'oci'
                      AND pv.origin = 'uploaded' AND pv.version = @digest)
                OR EXISTS(
                    SELECT 1 FROM tenant_artifact_access taa
                    JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                    WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.version = @digest)
            """,
            new { orgId, digest });
    }

    /// <summary>
    /// Reclaims every unclaimed <c>oci_blobs</c> row for the org, up to <paramref name="limit"/>
    /// rows, and returns how many were removed. Returns 0 without examining anything when the org's
    /// closure is incomplete.
    ///
    /// Each candidate is re-checked under <see cref="IsClaimedAsync"/> immediately before its delete
    /// rather than trusting the batch query, so a push that lands between the scan and the delete
    /// keeps its bytes. The physical file comes off only via <see cref="OciOrphanBlobDeleter"/>,
    /// which holds the per-key lock and counts references across every org — OCI blob keys carry no
    /// org segment, so this org dropping its row does not make the bytes unreferenced.
    /// </summary>
    public async Task<int> ReclaimUnreferencedAsync(string orgId, int limit, CancellationToken ct = default)
    {
        if (!await IsOrgClosureCompleteAsync(orgId, ct))
        {
            _logger.LogDebug(
                "OCI reclaim skipped for org {OrgId}: at least one manifest closure is still unknown", orgId);
            return 0;
        }

        var candidates = await ScanUnclaimedAsync(orgId, limit, ct);
        int reclaimed = 0;

        foreach (var (Digest, BlobKey, Origin) in candidates)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            // Re-check under the current state; the scan is only a shortlist.
            if (await IsClaimedAsync(orgId, Digest, ct))
            {
                continue;
            }

            await using (var conn = await _db.OpenAsync(ct))
            {
                // xtenant: (digest, org_id) PK is tenant-scoped.
                await conn.ExecuteAsync(
                    "DELETE FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
                    new { digest = Digest, orgId });
            }

            await _graph.RemoveManifestAsync(orgId, Digest, ct);

            // Only uploaded blobs live in the Registry tier and are deleted here; proxy blobs are
            // Cache-tier and reclaimed by the cache plane's own GC, matching the delete paths.
            if (Origin == "uploaded")
            {
                await _orphanBlobs.DeleteIfUnreferencedAsync(BlobKey, ct);
            }

            reclaimed++;
        }

        if (reclaimed > 0)
        {
            _logger.LogInformation("OCI reclaim removed {Count} unreferenced blob rows for org {OrgId}", reclaimed, orgId);
        }

        return reclaimed;
    }

    /// <summary>
    /// Shortlists this org's blob rows that no manifest references and no catalogue row claims.
    /// Expressed as one query so a sweep does not issue four round trips per blob; the authoritative
    /// per-row check is still <see cref="IsClaimedAsync"/> at delete time.
    /// </summary>
    private async Task<IReadOnlyList<(string Digest, string BlobKey, string Origin)>> ScanUnclaimedAsync(
        string orgId, int limit, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: every correlated sub-select is org_id-filtered to the caller's tenant.
        var rows = await conn.QueryAsync<(string Digest, string BlobKey, string Origin)>(
            """
            SELECT b.digest AS Digest, b.blob_key AS BlobKey, b.origin AS Origin
            FROM oci_blobs b
            WHERE b.org_id = @orgId
              AND NOT EXISTS (
                  SELECT 1 FROM oci_manifest_blobs g
                  WHERE g.org_id = b.org_id AND g.blob_digest = b.digest)
              AND NOT EXISTS (
                  SELECT 1 FROM oci_tags t
                  WHERE t.org_id = b.org_id AND t.digest = b.digest)
              AND NOT EXISTS (
                  SELECT 1 FROM package_versions pv
                  JOIN packages p ON p.id = pv.package_id
                  WHERE p.org_id = b.org_id AND p.ecosystem = 'oci'
                    AND pv.origin = 'uploaded' AND pv.version = b.digest)
              AND NOT EXISTS (
                  SELECT 1 FROM tenant_artifact_access taa
                  JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                  WHERE taa.org_id = b.org_id AND ca.ecosystem = 'oci' AND ca.version = b.digest)
            ORDER BY b.digest
            LIMIT @limit
            """,
            new { orgId, limit });

        return rows.AsList();
    }
}
