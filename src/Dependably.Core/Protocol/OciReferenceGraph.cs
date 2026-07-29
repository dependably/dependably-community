using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// The manifest → referenced-blob graph over <c>oci_blobs</c>, and the only place it is read or
/// written.
///
/// An OCI image is a manifest plus a config blob and N layers; an image index is a manifest plus N
/// child manifests. Layers are shared across images and repositories by design — content-addressing
/// is the point — so <c>oci_blobs</c>, which records that a digest exists for an org, cannot answer
/// whether anything still depends on it. That question is what stands between "reclaim an unused
/// layer" and "delete bytes a live image serves from", and it is why nothing evicts OCI storage
/// today.
///
/// The graph is recorded on both write paths as the manifest body is parsed — hosted push
/// (<see cref="OciUploadService"/>) and proxy pull (<see cref="OciUpstreamResolver"/>) — and
/// backfilled for manifests stored before it existed by <see cref="OciReferenceGraphBackfillService"/>.
///
/// <para><b>Absence is not a leaf.</b> A manifest with no edges is one whose closure is
/// <em>unknown</em>, not one that references nothing. Every consumer must distinguish those via
/// <see cref="IsClosureKnownAsync"/> and refuse to evict the unknown case, for the same reason a
/// missing advisory signal defers a scan rather than recording a clean one: a delete authorized by
/// missing evidence is unrecoverable, and the bytes it removes are the ones a running deployment
/// pulls.</para>
/// </summary>
public sealed class OciReferenceGraph
{
    private readonly IMetadataStore _db;

    public OciReferenceGraph(IMetadataStore db) => _db = db;

    /// <summary>
    /// Records the edges from <paramref name="manifestDigest"/> to every digest it references.
    /// Idempotent: re-recording the same manifest is a no-op, so a re-push, a proxy revalidation,
    /// and the backfill pass can all run over the same manifest without conflicting.
    ///
    /// A manifest that references nothing cannot occur — <see cref="OciManifestParser"/> rejects
    /// such a document as invalid — so an empty <paramref name="referenced"/> is a caller error and
    /// writes nothing rather than recording a manifest as a known leaf.
    /// </summary>
    public async Task RecordAsync(
        string orgId, string manifestDigest, IReadOnlyList<string> referenced, CancellationToken ct = default)
    {
        if (referenced.Count == 0)
        {
            return;
        }

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: org_id is in the INSERT column list; the PK is (org_id, manifest_digest, blob_digest).
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_manifest_blobs (org_id, manifest_digest, blob_digest)
            VALUES (@orgId, @manifestDigest, @blobDigest)
            ON CONFLICT (org_id, manifest_digest, blob_digest) DO NOTHING
            """,
            referenced.Distinct(StringComparer.Ordinal)
                .Select(blobDigest => new { orgId, manifestDigest, blobDigest }));
    }

    /// <summary>
    /// True when this org's graph knows what <paramref name="manifestDigest"/> references. False
    /// means the manifest predates the graph and has not been backfilled — its closure is unknown,
    /// and it must not be evicted.
    /// </summary>
    public async Task<bool> IsClosureKnownAsync(string orgId, string manifestDigest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: org_id filter scopes the lookup to the caller's tenant.
        return await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS(
                SELECT 1 FROM oci_manifest_blobs
                WHERE org_id = @orgId AND manifest_digest = @manifestDigest)
            """,
            new { orgId, manifestDigest });
    }

    /// <summary>
    /// The digests <paramref name="manifestDigest"/> directly references — config + layers for an
    /// image manifest, child manifests for an index. One level only: a caller walking an index
    /// recurses through each child that is itself a manifest.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetReferencedAsync(
        string orgId, string manifestDigest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: org_id filter scopes the lookup to the caller's tenant.
        var rows = await conn.QueryAsync<string>(
            """
            SELECT blob_digest FROM oci_manifest_blobs
            WHERE org_id = @orgId AND manifest_digest = @manifestDigest
            ORDER BY blob_digest
            """,
            new { orgId, manifestDigest });
        return rows.AsList();
    }

    /// <summary>
    /// True when any manifest in this org still references <paramref name="blobDigest"/>. This is
    /// the layer refcount: callers drop the evicted manifest's edges first, then ask this of each
    /// digest it referenced, so a true answer means another image still needs the bytes.
    ///
    /// Org-scoped by design — it answers "does this tenant still need it". The cross-org question,
    /// which governs the physical file, is <see cref="OciOrphanBlobDeleter"/>'s
    /// <c>oci_blobs.blob_key</c> count, since the key carries no org segment.
    /// </summary>
    public async Task<bool> IsReferencedAsync(string orgId, string blobDigest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: org_id filter scopes the refcount to the caller's tenant.
        return await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS(
                SELECT 1 FROM oci_manifest_blobs
                WHERE org_id = @orgId AND blob_digest = @blobDigest)
            """,
            new { orgId, blobDigest });
    }

    /// <summary>
    /// Drops every edge originating at <paramref name="manifestDigest"/>. Called as part of removing
    /// the manifest, before the referenced digests are refcounted, so the manifest's own references
    /// do not keep its layers alive.
    /// </summary>
    public async Task RemoveManifestAsync(string orgId, string manifestDigest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: org_id filter scopes the delete to the caller's tenant.
        await conn.ExecuteAsync(
            "DELETE FROM oci_manifest_blobs WHERE org_id = @orgId AND manifest_digest = @manifestDigest",
            new { orgId, manifestDigest });
    }
}
