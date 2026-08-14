using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;

namespace Dependably.Protocol;

/// <summary>
/// The one place a physical OCI blob is deleted. OCI blob keys
/// (<see cref="BlobKeys.OciBlob"/>) are content-addressed with no org segment, so every org that
/// pushed or pulled a given digest shares one physical blob and the file may only be removed once
/// the last <c>oci_blobs</c> row referencing it is gone.
///
/// The reference count and the physical delete are one critical section under
/// <see cref="OciBlobKeyLock"/>, held for the same key an in-flight finalize holds. Splitting them
/// — counting in one place and deleting in another, or taking no lock at all — reopens the race a
/// dedup push loses: the finalize observes the blob present and skips its write, the count reads
/// zero because the finalize has not recorded its row yet, the file is deleted, and the finalize's
/// row is left pointing at a blob that is gone. Serialised, the interleave is a total order per
/// key: either the count sees the finalize's row and skips the delete, or the finalize re-checks
/// existence after the delete and re-puts the blob.
///
/// Both delete sites route through here — the Distribution-Spec digest delete
/// (<c>OciController</c>) and the management-API version yank (<c>OrgController</c>) — so the
/// guard cannot be half-applied.
/// </summary>
public sealed class OciOrphanBlobDeleter
{
    private readonly IMetadataStore _db;
    private readonly TieredBlobStorage _blobs;
    private readonly OciBlobKeyLock _blobKeyLock;

    public OciOrphanBlobDeleter(IMetadataStore db, TieredBlobStorage blobs, OciBlobKeyLock blobKeyLock)
    {
        _db = db;
        _blobs = blobs;
        _blobKeyLock = blobKeyLock;
    }

    /// <summary>
    /// Physically deletes <paramref name="blobKey"/> when no <c>oci_blobs</c> row in any org still
    /// references it. Callers delete their own org's shadow rows first, so a zero count means the
    /// last reference is gone. Returns true when the delete ran, false when another org still
    /// references the key.
    ///
    /// <para><b>Both tiers.</b> An OCI blob key is content-addressed and identical whichever way the
    /// bytes arrived — a push writes them to the Registry tier, a proxy pull to the Cache tier — and
    /// the same digest can have arrived both ways in different orgs. The refcount is over
    /// <c>oci_blobs</c> rows, not over tiers, so once it reaches zero no org references the content
    /// by either route and both copies are orphaned. Deleting from only one tier is what left proxy
    /// OCI bytes unreclaimable: the row went, and with it the last pointer to bytes nothing would
    /// ever look for again. <see cref="IBlobStore.DeleteAsync"/> is a no-op on a key the tier does
    /// not hold, and in single-tier deployments both properties resolve to the same store, so the
    /// second delete is harmless in every configuration.</para>
    /// </summary>
    public async Task<bool> DeleteIfUnreferencedAsync(string blobKey, CancellationToken ct = default)
    {
        await using (await _blobKeyLock.AcquireAsync(blobKey, ct))
        {
            await using var conn = await _db.OpenAsync(ct);

            // xtenant: deliberately cross-org — content-addressed OCI blobs are shared, so the
            // physical blob is orphaned only when no org's row still references this key.
            long remainingRefs = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM oci_blobs WHERE blob_key = @key",
                new { key = blobKey });

            if (remainingRefs != 0)
            {
                return false;
            }

            string storeKey = BlobKeys.StoreKey(blobKey);
            await _blobs.Registry.DeleteAsync(storeKey, ct);
            await _blobs.Cache.DeleteAsync(storeKey, ct);
            return true;
        }
    }
}
