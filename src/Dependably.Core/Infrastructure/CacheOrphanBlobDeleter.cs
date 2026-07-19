using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// The one place a physical proxy-cache blob is deleted from the Cache tier. Proxy blob keys
/// (<see cref="BlobKeys.Proxy"/>) are content-addressed and carry no tenant or coordinate segment,
/// so any <c>cache_artifact</c> row with byte-identical upstream bytes under a distinct
/// ecosystem/name/version/filename coordinate shares one physical blob, and the file may only be
/// removed once no <c>cache_artifact</c> row anywhere still references it.
///
/// The reference count and the physical delete are one critical section under
/// <see cref="CacheBlobKeyLock"/>, held for the same key a concurrent eviction of a sibling row
/// holds it for — mirroring <see cref="Protocol.OciOrphanBlobDeleter"/>'s shape for the
/// structurally identical race on the OCI blob tier: a refcount and a delete that are not atomic
/// are a race, not a guard. Splitting them — counting in one place and deleting in another, or
/// taking no lock at all — reopens exactly the interleave this guards against: two evictions of
/// rows sharing a key (the LRU pass aging out one coordinate while the <c>local_only</c> claim
/// purge evicts another) can both observe the other's row as the last reference and skip the
/// delete forever (an unreclaimed blob), or race so a delete lands while the sibling eviction's own
/// row-delete has not yet committed.
///
/// Both cache-tier delete sites route through here — the LRU pass
/// (<see cref="CacheEvictionService"/>) and the <c>local_only</c> claim purge
/// (<c>ClaimsController.PurgeProxyArtefactsAsync</c>, downstream of
/// <see cref="CacheArtifactRepository.EvictTenantProxyVersionsForNameAsync"/>) — so the guard
/// cannot be half-applied.
///
/// Scope is a single process, the same boundary <see cref="Protocol.OciBlobKeyLock"/> documents for
/// its tier. A concurrent proxy first-fetch that hashes to this exact content under a new
/// coordinate checks blob existence and skips the write when present, then inserts its own row,
/// without taking this lock — a delete that wins a race against that narrower fill-side window is
/// not closed here, only the evict-vs-evict race this guard targets is.
/// </summary>
public sealed class CacheOrphanBlobDeleter
{
    private readonly CacheArtifactRepository _cache;
    private readonly CacheBlobKeyLock _blobKeyLock;

    public CacheOrphanBlobDeleter(CacheArtifactRepository cache, CacheBlobKeyLock blobKeyLock)
    {
        _cache = cache;
        _blobKeyLock = blobKeyLock;
    }

    /// <summary>
    /// Physically deletes <paramref name="storeKey"/> from <paramref name="cacheBlobs"/> when no
    /// <c>cache_artifact</c> row other than <paramref name="excludingId"/> still references
    /// <paramref name="dbBlobKey"/>. Returns true when the blob was deleted, false when another row
    /// still shares the content-addressed key (the physical blob is left alone for that sibling).
    ///
    /// <paramref name="dbBlobKey"/> is the value stored in <c>cache_artifact.blob_key</c> (the
    /// refcount and the lock stripe are keyed on it); <paramref name="storeKey"/> is the key the
    /// caller actually passes to the blob store, which callers resolve their own way — e.g. via
    /// <see cref="Storage.BlobKeys.StoreKey"/> — exactly as they did before this guard existed, so
    /// this type makes no assumption about that mapping.
    ///
    /// Pass the caller's own row id as <paramref name="excludingId"/> when it has not been deleted
    /// yet (the LRU path checks before deleting its row); pass an id that cannot match any real row
    /// (e.g. <see cref="string.Empty"/>, since every <c>cache_artifact.id</c> is a non-empty GUID)
    /// when the caller's row is already gone — the <c>local_only</c> claim purge deletes its row
    /// inside the transaction that determines eviction, before this method ever runs, so there is
    /// nothing left to exclude.
    ///
    /// Propagates any exception the blob store's delete raises — callers that want a
    /// best-effort/retry outcome around a failed delete catch around this call, exactly as they
    /// did before this guard existed.
    /// </summary>
    public async Task<bool> DeleteIfUnreferencedAsync(
        string dbBlobKey, string excludingId, string storeKey, IBlobStore cacheBlobs, CancellationToken ct = default)
    {
        await using (await _blobKeyLock.AcquireAsync(dbBlobKey, ct))
        {
            if (await _cache.BlobKeyReferencedElsewhereAsync(dbBlobKey, excludingId, ct))
            {
                return false;
            }

            await cacheBlobs.DeleteAsync(storeKey, ct);
            return true;
        }
    }
}
