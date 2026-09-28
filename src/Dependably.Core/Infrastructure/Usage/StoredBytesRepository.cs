using Dapper;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// The metadata side of the weekly stored-byte reconciliation: every row that names a blob,
/// with the size it records, across every tenant.
/// </summary>
public sealed class StoredBytesRepository
{
    private readonly IMetadataStore _db;

    public StoredBytesRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Streams every blob-naming row, unbuffered, in two reads on one connection. The hosted arm
    /// is <see cref="PackageRepository.HostedReferencedBlobsSql"/>, the row set the orphan sweep
    /// treats as referenced. The shared arm is the row set the cache and OCI deleters count before
    /// removing a physical blob: <c>cache_artifact</c> and each tenant's content binding in
    /// <c>tenant_artifact_access</c> (<c>CacheOrphanBlobDeleter</c>), and <c>oci_blobs</c>
    /// (<c>OciOrphanBlobDeleter</c>). Keys come back in database form; the caller normalises and
    /// deduplicates them.
    /// </summary>
    public async IAsyncEnumerable<ReferencedBlobRow> StreamRecordedBlobsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        // xtenant: the blob tiers are shared across every tenant and content-addressed keys are
        // held once for all of them, so the bytes a plane holds can only be compared against
        // every tenant's rows together.
        await using var conn = await _db.OpenCrossTenantAsync("stored-byte reconciliation", ct);

        await foreach (var row in conn.QueryUnbufferedAsync<ReferencedBlobRow>(
            PackageRepository.HostedReferencedBlobsSql, commandTimeout: 0))
        {
            ct.ThrowIfCancellationRequested();
            yield return row;
        }

        await foreach (var row in conn.QueryUnbufferedAsync<ReferencedBlobRow>(
            SharedPlaneBlobsSql, commandTimeout: 0))
        {
            ct.ThrowIfCancellationRequested();
            yield return row;
        }
    }

    // xtenant: proxy-cache and OCI blobs are content-addressed and shared across tenants; the
    // reconciliation sums every tenant's rows against the whole store, never one tenant's share.
    private const string SharedPlaneBlobsSql = """
        SELECT blob_key AS BlobKey, size_bytes AS SizeBytes FROM cache_artifact
        UNION ALL
        SELECT blob_key, size_bytes FROM tenant_artifact_access WHERE blob_key IS NOT NULL
        UNION ALL
        SELECT blob_key, size_bytes FROM oci_blobs
        """;
}
