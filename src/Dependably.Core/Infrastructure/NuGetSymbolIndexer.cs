using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Extracts the Portable PDBs from a <c>.snupkg</c> and records their SSQP keys in the per-org
/// symbol index. The single implementation behind both entry points — the symbol-push path, which
/// indexes the staged upload, and the management re-index path, which re-reads the stored archive
/// out of the blob store.
///
/// <para>
/// Indexing at push time is deliberately best-effort: the <c>package_versions</c> row is already
/// committed when it runs, so a corrupt PDB entry or an I/O blip must not fail an otherwise good
/// push. That leaves a <c>.snupkg</c> that downloads fine but whose PDBs never resolve by debug-id,
/// and re-pushing the coordinate is itself policy-gated — so the repair path is what makes the
/// best-effort posture safe rather than merely convenient.
/// </para>
/// </summary>
public sealed class NuGetSymbolIndexer(
    NuGetSymbolIndexRepository symbolIndex,
    IBlobStore blobs,
    ILogger<NuGetSymbolIndexer> logger)
{
    /// <summary>
    /// Indexes every Portable PDB in <paramref name="snupkg"/> against
    /// <paramref name="packageVersionId"/>, replacing whatever the version had indexed before, and
    /// returns the number of PDBs recorded.
    ///
    /// <para>
    /// Replace rather than insert-if-absent: the insert alone is idempotent, but it cannot repair
    /// rows pointing at a stale <c>snupkg_blob_key</c> — the exact state a re-pushed or
    /// re-addressed archive leaves behind. A returned zero means the archive held no PDB this
    /// build could read (native/Windows PDBs are out of scope), which is the signal an operator
    /// needs and previously had to find in the server log.
    /// </para>
    /// </summary>
    public async Task<int> ReplaceIndexAsync(
        string orgId, string packageVersionId, string snupkgBlobKey, Stream snupkg,
        CancellationToken ct = default)
    {
        // ZipArchive needs to seek the central directory; blob backends that stream (S3, Azure)
        // hand back a non-seekable stream. Buffering the COMPRESSED archive carries no
        // amplification risk of its own — the decompression bound is applied per entry inside
        // ExtractPortablePdbs.
        var source = snupkg;
        MemoryStream? buffered = null;
        if (!snupkg.CanSeek)
        {
            buffered = new MemoryStream();
            await snupkg.CopyToAsync(buffered, ct);
            buffered.Position = 0;
            source = buffered;
        }

        try
        {
            var symbols = NuGetSymbolKey.ExtractPortablePdbs(source);
            await symbolIndex.DeleteForVersionAsync(orgId, packageVersionId, ct);
            if (symbols.Count == 0)
            {
                logger.LogInformation(
                    "Symbol package for version {VersionId} in org {OrgId} contained no indexable Portable PDBs.",
                    packageVersionId, orgId);
                return 0;
            }

            await symbolIndex.IndexAsync(orgId, packageVersionId, snupkgBlobKey, symbols, ct);
            return symbols.Count;
        }
        finally
        {
            if (buffered is not null)
            {
                await buffered.DisposeAsync();
            }
        }
    }

    /// <summary>
    /// Re-reads a stored <c>.snupkg</c> out of the blob store and rebuilds its symbol index.
    /// Returns the number of PDBs recorded, or <see langword="null"/> when the blob named by
    /// <paramref name="snupkgBlobKey"/> is no longer present.
    /// </summary>
    public async Task<int?> ReindexFromBlobAsync(
        string orgId, string packageVersionId, string snupkgBlobKey, CancellationToken ct = default)
    {
        var stream = await blobs.GetAsync(BlobKeys.StoreKey(snupkgBlobKey), ct);
        if (stream is null)
        {
            return null;
        }

        await using (stream)
        {
            return await ReplaceIndexAsync(orgId, packageVersionId, snupkgBlobKey, stream, ct);
        }
    }
}
