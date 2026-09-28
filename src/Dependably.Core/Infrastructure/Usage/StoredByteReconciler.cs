using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Dependably.Storage;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// One plane's figures from a stored-byte pass. <see cref="StoreBytes"/> is what the blob store
/// holds under the plane's prefix; <see cref="MetadataBytes"/> is the sum, over distinct store
/// keys, of the size the metadata records for each. <see cref="NullSizeKeys"/> counts the
/// distinct keys whose every row records a NULL size: they add nothing to
/// <see cref="MetadataBytes"/> and are reported rather than guessed at.
/// </summary>
public sealed record PlaneByteTally(
    string Plane,
    long StoreBytes,
    long StoreObjects,
    long MetadataBytes,
    long MetadataKeys,
    long NullSizeKeys);

/// <summary>
/// The result of one stored-byte pass: a tally per plane, in <see cref="BlobKeys.PlanePrefixes"/>
/// order, plus the store-side bytes each exclusion kept out of the comparison.
/// </summary>
public sealed record StoredByteReport(
    IReadOnlyList<PlaneByteTally> Planes,
    bool TiersSplit,
    long ExcludedSymbolBytes,
    long ExcludedStagingBytes,
    long RecordlessBytes);

/// <summary>
/// Measures, per storage plane, the bytes the blob store holds and the bytes the metadata records.
///
/// <para><b>Planes</b> are the top-level key families in <see cref="BlobKeys.PlanePrefixes"/>. The
/// store side streams <see cref="IBlobStore.ListAsync"/> for each prefix and keeps only running
/// sums, never a key list. It walks both tiers when <see cref="TieredBlobStorage.IsSplit"/> and the
/// one store once when the tiers are the same instance, because several ecosystems read proxied
/// bytes from the registry tier and a tier-only sum would report drift that is not there. On a
/// split deployment an OCI digest that arrived by push in one org and by proxy pull in another is
/// held in both tiers, and the store side counts both copies, since both are stored.</para>
///
/// <para><b>The metadata side</b> streams <see cref="StoredBytesRepository.StreamRecordedBlobsAsync"/>,
/// normalises each row's key with <see cref="BlobKeys.StoreKey"/> (a <c>cache_artifact</c> row
/// stores <c>proxy/{sha}/{file}</c>; the object lives at <c>proxy/{sha}</c>) and deduplicates on
/// the normalised key, so coordinates that share bytes count once, as the store holds them once.
/// <c>oci_blobs</c> rows are per (digest, org) and their key is a function of the digest alone, so
/// this is deduplication by digest. When rows naming one key record different sizes the smallest
/// wins: a multi-file version's parent row names its first file's key with the sum of all its
/// files, while that file's own row records the file alone, and rows naming the same
/// content-addressed bytes otherwise agree.</para>
///
/// <para><b>Memory.</b> Deduplication needs the set of keys already seen. It holds an 8-byte hash
/// of each distinct store key (the first 8 bytes of its SHA-256) with its 8-byte size, about 30
/// bytes per distinct key with dictionary overhead: roughly 30 MB per million keys, released when
/// the pass ends. Two distinct keys colliding in 64 bits would count as one; across ten million
/// keys the chance is about three in a million.</para>
///
/// <para><b>Excluded from both sides</b>, by the same key test, so an exclusion cannot itself create
/// drift: <c>.snupkg</c> objects (<c>nuget_symbol_index</c> records no size);
/// <see cref="BlobKeys.OciStagingPrefix"/> (in-flight verify-then-commit objects no row names); and
/// the <see cref="BlobKeys.IsRecordless"/> families, which no metadata row records by design. Their
/// store-side bytes are reported beside the tallies. There is no grace window on either side: an
/// in-flight publish is noise well inside the tolerance, and excluding it on one side only would
/// create drift of its own.</para>
/// </summary>
public sealed class StoredByteReconciler
{
    // A key the metadata names but whose every row so far records a NULL size.
    private const long UnknownSize = -1;

    private readonly TieredBlobStorage _blobs;
    private readonly StoredBytesRepository _metadata;

    public StoredByteReconciler(TieredBlobStorage blobs, StoredBytesRepository metadata)
    {
        _blobs = blobs;
        _metadata = metadata;
    }

    /// <summary>Runs both sides and returns the per-plane tallies.</summary>
    public async Task<StoredByteReport> MeasureAsync(CancellationToken ct)
    {
        var store = await MeasureStoreAsync(ct);
        var metadata = await MeasureMetadataAsync(ct);

        var planes = BlobKeys.PlanePrefixes
            .Select(plane =>
            {
                var (bytes, objects) = store.PerPlane[plane];
                var sizes = metadata[plane];
                long metadataBytes = 0;
                long nullSizeKeys = 0;
                foreach (long size in sizes.Values)
                {
                    if (size == UnknownSize)
                    {
                        nullSizeKeys++;
                    }
                    else
                    {
                        metadataBytes += size;
                    }
                }

                return new PlaneByteTally(plane, bytes, objects, metadataBytes, sizes.Count, nullSizeKeys);
            })
            .ToList();

        return new StoredByteReport(
            planes, _blobs.IsSplit, store.SymbolBytes, store.StagingBytes, store.RecordlessBytes);
    }

    private enum KeyClass { Counted, Symbols, Staging, Recordless, OutsidePlanes }

    // The one exclusion test, applied to store keys on both sides.
    private static KeyClass Classify(string storeKey, out string? plane)
    {
        plane = BlobKeys.PlaneOf(storeKey);
        return plane is null ? KeyClass.OutsidePlanes
            : storeKey.StartsWith(BlobKeys.OciStagingPrefix, StringComparison.Ordinal) ? KeyClass.Staging
            : BlobKeys.IsNuGetSymbolPackage(storeKey) ? KeyClass.Symbols
            : BlobKeys.IsRecordless(storeKey) ? KeyClass.Recordless
            : KeyClass.Counted;
    }

    private sealed class StoreSums
    {
        public Dictionary<string, (long Bytes, long Objects)> PerPlane { get; } =
            BlobKeys.PlanePrefixes.ToDictionary(p => p, _ => (0L, 0L), StringComparer.Ordinal);

        public long SymbolBytes { get; private set; }
        public long StagingBytes { get; private set; }
        public long RecordlessBytes { get; private set; }

        /// <summary>Adds one listed object to the plane or exclusion bucket its key belongs to.</summary>
        public void Add(string storeKey, long sizeBytes)
        {
            switch (Classify(storeKey, out string? plane))
            {
                case KeyClass.Counted:
                    var (bytes, objects) = PerPlane[plane!];
                    PerPlane[plane!] = (bytes + sizeBytes, objects + 1);
                    break;
                case KeyClass.Symbols:
                    SymbolBytes += sizeBytes;
                    break;
                case KeyClass.Staging:
                    StagingBytes += sizeBytes;
                    break;
                case KeyClass.Recordless:
                    RecordlessBytes += sizeBytes;
                    break;
                case KeyClass.OutsidePlanes:
                    // A listing under a plane prefix only yields keys in that plane.
                    break;
            }
        }
    }

    private async Task<StoreSums> MeasureStoreAsync(CancellationToken ct)
    {
        var sums = new StoreSums();
        IBlobStore[] tiers = _blobs.IsSplit ? [_blobs.Registry, _blobs.Cache] : [_blobs.Registry];

        foreach (string prefix in BlobKeys.PlanePrefixes)
        {
            foreach (var tier in tiers)
            {
                await foreach (var blob in tier.ListAsync(prefix, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    sums.Add(blob.Key, blob.SizeBytes);
                }
            }
        }

        return sums;
    }

    private async Task<Dictionary<string, Dictionary<ulong, long>>> MeasureMetadataAsync(CancellationToken ct)
    {
        var perPlane = BlobKeys.PlanePrefixes.ToDictionary(
            p => p, _ => new Dictionary<ulong, long>(), StringComparer.Ordinal);

        await foreach (var row in _metadata.StreamRecordedBlobsAsync(ct))
        {
            string storeKey = BlobKeys.StoreKey(row.BlobKey);
            if (Classify(storeKey, out string? plane) != KeyClass.Counted)
            {
                continue;
            }

            Record(perPlane[plane!], KeyHash(storeKey), row.SizeBytes is { } s ? Math.Max(0, s) : UnknownSize);
        }

        return perPlane;
    }

    // Keeps the smallest recorded size per key; a recorded size always replaces an unknown one.
    private static void Record(Dictionary<ulong, long> sizes, ulong key, long size)
    {
        if (!sizes.TryGetValue(key, out long existing))
        {
            sizes[key] = size;
        }
        else if (size != UnknownSize && (existing == UnknownSize || size < existing))
        {
            sizes[key] = size;
        }
    }

    private static ulong KeyHash(string storeKey)
    {
        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(Encoding.UTF8.GetBytes(storeKey), digest);
        return BinaryPrimitives.ReadUInt64LittleEndian(digest);
    }
}
