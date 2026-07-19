namespace Dependably.Infrastructure;

/// <summary>
/// Per-key async mutex that serialises the shared-key refcount check and physical delete of a
/// single content-addressed proxy-cache blob key (<see cref="Storage.BlobKeys.Proxy"/>) within one
/// server node. Proxy blob keys carry no tenant or coordinate segment, so any <c>cache_artifact</c>
/// row with byte-identical upstream bytes under a distinct ecosystem/name/version/filename
/// coordinate shares one physical blob. Holding this lock across
/// <see cref="CacheOrphanBlobDeleter.DeleteIfUnreferencedAsync"/>'s count-then-delete keeps two
/// evictions of sibling rows — the LRU pass and the <c>local_only</c> claim purge, or two
/// concurrent runs of either — from both observing the other row as the last reference and
/// skipping the physical delete forever (an unreclaimed blob), or interleaving so a delete lands
/// while the sibling eviction's own bookkeeping has not yet committed.
///
/// Mirrors <see cref="Protocol.OciBlobKeyLock"/>'s shape for the structurally identical race on
/// the OCI blob tier, kept as a separate type so the cache tier's lock and the OCI tier's lock
/// stripe independently and neither's documentation has to speak to the other tier's callers.
///
/// Scope is a single process — the same limitation <see cref="Protocol.OciBlobKeyLock"/> documents
/// for its tier. A concurrent proxy first-fetch that hashes to this exact content under a new
/// coordinate (checks blob existence, skips the write when present, then inserts its own
/// <c>cache_artifact</c> row) does not take this lock, so that narrower fill-side window is not
/// closed by this guard — only the evict-vs-evict races above are.
///
/// Locks are striped over a fixed table so the map never grows with the number of distinct blob
/// keys; distinct keys may share a stripe (harmless extra serialisation), while the same key
/// always maps to one stripe.
/// </summary>
public sealed class CacheBlobKeyLock
{
    private const int DefaultStripeCount = 64;

    private readonly SemaphoreSlim[] _stripes;

    public CacheBlobKeyLock() : this(DefaultStripeCount)
    {
    }

    public CacheBlobKeyLock(int stripeCount)
    {
        if (stripeCount < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(stripeCount), stripeCount, "Stripe count must be positive.");
        }

        _stripes = new SemaphoreSlim[stripeCount];
        for (int i = 0; i < stripeCount; i++)
        {
            _stripes[i] = new SemaphoreSlim(1, 1);
        }
    }

    /// <summary>
    /// Acquires the lock for <paramref name="blobKey"/>. Await the returned handle's disposal (or
    /// wrap the call in <c>await using</c>) to release. Blocks while another holder of the same
    /// key's stripe owns the lock.
    /// </summary>
    public async Task<IAsyncDisposable> AcquireAsync(string blobKey, CancellationToken ct)
    {
        var stripe = StripeFor(blobKey);
        await stripe.WaitAsync(ct);
        return new Handle(stripe);
    }

    private SemaphoreSlim StripeFor(string blobKey)
    {
        // FNV-1a over the key. Deterministic within the process and independent of the randomised
        // string-hash seed, so the same key always lands on the same stripe.
        uint hash = 2166136261u;
        foreach (char c in blobKey)
        {
            hash = (hash ^ c) * 16777619u;
        }
        return _stripes[hash % (uint)_stripes.Length];
    }

    private sealed class Handle : IAsyncDisposable
    {
        private SemaphoreSlim? _stripe;

        public Handle(SemaphoreSlim stripe) => _stripe = stripe;

        public ValueTask DisposeAsync()
        {
            _stripe?.Release();
            _stripe = null;
            return ValueTask.CompletedTask;
        }
    }
}
