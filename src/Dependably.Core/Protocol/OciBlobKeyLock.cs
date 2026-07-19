namespace Dependably.Protocol;

/// <summary>
/// Per-key async mutex that serialises finalize and delete of a single content-addressed OCI
/// blob key within one server node. OCI blob keys (<see cref="Storage.BlobKeys.OciBlob"/>) carry
/// no org segment, so two tenants pushing the same layer — or a push racing a refcount-guarded
/// delete — target one physical blob. Holding this lock across the exists-check + quota reserve +
/// blob put (and, on the delete side, the reference count + physical delete) makes those
/// otherwise-interleavable blob-store and DB operations atomic for a given key, closing two races:
///   1. Two concurrent finalizes of the same new blob both observing "does not exist" and each
///      reserving the tenant's storage quota, double-charging one physically-stored blob.
///   2. A skip-the-write dedup finalize racing a refcount-guarded physical delete of the same
///      key, which can leave a metadata row pointing at a blob that was just deleted.
///
/// Scope is a single process, which matches the OCI upload path: staging is local and that path
/// already assumes one serving node. Both races above are therefore closed for a single-node
/// deployment only — running two nodes against one shared blob store reopens them, because a
/// finalize on one node takes no lock a delete on the other can observe. Serving OCI from more
/// than one node requires replacing this with a lock the nodes share (a DB advisory lock or a
/// distributed lease) rather than adding one alongside it.
///
/// Locks are striped over a fixed table so the map never grows with the number of distinct blob
/// keys; distinct keys may share a stripe (harmless extra serialisation), while the same key
/// always maps to one stripe.
/// </summary>
public sealed class OciBlobKeyLock
{
    private const int DefaultStripeCount = 64;

    private readonly SemaphoreSlim[] _stripes;

    public OciBlobKeyLock() : this(DefaultStripeCount)
    {
    }

    public OciBlobKeyLock(int stripeCount)
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
