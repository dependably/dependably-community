namespace Dependably.Storage;

/// <summary>
/// Per-instance running byte counter for <see cref="LocalBlobStore"/>.
///
/// The previous implementation recomputed total size on every <see cref="LocalBlobStore.GetTotalSizeAsync"/>
/// call by enumerating the entire blob tree. <see cref="BlobStoreSizePoller"/> hit that path
/// every 5 minutes — twice when cache and registry tiers point at different paths — and a
/// cache holding millions of blobs would block a thread-pool thread for seconds, contend on
/// the same disk that's serving downloads, and inflate p99 latency.
///
/// This counter takes the running total once on first access (the only walk that ever
/// runs), then accepts atomic increments/decrements from <see cref="LocalBlobStore.PutAsync"/>
/// and <see cref="LocalBlobStore.DeleteAsync"/>. A subsequent <c>GetTotalSizeAsync</c>
/// returns the counter in O(1) time. Drift across a process lifetime is bounded only by
/// the increments we observe — Put/Delete that goes through other paths is invisible — but
/// every write call site in the codebase routes through <see cref="LocalBlobStore"/>, so
/// in practice the counter stays exact within a single process.
///
/// On restart we walk again. The issue accepts &lt; 0.1% drift after restart; a full walk
/// gives 0%.
/// </summary>
public sealed class LocalBlobStoreSizeCounter
{
    private readonly string _root;
    private long _bytes;

    public LocalBlobStoreSizeCounter(string root)
    {
        _root = root;
        // Eager startup walk. The design contract is "one walk on process boot, then
        // O(1) reads thereafter." Doing the walk lazily on first read created a race with
        // Put/Delete writers — they'd add their delta first, then trigger the walk which
        // saw the just-written file and counted it again, double-billing the same byte.
        _bytes = WalkRoot();
    }

    /// <summary>Total bytes tracked by this counter — O(1) after construction.</summary>
    public long GetTotal() => Interlocked.Read(ref _bytes);

    /// <summary>Records that <paramref name="bytes"/> were just written. Overwrites are the
    /// caller's concern — <see cref="LocalBlobStore.PutAsync"/> subtracts the prior size
    /// first when replacing an existing file.</summary>
    public void Add(long bytes)
    {
        if (bytes != 0)
        {
            Interlocked.Add(ref _bytes, bytes);
        }
    }

    /// <summary>Records a deletion. Pass the positive byte count that was removed.</summary>
    public void Subtract(long bytes)
    {
        if (bytes > 0)
        {
            Interlocked.Add(ref _bytes, -bytes);
        }
    }

    /// <summary>Forces a fresh recompute via full directory walk. Backs the
    /// <c>/api/v1/system/blob-store/recompute</c> admin trigger.</summary>
    public void Recompute() => Interlocked.Exchange(ref _bytes, WalkRoot());

    private long WalkRoot()
    {
        if (!Directory.Exists(_root))
        {
            return 0L;
        }

        long total = 0;
        // EnumerateFiles streams, so even a million-file tree never materializes the full
        // list in memory.
        foreach (string path in Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories))
        {
            try { total += new FileInfo(path).Length; }
            catch { /* race: file removed mid-walk — skip */ }
        }
        return total;
    }
}
