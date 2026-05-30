using System.Runtime.CompilerServices;

namespace Dependably.Storage;

public sealed class LocalBlobStore : IBlobStore
{
    private readonly string _root;
    private readonly LocalBlobStoreSizeCounter _sizeCounter;

    public LocalBlobStore(string root)
    {
        _root = root;
        // deepcode ignore PT: `root` is built from LOCAL_STORAGE_PATH (operator-set env var) by
        // BlobStoreFactory. No tenant input reaches this constructor.
        Directory.CreateDirectory(root);
        _sizeCounter = new LocalBlobStoreSizeCounter(root);
    }

    // Test seam — lets the harness inject a counter and assert on increment/decrement.
    internal LocalBlobStore(string root, LocalBlobStoreSizeCounter counter)
    {
        _root = root;
        // deepcode ignore PT: see public constructor.
        Directory.CreateDirectory(root);
        _sizeCounter = counter;
    }

    /// <summary>
    /// Forces a fresh full-directory walk and resets the running counter. Backs the
    /// <c>/api/v1/system/blob-store/recompute</c> admin trigger from #92 so operators can
    /// recover after out-of-band writes to the blob root.
    /// </summary>
    public void RecomputeSize() => _sizeCounter.Recompute();

    private string FullPath(string key) => Path.Combine(_root, key.Replace('/', Path.DirectorySeparatorChar));

    public async Task PutAsync(string key, Stream data, CancellationToken ct = default)
    {
        var path = FullPath(key);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        // Overwrites are a real case (allow_version_overwrite flow). Subtract the prior
        // size before replacing the file so the counter doesn't double-count an overwrite.
        long previousSize = 0;
        if (File.Exists(path))
        {
            try { previousSize = new FileInfo(path).Length; } catch { /* ignore */ }
        }

        await using (var file = File.Create(path))
        {
            await data.CopyToAsync(file, ct);
        }

        long newSize;
        try { newSize = new FileInfo(path).Length; }
        catch { newSize = 0; } // race: file gone between write and stat

        if (previousSize > 0) _sizeCounter.Subtract(previousSize);
        if (newSize > 0) _sizeCounter.Add(newSize);
    }

    public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
    {
        var path = FullPath(key);
        if (!File.Exists(path))
            return Task.FromResult<Stream?>(null);
        return Task.FromResult<Stream?>(File.OpenRead(path));
    }

    public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        => Task.FromResult(File.Exists(FullPath(key)));

    public Task DeleteAsync(string key, CancellationToken ct = default)
    {
        var path = FullPath(key);
        if (File.Exists(path))
        {
            long removedBytes = 0;
            try { removedBytes = new FileInfo(path).Length; } catch { /* ignore */ }
            File.Delete(path);
            if (removedBytes > 0) _sizeCounter.Subtract(removedBytes);
        }
        return Task.CompletedTask;
    }

    public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
    {
        // #92: O(1) read of the running counter (first call lazily walks the tree once).
        // The pre-#92 path re-enumerated every file on every call which blocked a thread-
        // pool thread for seconds on caches with millions of blobs.
        return Task.FromResult(_sizeCounter.GetTotal());
    }

    public async IAsyncEnumerable<BlobInfo> ListAsync(
        string prefix, [EnumeratorCancellation] CancellationToken ct = default)
    {
        // Resolve the prefix to its on-disk equivalent so a `hosted/` prefix scans only
        // the hosted subtree rather than walking the whole root and filtering after.
        var prefixPath = Path.Combine(_root, prefix.Replace('/', Path.DirectorySeparatorChar));
        if (!Directory.Exists(prefixPath))
            yield break;

        // Use enumerate-options to avoid materializing the full list before the first yield —
        // a hosted tier with millions of files would otherwise hold the whole listing in RAM.
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
        };
        foreach (var path in Directory.EnumerateFiles(prefixPath, "*", options))
        {
            if (ct.IsCancellationRequested) yield break;
            FileInfo info;
            try { info = new FileInfo(path); }
            catch { continue; }  // race: file deleted between enumerate and stat
            if (!info.Exists) continue;

            // Reconstruct the logical key (forward slashes, relative to root).
            var rel = Path.GetRelativePath(_root, path)
                .Replace(Path.DirectorySeparatorChar, '/');
            yield return new BlobInfo(rel, info.Length, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero));
            await Task.Yield();
        }
    }
}
