using System.Collections.Concurrent;

namespace Dependably.Storage;

/// <summary>Thread-safe in-memory blob store for testing.</summary>
public sealed class InMemoryBlobStore : IBlobStore
{
    private readonly ConcurrentDictionary<string, Entry> _blobs = new();

    /// <summary>
    /// Test seam: callers (notably the orphan-reconciler tests) need to plant a blob with
    /// a backdated <c>LastModified</c> so the grace-window gate evaluates the way the test
    /// intends. Production code always goes through <see cref="PutAsync"/>, which stamps
    /// <c>DateTimeOffset.UtcNow</c>.
    /// </summary>
    public void SeedWithLastModified(string key, byte[] bytes, DateTimeOffset lastModified)
        => _blobs[key] = new Entry(bytes, lastModified);

    public Task PutAsync(string key, Stream data, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        data.CopyTo(ms);
        _blobs[key] = new Entry(ms.ToArray(), DateTimeOffset.UtcNow);
        return Task.CompletedTask;
    }

    public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
    {
        return !_blobs.TryGetValue(key, out var entry)
            ? Task.FromResult<Stream?>(null)
            : Task.FromResult<Stream?>(new MemoryStream(entry.Bytes));
    }

    public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
    {
        if (!_blobs.TryGetValue(key, out var entry))
        {
            return Task.FromResult<RangedStream?>(null);
        }

        long totalLength = entry.Bytes.Length;
        long effectiveTo = Math.Min(to, totalLength - 1);

        if (from > effectiveTo || totalLength == 0)
        {
            // Range starts past the end — return sentinel with empty range.
            return Task.FromResult<RangedStream?>(new RangedStream(Stream.Null, from, from - 1, totalLength));
        }

        int sliceLength = (int)(effectiveTo - from + 1);
        var slice = new MemoryStream(entry.Bytes, (int)from, sliceLength, writable: false);
        return Task.FromResult<RangedStream?>(new RangedStream(slice, from, effectiveTo, totalLength));
    }

    public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        => Task.FromResult(_blobs.ContainsKey(key));

    public Task DeleteAsync(string key, CancellationToken ct = default)
    {
        _blobs.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
        => Task.FromResult(_blobs.Values.Sum(e => (long)e.Bytes.Length));

    public async IAsyncEnumerable<BlobInfo> ListAsync(
        string prefix, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        // Snapshot the keys up front so an enumerator interleaved with a concurrent Put/Delete
        // doesn't throw. Test scope only — production stores stream from the backend.
        foreach (var kvp in _blobs.ToArray())
        {
            if (ct.IsCancellationRequested)
            {
                yield break;
            }

            if (!kvp.Key.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }

            yield return new BlobInfo(kvp.Key, kvp.Value.Bytes.Length, kvp.Value.LastModified);
            await Task.Yield();
        }
    }

    private readonly record struct Entry(byte[] Bytes, DateTimeOffset LastModified);
}
