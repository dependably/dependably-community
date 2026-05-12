using System.Collections.Concurrent;

namespace Dependably.Storage;

/// <summary>Thread-safe in-memory blob store for testing.</summary>
public sealed class InMemoryBlobStore : IBlobStore
{
    private readonly ConcurrentDictionary<string, byte[]> _blobs = new();

    public Task PutAsync(string key, Stream data, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        data.CopyTo(ms);
        _blobs[key] = ms.ToArray();
        return Task.CompletedTask;
    }

    public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
    {
        if (!_blobs.TryGetValue(key, out var bytes))
            return Task.FromResult<Stream?>(null);
        return Task.FromResult<Stream?>(new MemoryStream(bytes));
    }

    public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        => Task.FromResult(_blobs.ContainsKey(key));

    public Task DeleteAsync(string key, CancellationToken ct = default)
    {
        _blobs.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
        => Task.FromResult(_blobs.Values.Sum(b => (long)b.Length));
}
