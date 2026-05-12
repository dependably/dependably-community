using System.Collections.Concurrent;

namespace Dependably.Storage;

/// <summary>
/// Single-flight coordinator for upstream proxy fetches (#48). When multiple tenants request
/// the same uncached coordinate simultaneously, exactly one outbound fetch happens and the
/// others wait on the same task. Scoped to a single process — that's acceptable per #48,
/// because the de-duplication is a hot-path optimisation, not a correctness invariant
/// (cross-replica races resolve through the unique constraint on <c>cache_artifact</c>).
///
/// Keys are the cache coordinate (<c>{ecosystem}/{name}/{version}/{filename}</c>). Entries
/// are removed from the dictionary once their task completes, so the memory footprint stays
/// bounded by current in-flight fetches, not total cache size.
/// </summary>
public sealed class UpstreamFetchCoordinator
{
    private readonly ConcurrentDictionary<string, Lazy<Task<byte[]>>> _inflight = new();

    /// <summary>
    /// Runs <paramref name="fetch"/> exactly once across concurrent callers with the same
    /// key. Subsequent callers within the fetch's lifetime get the same task. Once the task
    /// completes (success or failure), the entry is removed; a fresh fetch may run for the
    /// next request.
    /// </summary>
    public async Task<byte[]> FetchAsync(string key, Func<Task<byte[]>> fetch)
    {
        // Lazy<T> ensures the factory runs once per added key even under concurrent
        // GetOrAdd calls. The factory wraps the fetch in a Task so all waiters await
        // the same instance.
        var lazy = _inflight.GetOrAdd(key, _ =>
            new Lazy<Task<byte[]>>(fetch, LazyThreadSafetyMode.ExecutionAndPublication));

        try
        {
            return await lazy.Value;
        }
        finally
        {
            // Best-effort cleanup; the next caller will start a fresh fetch.
            _inflight.TryRemove(key, out _);
        }
    }

    /// <summary>Number of fetches currently in flight. Diagnostic / metric only.</summary>
    public int InFlightCount => _inflight.Count;
}
