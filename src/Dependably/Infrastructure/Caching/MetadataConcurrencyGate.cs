namespace Dependably.Infrastructure.Caching;

/// <summary>
/// Process-wide concurrency gate for metadata cache-MISS rebuilds (npm packument, PyPI simple
/// index, NuGet registration). Wraps a <see cref="SemaphoreSlim"/> that caps the number of
/// rebuild lambdas executing simultaneously, bounding peak in-flight buffer allocation.
///
/// Registered as a DI singleton so the same semaphore is shared across all three typed
/// <see cref="RenderedResponseCache{TKey}"/> instances. Cache-HIT requests never acquire a
/// slot — only the MISS rebuild path does, via
/// <see cref="RenderedResponseCache{TKey}.GetOrRebuildAsync"/>.
/// </summary>
public sealed class MetadataConcurrencyGate : IDisposable
{
    /// <summary>The underlying semaphore shared across all gated cache instances.</summary>
    public SemaphoreSlim Semaphore { get; }

    /// <param name="maxConcurrency">
    /// Maximum number of simultaneous cache-MISS rebuilds. Configurable via
    /// <c>METADATA_REBUILD_CONCURRENCY</c>; defaults to 8.
    /// </param>
    public MetadataConcurrencyGate(int maxConcurrency)
    {
        Semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
    }

    public void Dispose() => Semaphore.Dispose();
}
