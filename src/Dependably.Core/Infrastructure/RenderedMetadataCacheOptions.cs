namespace Dependably.Infrastructure;

/// <summary>
/// Resolved TTLs for the rendered-metadata response caches shared by the npm packument, NuGet
/// registration, PyPI simple-index, and Maven metadata handlers. Those caches are process-local
/// (<see cref="Caching.RenderedResponseCache{TKey}"/> over IMemoryCache) and, for hosted
/// packages, are invalidated on publish/unpublish only on the node that served the mutation.
///
/// In a multi-replica (HA) deployment the other replicas keep serving pre-mutation metadata until
/// their copy expires, so operators need a knob to shorten the window (the documented mitigation:
/// "keep metadata TTLs short in multi-instance deployments where post-push staleness matters").
/// <see cref="LocalTtl"/> is that knob for locally-owned metadata; <see cref="ProxyTtl"/> bounds
/// proxy-merged metadata whose upstream can change out from under the cache.
///
/// Distinct from <see cref="Protocol.MetadataCacheOptions"/>, which configures the upstream
/// metadata fetch cache inside UpstreamClient; this record configures the rendered-body response
/// caches that front the protocol GET handlers.
/// </summary>
public sealed record RenderedMetadataCacheOptions(TimeSpan LocalTtl, TimeSpan ProxyTtl)
{
    /// <summary>Default TTL for locally-owned metadata (invalidation on mutation is primary).</summary>
    public const int DefaultLocalTtlSeconds = 600;

    /// <summary>Default TTL for proxy-merged metadata (upstream can change).</summary>
    public const int DefaultProxyTtlSeconds = 300;

    /// <summary>
    /// Resolves the cache TTLs from configuration:
    ///   - <c>METADATA_LOCAL_CACHE_TTL_SECONDS</c> for locally-owned metadata (default 600).
    ///   - <c>METADATA_PROXY_CACHE_TTL_SECONDS</c> for proxy-merged metadata (default 300).
    /// A non-positive or unparseable value falls back to the default rather than disabling the
    /// cache. Set the local TTL low (e.g. 30) in HA deployments where post-push staleness matters.
    /// </summary>
    public static RenderedMetadataCacheOptions Resolve(IConfiguration configuration)
    {
        int localSeconds = ParsePositiveOrDefault(
            configuration["METADATA_LOCAL_CACHE_TTL_SECONDS"], DefaultLocalTtlSeconds);
        int proxySeconds = ParsePositiveOrDefault(
            configuration["METADATA_PROXY_CACHE_TTL_SECONDS"], DefaultProxyTtlSeconds);

        return new RenderedMetadataCacheOptions(
            TimeSpan.FromSeconds(localSeconds),
            TimeSpan.FromSeconds(proxySeconds));
    }

    private static int ParsePositiveOrDefault(string? raw, int fallback) =>
        int.TryParse(raw, out int value) && value > 0 ? value : fallback;
}
