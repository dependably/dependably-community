namespace Dependably.Storage;

/// <summary>
/// Two-tier storage handle. Code that touches the proxy cache uses
/// <see cref="Cache"/>; code that touches the per-tenant registry uses <see cref="Registry"/>.
/// In default deployments both fields point to the same backing <see cref="IBlobStore"/>
/// instance, so the migration path from single-tier to split-tier is a config change
/// (<c>STORAGE_BACKEND_CACHE</c> / <c>STORAGE_BACKEND_REGISTRY</c> overrides) rather than a
/// code change.
///
/// Tier-aware code (<c>UpstreamClient</c>, <c>CacheEvictionService</c>,
/// <c>PackagePublishService</c>) consumes this type. Tier-agnostic code (anywhere else
/// that just needs blob R/W) keeps consuming <see cref="IBlobStore"/> directly — that
/// registration resolves to the registry tier so legacy callers default to the durable
/// store, not the cache.
/// </summary>
public sealed class TieredBlobStorage
{
    public IBlobStore Cache { get; }
    public IBlobStore Registry { get; }

    /// <summary>
    /// True when both fields point to the same backing instance. Exposed so health checks
    /// and the admin UI can show "split storage" badges only when it's actually split.
    /// </summary>
    public bool IsSplit => !ReferenceEquals(Cache, Registry);

    public TieredBlobStorage(IBlobStore cache, IBlobStore registry)
    {
        Cache = cache;
        Registry = registry;
    }
}
