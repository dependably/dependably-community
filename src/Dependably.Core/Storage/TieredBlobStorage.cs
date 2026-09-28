namespace Dependably.Storage;

/// <summary>
/// Two-tier storage handle. Code that touches the proxy cache uses
/// <see cref="Cache"/>; code that touches the per-tenant registry uses <see cref="Registry"/>.
/// In default deployments both fields point to the same backing <see cref="IBlobStore"/>
/// instance, so the migration path from single-tier to split-tier is a config change
/// (<c>STORAGE_BACKEND_CACHE</c> / <c>STORAGE_BACKEND_REGISTRY</c> overrides) rather than a
/// code change.
///
/// There is no tier-agnostic consumer: no <see cref="IBlobStore"/> is registered on its own,
/// so every service takes this type and each code path names the tier its bytes live in.
/// Tier is a physical-placement fact chosen per code path, not derived from the key or the
/// origin column: <c>oci/</c> keys live in both tiers (push vs pull), and Hex docs live in
/// the registry when published and in the cache when proxied. A method that takes an
/// <see cref="IBlobStore"/> parameter leaves that choice to its caller.
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

    // blobtier-ok: this is the tier pair itself; each store is bound to its named tier here.
    public TieredBlobStorage(IBlobStore cache, IBlobStore registry)
    {
        Cache = cache;
        Registry = registry;
    }
}
