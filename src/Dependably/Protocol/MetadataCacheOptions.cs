using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Resolved TTL-cache configuration for the upstream metadata fetch path
/// (<see cref="UpstreamClient.GetOrFetchMetadataAsync(string, string, System.Threading.CancellationToken)"/>).
/// A single resolve point keeps the four knobs — positive TTL, serve-stale window, negative
/// TTL, and the total memory bound — from drifting, and folds in the edge-mode defaults.
///
/// The cache is disabled by default on a standard (non-edge) instance so its behaviour is
/// byte-for-byte the previous single-flight-only path: every metadata request forwards
/// upstream. It defaults on in edge mode (<see cref="IEdgeMode.IsEdge"/>), where the whole
/// point of a headless pull-through node is to absorb metadata load and survive a flaky link
/// to the master. Explicit configuration always overrides the mode-derived default.
/// </summary>
public sealed record MetadataCacheOptions(
    TimeSpan PositiveTtl,
    TimeSpan MaxStale,
    TimeSpan NegativeTtl,
    long MaxBytes)
{
    /// <summary>Positive TTL applied in edge mode when <c>Proxy:MetadataCacheTtlSeconds</c> is unset.</summary>
    public const int EdgeDefaultTtlSeconds = 120;

    /// <summary>Serve-stale window default (24h) — how long an expired entry may still be served on a transient upstream failure.</summary>
    public const int DefaultMaxStaleSeconds = 86_400;

    /// <summary>Negative-TTL default (60s) applied whenever the cache is enabled.</summary>
    public const int DefaultNegativeTtlSeconds = 60;

    /// <summary>Total memory bound for cached metadata bodies (128 MB).</summary>
    public const long DefaultMaxBytes = 128L * 1024 * 1024;

    /// <summary>True when a positive TTL is configured — the cache does any work at all only when this holds.</summary>
    public bool Enabled => PositiveTtl > TimeSpan.Zero;

    /// <summary>True when 404s are cached (only meaningful when the cache is <see cref="Enabled"/>).</summary>
    public bool NegativeCachingEnabled => Enabled && NegativeTtl > TimeSpan.Zero;

    /// <summary>
    /// Resolves the cache knobs from configuration, layering the edge-mode default for the
    /// positive TTL over the disabled-by-default baseline. Explicit config wins in every case:
    ///   - <c>Proxy:MetadataCacheTtlSeconds</c>: positive TTL. Unset ⇒ 0 (disabled) on a
    ///     standard instance, <see cref="EdgeDefaultTtlSeconds"/> in edge mode. An explicit 0
    ///     disables the cache even in edge mode.
    ///   - <c>Proxy:MetadataCacheMaxStaleSeconds</c>: serve-stale window (default 24h).
    ///   - <c>Proxy:MetadataCacheNegativeTtlSeconds</c>: negative TTL (default 60s; 0 disables
    ///     negative caching).
    ///   - <c>Proxy:MetadataCacheMaxBytes</c>: total memory bound (default 128 MB).
    /// </summary>
    public static MetadataCacheOptions Resolve(IConfiguration configuration, IEdgeMode edge)
    {
        int defaultTtl = edge.IsEdge ? EdgeDefaultTtlSeconds : 0;
        int ttl = ReadInt(configuration, "Proxy:MetadataCacheTtlSeconds", defaultTtl);
        int maxStale = ReadInt(configuration, "Proxy:MetadataCacheMaxStaleSeconds", DefaultMaxStaleSeconds);
        int negativeTtl = ReadInt(configuration, "Proxy:MetadataCacheNegativeTtlSeconds", DefaultNegativeTtlSeconds);
        long maxBytes = ReadLong(configuration, "Proxy:MetadataCacheMaxBytes", DefaultMaxBytes);

        return new MetadataCacheOptions(
            PositiveTtl: TimeSpan.FromSeconds(Math.Max(0, ttl)),
            MaxStale: TimeSpan.FromSeconds(Math.Max(0, maxStale)),
            NegativeTtl: TimeSpan.FromSeconds(Math.Max(0, negativeTtl)),
            MaxBytes: maxBytes > 0 ? maxBytes : DefaultMaxBytes);
    }

    private static int ReadInt(IConfiguration configuration, string key, int fallback)
        => int.TryParse(configuration[key], out int v) ? v : fallback;

    private static long ReadLong(IConfiguration configuration, string key, long fallback)
        => long.TryParse(configuration[key], out long v) ? v : fallback;
}
