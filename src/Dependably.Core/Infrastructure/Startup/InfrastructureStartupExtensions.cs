using Dependably.Api;
using Dependably.Api.NpmProtocol;
using Dependably.Api.NuGetProtocol;
using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Observability;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers infrastructure services: in-process metadata caches, background services,
/// staging disk monitoring, claim gate, publish pipeline, controller service aggregates,
/// localization, and the CORS policy.
/// </summary>
internal static partial class InfrastructureStartupExtensions
{
    // Default fallback for BASE_URL; only used when running locally without configuration.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default value for BASE_URL env-var; only used locally. Override in production via BASE_URL.")]
    private const string DefaultBaseUrl = "http://localhost:8080";

    // In-process metadata response cache: 50 MB total across all ecosystems.
    private const long MetadataCacheSizeLimitBytes = 50 * 1024 * 1024;

    internal static void AddDependablyCaching(this WebApplicationBuilder builder)
    {
        // SizeLimit bounds total in-process metadata response bytes (npm packuments, PyPI
        // simple indices, NuGet registration pages). Each entry sets Size = bytes.Length.
        // 50 MB covers hundreds of typical packuments/indices with headroom for large ones.
        builder.Services.AddMemoryCache(o => o.SizeLimit = MetadataCacheSizeLimitBytes);

        // Configurable TTLs for the rendered-metadata caches (npm packument, NuGet registration,
        // PyPI simple index, Maven metadata). Resolved once from METADATA_LOCAL_CACHE_TTL_SECONDS /
        // METADATA_PROXY_CACHE_TTL_SECONDS so operators can shorten the post-publish staleness
        // window on non-publishing replicas in HA deployments.
        builder.Services.AddSingleton(RenderedMetadataCacheOptions.Resolve(builder.Configuration));

        // Per-ecosystem typed metadata caches over the one shared IMemoryCache. Registered as
        // singletons so each helper's single-flight in-flight map persists across the transient
        // controller instances that resolve it, and so every get/set/evict for a logical entry
        // routes through one key formatter (kills the cache-key-divergence class of bug).
        //
        // The metadata concurrency gate (MetadataConcurrencyGate) is a named wrapper around a
        // SemaphoreSlim that caps the number of simultaneous cache-MISS rebuilds across the hot
        // metadata GETs (npm packument, PyPI simple index, NuGet registration). Without it, a
        // burst of 200 concurrent cold-start requests can each allocate up to a 32 MB buffer —
        // ~6.4 GB total. The gate bounds peak in-flight buffer allocation regardless of request
        // rate; the rate limiter above sheds excess requests before they reach the rebuild.
        // Cache HITs bypass the gate and are served from already-allocated in-process memory.
        builder.Services.AddSingleton<MetadataConcurrencyGate>(sp =>
        {
            int slots = sp.GetRequiredService<IConfiguration>()
                .GetValue("METADATA_REBUILD_CONCURRENCY", defaultValue: 8);
            return new MetadataConcurrencyGate(slots);
        });

        // Org-level policy-invalidation epoch (see OrgCacheEpochStore) — shared across the four
        // ecosystem caches whose rendered bytes reflect the org's proxy-settings gate, so a policy
        // PUT can invalidate every cached document for that org in one call.
        builder.Services.AddSingleton<OrgCacheEpochStore>();

        builder.Services.AddSingleton(sp =>
            new RenderedResponseCache<PyPiSimpleIndexKey>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.PyPiSimpleIndex,
                sp.GetRequiredService<MetadataConcurrencyGate>().Semaphore,
                sp.GetRequiredService<OrgCacheEpochStore>()));
        builder.Services.AddSingleton(sp =>
            new RenderedResponseCache<NpmPackumentKey>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.NpmPackument,
                sp.GetRequiredService<MetadataConcurrencyGate>().Semaphore,
                sp.GetRequiredService<OrgCacheEpochStore>()));
        builder.Services.AddSingleton(sp =>
            new RenderedResponseCache<NuGetRegistrationKey>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.NuGetRegistration,
                sp.GetRequiredService<MetadataConcurrencyGate>().Semaphore,
                sp.GetRequiredService<OrgCacheEpochStore>()));
        builder.Services.AddSingleton(sp =>
            new MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.RpmMergedRepodata));
        builder.Services.AddSingleton(sp =>
            new RenderedResponseCache<RpmLocalRepodataKey>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.RpmLocalRepodata));
        builder.Services.AddSingleton(sp =>
            new RenderedResponseCache<MavenMetadataKey>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.MavenMetadata,
                sp.GetRequiredService<OrgCacheEpochStore>()));

        // Cross-replica invalidation. The coordinator owns the one expansion from package
        // coordinates to an ecosystem's full cache-key variant matrix, shared by the local
        // mutation path and the peer-message path so the two can never disagree.
        //
        // TryAddSingleton for the bus: standalone deployments keep the in-process path and take
        // on no broker dependency, while a composition root that configures a fan-out transport
        // (the management wiring registers the Redis one when REDIS_CONNECTION_STRING is set)
        // registers first and wins. The edge composition root never reaches that wiring, so it
        // binds the no-op here.
        builder.Services.TryAddSingleton<IMetadataInvalidationBus, NullMetadataInvalidationBus>();
        builder.Services.AddSingleton<MetadataInvalidationCoordinator>();
        builder.Services.AddSingleton<MetadataInvalidationReceiver>();
    }

    internal static void AddDependablyMetrics(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<MetricsAccessConfig>(sp =>
        {
            var orgs = sp.GetRequiredService<OrgRepository>();
            var configuration = sp.GetRequiredService<IConfiguration>();
            return new MetricsAccessConfig(
                orgs.GetInstanceSettingAsync, configuration,
                sp.GetRequiredService<TimeProvider>());
        });
        builder.Services.AddSingleton<ScrapeDiagnostics>();
        builder.Services.AddSingleton<Dependably.Security.AuthDenialAuditCoalescer>();
        builder.Services.AddSingleton<MetricsSnapshotProvider>();
    }
}
