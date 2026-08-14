using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Observability;
using Dependably.Security;

namespace Dependably.Infrastructure.Startup;

// Background hosted services (core startup, instance lock, health, cache eviction, orphan
// reconciliation), staging disk monitoring, and the publish pipeline. Split out of
// InfrastructureStartupExtensions.cs (partial class) to keep the class's dependency coupling
// spread across files below the S1200 threshold; see that file for caching/metrics registration.
internal static partial class InfrastructureStartupExtensions
{
    internal static void AddDependablyBackgroundServices(this WebApplicationBuilder builder)
    {
        // Core startup: schema migration + first-boot + instance-lock + edge reseed (must complete
        // before other services). The JWT signing-key load is a separate management hosted service
        // registered after this one so it runs once first-boot has written jwt_secret.
        builder.Services.AddHostedService<CoreStartupService>();

        // Shared-SQLite single-writer guard. CoreStartupService claims the lock before the server
        // accepts traffic (fail-fast on a live peer); this hosted service keeps the heartbeat alive
        // and releases the row on graceful shutdown. Self-skips for Postgres and in-memory stores.
        builder.Services.AddSingleton<InstanceLock>();
        builder.Services.AddHostedService<InstanceLockHeartbeatService>();

        // Multi-replica (HA) job coordination is per-job, not centralized: each scheduled job that
        // mutates shared state acquires its own distributed lock per tick (see
        // ScheduledBackgroundService.RequiresLeaderLock and the management sweep locks). In
        // standalone mode the in-process lock always grants, so every job runs on the single node.

        // Health infrastructure. ReadinessOptions carries the required/reported dependency
        // classification (per-plane defaults, overridable with READINESS_HARD_DEPENDENCIES) and
        // the blob-probe cache TTL, so /ready can be a load-balancer check without a shared-store
        // failure deregistering every replica at once.
        builder.Services.AddSingleton(sp =>
            ReadinessOptions.Resolve(sp.GetRequiredService<IConfiguration>()));
        builder.Services.AddSingleton<ReadinessAggregator>();
        builder.Services.AddSingleton<Dependably.Infrastructure.Health.HealthService>();
        builder.Services.AddHostedService<HealthcheckPinger>();

        builder.Services.AddSingleton<IAirGapMode, AirGapMode>();
        builder.Services.AddSingleton<IEdgeMode, EdgeMode>();
        // Passive master-reachability tracker fed at the UpstreamClient fetch boundary; read only
        // by the edge-only /edge/status endpoint. Registered in all modes (near-free), exposed on edge.
        builder.Services.AddSingleton<Dependably.Infrastructure.Observability.EdgeStatusTracker>();
        builder.Services.AddSingleton<CacheEvictionService.Dependencies>();
        builder.Services.AddHostedService<CacheEvictionService>();

        // Hosted-tier orphan reconciliation: closes the SIGKILL window in PackagePublishService
        // by sweeping the registry tier for blobs that no package_versions row references.
        // Schedule + grace are configurable; defaults to daily at 04:00 UTC with a 30-minute
        // grace window to skip in-flight publishes.
        builder.Services.AddHostedService<OrphanBlobReconcilerService>();
        builder.Services.AddHostedService<BlobStoreSizePoller>();
        builder.Services.AddHostedService<TenantCountPoller>();
        builder.Services.AddHostedService<AdvisoryInventoryPoller>();
    }

    internal static void AddDependablyStagingMonitor(this WebApplicationBuilder builder)
    {
        // Staging configuration resolved once: the proxy-fetch staging path and the
        // disk-full floor. Shared by UpstreamClient (floor guard), DriveInfoStagingDiskInfo
        // (disk probe), and StartupService (floor=0 opt-out warning) so the values can't diverge.
        var stagingOptions = StagingOptions.Resolve(builder.Configuration);
        builder.Services.AddSingleton(stagingOptions);

        // Staging disk space monitoring. IStagingDiskInfo reads DriveInfo for the
        // staging volume; StagingDiskMonitor samples it on a 60 s timer and emits
        // OTel gauges + a Serilog warning when free space falls below the threshold.
        builder.Services.AddSingleton<IStagingDiskInfo>(
            new DriveInfoStagingDiskInfo(stagingOptions.Path));
        builder.Services.AddHostedService<StagingDiskMonitor>();
    }

    internal static void AddDependablyPublishPipeline(this WebApplicationBuilder builder)
    {
        // Feature-flagged claim gate for publish/import paths. Default off; operators
        // flip CLAIM_ENFORCEMENT=on once their initial claim set is in place.
        builder.Services.AddSingleton<PublishGate>();

        // Name-level publish authorization: binds a name to its first hosted publisher and
        // refuses seizure by other principals when PUBLISH_NAME_BINDING=on. Ownership is
        // recorded regardless of the flag (populates the resurrection tombstone). The backing
        // NameBindingRepository is registered with the core infrastructure services.
        builder.Services.AddSingleton<NameBindingGate>();

        // Shared publish-flow tail (path safety, claim gate, dedup, blob put, version create,
        // audit). Used by NpmController/PyPiController/NuGetController publish handlers and
        // by ImportController bulk endpoints — replaces six near-identical inlined flows.
        builder.Services.AddSingleton<Dependably.Infrastructure.Publish.PublishAuditor>();
        // Fail-closed publish guard: refuses every publish/push/import on an edge node with a 405.
        // No-op in every non-edge mode. Shared by PackagePublishService and OciController.
        builder.Services.AddSingleton<Dependably.Infrastructure.Edge.EdgePublishGuard>();
        builder.Services.AddSingleton<Dependably.Infrastructure.Publish.IPackagePublishService,
                                      Dependably.Infrastructure.Publish.PackagePublishService>();
    }
}
