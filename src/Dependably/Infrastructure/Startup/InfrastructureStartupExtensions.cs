using Dependably.Api;
using Dependably.Api.NpmProtocol;
using Dependably.Api.NuGetProtocol;
using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Observability;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers infrastructure services: in-process metadata caches, background services,
/// staging disk monitoring, claim gate, publish pipeline, controller service aggregates,
/// localization, and the CORS policy.
/// </summary>
internal static class InfrastructureStartupExtensions
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
        builder.Services.AddSingleton(sp =>
            new RenderedResponseCache<PyPiSimpleIndexKey>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.PyPiSimpleIndex,
                sp.GetRequiredService<MetadataConcurrencyGate>().Semaphore));
        builder.Services.AddSingleton(sp =>
            new RenderedResponseCache<NpmPackumentKey>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.NpmPackument,
                sp.GetRequiredService<MetadataConcurrencyGate>().Semaphore));
        builder.Services.AddSingleton(sp =>
            new RenderedResponseCache<NuGetRegistrationKey>(
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                MetadataCacheKeys.NuGetRegistration,
                sp.GetRequiredService<MetadataConcurrencyGate>().Semaphore));
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
                MetadataCacheKeys.MavenMetadata));
    }

    internal static void AddDependablyBackgroundServices(this WebApplicationBuilder builder)
    {
        // Startup: schema migration + first-boot + JWT key load (must complete before other services)
        builder.Services.AddHostedService<StartupService>();

        // Leader election for background jobs in HA mode
        builder.Services.AddHostedService<LeaderElectedScheduler>();

        // Health infrastructure
        builder.Services.AddSingleton<ReadinessAggregator>();
        builder.Services.AddSingleton<Dependably.Infrastructure.Health.HealthService>();
        builder.Services.AddHostedService<HealthcheckPinger>();

        builder.Services.AddSingleton<Dependably.Storage.UpstreamFetchCoordinator>();
        builder.Services.AddSingleton<IAirGapMode, AirGapMode>();
        builder.Services.AddHostedService<CacheEvictionService>();

        // Hosted-tier orphan reconciliation: closes the SIGKILL window in PackagePublishService
        // by sweeping the registry tier for blobs that no package_versions row references.
        // Schedule + grace are configurable; defaults to daily at 04:00 UTC with a 30-minute
        // grace window to skip in-flight publishes.
        builder.Services.AddHostedService<OrphanBlobReconcilerService>();
        builder.Services.AddHostedService<BlobStoreSizePoller>();
        builder.Services.AddHostedService<TenantCountPoller>();

        builder.Services.AddHostedService<RetentionService>();
        builder.Services.AddHostedService<Dependably.Background.TenantHardDeleteService>();
        builder.Services.AddHostedService<DeprecationRefreshService>();
        builder.Services.AddHostedService<StatsRefreshService>();
        builder.Services.AddHostedService<SamlCertExpiryCheckService>();
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
        builder.Services.AddSingleton<MetricsSnapshotProvider>();
    }

    internal static void AddDependablyPublishPipeline(this WebApplicationBuilder builder)
    {
        // Feature-flagged claim gate for publish/import paths. Default off; operators
        // flip CLAIM_ENFORCEMENT=on once their initial claim set is in place.
        builder.Services.AddSingleton<PublishGate>();

        // Admin bulk import. One service record so the controller ctor stays
        // under S107; same shape as the protocol controllers. The factory reads the
        // resolved StagingOptions so the scoped record carries a plain string rather
        // than an IConfiguration dep.
        builder.Services.AddScoped<ImportControllerServices>(sp =>
        {
            string stagingPath = sp.GetRequiredService<StagingOptions>().Path;
            return new ImportControllerServices(
                Guard: sp.GetRequiredService<OrgAccessGuard>(),
                PublishGate: sp.GetRequiredService<PublishGate>(),
                Orgs: sp.GetRequiredService<OrgRepository>(),
                Publish: sp.GetRequiredService<Dependably.Infrastructure.Publish.IPackagePublishService>(),
                ClaimResolver: sp.GetRequiredService<ClaimResolver>(),
                Licenses: sp.GetRequiredService<LicenseRepository>(),
                LimitResolver: sp.GetRequiredService<Dependably.Protocol.IUploadLimitResolver>(),
                StagingPath: stagingPath,
                Cache: sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>());
        });

        // Shared publish-flow tail (path safety, claim gate, dedup, blob put, version create,
        // audit). Used by NpmController/PyPiController/NuGetController publish handlers and
        // by ImportController bulk endpoints — replaces six near-identical inlined flows.
        builder.Services.AddSingleton<Dependably.Infrastructure.Publish.PublishAuditor>();
        builder.Services.AddSingleton<Dependably.Infrastructure.Publish.IPackagePublishService,
                                      Dependably.Infrastructure.Publish.PackagePublishService>();

        // Claim REST surface. State machine + repository already registered
        // above; the controller services record bundles the deps.
        builder.Services.AddScoped<ClaimsControllerServices>();
    }

    internal static void AddDependablyControllerAggregates(this WebApplicationBuilder builder)
    {
        // Controller dependency aggregates — let DI assemble these from already-registered
        // singletons. Each is a single ctor param on its respective controller, replacing
        // 12-15 individual injections (S107). Bodies still reference the unpacked fields.
        builder.Services.AddNpmHandlers();
        builder.Services.AddNuGetHandlers();
        builder.Services.AddPyPiHandlers();
        builder.Services.AddScoped<MavenControllerServices>();
        builder.Services.AddScoped<VulnerabilityControllerDependencies>();
        builder.Services.AddSingleton<Dependably.Protocol.IRpmUpstreamProxy, Dependably.Protocol.RpmUpstreamProxy>();
        builder.Services.AddScoped<RpmControllerServices>();
        builder.Services.AddSingleton<Dependably.Storage.RpmRepodataService>();
        builder.Services.AddScoped<OciControllerServices>();
        builder.Services.AddScoped<OrgControllerServices>();
        builder.Services.AddSingleton<GoLatestFetchCoordinator>();
        builder.Services.AddScoped<GoControllerServices>();
    }

    internal static void AddDependablyLocalization(this WebApplicationBuilder builder)
    {
        // i18n — request localization with en (default) and fr
        builder.Services.AddLocalization(o => o.ResourcesPath = "Resources");
        builder.Services.Configure<Microsoft.AspNetCore.Builder.RequestLocalizationOptions>(options =>
        {
            var supported = new[] { new System.Globalization.CultureInfo("en"), new System.Globalization.CultureInfo("fr") };
            options.DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture("en");
            options.SupportedCultures = supported;
            options.SupportedUICultures = supported;
            options.RequestCultureProviders = new List<Microsoft.AspNetCore.Localization.IRequestCultureProvider>
            {
                new Microsoft.AspNetCore.Localization.QueryStringRequestCultureProvider(),
                new Microsoft.AspNetCore.Localization.CookieRequestCultureProvider(),
                new Microsoft.AspNetCore.Localization.AcceptLanguageHeaderRequestCultureProvider()
            };
        });

        // ProblemResults — scoped so IStringLocalizer resolves per-request culture
        builder.Services.AddScoped<ProblemResults>();
    }

    internal static void AddDependablyCors(this WebApplicationBuilder builder)
    {
        // CORS — management API only allows BASE_URL origin. PublicBaseUrl() strips any
        // trailing slash: a CORS origin with one never matches the browser-sent Origin header.
        string baseUrl = builder.Configuration.PublicBaseUrl() ?? DefaultBaseUrl;
        builder.Services.AddCors(o => o.AddPolicy("ManagementApi", policy =>
            policy.WithOrigins(baseUrl)
                  .AllowCredentials()
                  .WithHeaders("Content-Type", "Authorization")
                  .WithMethods("GET", "POST", "PUT", "DELETE")));
    }

    internal static void AddDependablyAuthServices(this WebApplicationBuilder builder)
    {
        // Auth services
        builder.Services.AddSingleton<LoginService.Dependencies>();
        builder.Services.AddSingleton<LoginService>();
        builder.Services.AddSingleton<OrgAccessGuard>();
        builder.Services.AddSingleton<PasswordPolicy>();
    }
}
