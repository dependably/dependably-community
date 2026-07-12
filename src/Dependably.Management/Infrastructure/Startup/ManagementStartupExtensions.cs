using Dependably.Api;
using Dependably.Infrastructure.Publish;
using Dependably.Security;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Management-plane DI wiring that layers on top of the Core registrations: the first-factor login
/// / bootstrap services, the management-controller dependency aggregates, the require-MFA mode, and
/// the management background jobs (retention, tenant hard-delete, deprecation + stats refresh,
/// license backfill, SAML cert-expiry). Registered only by the full composition root — a
/// protocol-only edge host wires
/// none of it, which is what keeps the BCrypt/SAML/JwtBearer closure out of the edge image.
/// </summary>
public static class ManagementStartupExtensions
{
    public static void AddDependablyManagementAuthServices(this WebApplicationBuilder builder)
    {
        // Auth services
        builder.Services.AddSingleton<LoginService.Dependencies>();
        builder.Services.AddSingleton<LoginService>();
        builder.Services.AddSingleton<OrgAccessGuard>();

        // Effective-MFA-mode resolver, read by MfaEnrollmentGuard and the auth/settings controllers.
        builder.Services.AddSingleton<IRequireMfaMode, RequireMfaMode>();

        // First-boot admin creation (BCrypt) for single/multi/header modes. Registered only by
        // the full management host — a protocol-only edge host leaves IAdminBootstrapper absent,
        // so FirstBootService can create no admin account by construction.
        builder.Services.AddSingleton<IAdminBootstrapper, AdminBootstrapper>();
    }

    public static void AddDependablyManagementControllerAggregates(this WebApplicationBuilder builder)
    {
        // Management-controller dependency aggregates — let DI assemble these from already-registered
        // singletons. Each is a single ctor param on its respective management controller. The
        // protocol-controller aggregates are registered by the Core wiring.
        builder.Services.AddScoped<VulnerabilityControllerDependencies>();
        builder.Services.AddScoped<OrgControllerServices>();

        // Admin bulk import. One service record so the controller ctor stays under S107; the factory
        // reads the resolved StagingOptions so the scoped record carries a plain string rather than
        // an IConfiguration dep.
        builder.Services.AddScoped<ImportControllerServices>(sp =>
        {
            string stagingPath = sp.GetRequiredService<StagingOptions>().Path;
            return new ImportControllerServices(
                Guard: sp.GetRequiredService<OrgAccessGuard>(),
                PublishGate: sp.GetRequiredService<PublishGate>(),
                Orgs: sp.GetRequiredService<OrgRepository>(),
                Publish: sp.GetRequiredService<IPackagePublishService>(),
                ClaimResolver: sp.GetRequiredService<ClaimResolver>(),
                Licenses: sp.GetRequiredService<LicenseRepository>(),
                LimitResolver: sp.GetRequiredService<Dependably.Protocol.IUploadLimitResolver>(),
                StagingPath: stagingPath,
                Cache: sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>());
        });

        // Claim REST surface. State machine + repository are registered by the Core wiring; the
        // controller services record bundles the deps.
        builder.Services.AddScoped<ClaimsControllerServices>();
    }

    public static void AddDependablyManagementBackgroundServices(this WebApplicationBuilder builder)
    {
        // Multi-replica (HA) job coordination is per-job: each scheduled management job that mutates
        // shared state acquires its own distributed lock per tick (ScheduledBackgroundService
        // .RequiresLeaderLock). In standalone mode the in-process lock always grants.
        builder.Services.AddSingleton<RetentionService.Dependencies>();
        builder.Services.AddHostedService<RetentionService>();
        builder.Services.AddHostedService<Dependably.Background.TenantHardDeleteService>();
        builder.Services.AddHostedService<DeprecationRefreshService>();
        builder.Services.AddHostedService<LicenseBackfillService>();
        builder.Services.AddHostedService<StatsRefreshService>();
        builder.Services.AddHostedService<SamlCertExpiryCheckService>();

        // JWT signing-key load. A hosted service registered after CoreStartupService so it runs
        // once first-boot has written jwt_secret; it copies the secret into the JwtBearer options.
        builder.Services.AddHostedService<StartupService>();
    }
}
