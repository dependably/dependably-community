using Dependably.Api;
using Dependably.Api.NpmProtocol;
using Dependably.Api.NuGetProtocol;
using Dependably.Api.PyPiProtocol;
using Dependably.Storage;

namespace Dependably.Infrastructure.Startup;

// Protocol controller dependency-aggregate registration (npm/NuGet/PyPI/Maven/RPM/OCI/Go/apk).
// Split out of InfrastructureStartupExtensions.cs (partial class) to keep the class's dependency
// coupling spread across files below the S1200 threshold; see that file for caching/metrics
// registration.
internal static partial class InfrastructureStartupExtensions
{
    internal static void AddDependablyControllerAggregates(this WebApplicationBuilder builder)
    {
        // Protocol controller dependency aggregates — let DI assemble these from already-registered
        // singletons. Each is a single ctor param on its respective controller, replacing
        // 12-15 individual injections (S107). Bodies still reference the unpacked fields. The
        // management-controller aggregates (org, vulnerability, import, claims) are registered by
        // the management wiring in Dependably.Management.
        builder.Services.AddNpmHandlers();
        builder.Services.AddNuGetHandlers();
        builder.Services.AddPyPiHandlers();
        builder.Services.AddScoped<MavenControllerServices>();
        builder.Services.AddSingleton<Dependably.Protocol.IRpmUpstreamProxy, Dependably.Protocol.RpmUpstreamProxy>();
        builder.Services.AddScoped<RpmControllerServices>();
        builder.Services.AddSingleton<Dependably.Storage.RpmRepodataService>();
        builder.Services.AddScoped<OciControllerServices>();
        builder.Services.AddSingleton<GoLatestFetchCoordinator>();
        builder.Services.AddScoped<GoControllerServices>();
        builder.Services.AddSingleton<ApkIndexFetchCoordinator>();
        builder.Services.AddScoped(sp =>
        {
            var config = sp.GetRequiredService<IConfiguration>();
            var negativeCacheTtl = TimeSpan.TryParse(config["Apk:NegativeCacheTtl"], out var n)
                ? n
                : TimeSpan.FromMinutes(5);
            return new ApkControllerServices(
                sp.GetRequiredService<OrgRepository>(),
                sp.GetRequiredService<TokenRepository>(),
                sp.GetRequiredService<AuditRepository>(),
                sp.GetRequiredService<PackageRepository>(),
                sp.GetRequiredService<IBlobStore>(),
                sp.GetRequiredService<Dependably.Protocol.UpstreamClient>(),
                sp.GetRequiredService<Dependably.Protocol.UpstreamRegistryResolver>(),
                sp.GetRequiredService<IMetadataStore>(),
                sp.GetRequiredService<CacheAccessRecorder>(),
                sp.GetRequiredService<CacheArtifactRepository>(),
                sp.GetRequiredService<TenantArtifactAccessRepository>(),
                sp.GetRequiredService<TimeProvider>(),
                sp.GetRequiredService<ILogger<ApkController>>(),
                sp.GetRequiredService<Dependably.Protocol.ReservedNamespaceService>(),
                sp.GetRequiredService<Dependably.Protocol.BlockGateService>(),
                sp.GetRequiredService<ApkIndexFetchCoordinator>(),
                negativeCacheTtl);
        });
    }
}
