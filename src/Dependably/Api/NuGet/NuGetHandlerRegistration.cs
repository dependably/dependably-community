using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Registers the per-endpoint NuGet handler classes and the controller services aggregate.
/// Isolated from <c>InfrastructureStartupExtensions</c> so the NuGet handler registrations
/// do not inflate that extension's coupling count.
/// </summary>
internal static class NuGetHandlerRegistration
{
    internal static void AddNuGetHandlers(this IServiceCollection services)
    {
        services.AddScoped<NuGetServiceIndexHandler>();
        services.AddScoped<NuGetSearchHandler>();
        services.AddScoped<NuGetRegistrationHandler>();
        services.AddScoped<NuGetFlatContainerHandler>();
        services.AddScoped<NuGetPublishHandler>(sp =>
        {
            string stagingPath = sp.GetRequiredService<StagingOptions>().Path;
            return new NuGetPublishHandler(
                orgs: sp.GetRequiredService<OrgRepository>(),
                packages: sp.GetRequiredService<PackageRepository>(),
                tokens: sp.GetRequiredService<TokenRepository>(),
                blobs: sp.GetRequiredService<IBlobStore>(),
                db: sp.GetRequiredService<IMetadataStore>(),
                publishGate: sp.GetRequiredService<PublishGate>(),
                publish: sp.GetRequiredService<IPackagePublishService>(),
                claimResolver: sp.GetRequiredService<ClaimResolver>(),
                licenses: sp.GetRequiredService<LicenseRepository>(),
                cache: sp.GetRequiredService<RenderedResponseCache<NuGetRegistrationKey>>(),
                logger: sp.GetRequiredService<ILogger<NuGetPublishHandler>>(),
                time: sp.GetRequiredService<TimeProvider>(),
                stagingPath: stagingPath);
        });
        services.AddScoped<NuGetControllerServices>();
    }
}
