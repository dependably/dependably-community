using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Registers the per-endpoint npm handler classes.
/// Isolated from <c>InfrastructureStartupExtensions</c> so the npm handler registrations
/// do not inflate that extension's coupling count.
/// </summary>
internal static class NpmHandlerRegistration
{
    internal static void AddNpmHandlers(this IServiceCollection services)
    {
        services.AddScoped<NpmPackumentHandler>();
        services.AddScoped<NpmTarballHandler>();
        services.AddScoped<NpmDistTagsHandler>();
        services.AddScoped<NpmPublishHandler>(sp =>
        {
            string path = sp.GetRequiredService<StagingOptions>().Path;
            return new NpmPublishHandler(
                orgs: sp.GetRequiredService<OrgRepository>(),
                packages: sp.GetRequiredService<PackageRepository>(),
                tokens: sp.GetRequiredService<TokenRepository>(),
                audit: sp.GetRequiredService<AuditRepository>(),
                blobs: sp.GetRequiredService<IBlobStore>(),
                publish: sp.GetRequiredService<IPackagePublishService>(),
                claimResolver: sp.GetRequiredService<ClaimResolver>(),
                licenses: sp.GetRequiredService<LicenseRepository>(),
                uploadLimits: sp.GetRequiredService<IUploadLimitResolver>(),
                distTags: sp.GetRequiredService<NpmDistTagRepository>(),
                cache: sp.GetRequiredService<RenderedResponseCache<NpmPackumentKey>>(),
                stagingPath: path);
        });
        services.AddScoped<NpmControllerHandlers>();
    }
}
