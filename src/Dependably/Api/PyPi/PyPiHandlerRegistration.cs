using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Registers the per-endpoint PyPI handler classes and the controller services aggregate.
/// Isolated so the PyPI handler registrations do not inflate <c>InfrastructureStartupExtensions</c>
/// coupling count.
/// </summary>
internal static class PyPiHandlerRegistration
{
    internal static void AddPyPiHandlers(this IServiceCollection services)
    {
        services.AddScoped<PyPiSimpleIndexHandler>();
        services.AddScoped<PyPiProxyFetcher>();
        services.AddScoped<PyPiDownloadHandler>();
        services.AddScoped<PyPiJsonApiHandler>();
        services.AddScoped<PyPiPublishHandler>(sp =>
        {
            string stagingPath = sp.GetRequiredService<StagingOptions>().Path;
            return new PyPiPublishHandler(
                orgs: sp.GetRequiredService<OrgRepository>(),
                tokens: sp.GetRequiredService<TokenRepository>(),
                publishGate: sp.GetRequiredService<PublishGate>(),
                publish: sp.GetRequiredService<IPackagePublishService>(),
                claimResolver: sp.GetRequiredService<ClaimResolver>(),
                licenses: sp.GetRequiredService<LicenseRepository>(),
                cache: sp.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>(),
                logger: sp.GetRequiredService<ILogger<PyPiPublishHandler>>(),
                stagingPath: stagingPath);
        });
        services.AddScoped<PyPiControllerServices>();
    }
}
