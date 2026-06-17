using Dependably.Infrastructure.OpenApi;
using Dependably.Security;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers MVC controllers, OpenAPI documents (management + protocol split by route prefix),
/// and response compression.
/// </summary>
internal static class ControllersStartupExtensions
{
    internal static void AddDependablyControllers(this WebApplicationBuilder builder)
    {
        // Controllers + OpenAPI
        // Explicit application part ensures controllers are found even when ConfigureBuilder
        // is called from a different entry assembly (e.g. the test project).
        builder.Services.AddControllers(options =>
            {
                options.Filters.AddService<RouteScopeFilter>();
                // After RouteScopeFilter (realm first), block flagged users until they rotate.
                options.Filters.AddService<PasswordRotationGuard>();
            })
            .AddApplicationPart(typeof(Program).Assembly)
            .AddDataAnnotationsLocalization()
            .AddJsonOptions(o =>
                // Strict API stance — unknown JSON fields fail binding with a 400. Prevents
                // silent intent loss (e.g. callers misspelling a field name or sending a
                // retired field), and complements the explicit retired-field guards in
                // controller actions.
                o.JsonSerializerOptions.UnmappedMemberHandling =
                    System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow);
    }

    internal static void AddDependablyOpenApi(this WebApplicationBuilder builder)
    {
        // Two named OpenAPI documents — split by route prefix so the management API
        // (versioned, /api/v1/…) and the registry protocol surfaces (canonical roots
        // mandated by each upstream spec: /v2/ OCI, /simple/ PyPI, /npm/, /nuget/v3/, …)
        // get separate specs and separate UI mounts. The split is route-prefix-driven,
        // not attribute-driven, so new controllers land in the right document automatically.
        static bool IsManagementPath(Microsoft.AspNetCore.Mvc.ApiExplorer.ApiDescription api) =>
            api.RelativePath is { } path
            && (path.StartsWith("api/v1/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("saml/", StringComparison.OrdinalIgnoreCase));

        static void ConfigureCommonOpenApi(Microsoft.AspNetCore.OpenApi.OpenApiOptions options)
        {
            options.AddDocumentTransformer<SecuritySchemeDocumentTransformer>();
            options.AddDocumentTransformer<DocumentMetadataTransformer>();
            options.AddOperationTransformer<SecuritySchemeOperationTransformer>();
        }

        builder.Services.AddOpenApi("management", options =>
        {
            ConfigureCommonOpenApi(options);
            options.ShouldInclude = IsManagementPath;
        });

        builder.Services.AddOpenApi("protocol", options =>
        {
            ConfigureCommonOpenApi(options);
            options.ShouldInclude = api => !IsManagementPath(api);
        });
    }

    internal static void AddDependablyCompression(this WebApplicationBuilder builder)
    {
        // Response compression — Brotli preferred, then GZip
        builder.Services.AddResponseCompression(o =>
        {
            o.EnableForHttps = true;
            o.Providers.Add<Microsoft.AspNetCore.ResponseCompression.BrotliCompressionProvider>();
            o.Providers.Add<Microsoft.AspNetCore.ResponseCompression.GzipCompressionProvider>();
        });
    }
}
