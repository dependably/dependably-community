using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Dependably.Infrastructure.OpenApi;

/// <summary>
/// Sets per-document title and description based on the named OpenAPI document
/// (<c>management</c> vs <c>protocol</c>). The split mirrors the route layout:
/// management endpoints live under <c>/api/v1/</c>; protocol surfaces live at the
/// roots their upstream specs mandate (<c>/v2/</c> OCI, <c>/simple/</c> PyPI, …).
/// </summary>
internal sealed class DocumentMetadataTransformer : IOpenApiDocumentTransformer
{
    public Task TransformAsync(
        OpenApiDocument document,
        OpenApiDocumentTransformerContext context,
        CancellationToken cancellationToken)
    {
        document.Info ??= new OpenApiInfo();
        switch (context.DocumentName)
        {
            case "management":
                document.Info.Title = "Dependably Management API";
                document.Info.Description =
                    "Tenant administration, authentication, tokens, settings, audit. All endpoints under /api/v1/.";
                break;
            case "protocol":
                document.Info.Title = "Dependably Registry Protocols";
                document.Info.Description =
                    "Package-registry protocol surfaces: OCI Distribution Spec v2 (/v2/), PyPI (/simple/), npm (/npm/), NuGet (/nuget/v3/), Maven, RPM.";
                break;
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Declares the three security schemes the API supports so Swagger UI can render
/// per-endpoint padlocks and an "Authorize" dialog.
/// </summary>
internal sealed class SecuritySchemeDocumentTransformer : IOpenApiDocumentTransformer
{
    internal const string BearerScheme = "Bearer";
    internal const string ApiTokenScheme = "ApiToken";
    internal const string NuGetApiKeyScheme = "NuGetApiKey";

    public Task TransformAsync(
        OpenApiDocument document,
        OpenApiDocumentTransformerContext context,
        CancellationToken cancellationToken)
    {
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();

        document.Components.SecuritySchemes[BearerScheme] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description =
                "Session JWT issued at sign-in. Accepted as `Authorization: Bearer <jwt>` " +
                "or via the `dependably_session` cookie fallback.",
        };

        document.Components.SecuritySchemes[ApiTokenScheme] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            Description =
                "API token for npm/PyPI/NuGet protocol clients. npm clients send " +
                "`Authorization: Bearer <token>`; PyPI and NuGet clients send " +
                "`Authorization: Basic base64(user:<token>)`.",
        };

        document.Components.SecuritySchemes[NuGetApiKeyScheme] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.ApiKey,
            In = ParameterLocation.Header,
            Name = "X-NuGet-ApiKey",
            Description = "NuGet push/unlist API key header used by `nuget push` and `dotnet nuget push`.",
        };

        return Task.CompletedTask;
    }
}

/// <summary>
/// Attaches per-operation security requirements based on [Authorize]/[AllowAnonymous]
/// metadata so Swagger UI renders padlocks only on endpoints that actually require auth.
/// </summary>
internal sealed class SecuritySchemeOperationTransformer : IOpenApiOperationTransformer
{
    public Task TransformAsync(
        OpenApiOperation operation,
        OpenApiOperationTransformerContext context,
        CancellationToken cancellationToken)
    {
        var metadata = context.Description.ActionDescriptor.EndpointMetadata;

        // Action-level [AllowAnonymous] beats class-level [Authorize].
        if (metadata.OfType<IAllowAnonymous>().Any())
        {
            return Task.CompletedTask;
        }

        var authorizeData = metadata.OfType<IAuthorizeData>().ToList();
        if (authorizeData.Count == 0)
        {
            return Task.CompletedTask;
        }

        var schemes = authorizeData
            .Select(a => a.AuthenticationSchemes)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .SelectMany(s => s!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool allowsApiToken = schemes.Contains(TokenAuthenticationDefaults.Scheme);

        operation.Security ??= new List<OpenApiSecurityRequirement>();

        if (allowsApiToken)
        {
            // Either Bearer (JWT) or ApiToken (protocol clients) satisfies these endpoints.
            // Each scheme is its own requirement object so Swagger UI treats them as alternatives.
            operation.Security.Add(RequirementFor(context, SecuritySchemeDocumentTransformer.BearerScheme));
            operation.Security.Add(RequirementFor(context, SecuritySchemeDocumentTransformer.ApiTokenScheme));

            if (IsNuGetPushOrUnlist(context))
            {
                operation.Security.Add(RequirementFor(context, SecuritySchemeDocumentTransformer.NuGetApiKeyScheme));
            }
        }
        else
        {
            operation.Security.Add(RequirementFor(context, SecuritySchemeDocumentTransformer.BearerScheme));
        }

        return Task.CompletedTask;
    }

    private static OpenApiSecurityRequirement RequirementFor(OpenApiOperationTransformerContext context, string schemeId)
    {
        var reference = new OpenApiSecuritySchemeReference(schemeId, context.Document, externalResource: null);
        return new OpenApiSecurityRequirement
        {
            [reference] = new List<string>(),
        };
    }

    private static bool IsNuGetPushOrUnlist(OpenApiOperationTransformerContext context)
    {
        if (context.Description.ActionDescriptor is not ControllerActionDescriptor cad)
        {
            return false;
        }

        if (!string.Equals(cad.ControllerName, "NuGet", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string? method = context.Description.HttpMethod;
        return string.Equals(method, "PUT", StringComparison.OrdinalIgnoreCase)
            || string.Equals(method, "DELETE", StringComparison.OrdinalIgnoreCase);
    }
}
