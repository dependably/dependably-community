using Dependably.Infrastructure.OpenApi;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for <see cref="SecuritySchemeDocumentTransformer"/> and
/// <see cref="SecuritySchemeOperationTransformer"/>. The transformers are exercised
/// directly with hand-built <see cref="OpenApiDocument"/> / context instances so we
/// don't need a Kestrel / ApiExplorer pipeline.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SecuritySchemeTransformerTests
{
    // ── Document transformer ────────────────────────────────────────────────

    [Fact]
    public async Task DocumentTransformer_AddsAllThreeSecuritySchemes_WhenComponentsMissing()
    {
        var doc = new OpenApiDocument(); // Components is null
        var ctx = BuildDocumentContext();
        var transformer = new SecuritySchemeDocumentTransformer();

        await transformer.TransformAsync(doc, ctx, CancellationToken.None);

        Assert.NotNull(doc.Components);
        Assert.NotNull(doc.Components!.SecuritySchemes);
        Assert.Equal(3, doc.Components.SecuritySchemes!.Count);
        Assert.Contains(SecuritySchemeDocumentTransformer.BearerScheme, doc.Components.SecuritySchemes.Keys);
        Assert.Contains(SecuritySchemeDocumentTransformer.ApiTokenScheme, doc.Components.SecuritySchemes.Keys);
        Assert.Contains(SecuritySchemeDocumentTransformer.NuGetApiKeyScheme, doc.Components.SecuritySchemes.Keys);
    }

    // ── Document metadata transformer (title/description per document) ────────

    [Fact]
    public async Task MetadataTransformer_ManagementDocument_SetsManagementTitle()
    {
        var doc = new OpenApiDocument(); // Info is null
        var transformer = new DocumentMetadataTransformer();

        await transformer.TransformAsync(doc, BuildDocumentContext("management"), CancellationToken.None);

        Assert.NotNull(doc.Info);
        Assert.Equal("Dependably Management API", doc.Info!.Title);
        Assert.Contains("/api/v1/", doc.Info.Description);
    }

    [Fact]
    public async Task MetadataTransformer_ProtocolDocument_SetsProtocolTitle()
    {
        var doc = new OpenApiDocument();
        var transformer = new DocumentMetadataTransformer();

        await transformer.TransformAsync(doc, BuildDocumentContext("protocol"), CancellationToken.None);

        Assert.Equal("Dependably Registry Protocols", doc.Info!.Title);
        Assert.Contains("OCI", doc.Info.Description);
    }

    [Fact]
    public async Task MetadataTransformer_UnknownDocument_LeavesTitleUnset()
    {
        var doc = new OpenApiDocument();
        var transformer = new DocumentMetadataTransformer();

        await transformer.TransformAsync(doc, BuildDocumentContext("v1"), CancellationToken.None);

        // Info is initialized but the switch falls through — no title assigned.
        Assert.NotNull(doc.Info);
        Assert.True(string.IsNullOrEmpty(doc.Info!.Title));
    }

    [Fact]
    public async Task DocumentTransformer_BearerScheme_IsHttpBearerJwt()
    {
        var doc = new OpenApiDocument();
        var transformer = new SecuritySchemeDocumentTransformer();

        await transformer.TransformAsync(doc, BuildDocumentContext(), CancellationToken.None);

        var bearer = (OpenApiSecurityScheme)doc.Components!.SecuritySchemes![SecuritySchemeDocumentTransformer.BearerScheme];
        Assert.Equal(SecuritySchemeType.Http, bearer.Type);
        Assert.Equal("bearer", bearer.Scheme);
        Assert.Equal("JWT", bearer.BearerFormat);
        Assert.False(string.IsNullOrEmpty(bearer.Description));
    }

    [Fact]
    public async Task DocumentTransformer_ApiTokenScheme_IsHttpBearerNoJwtFormat()
    {
        var doc = new OpenApiDocument();
        var transformer = new SecuritySchemeDocumentTransformer();

        await transformer.TransformAsync(doc, BuildDocumentContext(), CancellationToken.None);

        var apiToken = (OpenApiSecurityScheme)doc.Components!.SecuritySchemes![SecuritySchemeDocumentTransformer.ApiTokenScheme];
        Assert.Equal(SecuritySchemeType.Http, apiToken.Type);
        Assert.Equal("bearer", apiToken.Scheme);
        Assert.Null(apiToken.BearerFormat);
        Assert.Contains("npm", apiToken.Description);
        Assert.Contains("PyPI", apiToken.Description);
        Assert.Contains("NuGet", apiToken.Description);
    }

    [Fact]
    public async Task DocumentTransformer_NuGetApiKeyScheme_IsHeaderApiKey()
    {
        var doc = new OpenApiDocument();
        var transformer = new SecuritySchemeDocumentTransformer();

        await transformer.TransformAsync(doc, BuildDocumentContext(), CancellationToken.None);

        var key = (OpenApiSecurityScheme)doc.Components!.SecuritySchemes![SecuritySchemeDocumentTransformer.NuGetApiKeyScheme];
        Assert.Equal(SecuritySchemeType.ApiKey, key.Type);
        Assert.Equal(ParameterLocation.Header, key.In);
        Assert.Equal("X-NuGet-ApiKey", key.Name);
    }

    [Fact]
    public async Task DocumentTransformer_PreservesPreexistingComponents()
    {
        var doc = new OpenApiDocument
        {
            Components = new OpenApiComponents
            {
                SecuritySchemes = new Dictionary<string, IOpenApiSecurityScheme>
                {
                    ["Existing"] = new OpenApiSecurityScheme { Type = SecuritySchemeType.ApiKey, Name = "X-Foo", In = ParameterLocation.Header },
                },
            },
        };
        var transformer = new SecuritySchemeDocumentTransformer();

        await transformer.TransformAsync(doc, BuildDocumentContext(), CancellationToken.None);

        // Pre-existing entry is kept; new ones are added alongside.
        Assert.Contains("Existing", doc.Components!.SecuritySchemes!.Keys);
        Assert.Contains(SecuritySchemeDocumentTransformer.BearerScheme, doc.Components.SecuritySchemes.Keys);
        Assert.Equal(4, doc.Components.SecuritySchemes.Count);
    }

    [Fact]
    public async Task DocumentTransformer_IsIdempotent()
    {
        var doc = new OpenApiDocument();
        var transformer = new SecuritySchemeDocumentTransformer();

        await transformer.TransformAsync(doc, BuildDocumentContext(), CancellationToken.None);
        await transformer.TransformAsync(doc, BuildDocumentContext(), CancellationToken.None);

        Assert.Equal(3, doc.Components!.SecuritySchemes!.Count);
    }

    // ── Operation transformer ───────────────────────────────────────────────

    [Fact]
    public async Task OperationTransformer_NoMetadata_LeavesSecurityUntouched()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(controllerName: "PyPi", httpMethod: "GET", metadata: System.Array.Empty<object>());

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.Null(op.Security);
    }

    [Fact]
    public async Task OperationTransformer_AllowAnonymous_BeatsAuthorize()
    {
        var op = new OpenApiOperation();
        object[] metadata = new object[]
        {
            new AuthorizeAttribute(),
            new AllowAnonymousAttribute(),
        };
        var ctx = BuildOperationContext(controllerName: "PyPi", httpMethod: "GET", metadata: metadata);

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.Null(op.Security);
    }

    [Fact]
    public async Task OperationTransformer_AuthorizeWithoutScheme_AddsBearerOnly()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "Account",
            httpMethod: "GET",
            metadata: new object[] { new AuthorizeAttribute() });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.NotNull(op.Security);
        Assert.Single(op.Security!);
        Assert.Equal(new[] { SecuritySchemeDocumentTransformer.BearerScheme }, SchemeIds(op.Security!));
    }

    [Fact]
    public async Task OperationTransformer_AuthorizeWithBearerScheme_AddsBearerOnly()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "Account",
            httpMethod: "GET",
            metadata: new object[] { new AuthorizeAttribute { AuthenticationSchemes = "Bearer" } });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.Equal(new[] { SecuritySchemeDocumentTransformer.BearerScheme }, SchemeIds(op.Security!));
    }

    [Fact]
    public async Task OperationTransformer_AuthorizeWithApiTokenScheme_NpmGet_AddsBearerAndApiToken_NoNuGetKey()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "Npm",
            httpMethod: "GET",
            metadata: new object[]
            {
                new AuthorizeAttribute { AuthenticationSchemes = TokenAuthenticationDefaults.Scheme },
            });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.Equal(
            new[]
            {
                SecuritySchemeDocumentTransformer.BearerScheme,
                SecuritySchemeDocumentTransformer.ApiTokenScheme,
            },
            SchemeIds(op.Security!));
    }

    [Fact]
    public async Task OperationTransformer_PyPiPush_GetsBearerAndApiToken_NoNuGetKey()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "PyPi",
            httpMethod: "POST",
            metadata: new object[]
            {
                new AuthorizeAttribute { AuthenticationSchemes = TokenAuthenticationDefaults.Scheme },
            });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.Equal(
            new[]
            {
                SecuritySchemeDocumentTransformer.BearerScheme,
                SecuritySchemeDocumentTransformer.ApiTokenScheme,
            },
            SchemeIds(op.Security!));
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("put")]  // case-insensitive HTTP method
    [InlineData("delete")]
    public async Task OperationTransformer_NuGetPushOrUnlist_AddsAllThreeSchemes(string method)
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "NuGet",
            httpMethod: method,
            metadata: new object[]
            {
                new AuthorizeAttribute { AuthenticationSchemes = TokenAuthenticationDefaults.Scheme },
            });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.Equal(
            new[]
            {
                SecuritySchemeDocumentTransformer.BearerScheme,
                SecuritySchemeDocumentTransformer.ApiTokenScheme,
                SecuritySchemeDocumentTransformer.NuGetApiKeyScheme,
            },
            SchemeIds(op.Security!));
    }

    [Fact]
    public async Task OperationTransformer_NuGetController_CaseInsensitiveMatch_AddsNuGetKey()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "nuget",  // lowercase, but matched case-insensitively
            httpMethod: "PUT",
            metadata: new object[]
            {
                new AuthorizeAttribute { AuthenticationSchemes = TokenAuthenticationDefaults.Scheme },
            });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.Contains(SecuritySchemeDocumentTransformer.NuGetApiKeyScheme, SchemeIds(op.Security!));
    }

    [Fact]
    public async Task OperationTransformer_NuGetGet_DoesNotAddNuGetKey()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "NuGet",
            httpMethod: "GET",
            metadata: new object[]
            {
                new AuthorizeAttribute { AuthenticationSchemes = TokenAuthenticationDefaults.Scheme },
            });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.DoesNotContain(SecuritySchemeDocumentTransformer.NuGetApiKeyScheme, SchemeIds(op.Security!));
    }

    [Fact]
    public async Task OperationTransformer_NonNuGetController_PutMethod_DoesNotAddNuGetKey()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "Npm",
            httpMethod: "PUT",
            metadata: new object[]
            {
                new AuthorizeAttribute { AuthenticationSchemes = TokenAuthenticationDefaults.Scheme },
            });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        Assert.DoesNotContain(SecuritySchemeDocumentTransformer.NuGetApiKeyScheme, SchemeIds(op.Security!));
    }

    [Fact]
    public async Task OperationTransformer_NonControllerActionDescriptor_NeverAddsNuGetKey()
    {
        // Minimal API endpoint with [Authorize(ApiToken)] — IsNuGetPushOrUnlist must short-circuit
        // because ActionDescriptor isn't a ControllerActionDescriptor.
        var op = new OpenApiOperation();
        var description = new ApiDescription
        {
            HttpMethod = "PUT",
            ActionDescriptor = new Microsoft.AspNetCore.Mvc.Abstractions.ActionDescriptor
            {
                EndpointMetadata = new List<object>
                {
                    new AuthorizeAttribute { AuthenticationSchemes = TokenAuthenticationDefaults.Scheme },
                },
            },
        };
        var doc = new OpenApiDocument();
        var ctx = new OpenApiOperationTransformerContext
        {
            Description = description,
            Document = doc,
            DocumentName = "v1",
            ApplicationServices = EmptyServices,
        };

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        string[] ids = SchemeIds(op.Security!);
        Assert.Contains(SecuritySchemeDocumentTransformer.BearerScheme, ids);
        Assert.Contains(SecuritySchemeDocumentTransformer.ApiTokenScheme, ids);
        Assert.DoesNotContain(SecuritySchemeDocumentTransformer.NuGetApiKeyScheme, ids);
    }

    [Fact]
    public async Task OperationTransformer_CommaSeparatedSchemes_RecognizesApiToken()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "Npm",
            httpMethod: "GET",
            metadata: new object[]
            {
                new AuthorizeAttribute { AuthenticationSchemes = $"Bearer , {TokenAuthenticationDefaults.Scheme}" },
            });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        string[] ids = SchemeIds(op.Security!);
        Assert.Contains(SecuritySchemeDocumentTransformer.ApiTokenScheme, ids);
        Assert.Contains(SecuritySchemeDocumentTransformer.BearerScheme, ids);
    }

    [Fact]
    public async Task OperationTransformer_MultipleAuthorizeAttributes_MergesSchemes()
    {
        var op = new OpenApiOperation();
        var ctx = BuildOperationContext(
            controllerName: "Npm",
            httpMethod: "GET",
            metadata: new object[]
            {
                new AuthorizeAttribute { AuthenticationSchemes = "Bearer" },
                new AuthorizeAttribute { AuthenticationSchemes = TokenAuthenticationDefaults.Scheme },
            });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        string[] ids = SchemeIds(op.Security!);
        Assert.Contains(SecuritySchemeDocumentTransformer.BearerScheme, ids);
        Assert.Contains(SecuritySchemeDocumentTransformer.ApiTokenScheme, ids);
    }

    [Fact]
    public async Task OperationTransformer_PreservesPreExistingSecurity()
    {
        var op = new OpenApiOperation
        {
            Security = new List<OpenApiSecurityRequirement>
            {
                new(),
            },
        };
        var ctx = BuildOperationContext(
            controllerName: "Account",
            httpMethod: "GET",
            metadata: new object[] { new AuthorizeAttribute() });

        await new SecuritySchemeOperationTransformer().TransformAsync(op, ctx, CancellationToken.None);

        // Existing requirement preserved, new Bearer requirement appended.
        Assert.Equal(2, op.Security!.Count);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static IServiceProvider EmptyServices { get; } = new ServiceCollection().BuildServiceProvider();

    private static OpenApiDocumentTransformerContext BuildDocumentContext(string documentName = "v1")
    {
        return new OpenApiDocumentTransformerContext
        {
            DocumentName = documentName,
            DescriptionGroups = new List<ApiDescriptionGroup>(),
            ApplicationServices = EmptyServices,
        };
    }

    private static OpenApiOperationTransformerContext BuildOperationContext(
        string controllerName,
        string httpMethod,
        object[] metadata)
    {
        var actionDescriptor = new ControllerActionDescriptor
        {
            ControllerName = controllerName,
            ActionName = "Action",
            EndpointMetadata = new List<object>(metadata),
        };
        var description = new ApiDescription
        {
            HttpMethod = httpMethod,
            ActionDescriptor = actionDescriptor,
        };
        var doc = new OpenApiDocument
        {
            Components = new OpenApiComponents
            {
                SecuritySchemes = new Dictionary<string, IOpenApiSecurityScheme>
                {
                    [SecuritySchemeDocumentTransformer.BearerScheme] = new OpenApiSecurityScheme { Type = SecuritySchemeType.Http, Scheme = "bearer" },
                    [SecuritySchemeDocumentTransformer.ApiTokenScheme] = new OpenApiSecurityScheme { Type = SecuritySchemeType.Http, Scheme = "bearer" },
                    [SecuritySchemeDocumentTransformer.NuGetApiKeyScheme] = new OpenApiSecurityScheme { Type = SecuritySchemeType.ApiKey, In = ParameterLocation.Header, Name = "X-NuGet-ApiKey" },
                },
            },
        };
        return new OpenApiOperationTransformerContext
        {
            Description = description,
            Document = doc,
            DocumentName = "v1",
            ApplicationServices = EmptyServices,
        };
    }

    private static string[] SchemeIds(IList<OpenApiSecurityRequirement> security)
    {
        var ids = new List<string>();
        foreach (var requirement in security)
        {
            foreach (var key in requirement.Keys)
            {
                if (key is OpenApiSecuritySchemeReference reference && reference.Reference?.Id is { } id)
                {
                    ids.Add(id);
                }
            }
        }
        return ids.ToArray();
    }
}
