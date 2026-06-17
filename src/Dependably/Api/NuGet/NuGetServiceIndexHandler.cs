using Dependably.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Handles GET /nuget/v3/index.json and /nuget/index.json — returns the NuGet v3 service index
/// advertising all supported resource endpoints for this instance.
/// </summary>
public sealed class NuGetServiceIndexHandler(IPublicUrlBuilder urls)
{
    public IActionResult Handle(HttpContext httpContext)
    {
        string baseUrl = urls.Absolute(httpContext, "/nuget");

        static Dictionary<string, string> R(string id, string type) =>
            new() { ["@id"] = id, ["@type"] = type };

        // Advertise both registration resource types so SemVer 2-aware clients pick the
        // semver2 base URL (which we serve from the registration5-{,gz-}semver2 alias),
        // while older clients keep using the unversioned RegistrationsBaseUrl.
        // Catalog (Catalog/3.0.0) is intentionally not advertised — catalog-based mirroring
        // is unsupported; clients that require it must use a full catalog-publishing registry.
        return new JsonResult(new
        {
            version = "3.0.0",
            resources = new[]
            {
                R($"{baseUrl}/query",                       "SearchQueryService"),
                R($"{baseUrl}/autocomplete",                "SearchAutocompleteService"),
                R($"{baseUrl}/autocomplete",                "SearchAutocompleteService/3.0.0-beta"),
                R($"{baseUrl}/registration",                "RegistrationsBaseUrl"),
                R($"{baseUrl}/registration5-gz-semver2",    "RegistrationsBaseUrl/3.6.0"),
                R($"{baseUrl}/flatcontainer",               "PackageBaseAddress/3.0.0"),
                R($"{baseUrl}/publish",                     "PackagePublish/2.0.0"),
                R($"{baseUrl}/symbols",                     "SymbolPackagePublish/4.9.0")
            }
        });
    }
}
