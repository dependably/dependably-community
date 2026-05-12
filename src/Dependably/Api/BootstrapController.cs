using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;

namespace Dependably.Api;

/// <summary>
/// Public, unauthenticated bootstrap endpoint. The frontend calls this on mount to learn:
///   - which deployment mode the server is in (single | multi)
///   - whether the current request lives at apex (system surface) or a tenant subdomain
///   - the apex hostname (for clients that need to construct cross-host URLs in multi mode)
///
/// Single-mode response includes <c>tenantSlug</c> (only one tenant; not sensitive). Multi-mode
/// responses *omit* <c>tenantSlug</c> on tenant subdomain hits — the slug is in the URL the
/// caller already used; echoing it back to unauthenticated callers turns the endpoint into an
/// existence oracle. The SPA infers tenant identity from <c>window.location.hostname</c>.
/// </summary>
[ApiController]
[AllowAnonymous]
public sealed class BootstrapController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly IAirGapMode _airGap;
    private readonly IPublicUrlBuilder _urls;

    public BootstrapController(IConfiguration config, IAirGapMode airGap, IPublicUrlBuilder urls)
    {
        _config = config;
        _airGap = airGap;
        _urls = urls;
    }

    [HttpGet("api/v1/bootstrap")]
    public IActionResult Get()
    {
        var mode = ResolveMode(_config);
        var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;
        var airGapped = _airGap.IsEnabled;
        // True only when both runtime and config agree the connection is plain HTTP.
        // Avoids false positives on legitimate reverse-proxy setups where Request.IsHttps=true
        // but BASE_URL hasn't been updated yet.
        var insecureHttp = !HttpContext.Request.IsHttps && !_urls.IsHttpsDeployment;

        Response.Headers.CacheControl = "no-store";

        if (mode == "multi")
        {
            var apexHost = ResolveApexHost(_config);
            if (ctx is not null && ctx.IsApex)
            {
                return Ok(new
                {
                    mode = "multi",
                    apexHost,
                    isApex = true,
                    airGapped,
                    insecureHttp,
                    capabilities = new { },
                });
            }

            // Tenant subdomain — intentionally omit tenantSlug from the response.
            return Ok(new
            {
                mode = "multi",
                apexHost,
                isApex = false,
                airGapped,
                insecureHttp,
                capabilities = new { },
            });
        }

        // Single mode — include tenantSlug. If FirstBoot has not yet run, slug is null.
        return Ok(new
        {
            mode = "single",
            tenantSlug = ctx?.TenantSlug,
            isApex = false,
            airGapped,
            insecureHttp,
            capabilities = new { },
        });
    }

    internal static string ResolveMode(IConfiguration config)
    {
        var raw = (config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        return raw == "multi" ? "multi" : "single";
    }

    internal static string? ResolveApexHost(IConfiguration config)
    {
        var apex = config["APEX_HOST"];
        if (!string.IsNullOrWhiteSpace(apex)) return apex.Trim().ToLowerInvariant();

        var baseUrl = config["BASE_URL"];
        if (!string.IsNullOrWhiteSpace(baseUrl) &&
            Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
        {
            return uri.Host.ToLowerInvariant();
        }

        return null;
    }
}
