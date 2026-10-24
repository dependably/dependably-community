using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Public, unauthenticated bootstrap endpoint. The frontend calls this on mount to learn:
///   - which deployment mode the server is in (single | multi)
///   - whether the current request lives at apex (system surface) or a tenant subdomain
///   - the apex hostname and the tenant domain tenants resolve under (for clients that need to
///     construct cross-host URLs or derive the tenant slug in multi mode; the tenant domain
///     equals the apex unless TENANT_DOMAIN is set)
///
/// Single-mode response includes <c>tenantSlug</c> (only one tenant; not sensitive). Multi-mode
/// responses *omit* <c>tenantSlug</c> on tenant subdomain hits — the slug is in the URL the
/// caller already used; echoing it back to unauthenticated callers turns the endpoint into an
/// existence oracle. The SPA infers tenant identity from <c>window.location.hostname</c>.
///
/// Both <c>multi</c> and <c>header</c> DEPLOYMENT_MODE values are reported as <c>multi</c>
/// to the frontend — they share the same multi-tenant UI surface.
/// </summary>
[ApiController]
// authz-ok: the SPA's pre-login bootstrap probe — it must answer before any credential
// exists. Returns deployment mode and the apex and tenant-domain hosts only; the tenant slug is withheld on
// multi-mode tenant hits so it is not an existence oracle.
[AllowAnonymous]
[EnableRateLimiting("anon")]
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
        string mode = ResolveMode(_config);
        var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;
        bool airGapped = _airGap.IsEnabled;
        // True only when both runtime and config agree the connection is plain HTTP.
        // Avoids false positives on legitimate reverse-proxy setups where Request.IsHttps=true
        // but BASE_URL hasn't been updated yet.
        bool insecureHttp = !HttpContext.Request.IsHttps && !_urls.IsHttpsDeployment;

        Response.Headers.CacheControl = "no-store";

        if (mode == "multi")
        {
            string? apexHost = ResolveApexHost(_config);
            // TENANT_DOMAIN is a multi-mode setting; header mode reports the apex as the tenant
            // parent so a stray value cannot change the SPA's host-derived slug.
            string? tenantDomain = IsMultiDeployment(_config)
                ? BaseUrlHostHelper.ResolveTenantDomain(_config)
                : apexHost;
            if (ctx is not null && ctx.IsApex)
            {
                return Ok(new
                {
                    mode = "multi",
                    apexHost,
                    tenantDomain,
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
                tenantDomain,
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
        string raw = (config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        return raw is "multi" or "header" ? "multi" : "single";
    }

    private static bool IsMultiDeployment(IConfiguration config)
        => string.Equals((config["DEPLOYMENT_MODE"] ?? "single").Trim(), "multi", StringComparison.OrdinalIgnoreCase);

    internal static string? ResolveApexHost(IConfiguration config)
        => BaseUrlHostHelper.ResolveApexHost(config);
}
