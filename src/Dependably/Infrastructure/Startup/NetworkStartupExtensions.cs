using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.HttpOverrides;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers Kestrel limits, forwarded-header processing, and host filtering.
/// </summary>
internal static class NetworkStartupExtensions
{
    // Kestrel connection ceiling default (covers normal enterprise CI burst while bounding
    // memory under adversarial slow-client load; override via KESTREL_MAX_CONNECTIONS).
    private const long KestrelMaxConnectionsDefault = 10_000;

    internal static void ConfigureDependablyKestrel(this WebApplicationBuilder builder)
    {
        // Kestrel connection ceiling: caps the number of open TCP connections to prevent
        // connection-table exhaustion under a slow-client (slowloris) flood. Reads
        // KESTREL_MAX_CONNECTIONS from config; defaults to 10 000, which covers a normal
        // enterprise CI burst while bounding memory under adversarial load. Set to 0 to
        // remove the limit (not recommended on constrained hosts).
        long maxConn = long.TryParse(builder.Configuration["KESTREL_MAX_CONNECTIONS"], out long mc) && mc >= 0
            ? mc == 0 ? long.MaxValue : mc
            : KestrelMaxConnectionsDefault;
        builder.WebHost.ConfigureKestrel(opts =>
        {
            opts.AddServerHeader = false;
            opts.Limits.MaxConcurrentConnections = maxConn == long.MaxValue ? null : maxConn;
        });
    }

    // Forwarded headers — fail-closed design: forwarded-header processing is disabled when
    // TRUSTED_PROXIES is unset, so Connection.RemoteIpAddress stays the real socket peer and
    // Request.Host/Scheme stay the raw connection values. This prevents a remote caller from
    // spoofing the /metrics and /version IP allowlist, forging audit source_ip, or poisoning
    // per-IP rate-limit keys by injecting X-Forwarded-For with a loopback address. When
    // TRUSTED_PROXIES is set, X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host are
    // processed only from the listed IPs/CIDRs, and the full hop chain is walked (ForwardLimit=null).
    // X-Forwarded-Host is included so SubdomainTenantResolver reads the rewritten Request.Host
    // rather than the raw header, keeping proxy-allowlist validation consistent across all
    // consumers of Request.Host.
    internal static void ConfigureDependablyForwardedHeaders(this WebApplicationBuilder builder)
    {
        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.KnownIPNetworks.Clear();
            options.KnownProxies.Clear();

            var (networks, proxies) = ConfigurationExtensions.ParseTrustedProxies(builder.Configuration["TRUSTED_PROXIES"]);
            if (networks.Count > 0 || proxies.Count > 0)
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;

                foreach (var n in networks)
                {
                    options.KnownIPNetworks.Add(n);
                }

                foreach (var p in proxies)
                {
                    options.KnownProxies.Add(p);
                }

                options.ForwardLimit = null; // walk the chain to the first untrusted hop
            }
            else
            {
                // No trusted proxies configured — disable all forwarded-header processing.
                // RemoteIpAddress, Host, and Scheme reflect the real socket peer; caller-supplied
                // X-Forwarded-* headers are ignored. StartupService logs a warning explaining
                // what to set for reverse-proxy deployments.
                options.ForwardedHeaders = ForwardedHeaders.None;
            }
        });
    }

    // Host filtering — derives AllowedHosts from APEX_HOST / BASE_URL so Kestrel rejects unknown
    // Host headers before tenant resolution, preventing Host-header injection into SAML SP URLs,
    // absolute links, and CSRF Origin comparisons. Single mode permits the apex host and localhost;
    // multi mode additionally permits *.apex (all tenant subdomains). When neither APEX_HOST nor a
    // non-localhost BASE_URL is configured (dev/local mode), AllowedHosts stays "*" and a startup
    // warning is logged via StartupService — the permissive fallback keeps the local dev loop working
    // without requiring configuration. AllowEmptyHosts=false ensures requests with no Host header are
    // always rejected rather than passed through silently.
    //
    // Implementation note: ASP.NET Core's GenericWebHostBuilder registers a PostConfigure that binds
    // AllowedHosts from IConfiguration, overwriting any earlier Configure<> call. Setting the value
    // directly in the in-memory configuration layer ensures the framework's own PostConfigure reads
    // the derived allowlist rather than the appsettings.json default "*".
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    internal static void ConfigureDependablyHostFiltering(this WebApplicationBuilder builder)
    {
        string? apex = ResolveApexHostName(builder.Configuration);
        string? deploymentMode = (builder.Configuration["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();

        List<string> allowed;
        if (string.IsNullOrEmpty(apex))
        {
            // No usable apex — permissive fallback. StartupService logs a warning at startup.
            allowed = ["*"];
        }
        else
        {
            // Apex host accepted in all modes; localhost variants accepted for health-check routes.
            allowed = [apex, "localhost", "127.0.0.1", "[::1]"];

            if (deploymentMode == "multi")
            {
                // Wildcard subdomain: each tenant is reached at <slug>.<apex>.
                allowed.Add($"*.{apex}");
            }
        }

        // Override the AllowedHosts configuration value so the framework's PostConfigure reads
        // the derived list, and explicitly configure AllowEmptyHosts=false.
        builder.Configuration["AllowedHosts"] = string.Join(";", allowed);
        builder.Services.PostConfigure<Microsoft.AspNetCore.HostFiltering.HostFilteringOptions>(
            options => options.AllowEmptyHosts = false);
    }

    // Resolves the apex hostname from APEX_HOST (explicit) or the host portion of BASE_URL,
    // excluding localhost variants which are not a real apex for filtering purposes. Returns null
    // when no non-localhost apex is available (dev/unconfigured deployments).
    private static string? ResolveApexHostName(ConfigurationManager configuration)
    {
        string? apex = configuration["APEX_HOST"];
        if (!string.IsNullOrWhiteSpace(apex))
        {
            return apex.Trim().TrimEnd('.').ToLowerInvariant();
        }

        string? baseUrl = configuration["BASE_URL"];
        if (!string.IsNullOrWhiteSpace(baseUrl)
            && Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
        {
            string host = uri.Host.ToLowerInvariant();
            if (host is not "localhost" and not "127.0.0.1" and not "[::1]")
            {
                return host;
            }
        }

        return null;
    }
}
