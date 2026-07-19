using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers Kestrel limits, forwarded-header processing, and host filtering.
/// </summary>
public static class NetworkStartupExtensions
{
    // Kestrel connection ceiling default (covers normal enterprise CI burst while bounding
    // memory under adversarial slow-client load; override via KESTREL_MAX_CONNECTIONS).
    private const long KestrelMaxConnectionsDefault = 10_000;

    public static void ConfigureDependablyKestrel(this WebApplicationBuilder builder)
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
    public static void ConfigureDependablyForwardedHeaders(this WebApplicationBuilder builder)
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

    // Host filtering — derives AllowedHosts from the host portion of BASE_URL so Kestrel rejects
    // unknown Host headers before tenant resolution, preventing Host-header injection into SAML SP
    // URLs, absolute links, and CSRF Origin comparisons. Single mode permits the apex host and
    // localhost; multi mode additionally permits *.apex (all tenant subdomains). When BASE_URL is
    // unset or contains a localhost host (dev/local mode), no apex is derivable and filtering fails
    // closed to the loopback hostnames only — never "*" — so a reverse-proxied deployment that never
    // configures BASE_URL has every non-loopback Host header rejected rather than silently accepted.
    // Multi mode additionally permits *.localhost so the local subdomain-per-tenant dev loop keeps
    // working without a real BASE_URL. Any host configured via HOST_ROUTING is always permitted in
    // addition to the apex/loopback set — those hostnames (e.g. registry.npmjs.org) are explicit,
    // operator-configured transparent-intercept targets, not attacker input, and arrive as the raw
    // Host header ahead of TransparentInterceptMiddleware's rewrite. StartupService logs a warning
    // explaining how to set BASE_URL. AllowEmptyHosts=false ensures requests with no Host header are
    // always rejected rather than passed through silently.
    //
    // Implementation note: ASP.NET Core's GenericWebHostBuilder registers a PostConfigure that binds
    // AllowedHosts from IConfiguration, overwriting any earlier Configure<> call. Setting the value
    // directly in the in-memory configuration layer ensures the framework's own PostConfigure reads
    // the derived allowlist rather than the appsettings.json default "*".
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    public static void ConfigureDependablyHostFiltering(this WebApplicationBuilder builder)
    {
        string? apex = ResolveApexHostName(builder.Configuration);
        string? deploymentMode = (builder.Configuration["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();

        List<string> allowed;
        if (string.IsNullOrEmpty(apex))
        {
            // No usable apex — fail closed to the loopback hostnames only. StartupService logs a
            // warning at startup pointing the operator at BASE_URL.
            allowed = ["localhost", "127.0.0.1", "[::1]"];

            if (deploymentMode == "multi")
            {
                // Local multi-tenant dev loop: subdomains of the loopback hostname route by tenant
                // slug the same way *.apex does once BASE_URL names a real domain.
                allowed.Add("*.localhost");
            }
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

        allowed.AddRange(ParseHostRoutingHosts(builder.Configuration["HOST_ROUTING"]));

        // Override the AllowedHosts configuration value so the framework's PostConfigure reads
        // the derived list, and explicitly configure AllowEmptyHosts=false.
        builder.Configuration["AllowedHosts"] = string.Join(";", allowed);
        builder.Services.PostConfigure<Microsoft.AspNetCore.HostFiltering.HostFilteringOptions>(
            options => options.AllowEmptyHosts = false);
    }

    // Resolves the apex hostname from the host portion of BASE_URL, excluding localhost variants
    // which are not a real apex for filtering purposes. Returns null when no non-localhost apex
    // is available (dev/unconfigured deployments).
    private static string? ResolveApexHostName(ConfigurationManager configuration)
    {
        string? host = BaseUrlHostHelper.ExtractHost(configuration["BASE_URL"]);
        return host is not null
            and not "localhost"
            and not "127.0.0.1"
            and not "[::1]"
            ? host : null;
    }

    // Extracts just the host keys out of HOST_ROUTING ("host=ecosystem" pairs) for the host-filter
    // allowlist. Tolerant of malformed entries — HostEcosystemMap owns strict validation of the same
    // config value; a best-effort host list here only widens what Kestrel accepts, it never narrows it.
    private static IEnumerable<string> ParseHostRoutingHosts(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            yield break;
        }

        foreach (string pair in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = pair.IndexOf('=');
            string host = (eq > 0 ? pair[..eq] : pair).Trim();
            if (host.Length > 0)
            {
                yield return host;
            }
        }
    }
}
