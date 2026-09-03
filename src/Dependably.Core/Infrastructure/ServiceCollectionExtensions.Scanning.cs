using Dependably.Protocol;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Infrastructure;

// Split from ServiceCollectionExtensions.cs to keep the class's dependency coupling spread
// across files below the S1200 threshold; see that file for the repository registrations.
public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// OSV source + scanner. The hosted-service registration re-uses the singleton
    /// <see cref="VulnerabilityScanService"/> so controllers and the background worker
    /// share one instance. <c>OSV_MODE=local</c> binds <see cref="LocalOsvSource"/>;
    /// any other value binds <see cref="OsvClient"/> and registers the named "osv"
    /// HttpClient against <paramref name="remoteBaseUrl"/>.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Trailing '/' is required for HttpClient.BaseAddress to resolve relative URIs correctly; the host portion is config-driven.")]
    public static IServiceCollection AddDependablyVulnerabilityScanning(
        this IServiceCollection services,
        IConfiguration config,
        string remoteBaseUrl)
    {
        services.AddSingleton<VulnerabilityRepository>();

        // The one instance-level vulnerability-tracker connection behind the NVD-band/SSVC
        // enrichment overlay. Registered unconditionally and resolved lazily from
        // instance_settings: with no base URL stored the resolver reports Configured = false and
        // no request is ever made, so an unconfigured deployment carries no cost and no behaviour
        // change. Edited only from the apex system surface (multi mode) or the instance surface
        // (single mode) — never per-org.
        services.AddSingleton(sp => new Dependably.Infrastructure.VulnTracker.InstanceVulnTrackerConfig(
            sp.GetRequiredService<OrgRepository>().GetInstanceSettingAsync,
            sp.GetRequiredService<TimeProvider>()));

        // Observed health of that same connection. Registered unconditionally too: on a
        // deployment with no tracker configured the enrichment pass returns before it ever
        // reaches a lookup, so nothing is written and both tables stay empty — which is what
        // lets the read surfaces tell "never configured" apart from "configured and failing".
        services.AddSingleton<Dependably.Infrastructure.VulnTracker.VulnTrackerHealthRepository>();

        // The enrichment client itself. Registered unconditionally alongside the resolver above,
        // and just as inert without one: it re-reads the connection on every call and returns an
        // unreached result without dialing when there is none. The named client carries transport
        // posture only — no BaseAddress, because the address is instance state an operator edits
        // without a restart.
        services.TryAddSingleton(new Dependably.Security.SsrfConnectCallback(Dependably.Security.SsrfGuard.IsBlockedIp));
        services.AddHttpClient(
            Dependably.Infrastructure.VulnTracker.VulnTrackerEnrichmentClient.HttpClientName,
            client =>
            {
                client.Timeout = TimeSpan.FromSeconds(30);
                // A tracker answer is bounded metadata like every other upstream metadata read;
                // an oversized body fails the read rather than being buffered without limit.
                client.MaxResponseContentBufferSize = Dependably.Protocol.UpstreamClient.MaxMetadataResponseBytes;
            })
        // SSRF posture, and it is deliberately NOT the one the "osv" and "threatfeed" clients
        // use. Those dial public internet hosts (osv.dev, FIRST, CISA), where a private or
        // loopback address can only mean something has gone wrong. The tracker is the opposite:
        // it is a self-hosted sidecar, and a private or loopback address is its normal shape.
        // Sharing the app-wide guard made every private deployment — loopback, RFC 1918, and a
        // compose service name alike — fail to connect, with no configuration that lifted it.
        //
        // So this client gets the operator-endpoint predicate: the instance-metadata range stays
        // blocked, because a request forged through this path to IMDS would be a real escalation,
        // and everything else an operator can name is permitted. The URL is apex-only,
        // system-scoped instance configuration, not an attacker-influenced input.
        //
        // AllowAutoRedirect=false is kept for the reason it always applied: a 3xx must not
        // forward a bearer-credentialed request to a different host without re-validation.
        .ConfigurePrimaryHttpMessageHandler(sp => new SocketsHttpHandler
        {
            // UseProxy=false: an ambient HTTP(S)_PROXY would make ConnectCallback vet the proxy, not the target.
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectCallback = sp.GetRequiredService<Dependably.Security.OperatorEndpointConnectGate>()
                .Callback.ConnectAsync,
        });
        // TryAdd so a test can substitute the gate and assert the client really is gated. An
        // explicit factory, not the bare generic form: OperatorEndpointConnectGate has a second,
        // DI-injectable constructor for that test substitution, and an SsrfConnectCallback
        // singleton (the strict, tenant-facing one) is already registered above — the container's
        // default constructor selection picks the constructor with the most resolvable
        // parameters, so the bare form silently wires the strict guard in here instead of the
        // parameterless constructor's SsrfGuard.IsBlockedIpForOperatorEndpoint. The factory forces
        // the parameterless constructor explicitly.
        services.TryAddSingleton(_ => new Dependably.Security.OperatorEndpointConnectGate());
        services.AddSingleton<Dependably.Infrastructure.VulnTracker.VulnTrackerEnrichmentClient>();
        services.AddSingleton<Dependably.Protocol.IVulnerabilityEnrichmentSource>(sp =>
            sp.GetRequiredService<Dependably.Infrastructure.VulnTracker.VulnTrackerEnrichmentClient>());

        // Auto-select local OSV when AIR_GAPPED=true and OSV_MODE is not explicitly set,
        // preventing outbound OSV.dev calls in air-gapped deployments.
        bool airGapped = string.Equals(config["AIR_GAPPED"], "true", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(config["AIR_GAPPED"], "1", StringComparison.OrdinalIgnoreCase);
        string? osvModeRaw = config["OSV_MODE"];
        string osvMode = !string.IsNullOrWhiteSpace(osvModeRaw) ? osvModeRaw.Trim().ToLowerInvariant() : airGapped ? "local" : "remote";
        if (osvMode == "local")
        {
            services.AddSingleton<LocalOsvSource>();
            services.AddSingleton<IOsvSource>(sp => sp.GetRequiredService<LocalOsvSource>());
        }
        else
        {
            services.AddSingleton<OsvClient>();
            services.AddSingleton<IOsvSource>(sp => sp.GetRequiredService<OsvClient>());

            string baseUrl = remoteBaseUrl.EndsWith('/') ? remoteBaseUrl : remoteBaseUrl + "/";
            // TryAdd keeps the extension usable standalone (tests, future hosts) while the
            // app-level registration wins.
            services.TryAddSingleton(new Dependably.Security.SsrfConnectCallback(Dependably.Security.SsrfGuard.IsBlockedIp));
            services.AddHttpClient("osv", client =>
            {
                client.BaseAddress = new Uri(baseUrl);
                client.Timeout = TimeSpan.FromSeconds(30);
                // Cap buffered OSV response bodies to the same limit as other upstream
                // metadata reads. ReadAsStringAsync buffers through this cap and throws
                // HttpRequestException when a response exceeds it.
                client.MaxResponseContentBufferSize = Dependably.Protocol.UpstreamClient.MaxMetadataResponseBytes;
            })
            // SSRF defense-in-depth: OSV_BASE_URL is operator-supplied, but it must not
            // be routable to private/link-local ranges — same shared connect-time gate
            // as the upstream proxy clients. Public endpoints (api.osv.dev) pass.
            // AllowAutoRedirect=false so an upstream 3xx cannot forward the request to a
            // different host without re-validation, matching every sibling outbound client.
            .ConfigurePrimaryHttpMessageHandler(sp => new SocketsHttpHandler
            {
                // UseProxy=false: an ambient HTTP(S)_PROXY would make ConnectCallback vet the proxy, not the target.
                UseProxy = false,
                AllowAutoRedirect = false,
                ConnectCallback = sp.GetRequiredService<Dependably.Security.SsrfConnectCallback>().ConnectAsync,
            });
        }

        // SBOM component scan-result persistence and the shared OSV batch-scan primitive — used
        // by this service's nightly third pass and by the Management-plane SbomScanWorker.
        services.AddSingleton<SbomComponentVulnRepository>();
        services.AddSingleton<SbomComponentScanner>();

        services.AddSingleton<VulnerabilityScanService.Dependencies>();
        services.AddSingleton<VulnerabilityScanService>();
        services.AddHostedService(sp => sp.GetRequiredService<VulnerabilityScanService>());
        return services;
    }

    /// <summary>
    /// Registers the threat-feed enrichment pipeline: the named "threatfeed" HttpClient (KEV
    /// catalog + EPSS API, same SSRF connect-time guard as the OSV client),
    /// <see cref="HttpThreatFeedSource"/>, and <see cref="ThreatFeedRefreshService"/> as a
    /// hosted service. Air-gapped instances keep the registration — the service checks
    /// <see cref="IAirGapMode.IsJobDisabled"/> at run time and skips its passes.
    /// </summary>
    public static IServiceCollection AddDependablyThreatFeeds(this IServiceCollection services)
    {
        services.TryAddSingleton(new Dependably.Security.SsrfConnectCallback(Dependably.Security.SsrfGuard.IsBlockedIp));
        services.AddHttpClient("threatfeed", client => client.Timeout = TimeSpan.FromSeconds(60))
        // SSRF defense-in-depth: KEV_FEED_URL / EPSS_API_URL are operator-supplied, but they
        // must not be routable to private/link-local ranges — same shared connect-time gate
        // as the OSV and upstream proxy clients. AllowAutoRedirect=false so an upstream 3xx
        // cannot forward the request to a different host without re-validation.
        .ConfigurePrimaryHttpMessageHandler(sp => new SocketsHttpHandler
        {
            // UseProxy=false: an ambient HTTP(S)_PROXY would make ConnectCallback vet the proxy, not the target.
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectCallback = sp.GetRequiredService<Dependably.Security.SsrfConnectCallback>().ConnectAsync,
        });

        services.AddSingleton<IThreatFeedSource, HttpThreatFeedSource>();
        services.AddSingleton<ThreatFeedRefreshService>();
        services.AddHostedService(sp => sp.GetRequiredService<ThreatFeedRefreshService>());
        return services;
    }
}
