using Dependably.Infrastructure.Audit;
using Dependably.Protocol;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Infrastructure;

/// <summary>
/// IServiceCollection extension methods that group Core DI registrations by subsystem.
/// Used from <c>Program.ConfigureBuilder</c> so the bootstrap reads as a discoverable
/// list of subsystem wires (AddRepositories → AddVulnerabilityScanning → AddThreatFeeds)
/// rather than a wall of AddSingleton calls. Management-plane wiring (SIEM, webhook dispatch,
/// invite mail, management repositories) lives in the Dependably.Management assembly.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Core <c>*Repository</c> set + the async batched writers + per-tier storage
    /// repositories. Singleton because repositories hold no per-request state — they take
    /// <see cref="IMetadataStore"/> and open a fresh connection per call. Management-only
    /// repositories (org settings, SAML config, invites, banners, webhook subscriptions, …) are
    /// registered by the management wiring in Dependably.Management.
    /// </summary>
    public static IServiceCollection AddDependablyRepositories(
        this IServiceCollection services, IConfiguration config)
    {
        // Core repositories
        // The session-validity cache is dropped on a deployment with peer replicas so a
        // revocation performed on one replica binds on every other one's next request
        // instead of after its TTL — see SessionRevocationCachePolicy.
        services.AddSingleton(sp => new UserTokenVersionStore(
            sp.GetRequiredService<IMetadataStore>(),
            SessionRevocationCachePolicy.SessionCacheOrNull(sp)));
        services.AddSingleton<OrgRepository>();
        services.AddSingleton<ArtifactInventoryRepository>();
        services.AddSingleton<PackageRepository>();
        services.AddSingleton<PackageVersionFilesRepository>();
        services.AddSingleton<NuGetSymbolIndexRepository>();
        // Scoped, not singleton: it resolves IBlobStore, which is request-scoped for the
        // tier-resolving decorator.
        services.AddScoped<NuGetSymbolIndexer>();
        services.AddSingleton<StatsSnapshotRepository>();
        services.AddSingleton<OrgStatsHistoryRepository>();
        services.AddSingleton<TokenRepository>();
        // Async batched activity writer. The hosted service drains the channel into
        // batched INSERTs so the download/push hot paths no longer block on a SQLite
        // writer-lock acquisition per row. Capacity is operator-configurable via
        // ACTIVITY_WRITER_QUEUE_CAPACITY; defaults to ActivityWriter.DefaultChannelCapacity.
        int activityCapacity = int.TryParse(config["ACTIVITY_WRITER_QUEUE_CAPACITY"], out int ac) && ac > 0
            ? ac : ActivityWriter.DefaultChannelCapacity;
        services.AddSingleton(new ActivityWriter(activityCapacity));
        services.AddSingleton<ActivityWriterHostedService>();
        services.AddHostedService(sp => sp.GetRequiredService<ActivityWriterHostedService>());
        // Async batched download-count writer. The hosted service aggregates increments
        // per versionId/purl within each drain batch and issues one UPDATE per unique key,
        // removing synchronous DB writes from every download-serve path. Capacity is
        // configurable via DOWNLOAD_COUNT_WRITER_QUEUE_CAPACITY.
        int downloadCapacity = int.TryParse(config["DOWNLOAD_COUNT_WRITER_QUEUE_CAPACITY"], out int dc) && dc > 0
            ? dc : DownloadCountWriter.DefaultChannelCapacity;
        services.AddSingleton(new DownloadCountWriter(downloadCapacity));
        services.AddSingleton<DownloadCountWriterHostedService>();
        services.AddHostedService(sp => sp.GetRequiredService<DownloadCountWriterHostedService>());
        services.AddSingleton<AuditRepository>();
        services.AddSingleton<AuditEventRepository>();
        services.AddSingleton<Privacy.PersonalDataExportRepository>();
        services.AddSingleton<BackgroundJobRunRepository>();
        services.AddSingleton<AllowlistRepository>();
        services.AddSingleton<BlocklistRepository>();
        services.AddSingleton<Dependably.Protocol.ReservedNamespaceService>();
        services.AddSingleton<Dependably.Protocol.InstallScriptAllowlistService>();
        services.AddSingleton<QuarantineRepository>();
        services.AddSingleton<Alerts.AlertRepository>();
        services.AddSingleton<Alerts.AlertService>();
        services.AddSingleton<UpstreamRegistryRepository>();
        services.AddSingleton<TrustAnchorRepository>();
        services.AddSingleton<IPerOrgTrustAnchorStore, PerOrgTrustAnchorStore>();
        services.AddSingleton<LicenseRepository>();
        services.AddSingleton<SpdxLicenseSeeder>();
        services.AddSingleton<ProxyVersionRecorder>();
        services.AddSingleton<SourcePinRepository>();
        // Operator opt-ins for weak-digest acceptance (npm SHA-1 shasum, apk SHA-1 index
        // signatures). Singleton so the once-per-process acceptance/refusal warnings latch once.
        services.AddSingleton<Dependably.Security.WeakAlgorithmAcceptance>();
        services.AddSingleton<Dependably.Storage.ProxyFetchService>();

        // Two-tier storage formalisation
        services.AddSingleton<CacheArtifactRepository>();
        services.AddSingleton<TenantArtifactAccessRepository>();
        services.AddSingleton<CacheAccessRecorder>();
        // Serialises the shared-key refcount check + physical delete of a content-addressed
        // proxy-cache blob key; shared by the LRU eviction pass and the local_only claim purge so
        // both agree on one physical blob before either deletes it.
        services.AddSingleton<CacheBlobKeyLock>();
        // The only physical proxy-cache blob delete — both cache-tier eviction paths route
        // through it for the locked refcount guard.
        services.AddSingleton<CacheOrphanBlobDeleter>();

        // Name-claim mechanism
        services.AddSingleton<ClaimRepository>();
        // Name-ownership binding store. Registered here (alongside ClaimRepository) rather than in
        // the publish pipeline because ClaimResolver depends on it for the resurrection tombstone,
        // and ClaimResolver is composed in every deployment mode.
        services.AddSingleton<NameBindingRepository>();
        // Version-granular delete tombstones, read by the publish dedup/overwrite gate.
        services.AddSingleton<VersionTombstoneRepository>();
        services.AddSingleton<ClaimResolver>();
        services.AddSingleton<NpmDistTagRepository>();
        services.AddSingleton<CargoMetadataRepository>();

        // Projects plane — the application/collection tree the SBOM/VEX/SARIF documents hang off,
        // and the policy evaluation that stamps their component findings.
        services.AddSingleton<ProjectRepository>();
        services.AddSingleton<SbomPolicyRepository>();
        services.AddSingleton<Dependably.Protocol.SbomPolicyEvaluationService>();

        return services;
    }

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
