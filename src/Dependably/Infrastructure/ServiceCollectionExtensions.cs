using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Mail;
using Dependably.Infrastructure.Siem;
using Dependably.Protocol;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Infrastructure;

/// <summary>
/// IServiceCollection extension methods that group DI registrations by subsystem.
/// Used from <c>Program.ConfigureBuilder</c> so the bootstrap reads as a discoverable
/// list of subsystem wires (AddRepositories → AddSiemForwarding → AddVulnerabilityScanning)
/// rather than a 100-line wall of AddSingleton calls.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers every <c>*Repository</c> + the audit emitter pair + per-tier storage
    /// repositories. Singleton because repositories hold no per-request state — they
    /// take <see cref="IMetadataStore"/> and open a fresh connection per call.
    /// </summary>
    public static IServiceCollection AddDependablyRepositories(
        this IServiceCollection services, IConfiguration config)
    {
        // Core repositories
        services.AddSingleton<JwtRevocationRepository>();
        services.AddSingleton<UserTokenVersionStore>();
        services.AddSingleton<OrgRepository>();
        services.AddSingleton<OrgSettingsRepository>();
        services.AddSingleton<SystemAdminRepository>();
        services.AddSingleton<PackageRepository>();
        services.AddSingleton<PackageAnalyticsRepository>();
        services.AddSingleton<StatsSnapshotRepository>();
        services.AddSingleton<UserService>();
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
        services.AddSingleton<BackgroundJobRunRepository>();
        services.AddSingleton<IAuditEmitter, AuditEmitter>();
        services.AddSingleton<InviteRepository>();
        services.AddSingleton<AllowlistRepository>();
        services.AddSingleton<BlocklistRepository>();
        services.AddSingleton<Dependably.Protocol.ReservedNamespaceService>();
        services.AddSingleton<Dependably.Protocol.InstallScriptAllowlistService>();
        services.AddSingleton<QuarantineRepository>();
        services.AddSingleton<UpstreamRegistryRepository>();
        services.AddSingleton<LicenseRepository>();
        services.AddSingleton<SpdxLicenseRepository>();
        services.AddSingleton<SpdxLicenseSeeder>();
        services.AddSingleton<SamlConfigRepository>();
        services.AddSingleton<ExternalIdentityRepository>();
        services.AddSingleton<ProxyVersionRecorder>();
        services.AddSingleton<Dependably.Storage.ProxyFetchService>();

        // Two-tier storage formalisation
        services.AddSingleton<CacheArtifactRepository>();
        services.AddSingleton<TenantArtifactAccessRepository>();
        services.AddSingleton<CacheAccessRecorder>();

        // Name-claim mechanism
        services.AddSingleton<ClaimRepository>();
        services.AddSingleton<ClaimResolver>();
        services.AddSingleton<NpmDistTagRepository>();
        services.AddSingleton<CargoMetadataRepository>();
        services.AddSingleton<TrustedDeviceService>();

        return services;
    }

    /// <summary>
    /// SIEM push (opt-in via env vars). Webhook and syslog forwarders both sit behind
    /// <see cref="ISiemForwarder"/>; the queue + hosted service are registered once and
    /// stay the same regardless of which forwarder is selected. Webhook wins when both
    /// env vars are set. Returns silently when neither is configured.
    ///
    /// <c>SIEM_WEBHOOK_ALLOW_PRIVATE</c> (default <c>true</c>) permits RFC 1918 addresses so
    /// self-hosted SIEM collectors on private networks are reachable. Loopback, link-local,
    /// and cloud-metadata ranges remain blocked regardless.
    /// </summary>
    public static IServiceCollection AddDependablySiemForwarding(
        this IServiceCollection services, IConfiguration config)
    {
        string? webhookUrl = config["SIEM_WEBHOOK_URL"];
        string? syslogHost = config["SIEM_SYSLOG_HOST"];

        if (!string.IsNullOrWhiteSpace(webhookUrl))
        {
            // Determine which SSRF predicate to use: full block (loopback + private +
            // link-local) or partial block (loopback + link-local only, private allowed).
            // SIEM_WEBHOOK_ALLOW_PRIVATE defaults to true for back-compat with self-hosted
            // collectors on private networks.
            bool allowPrivate = !string.Equals(
                config["SIEM_WEBHOOK_ALLOW_PRIVATE"], "false", StringComparison.OrdinalIgnoreCase);
            Func<System.Net.IPAddress, bool> ssrfPredicate = allowPrivate
                ? Dependably.Security.SsrfGuard.IsBlockedIpExcludingPrivate
                : Dependably.Security.SsrfGuard.IsBlockedIp;

            // Fail-fast URL validation at startup. ValidateUrl covers scheme allowlist and
            // known-bad IP literals; private-IP literals pass through when allowPrivate=true.
            string? urlError = ValidateSiemWebhookUrl(webhookUrl, allowPrivate);
            if (urlError is not null)
            {
                throw new InvalidOperationException(
                    $"SIEM_WEBHOOK_URL is invalid: {urlError}");
            }

            // Named typed client with a per-client SSRF connect-time guard. The callback is
            // constructed with the predicate captured here so the allowPrivate flag takes
            // effect regardless of what other SsrfConnectCallback registrations exist in the
            // container. AllowAutoRedirect=false prevents a redirect from forwarding the
            // outbound request to a different, potentially internal, host.
            var siemCallback = new Dependably.Security.SsrfConnectCallback(ssrfPredicate);
            services.AddHttpClient<WebhookSiemForwarder>()
                .ConfigurePrimaryHttpMessageHandler(_ => new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    ConnectCallback = siemCallback.ConnectAsync,
                });
            services.AddSingleton<ISiemForwarder>(sp => sp.GetRequiredService<WebhookSiemForwarder>());
        }
        else if (!string.IsNullOrWhiteSpace(syslogHost))
        {
            services.AddSingleton<SyslogSiemForwarder>();
            services.AddSingleton<ISiemForwarder>(sp => sp.GetRequiredService<SyslogSiemForwarder>());
        }
        else
        {
            return services;
        }

        services.AddSingleton<SiemForwarderQueue>();
        services.AddHostedService(sp => sp.GetRequiredService<SiemForwarderQueue>());
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
            .ConfigurePrimaryHttpMessageHandler(sp => new SocketsHttpHandler
            {
                ConnectCallback = sp.GetRequiredService<Dependably.Security.SsrfConnectCallback>().ConnectAsync,
            });
        }

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
        // as the OSV and upstream proxy clients.
        .ConfigurePrimaryHttpMessageHandler(sp => new SocketsHttpHandler
        {
            ConnectCallback = sp.GetRequiredService<Dependably.Security.SsrfConnectCallback>().ConnectAsync,
        });

        services.AddSingleton<IThreatFeedSource, HttpThreatFeedSource>();
        services.AddSingleton<ThreatFeedRefreshService>();
        services.AddHostedService(sp => sp.GetRequiredService<ThreatFeedRefreshService>());
        return services;
    }

    /// <summary>
    /// Registers <see cref="SmtpInviteMailer"/> as <see cref="IInviteMailer"/> when
    /// <c>SMTP_HOST</c> is configured. Returns without registering anything when SMTP is
    /// absent — the controller checks whether the service is available via
    /// <see cref="IServiceProvider"/> resolution and falls back to the link-in-response path.
    /// </summary>
    public static IServiceCollection AddDependablyInviteMailer(
        this IServiceCollection services, IConfiguration config)
    {
        if (string.IsNullOrWhiteSpace(config["SMTP_HOST"]))
        {
            return services;
        }

        services.AddSingleton<IInviteMailer, SmtpInviteMailer>();
        return services;
    }

    /// <summary>
    /// Validates a SIEM webhook URL string at startup. Applies the scheme allowlist and
    /// IP-literal check from <see cref="Dependably.Security.UpstreamUrlValidator.ValidateUrl"/>,
    /// then re-runs the IP-literal check with the private-allow predicate when
    /// <paramref name="allowPrivate"/> is true. Returns a problem string on failure, null on
    /// success.
    /// </summary>
    internal static string? ValidateSiemWebhookUrl(string url, bool allowPrivate)
    {
        // Run the base validator first (scheme check + full blocked-IP check).
        string? baseError = Dependably.Security.UpstreamUrlValidator.ValidateUrl(url);

        // Fast paths: either the URL is fully valid, or private IPs are not permitted
        // (propagate the base error as-is).
        return baseError is null || !allowPrivate
            ? baseError
            : ValidateSiemWebhookUrlPrivateAllowed(url);
    }

    // Validates a SIEM webhook URL when RFC 1918 private addresses are permitted. Applies
    // the scheme allowlist and the always-blocked range check (loopback / link-local /
    // cloud-metadata), but passes 10/8, 172.16/12, and 192.168/16 through.
    private static string? ValidateSiemWebhookUrlPrivateAllowed(string url) =>
        !Uri.TryCreate(url, UriKind.Absolute, out var uri) ? "Invalid URL format." :
        uri.Scheme is not "http" and not "https" ? "Only http:// and https:// schemes are accepted." :
        System.Net.IPAddress.TryParse(uri.Host, out var ip) && Dependably.Security.SsrfGuard.IsBlockedIpExcludingPrivate(ip)
            ? $"Upstream URL resolves to a blocked IP range: {ip}"
            : null;
}
