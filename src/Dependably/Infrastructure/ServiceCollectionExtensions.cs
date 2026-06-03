using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Siem;
using Dependably.Protocol;

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
    public static IServiceCollection AddDependablyRepositories(this IServiceCollection services)
    {
        // Core repositories
        services.AddSingleton<JwtRevocationRepository>();
        services.AddSingleton<OrgRepository>();
        services.AddSingleton<OrgSettingsRepository>();
        services.AddSingleton<SystemAdminRepository>();
        services.AddSingleton<PackageRepository>();
        services.AddSingleton<PackageAnalyticsRepository>();
        services.AddSingleton<UserService>();
        services.AddSingleton<TokenRepository>();
        // Async batched activity writer. The hosted service drains the channel into
        // batched INSERTs so the download/push hot paths no longer block on a SQLite
        // writer-lock acquisition per row.
        services.AddSingleton<ActivityWriter>();
        services.AddSingleton<ActivityWriterHostedService>();
        services.AddHostedService(sp => sp.GetRequiredService<ActivityWriterHostedService>());
        services.AddSingleton<AuditRepository>();
        services.AddSingleton<AuditEventRepository>();
        services.AddSingleton<BackgroundJobRunRepository>();
        services.AddSingleton<IAuditEmitter, AuditEmitter>();
        services.AddSingleton<InviteRepository>();
        services.AddSingleton<AllowlistRepository>();
        services.AddSingleton<BlocklistRepository>();
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
        services.AddSingleton<MetadataCacheRepository>();
        services.AddSingleton<CacheAccessRecorder>();

        // Name-claim mechanism
        services.AddSingleton<ClaimRepository>();
        services.AddSingleton<ClaimResolver>();

        return services;
    }

    /// <summary>
    /// SIEM push (opt-in via env vars). Webhook and syslog forwarders both sit behind
    /// <see cref="ISiemForwarder"/>; the queue + hosted service are registered once and
    /// stay the same regardless of which forwarder is selected. Webhook wins when both
    /// env vars are set. Returns silently when neither is configured.
    /// </summary>
    public static IServiceCollection AddDependablySiemForwarding(
        this IServiceCollection services, IConfiguration config)
    {
        var webhookUrl = config["SIEM_WEBHOOK_URL"];
        var syslogHost = config["SIEM_SYSLOG_HOST"];

        if (!string.IsNullOrWhiteSpace(webhookUrl))
        {
            services.AddHttpClient<WebhookSiemForwarder>();
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
        var airGapped = string.Equals(config["AIR_GAPPED"], "true", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(config["AIR_GAPPED"], "1", StringComparison.OrdinalIgnoreCase);
        var osvModeRaw = config["OSV_MODE"];
        string osvMode;
        if (!string.IsNullOrWhiteSpace(osvModeRaw))
            osvMode = osvModeRaw.Trim().ToLowerInvariant();
        else
            osvMode = airGapped ? "local" : "remote";

        if (osvMode == "local")
        {
            services.AddSingleton<LocalOsvSource>();
            services.AddSingleton<IOsvSource>(sp => sp.GetRequiredService<LocalOsvSource>());
        }
        else
        {
            services.AddSingleton<OsvClient>();
            services.AddSingleton<IOsvSource>(sp => sp.GetRequiredService<OsvClient>());

            var baseUrl = remoteBaseUrl.EndsWith('/') ? remoteBaseUrl : remoteBaseUrl + "/";
            services.AddHttpClient("osv", client =>
            {
                client.BaseAddress = new Uri(baseUrl);
                client.Timeout = TimeSpan.FromSeconds(30);
            });
        }

        services.AddSingleton<VulnerabilityScanService>();
        services.AddHostedService(sp => sp.GetRequiredService<VulnerabilityScanService>());
        return services;
    }
}
