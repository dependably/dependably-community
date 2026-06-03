using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Siem;
using Dependably.Protocol;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Coverage for the DI extension wires in <see cref="ServiceCollectionExtensions"/>.
/// Inspects <see cref="ServiceDescriptor"/> metadata rather than building the provider
/// where doing so would force resolution of services with external dependencies
/// (IMetadataStore, HttpClient handlers, etc.).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ServiceCollectionExtensionsTests
{
    private static IConfiguration BuildConfig(params (string Key, string? Value)[] pairs)
    {
        var dict = new Dictionary<string, string?>();
        foreach (var (k, v) in pairs)
        {
            dict[k] = v;
        }
        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    private static bool HasSingleton<TService, TImpl>(IServiceCollection services) =>
        services.Any(d =>
            d.ServiceType == typeof(TService)
            && d.Lifetime == ServiceLifetime.Singleton
            && (d.ImplementationType == typeof(TImpl)
                || d.ImplementationFactory != null));

    private static bool HasSingleton<T>(IServiceCollection services) =>
        services.Any(d =>
            d.ServiceType == typeof(T) && d.Lifetime == ServiceLifetime.Singleton);

    // ── AddDependablyRepositories ────────────────────────────────────────────

    [Fact]
    public void AddDependablyRepositories_RegistersCoreRepositoriesAsSingletons()
    {
        var services = new ServiceCollection();

        var result = services.AddDependablyRepositories();

        Assert.Same(services, result);
        // Spot-check across the registration list — these cover the conditional
        // path-free body, every Add call must show up.
        Assert.True(HasSingleton<JwtRevocationRepository>(services));
        Assert.True(HasSingleton<OrgRepository>(services));
        Assert.True(HasSingleton<OrgSettingsRepository>(services));
        Assert.True(HasSingleton<SystemAdminRepository>(services));
        Assert.True(HasSingleton<PackageRepository>(services));
        Assert.True(HasSingleton<PackageAnalyticsRepository>(services));
        Assert.True(HasSingleton<UserService>(services));
        Assert.True(HasSingleton<TokenRepository>(services));
        Assert.True(HasSingleton<AuditRepository>(services));
        Assert.True(HasSingleton<AuditEventRepository>(services));
        Assert.True(HasSingleton<IAuditEmitter, AuditEmitter>(services));
        Assert.True(HasSingleton<InviteRepository>(services));
        Assert.True(HasSingleton<AllowlistRepository>(services));
        Assert.True(HasSingleton<BlocklistRepository>(services));
        Assert.True(HasSingleton<LicenseRepository>(services));
        Assert.True(HasSingleton<SpdxLicenseRepository>(services));
        Assert.True(HasSingleton<SpdxLicenseSeeder>(services));
        Assert.True(HasSingleton<SamlConfigRepository>(services));
        Assert.True(HasSingleton<ExternalIdentityRepository>(services));
        Assert.True(HasSingleton<ProxyVersionRecorder>(services));
        Assert.True(HasSingleton<Dependably.Storage.ProxyFetchService>(services));

        // Two-tier storage formalisation
        Assert.True(HasSingleton<CacheArtifactRepository>(services));
        Assert.True(HasSingleton<TenantArtifactAccessRepository>(services));
        Assert.True(HasSingleton<MetadataCacheRepository>(services));
        Assert.True(HasSingleton<CacheAccessRecorder>(services));

        // Name-claim mechanism
        Assert.True(HasSingleton<ClaimRepository>(services));
        Assert.True(HasSingleton<ClaimResolver>(services));
    }

    // ── AddDependablySiemForwarding ──────────────────────────────────────────

    [Fact]
    public void AddDependablySiemForwarding_NoConfig_RegistersNothing()
    {
        var services = new ServiceCollection();
        var config = BuildConfig();

        var result = services.AddDependablySiemForwarding(config);

        Assert.Same(services, result);
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(ISiemForwarder));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(SiemForwarderQueue));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IHostedService));
    }

    [Fact]
    public void AddDependablySiemForwarding_WhitespaceConfig_RegistersNothing()
    {
        // Covers the IsNullOrWhiteSpace branch for both vars (not null but blank).
        var services = new ServiceCollection();
        var config = BuildConfig(
            ("SIEM_WEBHOOK_URL", "   "),
            ("SIEM_SYSLOG_HOST", "  "));

        services.AddDependablySiemForwarding(config);

        Assert.DoesNotContain(services, d => d.ServiceType == typeof(ISiemForwarder));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(SiemForwarderQueue));
    }

    [Fact]
    public void AddDependablySiemForwarding_WebhookConfigured_RegistersWebhookForwarderAndQueue()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(("SIEM_WEBHOOK_URL", "https://example.invalid/collect"));

        services.AddDependablySiemForwarding(config);

        Assert.Contains(services, d =>
            d.ServiceType == typeof(WebhookSiemForwarder)
            && d.Lifetime == ServiceLifetime.Transient); // AddHttpClient<T> registers as Transient
        Assert.Contains(services, d =>
            d.ServiceType == typeof(ISiemForwarder)
            && d.Lifetime == ServiceLifetime.Singleton);
        Assert.True(HasSingleton<SiemForwarderQueue>(services));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IHostedService)
            && d.Lifetime == ServiceLifetime.Singleton);
        // No syslog forwarder when webhook wins
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(SyslogSiemForwarder));
    }

    [Fact]
    public void AddDependablySiemForwarding_WebhookWinsWhenBothSet()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(
            ("SIEM_WEBHOOK_URL", "https://example.invalid/collect"),
            ("SIEM_SYSLOG_HOST", "syslog.example.invalid"));

        services.AddDependablySiemForwarding(config);

        Assert.Contains(services, d => d.ServiceType == typeof(WebhookSiemForwarder));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(SyslogSiemForwarder));
    }

    [Fact]
    public void AddDependablySiemForwarding_SyslogOnly_RegistersSyslogForwarderAndQueue()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(("SIEM_SYSLOG_HOST", "syslog.example.invalid"));

        services.AddDependablySiemForwarding(config);

        Assert.True(HasSingleton<SyslogSiemForwarder>(services));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(ISiemForwarder)
            && d.Lifetime == ServiceLifetime.Singleton);
        Assert.True(HasSingleton<SiemForwarderQueue>(services));
        Assert.Contains(services, d => d.ServiceType == typeof(IHostedService));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(WebhookSiemForwarder));
    }

    // ── AddDependablyVulnerabilityScanning ──────────────────────────────────

    [Fact]
    public void AddDependablyVulnerabilityScanning_DefaultMode_RegistersOsvClientAndNamedHttpClient()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(); // OSV_MODE unset → defaults to "remote"

        var result = services.AddDependablyVulnerabilityScanning(
            config: config,
            remoteBaseUrl: "https://osv.example.invalid/v1");

        Assert.Same(services, result);
        Assert.True(HasSingleton<VulnerabilityRepository>(services));
        Assert.True(HasSingleton<OsvClient>(services));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IOsvSource)
            && d.Lifetime == ServiceLifetime.Singleton);
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(LocalOsvSource));
        Assert.True(HasSingleton<VulnerabilityScanService>(services));
        Assert.Contains(services, d => d.ServiceType == typeof(IHostedService));
        // Named HttpClient registration is observable via IHttpClientFactory registration
        Assert.Contains(services, d => d.ServiceType == typeof(IHttpClientFactory));
    }

    [Fact]
    public void AddDependablyVulnerabilityScanning_RemoteMode_BaseUrlMissingSlash_StillRegisters()
    {
        // Exercise the trailing-slash append branch (remoteBaseUrl does NOT end with '/').
        var services = new ServiceCollection();
        var config = BuildConfig(("OSV_MODE", "remote"));

        services.AddDependablyVulnerabilityScanning(config: config,
            remoteBaseUrl: "https://osv.example.invalid");

        Assert.True(HasSingleton<OsvClient>(services));
        Assert.Contains(services, d => d.ServiceType == typeof(IHttpClientFactory));

        // Build the named "osv" HttpClient and confirm trailing slash was appended.
        using var sp = services.BuildServiceProvider();
        var factory = sp.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("osv");
        Assert.NotNull(client.BaseAddress);
        Assert.EndsWith("/", client.BaseAddress!.ToString());
        Assert.Equal(TimeSpan.FromSeconds(30), client.Timeout);
    }

    [Fact]
    public void AddDependablyVulnerabilityScanning_RemoteMode_BaseUrlWithTrailingSlash_PreservesIt()
    {
        // Exercise the "already has trailing slash" branch (no append).
        var services = new ServiceCollection();
        var config = BuildConfig(("OSV_MODE", "REMOTE"));

        services.AddDependablyVulnerabilityScanning(config,
            "https://osv.example.invalid/v1/");

        using var sp = services.BuildServiceProvider();
        var factory = sp.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient("osv");
        Assert.Equal("https://osv.example.invalid/v1/", client.BaseAddress!.ToString());
    }

    [Fact]
    public void AddDependablyVulnerabilityScanning_LocalMode_RegistersLocalOsvSource()
    {
        var services = new ServiceCollection();
        var config = BuildConfig(("OSV_MODE", "local"));

        services.AddDependablyVulnerabilityScanning(config, "ignored");

        Assert.True(HasSingleton<LocalOsvSource>(services));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IOsvSource)
            && d.Lifetime == ServiceLifetime.Singleton);
        // The remote branch must NOT have registered the OSV HttpClient
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(OsvClient));
        Assert.True(HasSingleton<VulnerabilityScanService>(services));
        Assert.Contains(services, d => d.ServiceType == typeof(IHostedService));
    }

    [Fact]
    public void AddDependablyVulnerabilityScanning_LocalMode_CaseAndPaddingNormalized()
    {
        // The SUT does .Trim().ToLowerInvariant() — confirm "  LOCAL " still hits the local branch.
        var services = new ServiceCollection();
        var config = BuildConfig(("OSV_MODE", "  LOCAL "));

        services.AddDependablyVulnerabilityScanning(config, "ignored");

        Assert.True(HasSingleton<LocalOsvSource>(services));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(OsvClient));
    }
}
