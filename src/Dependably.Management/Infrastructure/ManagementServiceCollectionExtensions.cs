using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Mail;
using Dependably.Infrastructure.Siem;
using Dependably.Infrastructure.Webhooks;
using Dependably.Security;

namespace Dependably.Infrastructure;

/// <summary>
/// Management-plane DI registrations grouped by subsystem: the management-only repository set,
/// SIEM push, per-org webhook dispatch, and invite mail. These pull in the assemblies the edge
/// image excludes (Redis client, JwtBearer, SAML) transitively through the types they register,
/// so they live in Dependably.Management and are called only from the full composition root.
/// </summary>
public static class ManagementServiceCollectionExtensions
{
    /// <summary>
    /// Registers the management-plane repositories and services: org settings, system-admin,
    /// package analytics, users, invites, SPDX license lookup, SAML config, external identities,
    /// banners, webhook subscriptions, trusted-device tracking, JWT revocation, and the audit
    /// emitter (which fans package events out to the webhook dispatcher). Core repositories are
    /// registered separately by <see cref="ServiceCollectionExtensions.AddDependablyRepositories"/>.
    /// </summary>
    public static IServiceCollection AddDependablyManagementRepositories(this IServiceCollection services)
    {
        services.AddSingleton<JwtRevocationRepository>();
        services.AddSingleton<OrgSettingsRepository>();
        services.AddSingleton<SystemAdminRepository>();
        services.AddSingleton<PackageAnalyticsRepository>();
        services.AddSingleton<UserService>();
        services.AddSingleton<IAuditEmitter, AuditEmitter>();
        services.AddSingleton<InviteRepository>();
        services.AddSingleton<SpdxLicenseRepository>();
        services.AddSingleton<SamlConfigRepository>();
        services.AddSingleton<ExternalIdentityRepository>();
        services.AddSingleton<BannerRepository>();
        services.AddSingleton<Dependably.Infrastructure.Webhooks.WebhookSubscriptionRepository>();
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

    /// <summary>
    /// Registers the per-org webhook dispatcher: <see cref="WebhookDeliveryClient"/> (typed
    /// HTTP client with SSRF connect-time guard), <see cref="WebhookDispatchQueue"/> as both
    /// the <see cref="IPackageEventSink"/> singleton and a hosted background service.
    ///
    /// <c>WEBHOOK_ALLOW_PRIVATE</c> defaults to <c>false</c> — tenant-user-supplied URLs are
    /// higher risk than operator SIEM URLs. Loopback, link-local, and cloud-metadata ranges
    /// remain blocked regardless of this setting.
    /// </summary>
    public static IServiceCollection AddDependablyWebhookDispatcher(
        this IServiceCollection services, IConfiguration config)
    {
        bool allowPrivate = string.Equals(
            config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);

        Func<System.Net.IPAddress, bool> ssrfPredicate = allowPrivate
            ? SsrfGuard.IsBlockedIpExcludingPrivate
            : SsrfGuard.IsBlockedIp;

        var webhookCallback = new SsrfConnectCallback(ssrfPredicate);
        services.AddHttpClient<WebhookDeliveryClient>()
            .ConfigurePrimaryHttpMessageHandler(_ => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                ConnectCallback = webhookCallback.ConnectAsync,
            });

        services.AddSingleton<WebhookDispatchQueue>();
        services.AddSingleton<IPackageEventSink>(sp => sp.GetRequiredService<WebhookDispatchQueue>());
        services.AddHostedService(sp => sp.GetRequiredService<WebhookDispatchQueue>());
        return services;
    }
}
