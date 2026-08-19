using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Mail;
using Dependably.Infrastructure.Siem;
using Dependably.Infrastructure.Webhooks;
using Dependably.Security;

namespace Dependably.Infrastructure;

/// <summary>
/// Management-plane DI registrations grouped by subsystem: the management-only repository set,
/// SIEM push, per-org webhook dispatch, alert Slack delivery, and invite mail. These pull in the
/// assemblies the edge image excludes (Redis client, JwtBearer, SAML) transitively through the
/// types they register, so they live in Dependably.Management and are called only from the full
/// composition root.
/// </summary>
public static class ManagementServiceCollectionExtensions
{
    /// <summary>
    /// Registers the management-plane repositories and services: org settings, system-admin,
    /// package analytics, users, invites, SPDX license lookup, SAML config, external identities,
    /// banners, webhook subscriptions, alert settings, trusted-device tracking, JWT revocation,
    /// and the audit emitter (which fans package events out to the webhook dispatcher). Core
    /// repositories are registered separately by
    /// <see cref="ServiceCollectionExtensions.AddDependablyRepositories"/>.
    /// </summary>
    public static IServiceCollection AddDependablyManagementRepositories(this IServiceCollection services)
    {
        // Negative-result cache dropped when this deployment has peer replicas, so a
        // logout binds on every replica's next request — see SessionRevocationCachePolicy.
        services.AddSingleton(sp => new JwtRevocationRepository(
            sp.GetRequiredService<IMetadataStore>(),
            SessionRevocationCachePolicy.SessionCacheOrNull(sp),
            sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<OrgSettingsRepository>();
        services.AddSingleton<SystemAdminRepository>();
        services.AddSingleton<PackageAnalyticsRepository>();
        services.AddSingleton<UserService>();
        services.AddSingleton<IAuditEmitter, AuditEmitter>();
        services.AddSingleton<InviteRepository>();
        services.AddSingleton<PasswordResetTokenRepository>();
        services.AddSingleton<AccountSendThrottle>();
        services.AddSingleton<EmailChangeTokenRepository>();
        services.AddSingleton<SpdxLicenseRepository>();
        services.AddSingleton<PackageNoteRepository>();
        services.AddSingleton<SamlConfigRepository>();
        services.AddSingleton<ExternalIdentityRepository>();
        services.AddSingleton<BannerRepository>();
        services.AddSingleton<Dependably.Infrastructure.Webhooks.WebhookSubscriptionRepository>();
        services.AddSingleton<AlertSettingsRepository>();
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
    /// Registers <see cref="SmtpInviteMailer"/> as <see cref="IInviteMailer"/> — always, since
    /// delivery availability is now a DB-backed runtime signal (<see cref="InstanceSmtpConfig"/>)
    /// rather than a startup-time env var. The controller calls
    /// <see cref="IInviteMailer.IsAvailableAsync"/> per request and falls back to the
    /// link-in-response path when the instance SMTP config is disabled or unconfigured.
    /// </summary>
    public static IServiceCollection AddDependablyInviteMailer(this IServiceCollection services)
    {
        services.AddSingleton<IInviteMailer, SmtpInviteMailer>();
        return services;
    }

    /// <summary>
    /// Registers the instance-level SMTP config resolver and the MailKit-backed sender that is
    /// the single choke point for every outbound email. Always registered (unlike
    /// <see cref="AddDependablyInviteMailer"/>): the config resolves to <c>Configured = false</c>
    /// when <c>instance_settings</c> has no <c>smtp_*</c> rows, so callers (test-send endpoints,
    /// future alert-email delivery) treat an unconfigured instance as a no-op/400 rather than a
    /// missing service.
    ///
    /// <see cref="SmtpMailSender"/> gets its own <see cref="SsrfConnectCallback"/> instance (not
    /// shared with the webhook/Slack/SIEM HTTP clients — MailKit has no
    /// <c>SocketsHttpHandler</c> to hang a shared callback off) so it can resolve and vet the SMTP
    /// host itself before dialing. Reuses <c>WEBHOOK_ALLOW_PRIVATE</c> — an SMTP relay host is a
    /// caller-supplied value with the same SSRF risk profile as a generic outbound webhook.
    ///
    /// Also registers <see cref="EmailDeliveryQueue"/> — the shared channel/worker/retry core
    /// every outbound-email delivery channel enqueues onto (alert email, transactional account
    /// email) — as both the hosted background service and the singleton those channels resolve,
    /// plus <see cref="TransactionalEmailService"/> for account-lifecycle email that isn't tied to
    /// a specific alert or invite (currently: self-serve password reset).
    /// </summary>
    public static IServiceCollection AddDependablyMail(this IServiceCollection services, IConfiguration config)
    {
        bool allowPrivate = string.Equals(
            config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);
        Func<System.Net.IPAddress, bool> ssrfPredicate = allowPrivate
            ? SsrfGuard.IsBlockedIpExcludingPrivate
            : SsrfGuard.IsBlockedIp;
        var smtpConnectGuard = new SsrfConnectCallback(ssrfPredicate);

        services.AddSingleton(_ => new SmtpMailSender(smtpConnectGuard));
        services.AddSingleton(sp =>
        {
            var orgs = sp.GetRequiredService<OrgRepository>();
            var time = sp.GetRequiredService<TimeProvider>();
            return new InstanceSmtpConfig(orgs.GetInstanceSettingAsync, time);
        });

        // Resolves whether an org's alert-email channel can deliver and to whom: its gate and
        // recipient list, carried over the one instance-level transport resolved above.
        services.AddSingleton<EffectiveEmailConfigResolver>();

        services.AddSingleton<EmailDeliveryQueue>();
        services.AddHostedService(sp => sp.GetRequiredService<EmailDeliveryQueue>());
        services.AddSingleton<TransactionalEmailService>();

        // The durable outbox behind alert email: the bounds, the store, and the delivery worker
        // (registered as both the hosted service and the singleton AlertEmailQueue nudges after a
        // successful enqueue). Deliberately separate from EmailDeliveryQueue above, which keeps
        // carrying credential-bearing mail on its in-memory, fail-silent path.
        //
        // EmailTransportBreaker is process-local, in-memory state over the ONE shared SMTP transport
        // (see its own doc comment for why that is the deliberate choice for a Postgres multi-replica
        // deployment too). A singleton, not scoped: it is exactly one fact per process, read and
        // written only by EmailOutboxDeliveryService's single background loop.
        services.AddSingleton<EmailTransportBreaker>();
        services.AddSingleton<EmailOutboxPolicy>();
        services.AddSingleton<EmailOutboxRepository>();
        services.AddSingleton<EmailOutboxDeliveryService>();
        services.AddHostedService(sp => sp.GetRequiredService<EmailOutboxDeliveryService>());

        // The operator's aggregate relay-health surface: per-tenant alert_settings health rows plus
        // the outbox backlog, read together so a single request answers "is the shared relay okay".
        services.AddSingleton<RelayHealthAggregator>();
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
    /// Per-attempt HTTP timeout for outbound webhook deliveries. Left unset, the typed client
    /// takes <see cref="HttpClient"/>'s own default of 100 seconds, so a subscriber endpoint that
    /// accepts the connection and never answers holds each of the four delivery attempts for that
    /// long — a trivial slow-loris listener on a public IP, which the SSRF guard has no reason to
    /// block. The bound is what makes the dispatch queue's per-envelope fair-share budget
    /// meaningful: without it a single attempt can outlast the whole budget.
    /// </summary>
    private const int WebhookHttpTimeoutSeconds = 15;

    /// <summary>
    /// Per-attempt HTTP timeout for the Slack incoming-webhook client, bounded well below the
    /// 1s/5s/30s retry-backoff budget it runs inside, for the same reason as
    /// <see cref="WebhookHttpTimeoutSeconds"/>. Shared by <see cref="AlertSlackQueue"/> and
    /// <see cref="Dependably.Infrastructure.SystemEvents.SystemSlackQueue"/>, which use the same
    /// typed client.
    /// </summary>
    private const int SlackHttpTimeoutSeconds = 10;

    /// <summary>
    /// Registers the per-org webhook dispatcher: <see cref="WebhookDeliveryClient"/> (typed
    /// HTTP client with SSRF connect-time guard and an explicit
    /// <see cref="WebhookHttpTimeoutSeconds"/> per-attempt timeout), <see cref="WebhookDispatchQueue"/>
    /// as both the <see cref="IPackageEventSink"/> singleton and a hosted background service.
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
        services.AddHttpClient<WebhookDeliveryClient>(
                client => client.Timeout = TimeSpan.FromSeconds(WebhookHttpTimeoutSeconds))
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

    /// <summary>
    /// Registers the per-org alert delivery channels: <see cref="SlackWebhookClient"/> (typed
    /// HTTP client with SSRF connect-time guard, same posture as
    /// <see cref="WebhookDeliveryClient"/>) backing <see cref="AlertSlackQueue"/>, and
    /// <see cref="AlertEmailQueue"/> (a thin adapter over the shared
    /// <see cref="Mail.EmailDeliveryQueue"/> registered by <see cref="AddDependablyMail"/>).
    /// <see cref="AlertSlackQueue"/> is its own hosted background service; <see cref="AlertEmailQueue"/>
    /// is not — it only wraps alerts as jobs and enqueues them, the shared queue owns the
    /// worker/retry/drain machinery. <see cref="CompositeAlertNotifier"/> fans out to both and is
    /// the only <see cref="IAlertNotifier"/> the container exposes, so <c>AlertService</c> (Core)
    /// never depends on either concrete channel.
    ///
    /// Reuses <c>WEBHOOK_ALLOW_PRIVATE</c> (default <c>false</c>) — a Slack webhook URL is a
    /// tenant-user-supplied value with the same SSRF risk profile as a generic outbound webhook.
    /// The typed client carries an explicit <see cref="SlackHttpTimeoutSeconds"/> per-attempt
    /// timeout so an org-configured URL pointing at an unresponsive endpoint cannot hold a
    /// delivery worker for the <see cref="HttpClient"/> default of 100 seconds per attempt.
    /// </summary>
    public static IServiceCollection AddDependablyAlertNotifier(
        this IServiceCollection services, IConfiguration config)
    {
        bool allowPrivate = string.Equals(
            config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);

        Func<System.Net.IPAddress, bool> ssrfPredicate = allowPrivate
            ? SsrfGuard.IsBlockedIpExcludingPrivate
            : SsrfGuard.IsBlockedIp;

        var slackCallback = new SsrfConnectCallback(ssrfPredicate);
        services.AddHttpClient<SlackWebhookClient>(
                client => client.Timeout = TimeSpan.FromSeconds(SlackHttpTimeoutSeconds))
            .ConfigurePrimaryHttpMessageHandler(_ => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                ConnectCallback = slackCallback.ConnectAsync,
            });

        services.AddSingleton<AlertSlackQueue>();
        services.AddHostedService(sp => sp.GetRequiredService<AlertSlackQueue>());

        services.AddSingleton<AlertEmailQueue>();

        services.AddSingleton<IAlertNotifier>(sp => new CompositeAlertNotifier(
            [sp.GetRequiredService<AlertSlackQueue>(), sp.GetRequiredService<AlertEmailQueue>()],
            sp.GetRequiredService<ILogger<CompositeAlertNotifier>>()));
        return services;
    }

    /// <summary>
    /// Registers the operator-realm (system-scope) Slack event notifier:
    /// <see cref="Dependably.Infrastructure.SystemEvents.SystemSlackQueue"/> as both the
    /// <see cref="Dependably.Infrastructure.SystemEvents.ISystemEventNotifier"/> singleton and a
    /// hosted service. Reuses the <see cref="SlackWebhookClient"/> typed-client registration from
    /// <see cref="AddDependablyAlertNotifier"/> (same SSRF posture) rather than registering a
    /// second one — the two queues share the delivery client but never share a DI seam beyond it
    /// (see the type's isolation doc comment). Always registered, including in single mode: the
    /// producers are apex-gated system endpoints, so the queue is simply inert there.
    /// </summary>
    public static IServiceCollection AddDependablySystemEventNotifier(this IServiceCollection services)
    {
        services.AddSingleton<Dependably.Infrastructure.SystemEvents.SystemSlackQueue>();
        services.AddSingleton<Dependably.Infrastructure.SystemEvents.ISystemEventNotifier>(
            sp => sp.GetRequiredService<Dependably.Infrastructure.SystemEvents.SystemSlackQueue>());
        services.AddHostedService(
            sp => sp.GetRequiredService<Dependably.Infrastructure.SystemEvents.SystemSlackQueue>());
        return services;
    }
}
