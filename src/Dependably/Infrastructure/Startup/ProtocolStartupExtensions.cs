using Dependably.Protocol;
using Dependably.Security;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers protocol-layer services: upstream client, SSRF guards, OCI upload service,
/// RPM/Maven upstream proxies, upload limit resolver, HTTP clients, and the upstream
/// queue semaphore.
/// </summary>
internal static class ProtocolStartupExtensions
{
    // HTTP client: max simultaneous connections to each upstream registry server.
    private const int UpstreamMaxConnectionsPerServer = 10;

    // OCI upstream client allows more parallel connections (layer blobs are large and streamed).
    private const int OciUpstreamMaxConnectionsPerServer = 20;

    // Outbound User-Agent for every upstream request. A blank/absent UA is a common cause of
    // CDN 403s (Fastly in front of PyPI, the npm registry edge) — those edges reject or
    // throttle anonymous-looking clients, and the proxy would surface that as a failed fetch.
    // A real product token identifies us as a registry proxy. Version is stamped from the
    // assembly (Directory.Build.props <Version>); ToString(3) drops the trailing revision.
    private static readonly string UpstreamUserAgent =
        $"Dependably/{typeof(ProtocolStartupExtensions).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"} (+https://github.com/dependably/dependably; artifact-proxy)";

    internal static void AddDependablyProtocolServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<UpstreamClient>();
        builder.Services.AddSingleton<UpstreamRegistryResolver>();
        builder.Services.AddSingleton<IUpstreamLatestVersionResolver, UpstreamLatestVersionResolver>();
        builder.Services.AddSingleton<IUpstreamUrlValidator, UpstreamUrlValidator>();
        // Connect-time SSRF gate shared by the upstream HTTP handlers. Validates the IP
        // actually dialed (every connection + every redirect hop), closing the DNS-rebinding
        // window the URL-level pre-check cannot. Predicate is the same SsrfGuard block-list.
        builder.Services.AddSingleton(new SsrfConnectCallback(SsrfGuard.IsBlockedIp));
        builder.Services.AddSingleton<AllowlistService>();
        builder.Services.AddSingleton<BlockGateService>();

        // Artefact-provenance verifiers. The trust anchors are operator-pinned (Npm:SignatureKeys,
        // NuGet:SignatureCertificates, PyPI:SigstoreRoots + PyPI:TrustedPublishers), never the
        // upstream-fetched registry key/package/bundle. Resolved per-ecosystem at the proxy ingest path.
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.NpmSignatureKeyStore>();
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.NpmProvenanceVerifier>();
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.NuGetSignatureTrustStore>();
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.NuGetProvenanceVerifier>();
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.PyPiSigstoreTrustStore>();
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.PyPiProvenanceVerifier>();
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.RpmProvenanceVerifier>();
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.MavenSignatureKeyStore>();
        builder.Services.AddSingleton<Dependably.Protocol.Provenance.MavenProvenanceVerifier>();

        // Maven upstream proxy
        builder.Services.AddSingleton<MavenUpstreamFetcher>();

        // RPM upstream proxy
        builder.Services.AddSingleton<RpmUpstreamProxyServices>();
        builder.Services.AddSingleton<RpmUpstreamProxy>();

        // OCI upstream proxy — auth service is singleton (owns token cache + semaphores)
        builder.Services.AddOptions<Dependably.Configuration.OciOptions>()
            .BindConfiguration("Oci")
            .ValidateOnStart();
        builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<Dependably.Configuration.OciOptions>,
            Dependably.Configuration.OciOptionsValidator>();
        builder.Services.AddSingleton<OciUpstreamAuthService>();
        builder.Services.AddSingleton<OciUpstreamResolver>();
        builder.Services.AddSingleton<OciUploadService.Dependencies>();
        builder.Services.AddSingleton<OciUploadService>();
        builder.Services.AddHostedService<OciStagingJanitorService>();

        // Upload limit resolver
        builder.Services.AddSingleton<IUploadLimitResolver, UploadLimitResolver>();
    }

    internal static void AddDependablyUpstreamQueue(this WebApplicationBuilder builder)
    {
        // Shared semaphore that caps the total number of requests simultaneously queued
        // behind the upstream connection pool. SocketsHttpHandler limits open connections
        // per server but allows an unbounded number of tasks to wait; under a cache-miss
        // burst those waiting tasks accumulate memory until the client timeout fires.
        // 200 slots is deliberately generous — well above normal peak throughput —
        // so only genuine storms are shed. Both upstream HTTP clients share this instance
        // so the budget applies to total process load, not per-client.
        int upstreamQueueDepth = builder.Configuration.GetValue("Upstream:QueueDepth", defaultValue: 200);
        var upstreamQueueSemaphore = new SemaphoreSlim(upstreamQueueDepth, upstreamQueueDepth);
        builder.Services.AddSingleton(upstreamQueueSemaphore);
    }

    internal static void AddDependablyHttpClients(this WebApplicationBuilder builder)
    {
        // Named HTTP client for upstream proxy requests.
        // ConnectTimeout=30s, total timeout=2min (reduced from 5min to limit queued-task
        // lifetime and tail latency under a connection-pool storm), max 10 connections/server.
        // AllowAutoRedirect=false: SsrfAwareRedirectHandler owns redirect following and
        // validates each Location URL via IUpstreamUrlValidator before opening a connection,
        // providing defense-in-depth against redirect-based SSRF. SsrfConnectCallback
        // remains as the authoritative socket-level gate on every connection.
        // UpstreamQueueThrottleHandler is innermost (closest to the socket): it sheds requests
        // that cannot acquire a semaphore slot within 500 ms so the queue never grows unbounded.
        builder.Services.AddHttpClient("upstream", client =>
        {
            client.Timeout = TimeSpan.FromMinutes(2);
            client.DefaultRequestHeaders.UserAgent.ParseAdd(UpstreamUserAgent);
        })
        .ConfigurePrimaryHttpMessageHandler(sp => new System.Net.Http.SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(30),
            MaxConnectionsPerServer = UpstreamMaxConnectionsPerServer,
            AllowAutoRedirect = false,
            ResponseDrainTimeout = TimeSpan.FromSeconds(30),
            // api.nuget.org's registration5-gz-* variants force Content-Encoding: gzip
            // regardless of Accept-Encoding. Other upstream metadata endpoints (PyPI's
            // simple index, npm's registry) negotiate normally. Package blob downloads are
            // already compressed at the file level (.tar.gz, .tgz, .nupkg=zip) and upstream
            // CDNs serve them with Content-Encoding: identity, so checksum bytes are
            // unaffected.
            AutomaticDecompression = System.Net.DecompressionMethods.All,
            // SSRF gate: validates the dialed IP on every connection, including connections
            // opened by SsrfAwareRedirectHandler for each redirect hop.
            ConnectCallback = sp.GetRequiredService<SsrfConnectCallback>().ConnectAsync,
        })
        .AddHttpMessageHandler(sp =>
            new SsrfAwareRedirectHandler(
                sp.GetRequiredService<IUpstreamUrlValidator>()))
        .AddHttpMessageHandler(sp =>
            new UpstreamQueueThrottleHandler(
                sp.GetRequiredService<SemaphoreSlim>(),
                acquireTimeout: null,
                sp.GetRequiredService<ILogger<UpstreamQueueThrottleHandler>>()));

        // Named HTTP client for OCI upstream proxy.
        // Timeout is configurable via Oci:UpstreamHttpTimeout (default 30 min — large layer blobs).
        // AutomaticDecompression is disabled: OCI layer blobs are already compressed at the file
        // level and we need the raw bytes for SHA-256 digest verification.
        // AllowAutoRedirect=false: SsrfAwareRedirectHandler validates each redirect Location URL
        // before following it, providing the same defense-in-depth as the upstream client.
        // UpstreamQueueThrottleHandler shares the same semaphore as the upstream client, capping
        // total queued upstream requests across both clients.
        builder.Services.AddHttpClient("OciUpstream", (sp, client) =>
        {
            var opts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<Dependably.Configuration.OciOptions>>();
            client.Timeout = opts.Value.UpstreamHttpTimeout;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(UpstreamUserAgent);
        })
        .ConfigurePrimaryHttpMessageHandler(sp => new System.Net.Http.SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(30),
            MaxConnectionsPerServer = OciUpstreamMaxConnectionsPerServer,
            AllowAutoRedirect = false,
            ResponseDrainTimeout = TimeSpan.FromSeconds(30),
            // Do NOT decompress: OCI layer blobs are raw compressed tarballs.
            // Decompressing would corrupt the digest (the digest is over the compressed bytes).
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            // SSRF gate: validates the dialed IP on every connection, including connections
            // opened by SsrfAwareRedirectHandler for each redirect hop.
            ConnectCallback = sp.GetRequiredService<SsrfConnectCallback>().ConnectAsync,
        })
        .AddHttpMessageHandler(sp =>
            new SsrfAwareRedirectHandler(
                sp.GetRequiredService<IUpstreamUrlValidator>()))
        .AddHttpMessageHandler(sp =>
            new UpstreamQueueThrottleHandler(
                sp.GetRequiredService<SemaphoreSlim>(),
                acquireTimeout: null,
                sp.GetRequiredService<ILogger<UpstreamQueueThrottleHandler>>()));

        // Fallback generic client (used by non-upstream code)
        builder.Services.AddHttpClient();

        // Named client for outbound healthcheck pinger — no redirects, no auth, short timeout
        builder.Services.AddHttpClient("healthcheck-pinger", client => client.Timeout = TimeSpan.FromSeconds(
                int.TryParse(builder.Configuration["HEALTHCHECK_PING_TIMEOUT_SECONDS"], out int t) ? t : HealthcheckPingTimeoutSecondsDefault))
        .ConfigurePrimaryHttpMessageHandler(sp => new System.Net.Http.SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            // SSRF defense-in-depth: HEALTHCHECK_PING_URL is operator-supplied, but a
            // misconfigured or over-trusted value must not reach private/link-local
            // ranges — same shared gate as the upstream proxy clients.
            ConnectCallback = sp.GetRequiredService<SsrfConnectCallback>().ConnectAsync,
        });
    }

    // Default healthcheck ping timeout when HEALTHCHECK_PING_TIMEOUT_SECONDS is not set.
    private const int HealthcheckPingTimeoutSecondsDefault = 10;
}
