using System.Net;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the interaction between the <c>/metrics</c> IP allowlist (<see
/// cref="Dependably.Security.MetricsAccessMiddleware"/>) and forwarded-header resolution: the
/// allowlist is always evaluated against <c>Connection.RemoteIpAddress</c>, but that value is
/// itself rewritten by the framework's <c>ForwardedHeadersMiddleware</c> — registered in
/// <c>Program.ConfigureApp</c> ahead of the metrics gate — whenever <c>TRUSTED_PROXIES</c>
/// declares the immediate socket peer a trusted proxy. So a co-located reverse proxy on
/// loopback does not bypass the allowlist as long as its address is declared in
/// <c>TRUSTED_PROXIES</c>: the real client IP from <c>X-Forwarded-For</c> is what the allowlist
/// sees, not the proxy's own loopback address. When <c>TRUSTED_PROXIES</c> is left unset
/// (fail-closed default, per the <c>TRUSTED_PROXIES</c> contract), <c>X-Forwarded-For</c> is
/// ignored entirely and the raw socket peer is evaluated — an operator who fronts the app with
/// an undeclared co-located proxy remains exposed to the scenario the audit finding describes;
/// declaring the proxy in <c>TRUSTED_PROXIES</c> is the documented remedy, not a code change.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MetricsAllowlistForwardedIpTests
{
    // The address the fake "co-located reverse proxy" connects from (the immediate TCP peer
    // Kestrel would see for every request routed through it).
    private static readonly IPAddress ProxyPeerIp = IPAddress.Parse("127.0.0.1");

    // The real external caller's IP, forwarded by the proxy via X-Forwarded-For. Not in the
    // default metrics allowlist (127.0.0.1, ::1).
    private const string ExternalAttackerIp = "203.0.113.77";

    [Fact]
    public async Task TrustedProxiesConfigured_ForwardedExternalIp_IsDeniedNotProxyPeer()
    {
        // TRUSTED_PROXIES declares the loopback proxy trusted, so ForwardedHeadersMiddleware
        // rewrites Connection.RemoteIpAddress from X-Forwarded-For before the metrics gate runs.
        await using var factory = new MetricsForwardedIpFactory(trustedProxies: "127.0.0.1");
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Add("X-Forwarded-For", ExternalAttackerIp);
        var resp = await client.SendAsync(req);

        // The default allowlist (127.0.0.1, ::1) does not include the external IP — denied,
        // proving the allowlist saw the real forwarded client, not the proxy's own loopback peer.
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task TrustedProxiesConfigured_ForwardedAllowlistedIp_IsAllowed()
    {
        await using var factory = new MetricsForwardedIpFactory(trustedProxies: "127.0.0.1");
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        // Forward an IP that IS in the default allowlist (::1 normalizes to itself; use the
        // other default entry, 127.0.0.1, forwarded explicitly rather than being the raw peer).
        req.Headers.Add("X-Forwarded-For", "127.0.0.1");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task TrustedProxiesUnset_ForwardedHeaderIgnored_EvaluatesRawSocketPeer()
    {
        // Fail-closed default: TRUSTED_PROXIES unset means X-Forwarded-For is discarded
        // entirely, and the allowlist sees the raw socket peer (the proxy's own loopback
        // address in this scenario) regardless of what the header claims. This is the
        // documented residual risk of fronting the app with an undeclared co-located proxy —
        // TRUSTED_PROXIES is the fix, not a code change to the allowlist evaluation itself.
        await using var factory = new MetricsForwardedIpFactory(trustedProxies: null);
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Add("X-Forwarded-For", ExternalAttackerIp);
        var resp = await client.SendAsync(req);

        // The raw TestServer peer (127.0.0.1, matched by the default allowlist) is what gets
        // evaluated — the forwarded external IP is never consulted.
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    /// <summary>
    /// Sets <c>Connection.RemoteIpAddress</c> to a fixed value on every request — TestServer's
    /// in-memory transport leaves it null by default (there is no real socket), which is not
    /// representative of a real deployment where the raw peer is always a concrete address.
    /// Mirrors the pattern in <see cref="MetricsAccessPropagationTests"/>.
    /// </summary>
    private sealed class FixedRemoteIpFilter : IStartupFilter
    {
        private readonly IPAddress _ip;
        public FixedRemoteIpFilter(IPAddress ip) => _ip = ip;

        public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(
            Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) =>
                {
                    ctx.Connection.RemoteIpAddress = _ip;
                    await n();
                });
                next(app);
            };
    }

    /// <summary>
    /// Single-mode factory that starts with a configurable <c>TRUSTED_PROXIES</c> value and the
    /// default metrics allowlist (127.0.0.1, ::1). The raw socket peer is forced to
    /// <see cref="ProxyPeerIp"/> (127.0.0.1) via <see cref="FixedRemoteIpFilter"/>, standing in
    /// for the co-located reverse proxy's own loopback socket.
    /// </summary>
    private sealed class MetricsForwardedIpFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly TestMetadataStore _store = new();
        private readonly InMemoryBlobStore _blob = new();
        private readonly string? _trustedProxies;

        public MetricsForwardedIpFactory(string? trustedProxies) => _trustedProxies = trustedProxies;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            if (_trustedProxies is not null)
            {
                builder.Configuration["TRUSTED_PROXIES"] = _trustedProxies;
            }

            // Pin before ConfigureBuilder: the tenant resolver is selected from
            // DEPLOYMENT_MODE at service-registration time, so a UseSetting after this
            // line is inert. See TestHostEnv.
            TestHostEnv.PinAmbient(builder);
            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blob);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blob, _blob));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_store);

            builder.Services.RemoveAll<IUpstreamUrlValidator>();
            builder.Services.AddSingleton<IUpstreamUrlValidator, PermissiveUpstreamUrlValidator>();
            builder.Services.RemoveAll<SsrfConnectCallback>();
            builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

            builder.Services.AddSingleton<IStartupFilter>(new FixedRemoteIpFilter(ProxyPeerIp));

            builder.WebHost.UseTestServer();
            // Boots a real host via Program.ConfigureBuilder; disable the background jobs
            // that egress or mutate shared state at boot (see Infrastructure/DependablyFactory.cs
            // for the full rationale).
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }

        public new async Task DisposeAsync()
        {
            await _store.DisposeAsync();
            await base.DisposeAsync();
        }
    }
}
