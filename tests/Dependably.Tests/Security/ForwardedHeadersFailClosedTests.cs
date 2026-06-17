using System.Net;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Security;

/// <summary>
/// Verifies that forwarded-header processing fails closed when TRUSTED_PROXIES is unset.
///
/// Without TRUSTED_PROXIES: a caller-supplied X-Forwarded-For: 127.0.0.1 does not rewrite
/// Connection.RemoteIpAddress, so the /metrics and /version IP allowlist sees the real socket
/// peer (a non-loopback address injected by the test's startup filter) and returns 403 — the
/// spoofed loopback claim is not accepted.
///
/// With TRUSTED_PROXIES set to the test socket peer: the same X-Forwarded-For: 127.0.0.1 IS
/// honored and RemoteIpAddress becomes 127.0.0.1, which the default allowlist permits → 200.
///
/// The mixed scenario places both arms under the same test class: one denies, one allows,
/// driven solely by the presence or absence of TRUSTED_PROXIES.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ForwardedHeadersFailClosedTests : IAsyncLifetime
{
    // The address injected as the socket peer in both factories. This is a non-loopback address
    // so the default metrics allowlist (127.0.0.1/::1) denies it without the XFF rewrite.
    private const string SocketPeerIp = "10.200.0.1";

    // With TRUSTED_PROXIES unset (fail-closed), the XFF header is ignored and the allowlist
    // sees the socket peer — 403 expected.
    private readonly FailClosedFactory _noProxiesFactory = new(trustedProxies: null);

    // With TRUSTED_PROXIES set to the socket peer, the XFF is honored and the allowlist
    // sees the forged loopback — 200 expected.
    private readonly FailClosedFactory _withProxiesFactory = new(trustedProxies: SocketPeerIp);

    public async Task InitializeAsync()
    {
        await _noProxiesFactory.InitializeAsync();
        await _withProxiesFactory.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _noProxiesFactory.DisposeAsync();
        await _withProxiesFactory.DisposeAsync();
    }

    // ── Fail-closed (no TRUSTED_PROXIES): XFF denied ─────────────────────────

    [Fact]
    public async Task Version_SpoofedXff_NoTrustedProxies_Returns403()
    {
        using var client = _noProxiesFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/version");
        req.Headers.Add("X-Forwarded-For", "127.0.0.1");
        var resp = await client.SendAsync(req);

        // The XFF header is ignored; socket peer (10.200.0.1) is not in the default
        // loopback allowlist, so the request is forbidden.
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Metrics_SpoofedXff_NoTrustedProxies_Returns403()
    {
        using var client = _noProxiesFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Add("X-Forwarded-For", "127.0.0.1");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── With TRUSTED_PROXIES set: XFF honored ─────────────────────────────────
    // Mixed scenario: same X-Forwarded-For header, opposite outcome depending on
    // whether TRUSTED_PROXIES is configured. Both arms share this test class.

    [Fact]
    public async Task Version_SpoofedXff_WithTrustedProxies_Returns200()
    {
        using var client = _withProxiesFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/version");
        req.Headers.Add("X-Forwarded-For", "127.0.0.1");
        var resp = await client.SendAsync(req);

        // The socket peer is a trusted proxy, so XFF is honored. RemoteIpAddress
        // becomes 127.0.0.1, which the default allowlist permits.
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Metrics_SpoofedXff_WithTrustedProxies_AllowedThrough()
    {
        using var client = _withProxiesFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Add("X-Forwarded-For", "127.0.0.1");
        var resp = await client.SendAsync(req);

        // Socket peer is trusted; XFF honored; loopback passes allowlist.
        // Prometheus may return 200 or 404 depending on env — neither is 403.
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── HSTS: X-Forwarded-Proto ignored without TRUSTED_PROXIES ─────────────

    [Fact]
    public async Task SecurityHeaders_XForwardedProto_Ignored_NoTrustedProxies()
    {
        // Without TRUSTED_PROXIES, X-Forwarded-Proto: https must be ignored.
        // HSTS must not be emitted because Request.IsHttps stays false (no trusted proxy).
        using var client = _noProxiesFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("X-Forwarded-Proto", "https");
        var resp = await client.SendAsync(req);

        Assert.False(resp.Headers.Contains("Strict-Transport-Security"),
            "HSTS must not be set from X-Forwarded-Proto when TRUSTED_PROXIES is unset");
    }

    [Fact]
    public async Task SecurityHeaders_XForwardedProto_Honored_WithTrustedProxies()
    {
        // With TRUSTED_PROXIES set, X-Forwarded-Proto: https from the trusted proxy
        // rewrites Request.Scheme, and HSTS is emitted.
        using var client = _withProxiesFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("X-Forwarded-Proto", "https");
        var resp = await client.SendAsync(req);

        Assert.True(resp.Headers.Contains("Strict-Transport-Security"),
            "HSTS must be set when X-Forwarded-Proto: https comes from a trusted proxy");
    }

    // ── Factory ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Test factory that injects a non-loopback socket peer and optionally configures
    /// TRUSTED_PROXIES. When <paramref name="trustedProxies"/> is null, forwarded-header
    /// processing is disabled (fail-closed). When it names the injected socket peer,
    /// the ForwardedHeadersMiddleware trusts that peer and rewrites RemoteIpAddress from XFF.
    /// </summary>
    private sealed class FailClosedFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly string? _trustedProxies;
        private readonly InMemoryBlobStore _blob = new();
        private readonly TestMetadataStore _metadataStore = new();

        public FailClosedFactory(string? trustedProxies) => _trustedProxies = trustedProxies;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();
            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blob);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blob, _blob));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

            // Inject a non-loopback socket peer so the default allowlist (127.0.0.1/::1)
            // denies it without an XFF rewrite. Tests that set TRUSTED_PROXIES to this
            // address rely on XFF to rewrite it to loopback.
            builder.Services.AddSingleton<IStartupFilter>(new FixedRemoteIpFilter(IPAddress.Parse(SocketPeerIp)));

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");

            if (_trustedProxies is not null)
            {
                builder.WebHost.UseSetting("TRUSTED_PROXIES", _trustedProxies);
            }

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }

        public new async Task DisposeAsync()
        {
            await _metadataStore.DisposeAsync();
            await base.DisposeAsync();
        }

        private sealed class FixedRemoteIpFilter : IStartupFilter
        {
            private readonly IPAddress _ip;

            public FixedRemoteIpFilter(IPAddress ip) => _ip = ip;

            public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
                => app =>
                {
                    app.Use(async (ctx, n) => { ctx.Connection.RemoteIpAddress = _ip; await n(); });
                    next(app);
                };
        }
    }
}
