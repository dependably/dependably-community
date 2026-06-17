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

namespace Dependably.Tests.Integration.OpenApi;

/// <summary>
/// Verifies that the management OpenAPI document (<c>/openapi/management.json</c>)
/// and the management Swagger UI shell (<c>/api/v1/docs/</c>) and its static
/// assets are gated behind the metrics IP allowlist, while the protocol document
/// (<c>/openapi/protocol.json</c>) and protocol UI (<c>/docs/</c>) remain public.
///
/// The mixed scenario — management gated, protocol public, under a single
/// restrictive allowlist — is the house-rule partial-failure test that proves
/// the gate branches on document name / path rather than over-blocking.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ManagementDocsGateTests : IAsyncLifetime
{
    // Allowlist that excludes loopback so the test client is denied management
    // docs but the protocol docs are still reachable from the same client.
    private const string NonLoopbackAllowlist = "10.0.0.0/8";

    private readonly BlockedIpFactory _blockedFactory = new();
    private readonly LoopbackFactory _loopbackFactory = new();

    public async Task InitializeAsync()
    {
        await _blockedFactory.InitializeAsync();
        await _loopbackFactory.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _blockedFactory.DisposeAsync();
        await _loopbackFactory.DisposeAsync();
    }

    // ── Non-allowlisted IP: management gated ─────────────────────────────────

    [Fact]
    public async Task ManagementSpec_NonAllowlistedIp_Returns403()
    {
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/openapi/management.json");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementDocsShell_NonAllowlistedIp_Returns403()
    {
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/api/v1/docs/");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementDocsAsset_NonAllowlistedIp_Returns403()
    {
        // Static asset under the management prefix must also be gated.
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/api/v1/docs/swagger-ui-bundle.js");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Mixed scenario: same non-allowlisted client sees protocol as public ───
    // This is the house-rule partial-failure test: management is blocked while
    // protocol remains accessible in the same restrictive allowlist configuration.

    [Fact]
    public async Task ProtocolSpec_NonAllowlistedIp_Returns200()
    {
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/openapi/protocol.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ProtocolDocsShell_NonAllowlistedIp_IsNotForbidden()
    {
        // The protocol Swagger UI (/docs/) must not be blocked by the IP gate.
        // In the test environment the swagger index.html is not present so the
        // shell handler returns 404 (file-not-found) rather than 200 — that is
        // fine: the assertion is that the IP gate does not fire 403, not that
        // the static file exists.
        using var client = _blockedFactory.CreateClient();
        var resp = await client.GetAsync("/docs/");
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Loopback (default allowlist): management accessible ──────────────────
    // Regression guard: the default metrics allowlist permits loopback, so
    // existing tests using DependablyFactory (which connects from loopback via
    // TestServer) still reach management docs without any change.

    [Fact]
    public async Task ManagementSpec_LoopbackIp_Returns200()
    {
        using var client = _loopbackFactory.CreateClient();
        var resp = await client.GetAsync("/openapi/management.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementDocsShell_LoopbackIp_IsNotForbidden()
    {
        // From an allowlisted IP the gate must not fire. The shell handler
        // returns 404 in the test environment (no swagger index.html) rather
        // than 200 — the assertion is that the IP gate does not produce 403.
        using var client = _loopbackFactory.CreateClient();
        var resp = await client.GetAsync("/api/v1/docs/");
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ProtocolSpec_LoopbackIp_Returns200()
    {
        using var client = _loopbackFactory.CreateClient();
        var resp = await client.GetAsync("/openapi/protocol.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Factory: loopback IP, default allowlist (127.0.0.1/::1) ─────────────

    private sealed class LoopbackFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly InMemoryBlobStore _blob = new();
        private readonly TestMetadataStore _metadataStore = new();

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

            // Inject loopback as the connection IP — default allowlist (127.0.0.1/::1)
            // permits it, so management docs are reachable.
            builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }
        public new async Task DisposeAsync() { await _metadataStore.DisposeAsync(); await base.DisposeAsync(); }

        private sealed class LoopbackRemoteIpFilter : IStartupFilter
        {
            public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
                => app =>
                {
                    app.Use(async (ctx, n) => { ctx.Connection.RemoteIpAddress = IPAddress.Loopback; await n(); });
                    next(app);
                };
        }
    }

    // ── Factory: loopback IP, allowlist excludes loopback ────────────────────
    // Management docs are blocked; protocol docs remain public.

    private sealed class BlockedIpFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly InMemoryBlobStore _blob = new();
        private readonly TestMetadataStore _metadataStore = new();

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

            // Inject loopback as the connection IP, but restrict the allowlist
            // to a CIDR that excludes loopback — so management docs return 403
            // while protocol docs (no IP gate) return 200.
            builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("METRICS_ALLOWED_IPS", NonLoopbackAllowlist);
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }
        public new async Task DisposeAsync() { await _metadataStore.DisposeAsync(); await base.DisposeAsync(); }

        private sealed class LoopbackRemoteIpFilter : IStartupFilter
        {
            public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
                => app =>
                {
                    app.Use(async (ctx, n) => { ctx.Connection.RemoteIpAddress = IPAddress.Loopback; await n(); });
                    next(app);
                };
        }
    }
}
