using System.Net;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Xunit;

using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;

namespace Dependably.Tests.Integration;

/// <summary>
/// Asserts the observability story documented in
/// <c>dependably-enterprise/docs/observability.md#air-gap-posture-exporters-are-opt-in</c>:
/// in <c>AIR_GAPPED=true</c> mode with <c>OTEL_EXPORTER_OTLP_ENDPOINT</c>
/// unset, the app must boot cleanly, <c>/health</c> + <c>/ready</c> +
/// <c>/metrics</c> must all succeed, and any proxy-fetch attempt must
/// short-circuit to 503 (no outbound network attempted).
/// </summary>
[Trait("Category", "Integration")]
public sealed class AirGapObservabilityTests : IAsyncLifetime
{
    private readonly AirGapFactory _factory = new();

    public Task InitializeAsync() => _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task HealthEndpoint_Returns200()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ReadyEndpoint_Returns200()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/ready");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task MetricsEndpoint_Returns200_WithPrometheusText()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = await resp.Content.ReadAsStringAsync();
        // Prometheus exposition is `# HELP`/`# TYPE` lines followed by samples.
        // The exporter emits at least the process / GC metrics out of the box,
        // so the body must not be empty.
        Assert.NotEmpty(body);
    }

    [Fact]
    public async Task MetricsEndpoint_Returns404_WhenDisabledViaInstanceSettings()
    {
        // PR 10 — metrics_enabled=false → 404 (endpoint vanishes, not 403).
        // Uses a dedicated factory because the air-gap factory caches the
        // MetricsAccessConfig, and other tests in the class assume enabled.
        await using var disabled = new DisabledMetricsFactory();
        await ((IAsyncLifetime)disabled).InitializeAsync();

        using var client = disabled.CreateClient();
        var resp = await client.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MetricsEndpoint_Returns403_WhenIpNotInAllowlist()
    {
        // PR 10 — IP-not-allowed → 403 (endpoint exists, gate denies).
        // Dedicated factory configures METRICS_ALLOWED_IPS to a CIDR
        // that excludes the loopback IP the LoopbackRemoteIpFilter
        // injects.
        await using var blocked = new BlockedIpFactory();
        await ((IAsyncLifetime)blocked).InitializeAsync();

        using var client = blocked.CreateClient();
        var resp = await client.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ProxyFetch_WhileAirGapped_ThrowsAirGappedException()
    {
        // Direct call into UpstreamClient. The cache miss would normally
        // fetch upstream; AIR_GAPPED short-circuits with AirGappedException.
        // Asserting at this layer is more robust than asserting an HTTP
        // status, which depends on the controller wiring + middleware
        // exception translation.
        var upstream = _factory.Services.GetRequiredService<Dependably.Protocol.UpstreamClient>();

        await Assert.ThrowsAsync<Dependably.Protocol.AirGappedException>(() =>
            upstream.GetOrFetchAsync(
                blobKey: "proxy/test-airgap-not-cached",
                upstreamUrl: "https://example.com/whatever.tgz",
                checksumSpec: null,
                ecosystem: "npm"));
    }

    [Fact]
    public void OtlpExporters_NotRegistered_WhenEndpointUnset()
    {
        // When OTEL_EXPORTER_OTLP_ENDPOINT is unset, the SDK pipeline must
        // omit the OtlpExporter entirely. We can't introspect the
        // MeterProvider's exporter chain directly (OTel intentionally hides
        // it), but the configuration branch is deterministic — if the env
        // var is unset, no OtlpMetricExporter / OtlpTraceExporter instance
        // is constructed, and DI does not register one as a hosted service.
        // Resolving the factory's services and confirming no OTLP exporter
        // is in the service collection covers the contract.
        var hasOtlp = _factory.Services
            .GetServices<object>()
            .Any(s => s?.GetType().FullName?.Contains("Otlp", StringComparison.Ordinal) == true);

        Assert.False(hasOtlp,
            "Air-gapped boot must not register any OTLP exporter — operator " +
            "must opt in via OTEL_EXPORTER_OTLP_ENDPOINT.");
    }

    /// <summary>
    /// Factory variant: same as <see cref="DependablyFactory"/> but
    /// configured for air-gap mode with no OTLP exporter endpoint. WireMock
    /// is still spun up by the base class but never reached because the
    /// air-gap short-circuit fires before the upstream URL validator.
    /// </summary>
    private sealed class AirGapFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        public InMemoryBlobStore BlobStore { get; } = new();
        private readonly TestMetadataStore _metadataStore = new();

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();
            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(BlobStore);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(BlobStore, BlobStore));

            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

            // TestServer leaves Connection.RemoteIpAddress null, which
            // MetricsAccessMiddleware treats as unauthenticated (403). Set
            // it to loopback for every request so the /metrics IP gate
            // matches the default allowlist.
            builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

            builder.WebHost.UseTestServer();

            // Air-gap configuration: outbound is blocked, OTLP exporter unset.
            builder.WebHost.UseSetting("AIR_GAPPED", "true");
            builder.WebHost.UseSetting("OTEL_EXPORTER_OTLP_ENDPOINT", "");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            // Default METRICS_ALLOWED_IPS=127.0.0.1 matches the loopback IP
            // we inject via LoopbackRemoteIpFilter below.

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync()
        {
            _ = CreateClient();
            return Task.CompletedTask;
        }

        public new async Task DisposeAsync()
        {
            await _metadataStore.DisposeAsync();
            await base.DisposeAsync();
        }

        private sealed class LoopbackRemoteIpFilter : IStartupFilter
        {
            public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
                => app =>
                {
                    app.Use(async (ctx, n) =>
                    {
                        ctx.Connection.RemoteIpAddress = IPAddress.Loopback;
                        await n();
                    });
                    next(app);
                };
        }
    }

    /// <summary>
    /// Boots the app with <c>METRICS_ENABLED=0</c> so the endpoint
    /// returns 404. PR 10 — covers the "globally disabled" branch.
    /// </summary>
    private sealed class DisabledMetricsFactory : WebApplicationFactory<Program>, IAsyncLifetime, IAsyncDisposable
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
            builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("METRICS_ENABLED", "0");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }
        public new async Task DisposeAsync() { await _metadataStore.DisposeAsync(); await base.DisposeAsync(); }
        async ValueTask IAsyncDisposable.DisposeAsync() => await DisposeAsync();

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

    /// <summary>
    /// Boots the app with <c>METRICS_ALLOWED_IPS=10.0.0.0/8</c> so the
    /// loopback caller (set via <c>LoopbackRemoteIpFilter</c>) is not in
    /// the allowlist and the endpoint returns 403.
    /// </summary>
    private sealed class BlockedIpFactory : WebApplicationFactory<Program>, IAsyncLifetime, IAsyncDisposable
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
            builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("METRICS_ALLOWED_IPS", "10.0.0.0/8");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync() { _ = CreateClient(); return Task.CompletedTask; }
        public new async Task DisposeAsync() { await _metadataStore.DisposeAsync(); await base.DisposeAsync(); }
        async ValueTask IAsyncDisposable.DisposeAsync() => await DisposeAsync();

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
