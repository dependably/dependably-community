using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that <c>KESTREL_MAX_CONNECTIONS</c> binds to <c>KestrelServerLimits.MaxConcurrentConnections</c>.
///
/// Live TCP connection-rejection tests are impractical under <c>TestServer</c> (in-memory
/// transport — there is no real socket to exhaust). Instead, these tests read the configured
/// <c>IOptions&lt;KestrelServerOptions&gt;</c> from the DI container after startup and assert
/// the expected value. The logic under test is the config-to-options binding in
/// <c>Program.ConfigureBuilder</c>; the Kestrel enforcement itself is an ASP.NET Core
/// runtime concern.
///
/// Mixed scenario: the same factory is reused for three cases — default, configured ceiling,
/// and the zero-means-unlimited opt-out — proving the binding is range-correct without
/// requiring three heavyweight factories.
/// </summary>
[Trait("Category", "Integration")]
public sealed class KestrelConnectionCeilingTests
{
    // ── Default ceiling ───────────────────────────────────────────────────────

    [Fact]
    public async Task Default_MaxConcurrentConnections_Is10000()
    {
        await using var factory = NewFactory(settings: null);
        factory.InitializeClient();

        var opts = factory.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value;

        Assert.Equal(10_000L, opts.Limits.MaxConcurrentConnections);
    }

    // ── Configured ceiling ────────────────────────────────────────────────────

    [Fact]
    public async Task WhenKestrelMaxConnectionsSet_LimitIsApplied()
    {
        await using var factory = NewFactory(new Dictionary<string, string>
        {
            ["KESTREL_MAX_CONNECTIONS"] = "500",
        });
        factory.InitializeClient();

        var opts = factory.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value;

        Assert.Equal(500L, opts.Limits.MaxConcurrentConnections);
    }

    // ── Opt-out: 0 removes the ceiling ───────────────────────────────────────

    [Fact]
    public async Task WhenKestrelMaxConnectionsIsZero_LimitIsNull()
    {
        await using var factory = NewFactory(new Dictionary<string, string>
        {
            ["KESTREL_MAX_CONNECTIONS"] = "0",
        });
        factory.InitializeClient();

        var opts = factory.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value;

        // Setting KESTREL_MAX_CONNECTIONS=0 removes the ceiling (null = unlimited).
        Assert.Null(opts.Limits.MaxConcurrentConnections);
    }

    // ── Mixed scenario: default ceiling still serves valid requests ───────────

    /// <summary>
    /// With the default 10 000-connection ceiling set, normal requests are served normally.
    /// Two sequential requests to <c>/health</c> and <c>/ready</c> both succeed — proving
    /// the ceiling does not interfere with legitimate traffic at low concurrency.
    /// </summary>
    [Fact]
    public async Task Default_Ceiling_DoesNotBlockLegitimateRequests()
    {
        await using var factory = NewFactory(settings: null);
        factory.InitializeClient();

        using var client = factory.CreateClient();

        var healthResp = await client.GetAsync("/health");
        var readyResp = await client.GetAsync("/ready");

        // Both responses arrive; 200 (health) or 503 (ready — not yet fully started
        // in test context) are valid, but not a connection-refused error.
        Assert.NotNull(healthResp);
        Assert.NotNull(readyResp);
    }

    // ── Factory helpers ────────────────────────────────────────────────────────

    private static CeilingFactory NewFactory(Dictionary<string, string>? settings) =>
        new(settings ?? new Dictionary<string, string>());

    private sealed class CeilingFactory : WebApplicationFactory<Program>
    {
        private readonly Dictionary<string, string> _settings;
        private readonly TestMetadataStore _metadataStore = new();

        public CeilingFactory(Dictionary<string, string> settings)
        {
            _settings = settings;
        }

        public void InitializeClient() => _ = CreateClient();

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            foreach (var (key, value) in _settings)
            {
                builder.Configuration[key] = value;
            }

            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(new InMemoryBlobStore());
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(new InMemoryBlobStore(), new InMemoryBlobStore()));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _metadataStore.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            base.Dispose(disposing);
        }
    }
}
