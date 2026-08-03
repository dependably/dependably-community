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

namespace Dependably.Tests.Integration;

/// <summary>
/// Host-header filtering: when BASE_URL contains a non-localhost host, Kestrel's
/// HostFilteringMiddleware rejects requests with unknown Host headers before tenant resolution
/// runs. When BASE_URL is unset or localhost (dev/local), no apex is derivable and filtering
/// fails closed to the loopback hostnames only (never "*") so the local dev loop keeps working
/// without opening the door to an arbitrary attacker-supplied Host header.
///
/// Mixed scenario: same factory, one request with a valid Host accepted (2xx/non-400) and one
/// request with a forged Host rejected (400) — both in a single test class.
/// </summary>
[Trait("Category", "Integration")]
public sealed class HostFilteringTests
{
    private const string ApexHost = "repo.example.test";

    // ── Single-mode: apex host accepted, unknown host rejected ────────────────

    [Fact]
    public async Task SingleMode_KnownApexHost_IsAccepted()
    {
        await using var factory = NewSingleModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = ApexHost;

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task SingleMode_UnknownHost_IsRejected()
    {
        await using var factory = NewSingleModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = "evil.attacker.test";

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task SingleMode_Localhost_IsAccepted()
    {
        await using var factory = NewSingleModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = "localhost";

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    /// <summary>
    /// Mixed scenario: within a single factory (BASE_URL configured with a real host), one
    /// request with the correct apex host is accepted and one with a forged Host is rejected.
    /// This pins the filtering logic without requiring two separate factories.
    /// </summary>
    [Fact]
    public async Task SingleMode_Mixed_AcceptedAndRejectedInSameClass()
    {
        await using var factory = NewSingleModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();

        // Known host: accepted (2xx or non-400 — routing determines exact code)
        var goodReq = new HttpRequestMessage(HttpMethod.Get, "/health");
        goodReq.Headers.Host = ApexHost;
        var goodResp = await client.SendAsync(goodReq);
        Assert.NotEqual(HttpStatusCode.BadRequest, goodResp.StatusCode);

        // Forged host: rejected by HostFilteringMiddleware before any controller runs
        var badReq = new HttpRequestMessage(HttpMethod.Get, "/health");
        badReq.Headers.Host = "forged.evil.test";
        var badResp = await client.SendAsync(badReq);
        Assert.Equal(HttpStatusCode.BadRequest, badResp.StatusCode);
    }

    // ── Multi-mode: apex + wildcard subdomain accepted, other hosts rejected ──

    [Fact]
    public async Task MultiMode_ApexHost_IsAccepted()
    {
        await using var factory = NewMultiModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = ApexHost;

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantSubdomain_IsAccepted()
    {
        await using var factory = NewMultiModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = $"myorg.{ApexHost}";

        var resp = await client.SendAsync(req);

        // The subdomain resolves to TenantContext.Uninitialized (no org seeded for that slug)
        // but HostFilteringMiddleware passes it — tenant resolution returns 404, not 400.
        Assert.NotEqual(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_UnknownHost_IsRejected()
    {
        await using var factory = NewMultiModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = "other.domain.test";

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ── No apex configured: fails closed to loopback hosts only ───────────────

    /// <summary>
    /// Regression test for the Host-header-injection finding: with BASE_URL unset/localhost
    /// (the shipped docker-compose default) and no reverse proxy configured, an arbitrary
    /// attacker-controlled Host header must be rejected, not silently accepted. Fails on the
    /// pre-fix code (AllowedHosts="*") and passes once the fallback is restricted to loopback
    /// hostnames.
    /// </summary>
    [Fact]
    public async Task NoApex_ArbitraryHost_IsRejected()
    {
        await using var factory = NewNoApexFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = "arbitrary.unknown.test";

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    /// <summary>
    /// Mixed scenario for the same no-apex factory: the loopback hostname is still accepted
    /// (the local dev loop is not broken) while an arbitrary forged Host is rejected.
    /// </summary>
    [Fact]
    public async Task NoApex_Mixed_LoopbackAcceptedArbitraryRejected()
    {
        await using var factory = NewNoApexFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();

        var goodReq = new HttpRequestMessage(HttpMethod.Get, "/health");
        goodReq.Headers.Host = "localhost";
        var goodResp = await client.SendAsync(goodReq);
        Assert.NotEqual(HttpStatusCode.BadRequest, goodResp.StatusCode);

        var badReq = new HttpRequestMessage(HttpMethod.Get, "/health");
        badReq.Headers.Host = "arbitrary.unknown.test";
        var badResp = await client.SendAsync(badReq);
        Assert.Equal(HttpStatusCode.BadRequest, badResp.StatusCode);
    }

    [Fact]
    public async Task NoApexMultiMode_SubdomainOfLocalhost_IsAccepted()
    {
        await using var factory = NewNoApexMultiModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = "myorg.localhost";

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task NoApexMultiMode_ArbitraryHost_IsRejected()
    {
        await using var factory = NewNoApexMultiModeFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Host = "arbitrary.unknown.test";

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ── Factory helpers ────────────────────────────────────────────────────────

    private static HostFilterFactory NewSingleModeFactory() => new(new Dictionary<string, string>
    {
        ["BASE_URL"] = $"https://{ApexHost}",
        ["DEPLOYMENT_MODE"] = "single",
    });

    private static HostFilterFactory NewMultiModeFactory() => new(new Dictionary<string, string>
    {
        ["BASE_URL"] = $"https://{ApexHost}",
        ["DEPLOYMENT_MODE"] = "multi",
    });

    private static HostFilterFactory NewNoApexFactory() => new(new Dictionary<string, string>
    {
        ["BASE_URL"] = "http://localhost:8080",
        ["DEPLOYMENT_MODE"] = "single",
    });

    private static HostFilterFactory NewNoApexMultiModeFactory() => new(new Dictionary<string, string>
    {
        ["BASE_URL"] = "http://localhost:8080",
        ["DEPLOYMENT_MODE"] = "multi",
    });

    /// <summary>
    /// Lightweight factory focused on host-filtering behavior. Uses in-memory stores;
    /// does not share state between factory instances.
    /// </summary>
    private sealed class HostFilterFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly Dictionary<string, string> _settings;
        private readonly TestMetadataStore _metadataStore = new();

        public HostFilterFactory(Dictionary<string, string> settings)
        {
            _settings = settings;
        }

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            // Inject settings into IConfiguration before ConfigureBuilder runs so
            // ConfigureHostFiltering (which reads BASE_URL/DEPLOYMENT_MODE from
            // builder.Configuration at call time) sees the correct values.
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
            // Boots a real host via Program.ConfigureBuilder; disable the background jobs
            // that egress or mutate shared state at boot (see Infrastructure/DependablyFactory.cs
            // for the full rationale).
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep");
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
    }
}
