using System.Net;
using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// The enrichment client's DI wiring and the transport posture of its named HttpClient. The
/// posture assertions are behavioural rather than reflective: a connect that is not gated, or a
/// redirect that is followed, is only observable by making the client do it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnTrackerEnrichmentClientRegistrationTests : IDisposable
{
    private readonly WireMockServer _server = WireMockServer.Start();

    public void Dispose() => _server.Stop();

    private static IServiceCollection Scanning(SsrfConnectCallback guard, string? osvMode = null)
    {
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["OSV_MODE"] = osvMode })
            .Build();

        // Registered ahead of the extension so its TryAddSingleton keeps these. The tracker
        // client has its OWN gate type — its posture differs from the app-wide one, which
        // refuses loopback and RFC 1918 — so both are substituted here.
        services.AddSingleton(guard);
        services.AddSingleton(new Dependably.Security.OperatorEndpointConnectGate(guard));
        services.AddSingleton(TimeProvider.System);
        services.AddDependablyVulnerabilityScanning(config, "https://osv.example.invalid/v1/");
        return services;
    }

    [Theory]
    [InlineData(null)]
    [InlineData("local")]
    public void The_client_is_registered_in_every_osv_mode(string? osvMode)
    {
        // Including local mode. The overlay is inert in an air-gapped deployment because nothing
        // configures a connection there, not because the registration was omitted — a client
        // registered only on the remote branch would be a second, silently divergent gate.
        var services = Scanning(new SsrfConnectCallback(_ => false), osvMode);

        Assert.Contains(services, d =>
            d.ServiceType == typeof(VulnTrackerEnrichmentClient)
            && d.Lifetime == ServiceLifetime.Singleton);
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IVulnerabilityEnrichmentSource)
            && d.Lifetime == ServiceLifetime.Singleton);
        Assert.Contains(services, d => d.ServiceType == typeof(InstanceVulnTrackerConfig));
    }

    [Fact]
    public void The_named_client_carries_transport_posture_and_no_base_address()
    {
        var services = Scanning(new SsrfConnectCallback(_ => false));
        using var provider = services.BuildServiceProvider();

        using var client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(VulnTrackerEnrichmentClient.HttpClientName);

        // No BaseAddress: the address is instance state resolved per call, not a startup fact.
        Assert.Null(client.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(30), client.Timeout);
        Assert.Equal(UpstreamClient.MaxMetadataResponseBytes, client.MaxResponseContentBufferSize);
    }

    [Fact]
    public async Task The_resolved_OperatorEndpointConnectGate_uses_the_operator_predicate_not_the_shared_one()
    {
        // Unlike every other test in this class, this does NOT go through Scanning(): that
        // helper pre-registers OperatorEndpointConnectGate itself (services.AddSingleton(new
        // OperatorEndpointConnectGate(guard))), which wins over the extension's own
        // TryAddSingleton and so never exercises which constructor the container would have
        // picked. Calling AddDependablyVulnerabilityScanning directly, with nothing registered
        // ahead of it, reproduces production wiring exactly: the extension registers a strict,
        // tenant-facing SsrfConnectCallback (SsrfGuard.IsBlockedIp) BEFORE it registers
        // OperatorEndpointConnectGate, and OperatorEndpointConnectGate has a second, DI-visible
        // constructor that accepts one. The built-in container prefers the constructor with the
        // most resolvable parameters — if the registration ever regresses to the bare generic
        // `TryAddSingleton<OperatorEndpointConnectGate>()` form, the container silently injects
        // the strict guard instead of running OperatorEndpointConnectGate's own parameterless
        // constructor (SsrfGuard.IsBlockedIpForOperatorEndpoint), and a loopback/RFC-1918
        // tracker — the feature's whole reason to exist — is refused again.
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder().Build();
        services.AddDependablyVulnerabilityScanning(config, "https://osv.example.invalid/v1/");
        using var provider = services.BuildServiceProvider();

        var gate = provider.GetRequiredService<Dependably.Security.OperatorEndpointConnectGate>();

        var ex = await Record.ExceptionAsync(async () =>
            await gate.Callback.ConnectAsync("127.0.0.1", 65001,
                new CancellationTokenSource(TimeSpan.FromSeconds(2)).Token));

        Assert.IsNotType<SsrfBlockedException>(ex);
    }

    [Fact]
    public async Task The_named_clients_connect_is_gated_by_the_ssrf_callback()
    {
        // The tracker base URL is operator-supplied and stored in the database, so the
        // connect-time gate is the authority against a host that resolves somewhere unexpected
        // after it was saved. It is the OPERATOR-endpoint gate rather than the app-wide one —
        // see OperatorEndpointConnectGate — but it is still a gate, which is what this asserts.
        var services = Scanning(new SsrfConnectCallback(_ => true));
        using var provider = services.BuildServiceProvider();
        using var client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(VulnTrackerEnrichmentClient.HttpClientName);
        client.Timeout = TimeSpan.FromSeconds(5);

        var ex = await Assert.ThrowsAnyAsync<Exception>(
            () => client.GetAsync("http://192.0.2.1/lookup/batch"));

        Assert.True(HasInner<SsrfBlockedException>(ex),
            $"vulntracker HttpClient connect was not gated by SsrfConnectCallback; got {ex.GetType().Name}");
    }

    [Fact]
    public async Task The_named_client_reaches_a_permitted_host()
    {
        // The twin of the gate test: an all-blocking callback would also make that one pass on a
        // client that cannot dial anything at all.
        _server.Given(Request.Create().WithPath("/ping").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200));
        var services = Scanning(new SsrfConnectCallback(_ => false));
        using var provider = services.BuildServiceProvider();
        using var client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(VulnTrackerEnrichmentClient.HttpClientName);

        using var response = await client.GetAsync(_server.Urls[0] + "/ping");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task The_named_client_refuses_to_follow_a_redirect()
    {
        // A 3xx must not carry the bearer credential to a host that was never SSRF-validated.
        _server.Given(Request.Create().WithPath("/lookup/batch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(302)
                .WithHeader("Location", _server.Urls[0] + "/elsewhere"));
        _server.Given(Request.Create().WithPath("/elsewhere").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody("""{"results":[]}"""));

        var services = Scanning(new SsrfConnectCallback(_ => false));
        using var provider = services.BuildServiceProvider();
        using var client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(VulnTrackerEnrichmentClient.HttpClientName);

        using var response = await client.PostAsync(_server.Urls[0] + "/lookup/batch", null);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Single(_server.LogEntries);
    }

    private static bool HasInner<T>(Exception? ex) where T : Exception =>
        ex is not null && (ex is T || HasInner<T>(ex.InnerException));
}
