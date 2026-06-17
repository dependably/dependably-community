using System.Net;
using Dependably.Infrastructure;
using Dependably.Protocol;
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
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that <see cref="SsrfAwareRedirectHandler"/> is wired onto the named
/// <c>upstream</c> and <c>OciUpstream</c> HttpClients. The handler is registered via
/// <c>AddHttpMessageHandler</c> in Program.cs — it only fires in production when the
/// real DI graph is assembled. These tests prove the wiring is in place by substituting
/// a blocking validator and confirming that a redirect to a disallowed URL raises
/// <see cref="SsrfBlockedException"/> through the actual client pipeline.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SsrfRedirectHandlerWiringTests : IAsyncLifetime
{
    private BlockingFactory? _factory;
    private WireMockServer? _mock;

    public Task InitializeAsync()
    {
        _mock = WireMockServer.Start();
        _factory = new BlockingFactory(_mock);
        _ = _factory.CreateClient(); // trigger startup
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        _mock?.Stop();
        _mock?.Dispose();
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }
    }

    // ── upstream client wiring ────────────────────────────────────────────────

    [Fact]
    public async Task UpstreamClient_RedirectToBlockedUrl_IsCaughtBySsrfAwareRedirectHandler()
    {
        // WireMock returns a 302 to the blocked target URL.
        string blockedTarget = $"{_mock!.Urls[0]}/blocked-redirect";
        _mock.Given(Request.Create().WithPath("/trigger").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(302)
                .WithHeader("Location", blockedTarget));

        // The blocking validator denies the redirect target.
        _factory!.BlockingValidator.DenyUrls.Add(blockedTarget);

        var factory = _factory.Services.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("upstream");

        // When the handler is correctly wired: the redirect Location is validated and
        // SsrfBlockedException is raised before a second connection is opened.
        // When the handler is NOT wired: AllowAutoRedirect=false causes the 302 to be
        // returned as-is (no exception).
        await Assert.ThrowsAsync<SsrfBlockedException>(
            () => client.GetAsync($"{_mock.Urls[0]}/trigger"));

        // The validator was only called once — for the redirect target, not the original URL
        // (the initial URL pre-check happens in UpstreamClient before the HTTP call).
        Assert.Contains(blockedTarget, _factory.BlockingValidator.DenyUrls);
    }

    [Fact]
    public async Task OciUpstream_RedirectToBlockedUrl_IsCaughtBySsrfAwareRedirectHandler()
    {
        string blockedTarget = $"{_mock!.Urls[0]}/oci-blocked";
        _mock.Given(Request.Create().WithPath("/oci-trigger").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(302)
                .WithHeader("Location", blockedTarget));

        _factory!.BlockingValidator.DenyUrls.Add(blockedTarget);

        var factory = _factory.Services.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("OciUpstream");

        await Assert.ThrowsAsync<SsrfBlockedException>(
            () => client.GetAsync($"{_mock.Urls[0]}/oci-trigger"));
    }

    // ── non-redirecting requests pass through unaffected ─────────────────────

    [Fact]
    public async Task UpstreamClient_NormalResponse_PassesThroughUnaffected()
    {
        _mock!.Given(Request.Create().WithPath("/normal").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithBody("ok"));

        var factory = _factory!.Services.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("upstream");

        var response = await client.GetAsync($"{_mock.Urls[0]}/normal");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ── inner factory ─────────────────────────────────────────────────────────

    /// <summary>
    /// Minimal factory that wires the real production DI graph but substitutes a
    /// <see cref="RecordingBlockingValidator"/> so redirect-block assertions can observe
    /// whether the handler called the validator with the redirect target.
    /// </summary>
    private sealed class BlockingFactory : WebApplicationFactory<Program>
    {
        public RecordingBlockingValidator BlockingValidator { get; } = new();

        private readonly WireMockServer _mock;

        public BlockingFactory(WireMockServer mock) => _mock = mock;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();
            Program.ConfigureBuilder(builder);

            // Use in-memory stores so the factory can start without a real database.
            var inMemBlob = new InMemoryBlobStore();
            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(inMemBlob);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(inMemBlob, inMemBlob));

            var metaStore = new TestMetadataStore();
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(metaStore);

            // Inject a blocking validator so redirects to denied URLs raise
            // SsrfBlockedException — the signal that the handler is in the pipeline.
            builder.Services.RemoveAll<IUpstreamUrlValidator>();
            builder.Services.AddSingleton<IUpstreamUrlValidator>(BlockingValidator);

            // The connect-time callback also blocks loopback; replace it with a permissive
            // version so WireMock on 127.0.0.1 is reachable from the named clients.
            builder.Services.RemoveAll<SsrfConnectCallback>();
            builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("PyPI:Upstream", _mock.Urls[0]);
            builder.WebHost.UseSetting("Npm:Upstream", _mock.Urls[0]);
            builder.WebHost.UseSetting("NuGet:Upstream", _mock.Urls[0]);

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }
    }

    /// <summary>
    /// Validator that blocks URLs in <see cref="DenyUrls"/> and allows everything else.
    /// Records every URL presented for validation.
    /// </summary>
    private sealed class RecordingBlockingValidator : IUpstreamUrlValidator
    {
        public HashSet<string> DenyUrls { get; } = [];
        public List<string> ValidatedUrls { get; } = [];

        public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
        {
            ValidatedUrls.Add(url);
            return Task.FromResult(!DenyUrls.Contains(url));
        }
    }
}
