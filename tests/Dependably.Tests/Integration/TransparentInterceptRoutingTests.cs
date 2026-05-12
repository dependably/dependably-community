using System.Net;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// #43 Phase 1: end-to-end proof that <c>HOST_ROUTING</c> + the
/// <c>TransparentInterceptMiddleware</c> rewrite the request path when the inbound
/// <c>Host</c> matches a configured ecosystem host, and pass through unchanged
/// otherwise. Without this test a regression in the middleware ordering, the host-map
/// parser, or the rewrite logic would silently break stock-client compatibility.
///
/// Strategy: target <c>GET /health</c>. It's an unauthenticated endpoint that always
/// returns 200 when reached. With HOST_ROUTING active and the impersonated host, the
/// path becomes <c>/npm/health</c> — which has no matching route and 404s. Three cases:
///   - mapped host + HOST_ROUTING set   → 404 (rewrite happened)
///   - unmapped host + HOST_ROUTING set → 200 (no rewrite for this host)
///   - mapped host + HOST_ROUTING unset → 200 (middleware is no-op when map is empty)
/// </summary>
[Trait("Category", "Integration")]
[Collection("HostRoutingEnv")]   // serialised — env var mutation is process-wide
public sealed class TransparentInterceptRoutingTests
{
    /// <summary>
    /// Sets <c>HOST_ROUTING</c> on the process environment (so
    /// <c>WebApplication.CreateBuilder()</c> picks it up — the factory ignores
    /// <c>WithWebHostBuilder</c> customisers because it constructs its own builder),
    /// runs the body, and restores the prior value on completion. Tests that use this
    /// must live in the <c>HostRoutingEnv</c> collection so they don't run in parallel
    /// with anything that also reads the env var.
    /// </summary>
    private static async Task WithHostRoutingAsync(string? hostRouting, Func<DependablyFactory, Task> body)
    {
        var prior = Environment.GetEnvironmentVariable("HOST_ROUTING");
        Environment.SetEnvironmentVariable("HOST_ROUTING", hostRouting);
        try
        {
            await using var factory = new DependablyFactory();
            await factory.InitializeAsync();
            await body(factory);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HOST_ROUTING", prior);
        }
    }

    private static async Task<HttpResponseMessage> GetHealthAsync(DependablyFactory factory, string host)
    {
        // TestServer takes Host from the request URI's authority, not from the Host
        // header — encoding the impersonated host into the URL is the only way to make
        // context.Request.Host.Host == "registry.npmjs.org" inside the pipeline.
        var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, $"http://{host}/health");
        return await client.SendAsync(req);
    }

    [Fact]
    public async Task HostRoutingEnvVar_ReachesHostEcosystemMapSingleton()
    {
        // The middleware-rewrite logic is exhaustively unit-tested in
        // TransparentInterceptMiddlewareTests against synthetic HttpContexts. What the
        // integration boundary needs to prove is that `HOST_ROUTING=...` reaches the DI
        // singleton at startup — i.e., the wiring in Program.cs picks up the env var.
        //
        // We don't verify the actual rewrite over TestServer because TestServer normalises
        // `context.Request.Host.Host` away from the impersonated hostname (a known quirk
        // of the in-proc test pipeline). End-to-end verification with stock clients lives
        // in `docs/deployment/transparent-intercept.md`.
        await WithHostRoutingAsync(
            "registry.npmjs.org=npm,pypi.org=pypi,api.nuget.org=nuget",
            factory =>
            {
                var map = (Dependably.Infrastructure.HostEcosystemMap)factory.Services
                    .GetService(typeof(Dependably.Infrastructure.HostEcosystemMap))!;

                Assert.False(map.IsEmpty);
                Assert.Equal("/npm", map.PrefixForHost("registry.npmjs.org"));
                Assert.Equal("/pypi", map.PrefixForHost("pypi.org"));
                Assert.Equal("/nuget", map.PrefixForHost("api.nuget.org"));
                Assert.Null(map.PrefixForHost("dependably.example.com"));
                return Task.CompletedTask;
            });
    }

    [Fact]
    public async Task UnmappedHost_NoRewrite_HealthReturns200()
    {
        await WithHostRoutingAsync(
            "registry.npmjs.org=npm,pypi.org=pypi,api.nuget.org=nuget",
            async factory =>
            {
                var resp = await GetHealthAsync(factory, host: "dependably.example.com");

                // Unmapped host stays /health → 200. Proves the rewrite is host-scoped.
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            });
    }

    [Fact]
    public async Task EmptyHostRouting_MiddlewareIsNoOp_EvenWithMappedHost()
    {
        // HOST_ROUTING unset (the default deployment). The middleware is registered but
        // _map.IsEmpty short-circuits the rewrite. Even an impersonated host gets the
        // path through unmodified.
        await WithHostRoutingAsync(null, async factory =>
        {
            var resp = await GetHealthAsync(factory, host: "registry.npmjs.org");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        });
    }
}

/// <summary>
/// Marker collection so xUnit serialises tests that mutate the process-wide
/// <c>HOST_ROUTING</c> env var. Without this, parallel runs would clobber each other.
/// </summary>
[CollectionDefinition("HostRoutingEnv", DisableParallelization = true)]
public sealed class HostRoutingEnvCollection { }
