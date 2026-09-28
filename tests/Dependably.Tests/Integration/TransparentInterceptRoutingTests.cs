using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end proof that <c>HOST_ROUTING</c> + the
/// <c>TransparentInterceptMiddleware</c> rewrite the request path when the inbound
/// <c>Host</c> matches a configured ecosystem host, and pass through unchanged
/// otherwise. Without this test a regression in the middleware ordering, the host-map
/// parser, or the rewrite logic would silently break stock-client compatibility.
///
/// Strategy: target <c>GET /health</c>. It's an unauthenticated endpoint that always
/// returns 200 when reached with the path unrewritten. Three route-outcome cases:
///   - localhost (unmapped) + HOST_ROUTING set → 200 (no rewrite for this host)
///   - localhost + HOST_ROUTING unset    → 200 (middleware is no-op when map is empty)
///   - mapped host + HOST_ROUTING set    → rewritten to <c>/npm/health</c>, which
///     <c>NpmController</c>'s <c>/npm/{package}</c> treats as a package name; that case is
///     proven on response headers, not status code.
/// Which controller actually answers an intercepted request is proven separately, per mapped
/// ecosystem, by <see cref="MappedHost_ReachesThePrefixedProtocolController_ForEveryEcosystem"/>:
/// a header-only assertion cannot tell the rewritten route from whatever endpoint the original
/// path matched.
/// Every mapped host is also always accepted by host filtering (regardless of BASE_URL) —
/// those hostnames are the entire point of transparent intercept; localhost stands in for
/// "any host the filter would accept but the map doesn't recognise" without also having to
/// stand up a real BASE_URL/apex for these tests.
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
    private static async Task WithHostRoutingAsync(
        string? hostRouting, Func<DependablyFactory, Task> body, Action<IServiceCollection>? serviceOverrides = null)
    {
        string? prior = Environment.GetEnvironmentVariable("HOST_ROUTING");
        Environment.SetEnvironmentVariable("HOST_ROUTING", hostRouting);
        try
        {
            await using var factory = new DependablyFactory { ServiceOverrides = serviceOverrides };
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
        // header — encoding the target host into the URL is the only way to make
        // context.Request.Host.Host reflect it inside the pipeline.
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
        // TestServer DOES propagate the impersonated Host correctly when it is encoded into
        // the request URI's authority (see GetHealthAsync) — verified directly by
        // MappedHost_SecurityHeadersClassifyOnTheRewrittenPath_ThroughTheRealPipeline below,
        // which asserts on the rewrite's actual effect. This test stays narrower on purpose:
        // it isolates the DI-wiring question (does HOST_ROUTING reach the singleton at all)
        // from the pipeline-behaviour question the other test answers.
        await WithHostRoutingAsync(
            "registry.npmjs.org=npm,pypi.org=pypi,api.nuget.org=nuget",
            factory =>
            {
                var map = (Dependably.Infrastructure.HostEcosystemMap)factory.Services
                    .GetService(typeof(Dependably.Infrastructure.HostEcosystemMap))!;

                Assert.False(map.IsEmpty);
                Assert.Equal("/npm", map.PrefixForHost("registry.npmjs.org", "/lodash"));
                Assert.Equal(string.Empty, map.PrefixForHost("pypi.org", "/simple/lodash/"));
                Assert.Equal("/pypi", map.PrefixForHost("pypi.org", "/legacy/"));
                Assert.Equal("/nuget", map.PrefixForHost("api.nuget.org", "/v3/index.json"));
                Assert.Null(map.PrefixForHost("dependably.example.com", "/health"));
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
                // localhost is never a HOST_ROUTING entry, and (unlike an arbitrary hostname)
                // always clears host filtering regardless of BASE_URL — isolating the assertion
                // to the middleware's own host-scoping rather than the filter allowlist.
                var resp = await GetHealthAsync(factory, host: "localhost");

                // Unmapped host stays /health → 200. Proves the rewrite is host-scoped.
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            });
    }

    [Fact]
    public async Task EmptyHostRouting_MiddlewareIsNoOp_HealthReturns200()
    {
        // HOST_ROUTING unset (the default deployment). The middleware is registered but
        // _map.IsEmpty short-circuits the rewrite. localhost always clears host filtering
        // (even with no apex configured), so the request reaches the middleware and proves
        // it leaves the path through unmodified when there is nothing to map.
        await WithHostRoutingAsync(null, async factory =>
        {
            var resp = await GetHealthAsync(factory, host: "localhost");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        });
    }

    /// <summary>
    /// The actual registration-order proof, through the real pipeline —
    /// <see cref="DependablyFactory"/> boots via the genuine <c>Program.ConfigureApp</c>, so this
    /// exercises the real middleware order in the composition root, not a hand-built chain.
    /// <c>TransparentInterceptMiddlewareTests.MappedHost_SecurityHeadersClassifyOnRewrittenPath_NotTheOriginalHostRelativePath</c>
    /// proves the invariant holds when the two middlewares are composed correctly; it cannot
    /// prove <c>Program.cs</c> actually composes them that way, because it builds its own chain.
    /// This test is what can, and did: hoisting <c>SecurityHeadersMiddleware</c> above
    /// <c>TransparentInterceptMiddleware</c> in <c>src/Dependably/Program.cs</c> was confirmed to
    /// fail this test while leaving the rest of the suite green.
    ///
    /// <c>SecurityHeadersMiddleware</c> runs unconditionally before routing and classifies off
    /// <c>Request.Path</c> at that point, regardless of what routing later does with the
    /// (possibly rewritten) path — so a registry CSP and <c>Cache-Control: no-store</c> on this
    /// response are only possible if <c>TransparentInterceptMiddleware</c> already rewrote
    /// <c>/health</c> to <c>/npm/health</c> before <c>SecurityHeadersMiddleware</c> ran.
    /// </summary>
    [Fact]
    public async Task MappedHost_SecurityHeadersClassifyOnTheRewrittenPath_ThroughTheRealPipeline()
    {
        await WithHostRoutingAsync(
            "registry.npmjs.org=npm,pypi.org=pypi,api.nuget.org=nuget",
            async factory =>
            {
                var resp = await GetHealthAsync(factory, host: "registry.npmjs.org");

                string csp = Assert.Single(resp.Headers.GetValues("Content-Security-Policy"));
                Assert.Contains("default-src 'none'", csp);
                // The frontend CSP this regresses to if the ordering is ever wrong — asserting
                // its absence, not just the registry CSP's presence, is what makes this a
                // negative control against the specific historical regression, not just a
                // positive assertion that could coincidentally pass some other way.
                Assert.DoesNotContain("script-src 'self'", csp);
                Assert.Equal(
                    "no-store",
                    resp.Headers.CacheControl?.ToString(),
                    ignoreCase: true);
            });
    }

    private const string AllEcosystemsHostRouting =
        "registry.npmjs.org=npm,pypi.org=pypi,api.nuget.org=nuget,repo.maven.apache.org=maven,"
        + "rpm.example.test=rpm,registry-1.docker.io=oci,repo.hex.pm=hex";

    /// <summary>
    /// One intercepted request per mapped ecosystem: the bare-host path a stock client sends, the
    /// prefixed path the rewrite must route it to, and a signal only the target controller
    /// produces (routing to the original, unprefixed path yields the SPA fallback, a 404, or a
    /// 405 — never these). The pypi <c>/simple/</c> case is the path-dependent pass-through: the
    /// prefix resolves to empty and the unprefixed route is already the served one.
    /// </summary>
    private sealed record InterceptCase(
        string Ecosystem, string Host, string Method, string BarePath, string PrefixedPath,
        HttpStatusCode Status, string? RequiredHeader, string? BodyMarker);

    private static readonly InterceptCase[] InterceptCases =
    [
        new("npm", "registry.npmjs.org", "GET", "/-/ping", "/npm/-/ping", HttpStatusCode.OK, null, "{}"),
        new("nuget", "api.nuget.org", "GET", "/v3/index.json", "/nuget/v3/index.json", HttpStatusCode.OK, null, "SearchQueryService"),
        new("oci", "registry-1.docker.io", "GET", "/", "/v2/", HttpStatusCode.Unauthorized, "Docker-Distribution-API-Version", "\"UNAUTHORIZED\""),
        new("pypi upload", "pypi.org", "POST", "/legacy/", "/pypi/legacy/", HttpStatusCode.Unauthorized, "WWW-Authenticate", null),
        new("pypi simple", "pypi.org", "GET", "/simple/", "/simple/", HttpStatusCode.Unauthorized, "WWW-Authenticate", null),
        new("maven", "repo.maven.apache.org", "GET", "/com/example/foo/maven-metadata.xml", "/maven/com/example/foo/maven-metadata.xml", HttpStatusCode.Unauthorized, "WWW-Authenticate", null),
        new("rpm", "rpm.example.test", "POST", "/upload", "/rpm/upload", HttpStatusCode.Unauthorized, "WWW-Authenticate", null),
        new("hex", "repo.hex.pm", "GET", "/api/users/me", "/hex/api/users/me", HttpStatusCode.Unauthorized, null, "\"Unauthorized\""),
    ];

    private sealed record Reply(HttpStatusCode Status, string? ContentType, HttpResponseHeaders Headers, string Body);

    private static async Task<Reply> SendAsync(HttpClient client, string method, string url)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), url);
        using var resp = await client.SendAsync(req);
        string body = await resp.Content.ReadAsStringAsync();
        return new Reply(resp.StatusCode, resp.Content.Headers.ContentType?.MediaType, resp.Headers, body);
    }

    /// <summary>
    /// Proves the rewritten request is served by the prefixed protocol controller, not by the
    /// endpoint the original path matched. Endpoint routing selects the endpoint from
    /// <c>Request.Path</c> once, when the routing middleware runs; a rewrite placed after that
    /// point changes the path the downstream middleware see but not the endpoint that executes.
    /// Each case compares the intercepted response with the same request sent to the prefixed
    /// path directly on an unmapped host (the oracle), and checks a signal unique to the target
    /// controller so a matching pair of generic 404s cannot pass.
    /// </summary>
    [Fact]
    public async Task MappedHost_ReachesThePrefixedProtocolController_ForEveryEcosystem()
    {
        await WithHostRoutingAsync(AllEcosystemsHostRouting, async factory =>
        {
            var client = factory.CreateClient();
            var failures = new List<string>();

            foreach (var c in InterceptCases)
            {
                var direct = await SendAsync(client, c.Method, $"http://localhost{c.PrefixedPath}");
                var intercepted = await SendAsync(client, c.Method, $"http://{c.Host}{c.BarePath}");

                if (direct.Status != c.Status)
                {
                    failures.Add($"{c.Ecosystem}: oracle {c.Method} {c.PrefixedPath} answered {(int)direct.Status}, expected {(int)c.Status}");
                }

                string label = $"{c.Ecosystem}: {c.Method} http://{c.Host}{c.BarePath}";
                if (intercepted.Status != c.Status)
                {
                    failures.Add($"{label} answered {(int)intercepted.Status}, expected {(int)c.Status} from {c.PrefixedPath}");
                    continue;
                }

                if (intercepted.ContentType != direct.ContentType)
                {
                    failures.Add($"{label} content type '{intercepted.ContentType}' differs from the direct route's '{direct.ContentType}'");
                }

                if (c.RequiredHeader is { } header && !intercepted.Headers.Contains(header))
                {
                    failures.Add($"{label} is missing the {header} header {c.PrefixedPath} emits");
                }

                if (c.BodyMarker is { } marker && !intercepted.Body.Contains(marker, StringComparison.Ordinal))
                {
                    failures.Add($"{label} body lacks '{marker}': {intercepted.Body}");
                }
            }

            Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
        });
    }

    /// <summary>
    /// The tenant-status gate and the rate limiter classify a request by its routed endpoint
    /// (<c>RateLimitPartitions.IsProtocolControllerRequest</c>), so an intercepted request must be
    /// routed on its rewritten path before they run. Mixed outcome through one host: while the org
    /// is active, a bare-host npm publish reaches <c>NpmController</c> and succeeds; once the org
    /// is read-only, the same bare-host publish is classified as a protocol-plane write and
    /// refused with the read-only reason instead of falling through to a non-protocol endpoint.
    /// </summary>
    [Fact]
    public async Task MappedHost_NpmPublish_ReachesController_AndReadOnlyGateClassifiesItAsProtocolWrite()
    {
        await WithHostRoutingAsync(AllEcosystemsHostRouting, async factory =>
        {
            string token = await factory.CreateToken("push");
            using var client = factory.CreateClientWithBearer(token);

            string activeName = $"icpt-active-{Guid.NewGuid():N}"[..20];
            using (var activeResp = await client.PutAsync(
                $"http://registry.npmjs.org/{activeName}",
                new StringContent(NpmFixtures.BuildPublishBody(activeName, "1.0.0"), Encoding.UTF8, "application/json")))
            {
                Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);
            }

            await factory.SetOrgStatus("default", "read_only");

            string blockedName = $"icpt-block-{Guid.NewGuid():N}"[..20];
            using var roResp = await client.PutAsync(
                $"http://registry.npmjs.org/{blockedName}",
                new StringContent(NpmFixtures.BuildPublishBody(blockedName, "1.0.0"), Encoding.UTF8, "application/json"));

            Assert.Equal(HttpStatusCode.Locked, roResp.StatusCode);
            using var doc = JsonDocument.Parse(await roResp.Content.ReadAsStringAsync());
            Assert.Equal("ReadOnlyWrite", doc.RootElement.GetProperty("reason").GetString());
        });
    }

    /// <summary>
    /// The headless edge root composes its own pipeline, so it needs the same guarantee: an
    /// intercepted request is routed on the rewritten path. The npm ping's <c>{}</c> JSON body is
    /// produced only by <c>NpmController</c>; the unprefixed <c>/-/ping</c> matches no edge route.
    /// </summary>
    [Fact]
    public async Task EdgeRoot_MappedHost_ReachesThePrefixedProtocolController()
    {
        string? prior = Environment.GetEnvironmentVariable("HOST_ROUTING");
        Environment.SetEnvironmentVariable("HOST_ROUTING", AllEcosystemsHostRouting);
        try
        {
            await using var factory = new EdgeFactory();
            using var client = factory.CreateClient();

            var nuget = await SendAsync(client, "GET", "http://api.nuget.org/v3/index.json");
            Assert.Equal(HttpStatusCode.OK, nuget.Status);
            Assert.Contains("SearchQueryService", nuget.Body, StringComparison.Ordinal);

            var ping = await SendAsync(client, "GET", "http://registry.npmjs.org/-/ping");
            Assert.Equal(HttpStatusCode.OK, ping.Status);
            Assert.Equal("application/json", ping.ContentType);
            Assert.Equal("{}", ping.Body);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HOST_ROUTING", prior);
        }
    }

    // Documentation range (RFC 5737): never loopback, never in the default metrics allowlist.
    private static readonly IPAddress NonAllowlistedPeer = IPAddress.Parse("203.0.113.7");

    /// <summary>
    /// Sets <c>Connection.RemoteIpAddress</c> to <see cref="NonAllowlistedPeer"/>. Registered
    /// through <c>ServiceOverrides</c>, after the factory's loopback filter, so it runs inside it
    /// and its address is the one the pipeline sees.
    /// </summary>
    private sealed class NonAllowlistedPeerFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (ctx, n) =>
            {
                ctx.Connection.RemoteIpAddress = NonAllowlistedPeer;
                await n();
            });
            next(app);
        };
    }

    /// <summary>
    /// The operator surfaces gated by path — <c>/metrics</c> and <c>/version</c> (the metrics IP
    /// allowlist in <c>MetricsAccessMiddleware</c> and the <c>/version</c> handler) and the
    /// management Swagger shell (<c>ManagementDocsAllowlistMiddleware</c>) — must stay gated when
    /// the request arrives on a mapped host. The gates classify on the rewritten path
    /// (<c>/npm/metrics</c> is not <c>/metrics</c>), so the endpoint that executes must be chosen
    /// from that same rewritten path; routed on the bare path, a non-allowlisted peer reaches the
    /// Prometheus exposition and the docs shell simply by sending <c>Host: registry.npmjs.org</c>.
    /// Each case first confirms, on an unmapped host, that the peer really is refused.
    /// </summary>
    [Fact]
    public async Task MappedHost_DoesNotBypassThePathBasedOperatorSurfaceGates()
    {
        await WithHostRoutingAsync(
            AllEcosystemsHostRouting,
            async factory =>
            {
                var client = factory.CreateClient();
                var failures = new List<string>();

                foreach (string path in new[] { "/metrics", "/version", "/api/v1/docs/" })
                {
                    var control = await SendAsync(client, "GET", $"http://localhost{path}");
                    if (control.Status != HttpStatusCode.Forbidden)
                    {
                        failures.Add($"control: {path} from {NonAllowlistedPeer} on localhost answered {(int)control.Status}, expected 403");
                    }

                    var mapped = await SendAsync(client, "GET", $"http://registry.npmjs.org{path}");
                    bool leaked = path switch
                    {
                        "/metrics" => mapped.Body.Contains("# TYPE", StringComparison.Ordinal)
                            || mapped.Body.Contains("# HELP", StringComparison.Ordinal),
                        "/version" => mapped.Status == HttpStatusCode.OK
                            && mapped.Body.Contains("\"version\"", StringComparison.Ordinal),
                        _ => mapped.Status == HttpStatusCode.OK && mapped.ContentType == "text/html",
                    };
                    if (leaked)
                    {
                        failures.Add($"{path} on registry.npmjs.org from {NonAllowlistedPeer} was served ({(int)mapped.Status} {mapped.ContentType}): {mapped.Body[..Math.Min(120, mapped.Body.Length)]}");
                    }
                }

                Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
            },
            services => services.AddSingleton<IStartupFilter, NonAllowlistedPeerFilter>());
    }
}

/// <summary>
/// Marker collection so xUnit serialises tests that mutate the process-wide
/// <c>HOST_ROUTING</c> env var. Without this, parallel runs would clobber each other.
/// </summary>
[CollectionDefinition("HostRoutingEnv", DisableParallelization = true)]
public sealed class HostRoutingEnvCollection { }
