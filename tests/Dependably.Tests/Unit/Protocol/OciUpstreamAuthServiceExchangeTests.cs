using System.Collections;
using System.Net;
using System.Reflection;
using System.Text;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Token-cache behaviour of the OCI upstream auth service under load and concurrency: expired
/// entries are pruned when the cache reaches its cap, concurrent callers for one key share a single
/// token exchange, and a challenge carrying parameters the parser does not know still yields the
/// realm and service it does.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamAuthServiceExchangeTests
{
    private const string Host = "registry.internal.example";
    private const string Realm = "https://registry.internal.example/token";

    private static OciUpstreamRegistryOptions Upstream() => new()
    {
        Name = "internal",
        Host = Host,
        AuthType = OciAuthType.DockerHubTokenExchange,
        Prefixes = [""],
    };

    private static HttpResponseMessage Challenge(string header)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        resp.Headers.TryAddWithoutValidation("WWW-Authenticate", header);
        return resp;
    }

    private static OciUpstreamAuthService Service(IHttpClientFactory factory, FakeTimeProvider clock)
        => new(factory, Options.Create(new OciOptions()), new NoAirGap(), NullLogger<OciUpstreamAuthService>.Instance, clock);

    [Fact]
    public async Task AtTheCap_ExpiredTokensArePruned_BeforeTheNewOneIsStored()
    {
        var clock = TestTime.Frozen();
        int exchanges = 0;
        var factory = new Factory(request => Task.FromResult(request.RequestUri!.AbsolutePath == "/v2/"
            ? Challenge($"Bearer realm=\"{Realm}\",service=\"registry\"")
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{{\"token\":\"t-{Interlocked.Increment(ref exchanges)}\",\"expires_in\":60}}", Encoding.UTF8, "application/json"),
            }));
        using var svc = Service(factory, clock);
        var upstream = Upstream();

        for (int i = 0; i < 512; i++)
        {
            await svc.GetAuthorizationAsync("org-a", upstream, $"team/app-{i}", "pull", default);
        }

        Assert.Equal(512, TokenCount(svc));
        clock.Advance(TimeSpan.FromMinutes(5));

        await svc.GetAuthorizationAsync("org-a", upstream, "team/app-fresh", "pull", default);

        Assert.Equal(1, TokenCount(svc));
    }

    [Fact]
    public async Task ConcurrentCallersForOneKey_ShareASingleExchange()
    {
        var clock = TestTime.Frozen();
        var probeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int requests = 0;
        var factory = new Factory(async request =>
        {
            Interlocked.Increment(ref requests);
            if (request.RequestUri!.AbsolutePath == "/v2/")
            {
                probeStarted.TrySetResult();
                await release.Task;
                return Challenge($"Bearer realm=\"{Realm}\",service=\"registry\"");
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"token":"shared-token","expires_in":300}""", Encoding.UTF8, "application/json"),
            };
        });
        using var svc = Service(factory, clock);
        var upstream = Upstream();

        var first = svc.GetAuthorizationAsync("org-a", upstream, "team/app", "pull", default);
        await probeStarted.Task;
        var second = svc.GetAuthorizationAsync("org-a", upstream, "team/app", "pull", default);
        for (int i = 0; i < 50; i++)
        {
            await Task.Yield();
        }

        release.SetResult();

        Assert.Equal("Bearer shared-token", await first);
        Assert.Equal("Bearer shared-token", await second);
        Assert.Equal(2, requests);
    }

    [Fact]
    public async Task AChallengeWithAParameterTheParserDoesNotKnow_StillYieldsItsRealm()
    {
        var clock = TestTime.Frozen();
        var factory = new Factory(request => Task.FromResult(request.RequestUri!.AbsolutePath == "/v2/"
            ? Challenge($"Bearer realm=\"{Realm}\", error=\"insufficient_scope\", scope=\"repository:team/app:pull,push\", service=\"registry\"")
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"token":"scoped-token"}""", Encoding.UTF8, "application/json"),
            }));
        using var svc = Service(factory, clock);

        string? header = await svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default);

        Assert.Equal("Bearer scoped-token", header);
    }

    private static int TokenCount(OciUpstreamAuthService svc)
    {
        var field = typeof(OciUpstreamAuthService).GetField("_tokens", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return ((ICollection)field.GetValue(svc)!).Count;
    }

    private sealed class Factory(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new Handler(respond));

        private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
                => respond(request);
        }
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;

        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();

        public bool IsJobDisabled(string jobName) => false;
    }
}
