using System.Net;
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
/// The refusal and malformed-challenge arms of <see cref="OciUpstreamAuthService"/>: a probe that
/// carries no usable challenge, a token endpoint that answers with an error or a body without a
/// token, credential forwarding to the token endpoint, and token expiry measured on the injected
/// clock. Each failure path denies (throws or yields no header) rather than returning a token.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamAuthServiceRefusalTests
{
    private const string Host = "registry.internal.example";
    private const string Realm = "https://registry.internal.example/token";

    private static OciUpstreamRegistryOptions Upstream(
        OciAuthType authType = OciAuthType.DockerHubTokenExchange, string? user = null, string? password = null)
        => new()
        {
            Name = "internal",
            Host = Host,
            AuthType = authType,
            Username = user,
            Password = password,
            Prefixes = [""],
        };

    private static HttpResponseMessage Challenge(string header)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        resp.Headers.WwwAuthenticate.ParseAdd(header);
        return resp;
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static (OciUpstreamAuthService Svc, ScriptedFactory Factory) Build(
        FakeTimeProvider? clock = null, OciOptions? options = null, params HttpResponseMessage[] responses)
    {
        var factory = new ScriptedFactory(responses);
        var svc = new OciUpstreamAuthService(
            factory, Options.Create(options ?? new OciOptions()), new NoAirGap(),
            NullLogger<OciUpstreamAuthService>.Instance, clock ?? TestTime.Frozen());
        return (svc, factory);
    }

    [Fact]
    public async Task ProbeUnauthorizedWithoutAChallengeHeader_YieldsNoAuthorization()
    {
        var (svc, factory) = Build(responses: new HttpResponseMessage(HttpStatusCode.Unauthorized));
        using var _ = svc;

        string? header = await svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default);

        Assert.Null(header);
        Assert.Single(factory.Requests);
    }

    [Fact]
    public async Task ChallengeWithoutAParameter_YieldsNoAuthorization()
    {
        var (svc, factory) = Build(responses: Challenge("Bearer"));
        using var _ = svc;

        string? header = await svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default);

        Assert.Null(header);
        Assert.Single(factory.Requests);
    }

    [Fact]
    public async Task ChallengeWithoutARealm_YieldsNoAuthorization_AndNeverCallsATokenEndpoint()
    {
        var (svc, factory) = Build(responses: Challenge("Bearer service=\"registry.internal.example\""));
        using var _ = svc;

        string? header = await svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default);

        Assert.Null(header);
        Assert.Single(factory.Requests);
    }

    [Fact]
    public async Task TokenEndpointError_ThrowsUnauthorized_AndCachesNothing()
    {
        var (svc, factory) = Build(responses:
        [
            Challenge($"Bearer realm=\"{Realm}\",service=\"registry\""),
            new HttpResponseMessage(HttpStatusCode.Forbidden),
            Challenge($"Bearer realm=\"{Realm}\",service=\"registry\""),
            Json("""{"token":"tok-after-recovery","expires_in":300}"""),
        ]);
        using var _ = svc;

        var ex = await Assert.ThrowsAsync<OciUnauthorizedException>(() =>
            svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default));
        Assert.Contains("Forbidden", ex.Message, StringComparison.Ordinal);

        string? recovered = await svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default);
        Assert.Equal("Bearer tok-after-recovery", recovered);
        Assert.Equal(4, factory.Requests.Count);
    }

    [Fact]
    public async Task TokenBodyWithNeitherTokenNorAccessToken_ThrowsUnauthorized()
    {
        var (svc, _) = Build(responses:
        [
            Challenge($"Bearer realm=\"{Realm}\""),
            Json("""{"expires_in":300}"""),
        ]);
        using var _ = svc;

        var ex = await Assert.ThrowsAsync<OciUnauthorizedException>(() =>
            svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default));

        Assert.Contains("No token", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AccessTokenField_IsAcceptedWhenTheTokenFieldIsAbsent()
    {
        var (svc, factory) = Build(responses:
        [
            Challenge($"Bearer realm=\"{Realm}\",service=\"registry.internal.example\""),
            Json("""{"access_token":"oauth-style-token"}"""),
        ]);
        using var _ = svc;

        string? header = await svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default);

        Assert.Equal("Bearer oauth-style-token", header);
        var tokenRequest = factory.Requests[1];
        Assert.Contains("scope=repository:team/app:pull", tokenRequest.Url, StringComparison.Ordinal);
        Assert.Contains("service=registry.internal.example", tokenRequest.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenRequest_FallsBackToTheUpstreamHostWhenTheChallengeNamesNoService()
    {
        var (svc, factory) = Build(responses:
        [
            Challenge($"Bearer realm=\"{Realm}\""),
            Json("""{"token":"t1"}"""),
        ]);
        using var _ = svc;

        await svc.GetAuthorizationAsync("org-a", Upstream(), "team/app", "pull", default);

        Assert.Contains($"service={Host}", factory.Requests[1].Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConfiguredCredentials_AreSentToTheTokenEndpoint_AndAnonymousUpstreamsSendNone()
    {
        var (svc, factory) = Build(responses:
        [
            Challenge($"Bearer realm=\"{Realm}\""),
            Json("""{"token":"authed"}"""),
            Challenge($"Bearer realm=\"{Realm}\""),
            Json("""{"token":"anon"}"""),
        ]);
        using var _ = svc;

        await svc.GetAuthorizationAsync("org-a", Upstream(user: "ci-bot", password: "s3cret"), "team/app", "pull", default);
        await svc.GetAuthorizationAsync("org-b", Upstream(), "team/app", "pull", default);

        string expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("ci-bot:s3cret"));
        Assert.Equal(expected, factory.Requests[1].Authorization);
        Assert.Null(factory.Requests[3].Authorization);
    }

    [Fact]
    public async Task TokenLifetime_IsCappedByTheConfiguredCacheDuration_AndExpiryUsesTheInjectedClock()
    {
        var clock = TestTime.Frozen();
        var (svc, factory) = Build(clock, new OciOptions { TokenCacheDuration = TimeSpan.FromMinutes(2) },
        [
            Challenge($"Bearer realm=\"{Realm}\""),
            Json("""{"token":"long-lived","expires_in":86400}"""),
            Challenge($"Bearer realm=\"{Realm}\""),
            Json("""{"token":"renewed","expires_in":86400}"""),
        ]);
        using var _ = svc;
        var upstream = Upstream();

        Assert.Equal("Bearer long-lived", await svc.GetAuthorizationAsync("org-a", upstream, "team/app", "pull", default));

        clock.Advance(TimeSpan.FromSeconds(80));
        Assert.Equal("Bearer long-lived", await svc.GetAuthorizationAsync("org-a", upstream, "team/app", "pull", default));
        Assert.Equal(2, factory.Requests.Count);

        // 120s lifetime minus the 30s refresh margin: a token 95s old is already stale.
        clock.Advance(TimeSpan.FromSeconds(15));
        Assert.Equal("Bearer renewed", await svc.GetAuthorizationAsync("org-a", upstream, "team/app", "pull", default));
        Assert.Equal(4, factory.Requests.Count);
    }

    [Fact]
    public async Task ACachedToken_IsNeverSharedAcrossOrgs()
    {
        var (svc, factory) = Build(responses:
        [
            Challenge($"Bearer realm=\"{Realm}\""),
            Json("""{"token":"org-a-token"}"""),
            Challenge($"Bearer realm=\"{Realm}\""),
            Json("""{"token":"org-b-token"}"""),
        ]);
        using var _ = svc;
        var upstream = Upstream();

        string? a = await svc.GetAuthorizationAsync("org-a", upstream, "team/app", "pull", default);
        string? b = await svc.GetAuthorizationAsync("org-b", upstream, "team/app", "pull", default);

        Assert.Equal("Bearer org-a-token", a);
        Assert.Equal("Bearer org-b-token", b);
        Assert.Equal(4, factory.Requests.Count);
    }

    [Fact]
    public async Task AnUnknownAuthType_YieldsNoAuthorization()
    {
        var (svc, factory) = Build();
        using var _ = svc;

        string? header = await svc.GetAuthorizationAsync("org-a", Upstream((OciAuthType)99), "team/app", "pull", default);

        Assert.Null(header);
        Assert.Empty(factory.Requests);
    }

    private sealed record Seen(string Url, string? Authorization);

    private sealed class ScriptedFactory : IHttpClientFactory
    {
        private readonly Queue<HttpResponseMessage> _queue;

        public ScriptedFactory(HttpResponseMessage[] responses) => _queue = new Queue<HttpResponseMessage>(responses);

        public List<Seen> Requests { get; } = new();

        public HttpClient CreateClient(string name) => new(new Handler(this));

        private sealed class Handler(ScriptedFactory owner) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                owner.Requests.Add(new Seen(request.RequestUri!.ToString(), request.Headers.Authorization?.ToString()));
                return owner._queue.TryDequeue(out var resp)
                    ? Task.FromResult(resp)
                    : throw new InvalidOperationException($"unexpected request to {request.RequestUri}");
            }
        }
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
