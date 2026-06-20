using System.Net;
using System.Text;
using System.Text.Json;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Unit coverage for <see cref="OciUpstreamAuthService"/>.
///
/// Coverage targets:
///  - Anonymous upstream: GetAuthorizationAsync returns null
///  - Basic upstream: returns correct "Basic base64(user:password)" header
///  - DockerHub token exchange: parse Www-Authenticate challenge, GET token endpoint,
///    cache the result, return "Bearer {token}"
///  - DockerHub cache: second call within expiry does not re-exchange
///  - InvalidateToken: evicts cached token so next call re-exchanges
///  - Air-gap: throws AirGappedException
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamAuthServiceTests : IDisposable
{
    private readonly SequentialHandlerFactory _factory = new();

    public void Dispose() => _factory.Dispose();

    // ── Helpers ────────────────────────────────────────────────────────────────

    private OciUpstreamAuthService Build(
        IOptions<OciOptions>? opts = null,
        bool airGapped = false)
    {
        var options = opts ?? Options.Create(new OciOptions());
        return new OciUpstreamAuthService(
            _factory,
            options,
            new StubAirGap(airGapped),
            NullLogger<OciUpstreamAuthService>.Instance, TimeProvider.System);
    }

    private static OciUpstreamRegistryOptions MakeUpstream(
        OciAuthType authType,
        string host = "registry.docker.io",
        string? username = null,
        string? password = null,
        string? tokenEndpoint = null)
        => new()
        {
            Name = "test",
            Host = host,
            AuthType = authType,
            Username = username,
            Password = password,
            TokenEndpoint = tokenEndpoint,
            Prefixes = [""],
        };

    private static HttpResponseMessage JsonResponse(object body, HttpStatusCode status = HttpStatusCode.OK)
    {
        string json = JsonSerializer.Serialize(body);
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static string BuildTokenJson(string token, int expiresIn = 300)
        => JsonSerializer.Serialize(new { token, expires_in = expiresIn });

    // ── Anonymous ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetAuthorizationAsync_Anonymous_ReturnsNull()
    {
        using var svc = Build();
        var upstream = MakeUpstream(OciAuthType.Anonymous, host: "ghcr.io");

        string? result = await svc.GetAuthorizationAsync("test-org", upstream, "owner/image", "pull", default);

        Assert.Null(result);
    }

    // ── Basic ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetAuthorizationAsync_Basic_ReturnsCorrectHeader()
    {
        using var svc = Build();
        var upstream = MakeUpstream(OciAuthType.Basic, username: "alice", password: "hunter2");

        string? result = await svc.GetAuthorizationAsync("test-org", upstream, "library/ubuntu", "pull", default);

        string expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:hunter2"));
        Assert.Equal(expected, result);
    }

    // ── DockerHub token exchange ───────────────────────────────────────────────

    [Fact]
    public async Task GetAuthorizationAsync_DockerHub_ExchangesTokenAndReturnsBearerHeader()
    {
        // Step 1: /v2/ probe returns 401 with Www-Authenticate challenge.
        var probeResp = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        probeResp.Headers.WwwAuthenticate.ParseAdd(
            "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"\"");

        // Step 2: token exchange returns a JWT.
        const string tokenValue = "my.jwt.token";
        var tokenResp = JsonResponse(new { token = tokenValue, expires_in = 300 });

        _factory.Enqueue(probeResp, tokenResp);

        using var svc = Build();
        // Docker Hub's auth realm (auth.docker.io) differs from the registry host
        // (registry-1.docker.io) — the operator must pin TokenEndpoint to allow it.
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry-1.docker.io",
            tokenEndpoint: "https://auth.docker.io/token");

        string? result = await svc.GetAuthorizationAsync("test-org", upstream, "library/ubuntu", "pull", default);

        Assert.Equal("Bearer " + tokenValue, result);
    }

    [Fact]
    public async Task GetAuthorizationAsync_DockerHub_CachesToken_SecondCallDoesNotFetchAgain()
    {
        var probeResp = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        probeResp.Headers.WwwAuthenticate.ParseAdd(
            "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"\"");
        var tokenResp = JsonResponse(new { token = "cached-token", expires_in = 3600 });

        _factory.Enqueue(probeResp, tokenResp);
        // Only two responses queued; a third HTTP call would throw.

        using var svc = Build();
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry-1.docker.io",
            tokenEndpoint: "https://auth.docker.io/token");

        string? first = await svc.GetAuthorizationAsync("test-org", upstream, "library/ubuntu", "pull", default);
        string? second = await svc.GetAuthorizationAsync("test-org", upstream, "library/ubuntu", "pull", default);

        Assert.Equal("Bearer cached-token", first);
        Assert.Equal("Bearer cached-token", second);
        Assert.Equal(0, _factory.RemainingCount); // both HTTP calls consumed on first attempt
    }

    [Fact]
    public async Task GetAuthorizationAsync_DockerHub_InvalidateToken_RefetchesOnNextCall()
    {
        // First token exchange.
        var probe1 = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        probe1.Headers.WwwAuthenticate.ParseAdd(
            "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"\"");
        var tokenResp1 = JsonResponse(new { token = "token-v1", expires_in = 3600 });

        // Second token exchange (after invalidation).
        var probe2 = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        probe2.Headers.WwwAuthenticate.ParseAdd(
            "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"\"");
        var tokenResp2 = JsonResponse(new { token = "token-v2", expires_in = 3600 });

        _factory.Enqueue(probe1, tokenResp1, probe2, tokenResp2);

        using var svc = Build();
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry-1.docker.io",
            tokenEndpoint: "https://auth.docker.io/token");

        string? first = await svc.GetAuthorizationAsync("test-org", upstream, "library/ubuntu", "pull", default);
        Assert.Equal("Bearer token-v1", first);

        svc.InvalidateToken("test-org", upstream, "library/ubuntu", "pull");

        string? second = await svc.GetAuthorizationAsync("test-org", upstream, "library/ubuntu", "pull", default);
        Assert.Equal("Bearer token-v2", second);
    }

    [Fact]
    public async Task GetAuthorizationAsync_DockerHub_ProbeNoChallenge_ReturnsNull()
    {
        // /v2/ returns 200 (public registry with no auth needed).
        var probeResp = new HttpResponseMessage(HttpStatusCode.OK);
        _factory.Enqueue(probeResp);

        using var svc = Build();
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "internal.registry.local");

        string? result = await svc.GetAuthorizationAsync("test-org", upstream, "team/app", "pull", default);

        Assert.Null(result);
    }

    // ── Realm-redirect credential leak protection ──────────────────────────────

    /// <summary>
    /// Regression: a hostile upstream presenting a sibling-domain realm (sharing only the
    /// registrable domain, not the exact host) must not receive credentials. Without the fix,
    /// the registrable-domain fallback in IsTrustedRealm allowed harvest.attacker.com to
    /// receive credentials when registry.attacker.com was configured as the upstream.
    /// </summary>
    [Fact]
    public async Task GetAuthorizationAsync_DockerHub_SiblingDomainRealm_ThrowsWithoutPinnedEndpoint()
    {
        // Attacker-controlled registry.attacker.com returns a realm on a sibling domain
        // (harvest.attacker.com) — both under attacker.com's registrable domain.
        var probeResp = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        probeResp.Headers.WwwAuthenticate.ParseAdd(
            "Bearer realm=\"https://harvest.attacker.com/token\",service=\"registry.attacker.com\",scope=\"\"");

        _factory.Enqueue(probeResp);
        // If vulnerable: a second HTTP call to harvest.attacker.com would be issued here
        // carrying upstream credentials. The fix ensures we throw before issuing that call.

        using var svc = Build();
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry.attacker.com");

        await Assert.ThrowsAsync<OciUnauthorizedException>(() =>
            svc.GetAuthorizationAsync("test-org", upstream, "victim/image", "pull", default));

        // Verify no token-exchange HTTP call was made (queue still has no extra dequeues).
        Assert.Equal(0, _factory.RemainingCount);
    }

    /// <summary>
    /// Mixed partial-failure scenario: the first upstream has a pinned endpoint and succeeds;
    /// the second uses an untrusted sibling-domain realm and fails. Both paths are verified
    /// in the same call sequence to confirm the gate is per-upstream.
    /// </summary>
    [Fact]
    public async Task GetAuthorizationAsync_MixedUpstreams_PinnedSucceedsSiblingDomainFails()
    {
        // Upstream A: registry-1.docker.io with TokenEndpoint pinned — succeeds.
        var probeA = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        probeA.Headers.WwwAuthenticate.ParseAdd(
            "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"\"");
        var tokenA = JsonResponse(new { token = "legit-token", expires_in = 3600 });

        // Upstream B: registry.evil.io with a sibling-domain realm — fails.
        var probeB = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        probeB.Headers.WwwAuthenticate.ParseAdd(
            "Bearer realm=\"https://harvest.evil.io/token\",service=\"registry.evil.io\",scope=\"\"");

        _factory.Enqueue(probeA, tokenA, probeB);

        using var svc = Build();

        var upstreamA = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry-1.docker.io",
            tokenEndpoint: "https://auth.docker.io/token");
        var upstreamB = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry.evil.io");

        // Upstream A succeeds.
        string? resultA = await svc.GetAuthorizationAsync("test-org", upstreamA, "library/ubuntu", "pull", default);
        Assert.Equal("Bearer legit-token", resultA);

        // Upstream B's sibling-domain realm is refused.
        await Assert.ThrowsAsync<OciUnauthorizedException>(() =>
            svc.GetAuthorizationAsync("test-org", upstreamB, "victim/image", "pull", default));

        // All queued responses consumed — no extra HTTP calls were made.
        Assert.Equal(0, _factory.RemainingCount);
    }

    // ── Air-gap ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetAuthorizationAsync_AirGapped_Throws()
    {
        using var svc = Build(airGapped: true);
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange);

        await Assert.ThrowsAsync<AirGappedException>(() =>
            svc.GetAuthorizationAsync("test-org", upstream, "library/ubuntu", "pull", default));
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    /// <summary>
    /// IHttpClientFactory backed by a queue of pre-staged HttpResponseMessages.
    /// Each CreateClient returns a client that dequeues the next response.
    /// </summary>
    private sealed class SequentialHandlerFactory : IHttpClientFactory, IDisposable
    {
        private readonly Queue<HttpResponseMessage> _queue = new();

        public int RemainingCount => _queue.Count;

        public void Enqueue(params HttpResponseMessage[] responses)
        {
            foreach (var r in responses)
            {
                _queue.Enqueue(r);
            }
        }

        public HttpClient CreateClient(string name) => new(new DequeueHandler(_queue));

        public void Dispose()
        {
            foreach (var r in _queue)
            {
                r.Dispose();
            }

            _queue.Clear();
        }

        private sealed class DequeueHandler : HttpMessageHandler
        {
            private readonly Queue<HttpResponseMessage> _q;
            public DequeueHandler(Queue<HttpResponseMessage> q) => _q = q;

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return !_q.TryDequeue(out var resp)
                    ? throw new InvalidOperationException(
                        $"No more queued responses (unexpected request to {request.RequestUri})")
                    : Task.FromResult(resp);
            }
        }
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public StubAirGap(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
    }
}
