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
            NullLogger<OciUpstreamAuthService>.Instance);
    }

    private static OciUpstreamRegistryOptions MakeUpstream(
        OciAuthType authType,
        string host = "registry.docker.io",
        string? username = null,
        string? password = null)
        => new()
        {
            Name = "test",
            Host = host,
            AuthType = authType,
            Username = username,
            Password = password,
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

        string? result = await svc.GetAuthorizationAsync(upstream, "owner/image", "pull", default);

        Assert.Null(result);
    }

    // ── Basic ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetAuthorizationAsync_Basic_ReturnsCorrectHeader()
    {
        using var svc = Build();
        var upstream = MakeUpstream(OciAuthType.Basic, username: "alice", password: "hunter2");

        string? result = await svc.GetAuthorizationAsync(upstream, "library/ubuntu", "pull", default);

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
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry-1.docker.io");

        string? result = await svc.GetAuthorizationAsync(upstream, "library/ubuntu", "pull", default);

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
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry-1.docker.io");

        string? first = await svc.GetAuthorizationAsync(upstream, "library/ubuntu", "pull", default);
        string? second = await svc.GetAuthorizationAsync(upstream, "library/ubuntu", "pull", default);

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
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange, host: "registry-1.docker.io");

        string? first = await svc.GetAuthorizationAsync(upstream, "library/ubuntu", "pull", default);
        Assert.Equal("Bearer token-v1", first);

        svc.InvalidateToken(upstream, "library/ubuntu", "pull");

        string? second = await svc.GetAuthorizationAsync(upstream, "library/ubuntu", "pull", default);
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

        string? result = await svc.GetAuthorizationAsync(upstream, "team/app", "pull", default);

        Assert.Null(result);
    }

    // ── Air-gap ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetAuthorizationAsync_AirGapped_Throws()
    {
        using var svc = Build(airGapped: true);
        var upstream = MakeUpstream(OciAuthType.DockerHubTokenExchange);

        await Assert.ThrowsAsync<AirGappedException>(() =>
            svc.GetAuthorizationAsync(upstream, "library/ubuntu", "pull", default));
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
