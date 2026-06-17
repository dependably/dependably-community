using System.Net;
using Dependably.Protocol;
using Dependably.Security;

namespace Dependably.Tests.Unit;

/// <summary>
/// Tests for <see cref="SsrfAwareRedirectHandler"/>.
///
/// Verifies that redirect-based SSRF attacks are blocked as a defense-in-depth layer:
/// an upstream server returning a 3xx redirect to a cloud-metadata endpoint or RFC1918
/// range raises <see cref="SsrfBlockedException"/> without opening a connection to the
/// blocked target. The inner call count proves the handler intercepts before the second
/// TCP hop.
/// </summary>
[Trait("Category", "Security")]
public class SsrfAwareRedirectHandlerTests
{
    // ── blocking redirect to cloud metadata ──────────────────────────────────────

    [Fact]
    public async Task SendAsync_RedirectToBlockedUrl_ThrowsSsrfBlockedException()
    {
        var validator = new StubValidator();
        var inner = new StubInnerHandler();
        var client = new HttpClient(new SsrfAwareRedirectHandler(validator) { InnerHandler = inner });

        // Initial response: 302 redirecting to cloud metadata endpoint.
        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("http://169.254.169.254/latest/meta-data/iam/") }
        });

        // The validator allows the initial URL but blocks the redirect target.
        validator.BlockedUrls.Add("http://169.254.169.254/latest/meta-data/iam/");

        await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            client.GetAsync("http://upstream.test/packages/foo-1.0.tar.gz"));

        // The redirect target was validated and blocked — no second HTTP call made.
        Assert.Equal(1, inner.CallCount);
    }

    [Fact]
    public async Task SendAsync_RedirectTo169_254_BlockedRegardlessOfPath()
    {
        var validator = new StubValidator();
        var inner = new StubInnerHandler();
        var client = new HttpClient(new SsrfAwareRedirectHandler(validator) { InnerHandler = inner });

        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.MovedPermanently)
        {
            Headers = { Location = new Uri("http://169.254.169.254/") }
        });
        validator.BlockedUrls.Add("http://169.254.169.254/");

        await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            client.GetAsync("http://upstream.test/simple/foo/"));
    }

    [Fact]
    public async Task SendAsync_RedirectToInternalIp_ThrowsSsrfBlockedException()
    {
        var validator = new StubValidator();
        var inner = new StubInnerHandler();
        var client = new HttpClient(new SsrfAwareRedirectHandler(validator) { InnerHandler = inner });

        // 302 to an RFC1918 address
        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("http://10.0.0.1/sensitive-data") }
        });
        validator.BlockedUrls.Add("http://10.0.0.1/sensitive-data");

        await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            client.GetAsync("http://upstream.test/pkg"));
    }

    // ── legitimate redirect is followed ──────────────────────────────────────────

    [Fact]
    public async Task SendAsync_RedirectToAllowedUrl_FollowsAndReturnsResponse()
    {
        var validator = new StubValidator();
        var inner = new StubInnerHandler();
        var client = new HttpClient(new SsrfAwareRedirectHandler(validator) { InnerHandler = inner });

        // 302 to a CDN mirror (allowed)
        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("https://cdn.example.com/foo-1.0.tar.gz") }
        });
        // Final CDN response
        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([1, 2, 3])
        });

        var response = await client.GetAsync("http://upstream.test/foo-1.0.tar.gz");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, inner.CallCount);
    }

    // ── redirect chain stops at MaxRedirects ─────────────────────────────────────

    [Fact]
    public async Task SendAsync_ExceedingMaxRedirects_ReturnsLastRedirectResponse()
    {
        var validator = new StubValidator();
        var inner = new StubInnerHandler();
        var client = new HttpClient(new SsrfAwareRedirectHandler(validator) { InnerHandler = inner });

        // Enqueue MaxRedirects+1 redirect responses (all allowed)
        for (int i = 0; i <= SsrfAwareRedirectHandler.MaxRedirects; i++)
        {
            inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.Found)
            {
                Headers = { Location = new Uri($"https://cdn.example.com/hop{i + 1}") }
            });
        }

        // Stops after MaxRedirects hops and returns the last redirect response
        var response = await client.GetAsync("http://upstream.test/start");

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        // Total calls: 1 initial + MaxRedirects followed
        Assert.Equal(SsrfAwareRedirectHandler.MaxRedirects + 1, inner.CallCount);
    }

    // ── 200 OK (no redirect) passes through unchanged ─────────────────────────────

    [Fact]
    public async Task SendAsync_OkResponse_PassesThroughWithoutValidatingAgain()
    {
        var validator = new StubValidator();
        var inner = new StubInnerHandler();
        var client = new HttpClient(new SsrfAwareRedirectHandler(validator) { InnerHandler = inner });

        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"version\":\"3.0.0\"}")
        });

        var response = await client.GetAsync("http://upstream.test/index.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, inner.CallCount);
        // Validator is only called on redirect targets; the initial URL is pre-checked by
        // UpstreamClient.FetchAndStageAsync / GetOrFetchMetadataAsync before the request is sent.
        Assert.Empty(validator.ValidatedUrls);
    }

    // ── Authorization header is NOT forwarded across redirects ───────────────────

    [Fact]
    public async Task SendAsync_RedirectWithAuth_DoesNotForwardAuthorizationHeader()
    {
        var validator = new StubValidator();
        var inner = new StubInnerHandler();
        var client = new HttpClient(new SsrfAwareRedirectHandler(validator) { InnerHandler = inner });

        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("https://cdn.example.com/blob") }
        });
        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK));

        var request = new HttpRequestMessage(HttpMethod.Get, "http://upstream.test/blob");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer secret-token");
        await client.SendAsync(request);

        // Second (redirect) call must not carry the Authorization header
        var secondRequest = inner.Requests[1];
        Assert.False(secondRequest.Headers.Contains("Authorization"));
    }

    // ── org context propagation ───────────────────────────────────────────────────

    [Fact]
    public async Task SendAsync_RedirectBlocked_ValidatorReceivesOrgIdFromRequestOptions()
    {
        var validator = new StubValidator();
        var inner = new StubInnerHandler();
        var client = new HttpClient(new SsrfAwareRedirectHandler(validator) { InnerHandler = inner });

        inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("http://169.254.169.254/iam") }
        });
        validator.BlockedUrls.Add("http://169.254.169.254/iam");

        var request = new HttpRequestMessage(HttpMethod.Get, "http://upstream.test/pkg");
        request.Options.Set(SsrfAwareRedirectHandler.OrgIdOption, "org-abc");

        await Assert.ThrowsAsync<SsrfBlockedException>(() => client.SendAsync(request));

        // The validator was called with the org context from the request options.
        Assert.Single(validator.ValidatedUrls);
        Assert.Equal(("http://169.254.169.254/iam", "org-abc"), validator.ValidatedCalls[0]);
    }

    // ── mixed partial-failure: first succeeds, second blocked, third succeeds ────

    [Fact]
    public async Task SendAsync_MixedRedirects_BlocksOnlyForbiddenTarget()
    {
        // Three independent fetch operations: safe redirect → blocked redirect → safe redirect.
        // Verifies that per-hop validation is independent across calls and that a blocked
        // middle hop does not prevent the third call from succeeding.
        var validator = new StubValidator();
        validator.BlockedUrls.Add("http://169.254.169.254/creds");

        var results = new List<(bool Blocked, int CallsWhenResolved)>();

        foreach (var (redirectTarget, blocked) in new[]
        {
            ("https://cdn.safe.com/pkg-a.tgz", false),
            ("http://169.254.169.254/creds", true),
            ("https://cdn.safe.com/pkg-b.tgz", false),
        })
        {
            var inner = new StubInnerHandler();
            inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.Found)
            {
                Headers = { Location = new Uri(redirectTarget) }
            });
            if (!blocked)
            {
                inner.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent([0xDE, 0xAD])
                });
            }

            var handler = new SsrfAwareRedirectHandler(validator) { InnerHandler = inner };
            using var c = new HttpClient(handler);
            try
            {
                await c.GetAsync("http://upstream.test/pkg");
                results.Add((Blocked: false, CallsWhenResolved: inner.CallCount));
            }
            catch (SsrfBlockedException)
            {
                results.Add((Blocked: true, CallsWhenResolved: inner.CallCount));
            }
        }

        // First fetch: followed redirect to safe CDN — not blocked, 2 HTTP calls
        Assert.False(results[0].Blocked);
        Assert.Equal(2, results[0].CallsWhenResolved);

        // Second fetch: redirect to blocked metadata — blocked, only 1 HTTP call (initial)
        Assert.True(results[1].Blocked);
        Assert.Equal(1, results[1].CallsWhenResolved);

        // Third fetch: followed redirect to safe CDN — not blocked, 2 HTTP calls
        Assert.False(results[2].Blocked);
        Assert.Equal(2, results[2].CallsWhenResolved);
    }
}

// ── Test doubles ──────────────────────────────────────────────────────────────

/// <summary>
/// Validator that blocks a configurable set of URLs and allows everything else.
/// Records all (url, orgId) pairs so tests can assert on call sites and org attribution.
/// </summary>
file sealed class StubValidator : IUpstreamUrlValidator
{
    public HashSet<string> BlockedUrls { get; } = [];
    public List<string> ValidatedUrls { get; } = [];
    public List<(string Url, string? OrgId)> ValidatedCalls { get; } = [];

    public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
    {
        ValidatedUrls.Add(url);
        ValidatedCalls.Add((url, orgId));
        return Task.FromResult(!BlockedUrls.Contains(url));
    }
}

/// <summary>
/// HttpMessageHandler backed by a queue of responses. Records all received requests.
/// </summary>
file sealed class StubInnerHandler : HttpMessageHandler
{
    public Queue<HttpResponseMessage> Responses { get; } = new();
    public List<HttpRequestMessage> Requests { get; } = [];
    public int CallCount { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CallCount++;
        Requests.Add(request);
        return Task.FromResult(
            Responses.Count > 0
                ? Responses.Dequeue()
                : new HttpResponseMessage(HttpStatusCode.OK));
    }
}
