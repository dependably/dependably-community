using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for CsrfDefenseMiddleware — the CSRF defence-in-depth layer that
/// sits after UseAuthorization.
///
/// Rules under test:
///   - Cookie-authed POST with Sec-Fetch-Site: cross-site → 403
///   - Cookie-authed POST with Sec-Fetch-Site: same-origin → passes through
///   - Bearer-authed POST with Sec-Fetch-Site: cross-site → unaffected (passes through to controller)
///   - GET with Sec-Fetch-Site: cross-site → unaffected (safe method)
///   - SAML ACS POST (no Authorization, Sec-Fetch-Site: cross-site) → exempted, passes through
///   - Cookie-authed POST with Origin mismatch → 403
///   - Cookie-authed POST with Origin match → passes through
///   - Cookie-authed POST with no CSRF header and no form body → passes through
///   - Cookie-authed POST with no CSRF header and a form-encoded/multipart body → 403
/// </summary>
[Trait("Category", "Integration")]
public sealed class CsrfDefenseMiddlewareTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public CsrfDefenseMiddlewareTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Sec-Fetch-Site header ─────────────────────────────────────────────────

    [Fact]
    public async Task CookieAuthed_Post_SecFetchSite_CrossSite_Returns403()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        req.Headers.Add("Sec-Fetch-Site", "cross-site");

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task CookieAuthed_Post_SecFetchSite_SameSite_Returns403()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        req.Headers.Add("Sec-Fetch-Site", "same-site");

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task CookieAuthed_Post_SecFetchSite_SameOrigin_PassesThrough()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        req.Headers.Add("Sec-Fetch-Site", "same-origin");

        var resp = await client.SendAsync(req);

        // Middleware allows the request; the controller handles it (logout returns 200 or 401).
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task CookieAuthed_Post_SecFetchSite_None_PassesThrough()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        req.Headers.Add("Sec-Fetch-Site", "none");

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Authorization header skips CSRF check ─────────────────────────────────

    [Fact]
    public async Task BearerAuthed_Post_SecFetchSite_CrossSite_IsNotBlocked()
    {
        // Bearer-authenticated requests (API tokens, SPA using Authorization header) carry
        // no CSRF risk — the token is not a cookie and cross-site forms cannot set it.
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        req.Headers.Add("Sec-Fetch-Site", "cross-site");

        var resp = await client.SendAsync(req);

        // Middleware skips; controller handles (logout returns 200 or 204, never 403 from middleware).
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Safe methods skip CSRF check ─────────────────────────────────────────

    [Fact]
    public async Task Get_SecFetchSite_CrossSite_IsNotBlocked()
    {
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/methods");
        req.Headers.Add("Sec-Fetch-Site", "cross-site");

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── SAML ACS exemption ────────────────────────────────────────────────────

    [Fact]
    public async Task SamlAcs_Post_CrossSite_IsExempted()
    {
        // The IdP always POST cross-site to /saml/acs. Middleware must never block it.
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/saml/acs");
        req.Headers.Add("Sec-Fetch-Site", "cross-site");
        req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["SAMLResponse"] = "garbage-payload"
        });

        var resp = await client.SendAsync(req);

        // CSRF middleware exempts the path; the SAML controller returns an error for the
        // bad payload, but NOT a 403 from the CSRF layer.
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Origin header fallback ────────────────────────────────────────────────

    [Fact]
    public async Task CookieAuthed_Post_OriginMismatch_Returns403()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        // Sec-Fetch-Site absent; Origin is from a different host.
        req.Headers.Add("Origin", "https://evil.example.com");

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task CookieAuthed_Post_OriginMatchesHost_PassesThrough()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        // TestServer host is "localhost"; Origin matches.
        req.Headers.Add("Origin", "http://localhost");

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── No CSRF headers ───────────────────────────────────────────────────────

    [Fact]
    public async Task CookieAuthed_Post_NoCsrfHeader_PassesThrough()
    {
        // Neither Sec-Fetch-Site nor Origin, and no form body: a browser cannot produce this
        // request cross-site (it would need a CORS preflight the management policy refuses), so
        // the scripted clients that do send it keep working.
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    /// <summary>
    /// The gap a blanket "neither header → allow" leaves open. SameSite is scoped to the
    /// registrable domain, so a page on a sibling tenant subdomain is same-site and its form POST
    /// carries the victim's SameSite=Strict session cookie; a browser old enough to send no Fetch
    /// Metadata and no Origin on a form submission then reaches the API with no cross-origin
    /// signal at all. A form-encoded body with neither header is exactly that shape.
    /// </summary>
    [Fact]
    public async Task CookieAuthed_Post_NoCsrfHeader_FormEncodedBody_Returns403()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout")
        {
            Content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("x", "y") }),
        };
        req.Headers.Add("Cookie", $"dependably_session={jwt}");

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task CookieAuthed_Post_NoCsrfHeader_MultipartBody_Returns403()
    {
        // multipart/form-data is the other form-producible encoding, and the one the bulk-import
        // upload accepts — the content-type parameter (boundary) must not defeat the match.
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var content = new MultipartFormDataContent { { new ByteArrayContent([1, 2, 3]), "file", "a.tgz" } };
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/admin/import/upload") { Content = content };
        req.Headers.Add("Cookie", $"dependably_session={jwt}");

        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    /// <summary>
    /// The rule is scoped to requests that actually carry the credential a cross-site page would
    /// spend. An anonymous form POST — a mis-targeted <c>twine upload</c> at the bare host, say —
    /// has no session cookie to confuse the deputy with, so it must still get its real answer
    /// (405 here) rather than a CSRF refusal that hides what went wrong.
    /// </summary>
    [Fact]
    public async Task Anonymous_Post_NoCsrfHeader_FormBody_IsNotACsrfRejection()
    {
        using var client = _factory.CreateClient();
        var content = new MultipartFormDataContent { { new ByteArrayContent([1, 2, 3]), "content", "anything.whl" } };

        var resp = await client.PostAsync("/", content);

        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task CookieAuthed_Post_OriginMatch_FormEncodedBody_PassesThrough()
    {
        // The browser path for a legitimate form/multipart submission still carries Origin, so
        // the tightened rule costs the SPA nothing.
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout")
        {
            Content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("x", "y") }),
        };
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        req.Headers.Add("Origin", "http://localhost");

        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
    }
}
