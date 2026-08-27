using System.Net;
using System.Net.Http.Headers;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// The 423/403 a suspended (or archived/deleting) tenant gets back from
/// <c>TenantStatusEnforcementMiddleware</c> is written by <see cref="Dependably.Infrastructure.TenantNotReadyResponseWriter"/>,
/// which calls <c>Response.Clear()</c> before writing its own body. <c>SecurityHeadersMiddleware</c>
/// writes its headers directly onto the response on the way in (CSP, X-Frame-Options,
/// Referrer-Policy, Permissions-Policy, HSTS, nosniff, and — on registry paths —
/// <c>Cache-Control: no-store</c>), so <c>Response.Clear()</c> wipes them unless
/// <c>ResponseHeaderPreserver</c> restores the snapshot taken before the clear — the
/// security-header assertions below regress without that restore. This class pins that
/// restoration end to end, through the real pipeline (not the writer directly, as
/// <see cref="Dependably.Tests.Unit.Infrastructure.TenantNotReadyResponseWriterTests"/> and
/// <see cref="Dependably.Tests.Unit.Infrastructure.TenantNotReadyExceptionMiddlewareTests"/>
/// already do).
///
/// <para>
/// The CORS assertions pin correct end-to-end behaviour rather than the restore mechanism
/// specifically: ASP.NET Core's <c>CorsMiddleware</c> applies its headers for an actual
/// (non-preflight) request through <c>Response.OnStarting</c>, a callback that fires when the
/// response body actually starts — after this writer's <c>Response.Clear()</c> — so
/// <c>Access-Control-Allow-Origin</c> already survives independently of the restore. The
/// preserved-header allowlist still names the CORS headers, both as documented intent and as a
/// defence against a future CORS integration that writes them synchronously instead.
/// </para>
///
/// Every negative probe (the suspended response) is paired with its active-org twin, so a helper
/// that stripped headers on every response — not just the refusal — would still fail the twin.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantSuspensionResponseHeaderTests : IAsyncLifetime
{
    // TestServer's default connection peer is loopback; trusting it lets X-Forwarded-Proto:
    // https rewrite Request.Scheme so SecurityHeadersMiddleware actually emits HSTS — the header
    // most likely to go unnoticed missing, since #589's whole premise is a browser's first HTTPS
    // navigation to a suspended tenant getting no pin.
    private readonly DependablyFactory _factory = new() { TrustedProxies = "127.0.0.1" };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private static HttpRequestMessage HttpsRequest(HttpMethod method, string path)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.Add("X-Forwarded-Proto", "https");
        return req;
    }

    // ── Management API problem+json path ────────────────────────────────────

    [Fact]
    public async Task Suspended_ManagementApi_423_CarriesFullSecurityHeaderSet_ActiveTwinCarriesSameSet()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(jwt);

        var activeResp = await client.SendAsync(HttpsRequest(HttpMethod.Get, "/api/v1/stats"));
        Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);
        AssertPathIndependentSecurityHeaderSet(activeResp);

        await _factory.SetOrgStatus("default", "suspended");

        var blockedResp = await client.SendAsync(HttpsRequest(HttpMethod.Get, "/api/v1/stats"));
        Assert.Equal(HttpStatusCode.Locked, blockedResp.StatusCode);
        AssertPathIndependentSecurityHeaderSet(blockedResp);

        // The refusal's own body shape — not whatever the controller might have started with,
        // since the enforcement middleware runs before the controller is ever reached here.
        Assert.Equal("application/problem+json", blockedResp.Content.Headers.ContentType?.MediaType);

        // /api/v1/ is not a registry path — SecurityHeadersMiddleware never sets Cache-Control
        // there, so the restore must not manufacture one either. Adversarial twin of the registry
        // tests below: proves the fix restores what was actually present, not a blanket grant.
        Assert.False(blockedResp.Headers.CacheControl?.NoStore ?? false);
    }

    /// <summary>
    /// The five headers <c>SecurityHeadersMiddleware</c> sets on every response regardless of
    /// path — Content-Security-Policy's exact value and Cache-Control differ per path (registry
    /// vs. management vs. frontend), so those two are asserted separately by each call site
    /// rather than folded into this shared helper.
    /// </summary>
    private static void AssertPathIndependentSecurityHeaderSet(HttpResponseMessage resp)
    {
        Assert.Equal("nosniff", Assert.Single(resp.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("DENY", Assert.Single(resp.Headers.GetValues("X-Frame-Options")));
        Assert.Equal(
            "strict-origin-when-cross-origin", Assert.Single(resp.Headers.GetValues("Referrer-Policy")));
        Assert.True(resp.Headers.Contains("Permissions-Policy"));
        Assert.True(resp.Headers.Contains("Content-Security-Policy"));
        Assert.True(
            resp.Headers.Contains("Strict-Transport-Security"),
            "HSTS must survive a suspended tenant's refusal — a browser's first HTTPS " +
            "navigation to a suspended subdomain is otherwise left with no pin.");
    }

    // ── OCI /v2/ error-envelope path ────────────────────────────────────────

    [Fact]
    public async Task Suspended_OciRefusal_403_CarriesFullSecurityHeaderSet_IncludingRegistryCacheControl()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        await _factory.SetOrgStatus("default", "suspended");

        var req = HttpsRequest(HttpMethod.Post, "/v2/suspend-headers-oci/blobs/uploads/?digest=sha256:0");
        req.Content = new ByteArrayContent([1, 2, 3]);
        var resp = await client.SendAsync(req);

        // The OCI branch maps StatusInactive to 403, not the 423 the problem+json branch uses —
        // the OCI Distribution Spec has no locked-resource semantics.
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);
        AssertPathIndependentSecurityHeaderSet(resp);

        // /v2/ is a registry path (SecurityHeadersMiddleware.IsRegistryPath), so the full set here
        // is seven headers, not six — a bare 403 is heuristically cacheable (RFC 9111 §4.2.2), and
        // an intermediary must not be allowed to store and replay a suspended tenant's refusal.
        Assert.True(resp.Headers.CacheControl?.NoStore, "registry-path refusals must carry Cache-Control: no-store");
    }

    // ── Non-OCI registry path (npm) ──────────────────────────────────────────

    [Fact]
    public async Task Suspended_NpmRegistryPath_423_CarriesFullSecurityHeaderSet_IncludingCacheControlNoStore()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        await _factory.SetOrgStatus("default", "suspended");

        var resp = await client.SendAsync(HttpsRequest(HttpMethod.Get, "/npm/left-pad"));

        Assert.Equal(HttpStatusCode.Locked, resp.StatusCode);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        AssertPathIndependentSecurityHeaderSet(resp);
        Assert.True(resp.Headers.CacheControl?.NoStore, "registry-path refusals must carry Cache-Control: no-store");
    }

    // ── Cross-origin CORS on the management API (#588) ──────────────────────

    [Fact]
    public async Task Suspended_CrossOrigin_423CarriesAccessControlAllowOrigin_ActiveTwinCarriesItToo()
    {
        // DependablyFactory leaves BASE_URL unset, so the management CORS policy falls back to
        // http://localhost:8080 — the origin this test presents.
        const string allowedOrigin = "http://localhost:8080";
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(jwt);

        var activeReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/stats");
        activeReq.Headers.Add("Origin", allowedOrigin);
        var activeResp = await client.SendAsync(activeReq);
        Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);
        Assert.Equal(allowedOrigin, Assert.Single(activeResp.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("true", Assert.Single(activeResp.Headers.GetValues("Access-Control-Allow-Credentials")));

        await _factory.SetOrgStatus("default", "suspended");

        var blockedReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/stats");
        blockedReq.Headers.Add("Origin", allowedOrigin);
        var blockedResp = await client.SendAsync(blockedReq);

        // The behaviour #588 asks for: a cross-origin SPA's request against a suspended tenant
        // must see Access-Control-Allow-Origin on the 423, or the browser reports a CORS error
        // instead of surfacing the lockout to application code.
        Assert.Equal(HttpStatusCode.Locked, blockedResp.StatusCode);
        Assert.Equal(allowedOrigin, Assert.Single(blockedResp.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("true", Assert.Single(blockedResp.Headers.GetValues("Access-Control-Allow-Credentials")));
    }

    [Fact]
    public async Task Suspended_MismatchedOrigin_423DoesNotCarryAccessControlAllowOrigin()
    {
        // Adversarial twin: the restore must not synthesize a CORS grant that CorsMiddleware
        // never issued in the first place — only echo what was actually present pre-Clear().
        const string disallowedOrigin = "https://evil.example.com";
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(jwt);

        await _factory.SetOrgStatus("default", "suspended");

        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/stats");
        req.Headers.Add("Origin", disallowedOrigin);
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Locked, resp.StatusCode);
        Assert.False(resp.Headers.Contains("Access-Control-Allow-Origin"));
    }
}
