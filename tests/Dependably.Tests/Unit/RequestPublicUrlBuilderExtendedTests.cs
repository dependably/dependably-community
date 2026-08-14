using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers IsHttpsDeployment + SessionCookieOptions — the slices of RequestPublicUrlBuilder
/// the existing tests don't touch. SessionCookieOptions in particular is the load-bearing
/// helper for the auth-cookie code path.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RequestPublicUrlBuilderExtendedTests
{
    private static IConfiguration Config(string? baseUrl = null, string? requireSecureCookies = null)
    {
        var dict = new Dictionary<string, string?>();
        if (baseUrl is not null)
        {
            dict["BASE_URL"] = baseUrl;
        }

        if (requireSecureCookies is not null)
        {
            dict["REQUIRE_SECURE_COOKIES"] = requireSecureCookies;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    private static DefaultHttpContext Ctx(string scheme, string host)
    {
        var c = new DefaultHttpContext();
        c.Request.Scheme = scheme;
        c.Request.Host = new HostString(host);
        return c;
    }

    [Fact]
    public void IsHttpsDeployment_True_WhenBaseUrlIsHttps()
    {
        var b = new RequestPublicUrlBuilder(Config("https://dependably.example.com"));
        Assert.True(b.IsHttpsDeployment);
    }

    [Fact]
    public void IsHttpsDeployment_False_WhenBaseUrlIsHttp()
    {
        var b = new RequestPublicUrlBuilder(Config("http://internal.dev"));
        Assert.False(b.IsHttpsDeployment);
    }

    [Fact]
    public void IsHttpsDeployment_False_WhenBaseUrlMissingOrMalformed()
    {
        Assert.False(new RequestPublicUrlBuilder(Config()).IsHttpsDeployment);
        Assert.False(new RequestPublicUrlBuilder(Config("not-a-url")).IsHttpsDeployment);
    }

    [Fact]
    public void SessionCookieOptions_AlwaysHttpOnlyAndEssential()
    {
        var b = new RequestPublicUrlBuilder(Config());
        var opts = b.SessionCookieOptions(Ctx("http", "localhost"));
        Assert.True(opts.HttpOnly);
        Assert.True(opts.IsEssential);
    }

    [Fact]
    public void SessionCookieOptions_SecureFalseOnInsecureRequest_AndInsecureDeployment()
    {
        var b = new RequestPublicUrlBuilder(Config("http://dev.local"));
        var opts = b.SessionCookieOptions(Ctx("http", "dev.local"));
        Assert.False(opts.Secure);
    }

    [Fact]
    public void SessionCookieOptions_SecureTrueWhenRequestIsHttps()
    {
        var b = new RequestPublicUrlBuilder(Config());
        var opts = b.SessionCookieOptions(Ctx("https", "acme.example.com"));
        Assert.True(opts.Secure);
    }

    [Fact]
    public void SessionCookieOptions_SecureTrueWhenDeploymentIsHttps_EvenIfRequestIsHttp()
    {
        // Behind a TLS-terminating proxy: the request reaches the app as http but
        // BASE_URL declares the deployment as https. Cookie must be Secure regardless.
        var b = new RequestPublicUrlBuilder(Config("https://dependably.example.com"));
        var opts = b.SessionCookieOptions(Ctx("http", "internal.svc"));
        Assert.True(opts.Secure);
    }

    [Fact]
    public void SessionCookieOptions_RequireSecureCookiesUnset_DefaultsToOldBehavior()
    {
        // Regression: REQUIRE_SECURE_COOKIES defaults to off so local plain-HTTP dev is unaffected.
        var b = new RequestPublicUrlBuilder(Config("http://dev.local"));
        var opts = b.SessionCookieOptions(Ctx("http", "dev.local"));
        Assert.False(opts.Secure);
    }

    [Fact]
    public void SessionCookieOptions_RequireSecureCookiesTrue_ForcesSecureOnPlainHttpRequest()
    {
        // A plain-HTTP request/deployment would otherwise ship the session cookie without
        // Secure (MITM can capture the session JWT). REQUIRE_SECURE_COOKIES=true forces it.
        var b = new RequestPublicUrlBuilder(Config("http://dev.local", requireSecureCookies: "true"));
        var opts = b.SessionCookieOptions(Ctx("http", "dev.local"));
        Assert.True(opts.Secure);
    }

    /// <summary>
    /// The documented fail-closed proxy default (<c>TRUSTED_PROXIES</c> unset) makes
    /// <c>ForwardedHeadersMiddleware</c> discard <c>X-Forwarded-Proto</c>, so an app behind a
    /// TLS-terminating proxy sees a plain-HTTP request. With no <c>BASE_URL</c> and
    /// <c>REQUIRE_SECURE_COOKIES</c> unset — all three signals absent at once — the session
    /// cookie would ship without <c>Secure</c> to a browser that is on HTTPS. The proxy's own
    /// claim about the client hop settles it.
    /// </summary>
    [Fact]
    public void SessionCookieOptions_ForwardedProtoHttps_ForcesSecure_WhenEveryOtherSignalIsAbsent()
    {
        var b = new RequestPublicUrlBuilder(Config());
        var ctx = Ctx("http", "internal.svc");
        ctx.Request.Headers["X-Forwarded-Proto"] = "https";

        Assert.True(b.SessionCookieOptions(ctx).Secure);
    }

    [Fact]
    public void SessionCookieOptions_ChainedForwardedProto_ReadsTheClientHop()
    {
        // Chained proxies append, so the left-most entry is the scheme the browser used.
        var b = new RequestPublicUrlBuilder(Config());
        var ctx = Ctx("http", "internal.svc");
        ctx.Request.Headers["X-Forwarded-Proto"] = "https, http";

        Assert.True(b.SessionCookieOptions(ctx).Secure);
    }

    [Fact]
    public void SessionCookieOptions_ForwardedProtoHttp_LeavesPlainHttpDevAlone()
    {
        // A proxy that reports a plaintext client hop must not turn Secure on: a browser refuses
        // to store a Secure cookie over http, which would silently break login.
        var b = new RequestPublicUrlBuilder(Config());
        var ctx = Ctx("http", "dev.local");
        ctx.Request.Headers["X-Forwarded-Proto"] = "http";

        Assert.False(b.SessionCookieOptions(ctx).Secure);
    }

    /// <summary>The URL builder deliberately does not read the untrusted header: a forged value
    /// there is reflected to other callers, where it would be an open-redirect/link-forgery
    /// primitive rather than a self-inflicted cookie restriction.</summary>
    [Fact]
    public void ForwardedProtoHttps_DoesNotChangeTheBuiltUrlScheme()
    {
        var b = new RequestPublicUrlBuilder(Config());
        var ctx = Ctx("http", "dev.local");
        ctx.Request.Headers["X-Forwarded-Proto"] = "https";

        Assert.Equal("http://dev.local", b.BaseUrl(ctx));
    }

    [Fact]
    public void SessionCookieOptions_RequireSecureCookiesTrue_NoBaseUrl_StillForcesSecure()
    {
        var b = new RequestPublicUrlBuilder(Config(requireSecureCookies: "true"));
        var opts = b.SessionCookieOptions(Ctx("http", "localhost"));
        Assert.True(opts.Secure);
    }

    [Fact]
    public void SessionCookieOptions_RequireSecureCookiesFalseValue_DoesNotForceSecure()
    {
        // Any value other than "true" (case-insensitive) leaves the existing precedence intact.
        var b = new RequestPublicUrlBuilder(Config("http://dev.local", requireSecureCookies: "false"));
        var opts = b.SessionCookieOptions(Ctx("http", "dev.local"));
        Assert.False(opts.Secure);
    }

    [Fact]
    public void SessionCookieOptions_DefaultsToSameSiteStrict()
    {
        var opts = new RequestPublicUrlBuilder(Config()).SessionCookieOptions(Ctx("https", "acme"));
        Assert.Equal(SameSiteMode.Strict, opts.SameSite);
    }

    [Fact]
    public void SessionCookieOptions_AcceptsExplicitSameSite()
    {
        var opts = new RequestPublicUrlBuilder(Config())
            .SessionCookieOptions(Ctx("https", "acme"), SameSiteMode.Lax);
        Assert.Equal(SameSiteMode.Lax, opts.SameSite);
    }

    // Invoked through the interface type so the interface-declared default value
    // (SameSiteMode.Strict on IPublicUrlBuilder.SessionCookieOptions) is the one the
    // compiler bakes into the call site — covers the lone uncovered line in
    // IPublicUrlBuilder.cs (the default-parameter on the interface declaration).
#pragma warning disable CA1859 // interface typing is intentional — see comment above
    [Fact]
    public void SessionCookieOptions_ViaInterface_DefaultIsStrict()
    {
        IPublicUrlBuilder b = new RequestPublicUrlBuilder(Config());
        var opts = b.SessionCookieOptions(Ctx("https", "acme.example.com"));
        Assert.Equal(SameSiteMode.Strict, opts.SameSite);
        Assert.True(opts.HttpOnly);
        Assert.True(opts.IsEssential);
    }

    [Fact]
    public void SessionCookieOptions_ViaInterface_AcceptsExplicitSameSite()
    {
        IPublicUrlBuilder b = new RequestPublicUrlBuilder(Config());
        var opts = b.SessionCookieOptions(Ctx("https", "acme.example.com"), SameSiteMode.Lax);
        Assert.Equal(SameSiteMode.Lax, opts.SameSite);
    }
#pragma warning restore CA1859
}
