using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers IsHttpsDeployment + SessionCookieOptions — the slices of RequestPublicUrlBuilder
/// the existing tests don't touch. SessionCookieOptions in particular is the load-bearing
/// helper for the auth-cookie code path.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RequestPublicUrlBuilderExtendedTests
{
    private static IConfiguration Config(string? baseUrl = null) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            baseUrl is null ? [] : new Dictionary<string, string?> { ["BASE_URL"] = baseUrl }
        ).Build();

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
}
