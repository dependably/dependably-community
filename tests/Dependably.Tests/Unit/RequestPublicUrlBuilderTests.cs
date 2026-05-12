using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class RequestPublicUrlBuilderTests
{
    private static IConfiguration Config(string? baseUrl = null)
    {
        var dict = new Dictionary<string, string?>();
        if (baseUrl is not null) dict["BASE_URL"] = baseUrl;
        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    private static DefaultHttpContext Request(string scheme, string host)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Scheme = scheme;
        ctx.Request.Host = new HostString(host);
        return ctx;
    }

    [Fact]
    public void BaseUrl_NoBaseUrl_DerivedFromRequest()
    {
        var b = new RequestPublicUrlBuilder(Config());
        Assert.Equal("https://acme.dependably.example.com",
            b.BaseUrl(Request("https", "acme.dependably.example.com")));
    }

    [Fact]
    public void BaseUrl_BaseUrlSchemeOverridesRequest()
    {
        // Behind a TLS-terminating proxy: request comes in as http, BASE_URL declares https.
        var b = new RequestPublicUrlBuilder(Config("https://dependably.example.com"));
        Assert.Equal("https://internal.svc",
            b.BaseUrl(Request("http", "internal.svc")));
    }

    [Fact]
    public void BaseUrl_HostFromRequest_NotBaseUrl()
    {
        // Transparent intercept: client reaches us at registry.npmjs.org, BASE_URL is the
        // canonical deployment hostname. Echo back the inbound host.
        var b = new RequestPublicUrlBuilder(Config("https://dependably.example.com"));
        Assert.Equal("https://registry.npmjs.org",
            b.BaseUrl(Request("https", "registry.npmjs.org")));
    }

    [Fact]
    public void Absolute_AppendsPath()
    {
        var b = new RequestPublicUrlBuilder(Config());
        Assert.Equal("https://acme.example.com/npm/tarballs",
            b.Absolute(Request("https", "acme.example.com"), "/npm/tarballs"));
    }

    [Fact]
    public void Absolute_EmptyPath_EquivalentToBaseUrl()
    {
        var b = new RequestPublicUrlBuilder(Config());
        var ctx = Request("https", "acme.example.com");
        Assert.Equal(b.BaseUrl(ctx), b.Absolute(ctx, ""));
    }

    [Fact]
    public void Absolute_PathWithoutLeadingSlash_Throws()
    {
        var b = new RequestPublicUrlBuilder(Config());
        Assert.Throws<ArgumentException>(() =>
            b.Absolute(Request("https", "acme.example.com"), "npm/tarballs"));
    }

    [Fact]
    public void Absolute_PreservesPort()
    {
        var b = new RequestPublicUrlBuilder(Config());
        Assert.Equal("http://localhost:8080/saml/acs",
            b.Absolute(Request("http", "localhost:8080"), "/saml/acs"));
    }

    [Fact]
    public void Absolute_MalformedBaseUrl_FallsBackToRequestScheme()
    {
        // BASE_URL set to garbage; behavior is to ignore it and fall back to request scheme.
        var b = new RequestPublicUrlBuilder(Config("not-a-url"));
        Assert.Equal("http://localhost/x",
            b.Absolute(Request("http", "localhost"), "/x"));
    }
}
