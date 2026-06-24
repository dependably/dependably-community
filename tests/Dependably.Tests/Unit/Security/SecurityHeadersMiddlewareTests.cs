using Dependably.Security;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class SecurityHeadersMiddlewareTests
{
    private static async Task<DefaultHttpContext> InvokeForPath(string path)
    {
        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new SecurityHeadersMiddleware(next);

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        await middleware.InvokeAsync(ctx);
        return ctx;
    }

    // Every package-manager registry surface must get the locked-down RegistryCsp
    // (default-src 'none') and Cache-Control: no-store — not the SPA FrontendCsp.
    [Theory]
    [InlineData("/simple/")]
    [InlineData("/packages/some-file.whl")]
    [InlineData("/npm/left-pad")]
    [InlineData("/nuget/v3/index.json")]
    [InlineData("/pypi/legacy/")]
    [InlineData("/v2/library/alpine/manifests/latest")]
    [InlineData("/maven/com/example/artifact/1.0/artifact-1.0.jar")]
    [InlineData("/rpm/repodata/repomd.xml")]
    [InlineData("/cargo/config.json")]
    [InlineData("/go/example.com/mod/@v/list")]
    public async Task InvokeAsync_RegistryPath_GetsRegistryCspAndNoStore(string path)
    {
        var ctx = await InvokeForPath(path);

        Assert.Equal("no-store", ctx.Response.Headers.CacheControl.ToString());
        string? csp = ctx.Response.Headers.ContentSecurityPolicy.ToString();
        Assert.Contains("default-src 'none'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("form-action 'none'", csp);
    }

    // SPA deep links that merely contain a registry token as a substring (e.g. the
    // /package/npm/... detail route) must keep the FrontendCsp so the bundle loads.
    [Theory]
    [InlineData("/package/npm/left-pad")]
    [InlineData("/package/maven/com.example")]
    [InlineData("/")]
    public async Task InvokeAsync_SpaPath_GetsFrontendCspNotRegistry(string path)
    {
        var ctx = await InvokeForPath(path);

        string? csp = ctx.Response.Headers.ContentSecurityPolicy.ToString();
        Assert.Contains("script-src 'self'", csp);
        Assert.DoesNotContain("default-src 'none'", csp);
        Assert.True(string.IsNullOrEmpty(ctx.Response.Headers.CacheControl.ToString()),
            "SPA responses must not carry Cache-Control: no-store");
    }
}
