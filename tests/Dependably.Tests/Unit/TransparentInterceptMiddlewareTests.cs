using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class TransparentInterceptMiddlewareTests
{
    private static (TransparentInterceptMiddleware mw, Func<HttpContext, Task> capturedNext, List<string> seen)
        Build(IDictionary<string, string> mapping)
    {
        var seen = new List<string>();
        Task Next(HttpContext ctx)
        {
            seen.Add(ctx.Request.Path);
            return Task.CompletedTask;
        }
        var map = new HostEcosystemMap(mapping);
        return (new TransparentInterceptMiddleware(Next, map), Next, seen);
    }

    private static DefaultHttpContext Request(string host, string path)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Host = new HostString(host);
        ctx.Request.Path = path;
        return ctx;
    }

    [Fact]
    public async Task EmptyMap_NoRewrite()
    {
        var (mw, _, seen) = Build(new Dictionary<string, string>());
        await mw.InvokeAsync(Request("registry.npmjs.org", "/lodash"));
        Assert.Single(seen);
        Assert.Equal("/lodash", seen[0]);
    }

    [Fact]
    public async Task MappedHost_PrependsEcosystemPrefix()
    {
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["registry.npmjs.org"] = "npm"
        });
        await mw.InvokeAsync(Request("registry.npmjs.org", "/lodash"));
        Assert.Equal("/npm/lodash", seen[0]);
    }

    [Fact]
    public async Task UnmappedHost_NoRewrite()
    {
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["registry.npmjs.org"] = "npm"
        });
        await mw.InvokeAsync(Request("dependably.example.com", "/api/v1/orgs"));
        Assert.Equal("/api/v1/orgs", seen[0]);
    }

    [Fact]
    public async Task AlreadyPrefixed_Idempotent()
    {
        // Internal redirect / direct prefixed call: don't double-prefix.
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["registry.npmjs.org"] = "npm"
        });
        await mw.InvokeAsync(Request("registry.npmjs.org", "/npm/lodash"));
        Assert.Equal("/npm/lodash", seen[0]);
    }

    [Fact]
    public async Task PrefixCollisionPrefix_NotConfusedWithSimilarPath()
    {
        // A path like "/npmjs-something" should still be rewritten to "/npm/npmjs-something"
        // because it doesn't start with the "/npm" segment (segment boundaries matter).
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["registry.npmjs.org"] = "npm"
        });
        await mw.InvokeAsync(Request("registry.npmjs.org", "/npmjs-thing"));
        Assert.Equal("/npm/npmjs-thing", seen[0]);
    }

    [Fact]
    public async Task PyPiSplitsAcrossHosts_BothRouteToPyPi()
    {
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["pypi.org"] = "pypi",
            ["files.pythonhosted.org"] = "pypi"
        });
        await mw.InvokeAsync(Request("pypi.org", "/simple/lodash/"));
        await mw.InvokeAsync(Request("files.pythonhosted.org", "/packages/abc/lodash-1.0.0.tgz"));
        Assert.Equal("/pypi/simple/lodash/", seen[0]);
        Assert.Equal("/pypi/packages/abc/lodash-1.0.0.tgz", seen[1]);
    }
}
