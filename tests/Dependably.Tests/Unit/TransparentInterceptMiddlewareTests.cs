using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;

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
    public async Task PyPiSplitsAcrossHosts_BothPassThroughUnprefixed()
    {
        // PyPI's protocol surface (PEP 503 /simple/, download host /packages/{file}) is served
        // unprefixed already, so an intercepted pip request must reach the route that actually
        // exists — not get rewritten onto a nonexistent /pypi/simple/... or /pypi/packages/...
        // path. The /packages/{file} route is single-segment (PyPiController.DownloadPackage),
        // matching the flat root-relative hrefs PyPiSimpleIndexHelper renders — not the
        // multi-segment CDN shape files.pythonhosted.org itself serves lockfile-pinned URLs
        // under (that shape isn't reachable through this intercept; tracked separately).
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["pypi.org"] = "pypi",
            ["files.pythonhosted.org"] = "pypi"
        });
        await mw.InvokeAsync(Request("pypi.org", "/simple/lodash/"));
        await mw.InvokeAsync(Request("files.pythonhosted.org", "/packages/lodash-1.0.0.tgz"));
        Assert.Equal("/simple/lodash/", seen[0]);
        Assert.Equal("/packages/lodash-1.0.0.tgz", seen[1]);
    }

    [Fact]
    public async Task PyPiJsonApiHost_StillReachesPrefixedRoute()
    {
        // The legacy JSON API genuinely lives under /pypi/; a bare-host request to it already
        // carries the segment, so the resolved PyPI prefix must leave it alone rather than
        // needing (or performing) a rewrite. This exercises the middleware's idempotency
        // branch (prefix "/pypi" already present in the path) rather than pinning
        // HostEcosystemMap's path-dependent prefix selection itself.
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["pypi.org"] = "pypi"
        });
        await mw.InvokeAsync(Request("pypi.org", "/pypi/lodash/json"));
        Assert.Equal("/pypi/lodash/json", seen[0]);
    }

    [Fact]
    public async Task PyPiUploadHost_UnprefixedLegacyPath_GetsPypiPrefixPrepended()
    {
        // twine's stock upload endpoint is bare-host "/legacy/" (upload.pypi.org/legacy/) —
        // no "/pypi" segment, unlike the JSON API. Only "POST /pypi/legacy/" is a routed
        // endpoint (PyPiController.Upload), so an intercepted upload must still get /pypi
        // prepended even though PyPI's /simple/ and /packages/ paths do not.
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["upload.pypi.org"] = "pypi"
        });
        await mw.InvokeAsync(Request("upload.pypi.org", "/legacy/"));
        Assert.Equal("/pypi/legacy/", seen[0]);
    }

    [Fact]
    public async Task ExactPrefixMatch_NoDoubleRewrite()
    {
        // Covers the StartsWithSegment branch where path.Length == prefix.Length (e.g. "/npm").
        // Without this short-circuit the middleware would rewrite "/npm" to "/npm/npm".
        var (mw, _, seen) = Build(new Dictionary<string, string>
        {
            ["registry.npmjs.org"] = "npm"
        });
        await mw.InvokeAsync(Request("registry.npmjs.org", "/npm"));
        Assert.Equal("/npm", seen[0]);
    }

    [Fact]
    public async Task MappedHost_EmptyPath_FallsBackToRootAndPrefixes()
    {
        // Covers the `context.Request.Path.Value ?? "/"` fallback: when no Path is set on the
        // request, the middleware treats it as "/" and rewrites to the bare ecosystem prefix.
        var seen = new List<string>();
        Task Next(HttpContext ctx)
        {
            seen.Add(ctx.Request.Path.Value ?? string.Empty);
            return Task.CompletedTask;
        }
        var map = new HostEcosystemMap(new Dictionary<string, string>
        {
            ["registry.npmjs.org"] = "npm"
        });
        var mw = new TransparentInterceptMiddleware(Next, map);

        var ctx = new DefaultHttpContext();
        ctx.Request.Host = new HostString("registry.npmjs.org");
        // Path intentionally left at its default (empty PathString, Value == null).

        await mw.InvokeAsync(ctx);

        // PathString normalises trailing "/" away, so "/npm/" surfaces as "/npm" on the next hop.
        Assert.Equal("/npm", seen[0]);
    }
}
