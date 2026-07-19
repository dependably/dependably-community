using Dependably.Infrastructure;
using Dependably.Protocol;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="SsrfBlockedExceptionMiddleware"/> mapping: an escaping
/// <see cref="SsrfBlockedException"/> becomes a deterministic 502 problem-JSON response
/// (never the unhandled 500 the framework would otherwise surface).
/// </summary>
[Trait("Category", "Unit")]
public sealed class SsrfBlockedExceptionMiddlewareTests
{
    private static DefaultHttpContext BuildContext()
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    [Fact]
    public async Task SsrfBlocked_MapsTo502_WithProblemJsonBody()
    {
        var middleware = new SsrfBlockedExceptionMiddleware(
            _ => throw new SsrfBlockedException("http://169.254.169.254/latest/meta-data/"),
            NullLogger<SsrfBlockedExceptionMiddleware>.Instance);

        var ctx = BuildContext();
        await middleware.InvokeAsync(ctx);

        Assert.Equal(502, ctx.Response.StatusCode);
        Assert.Equal("application/problem+json", ctx.Response.ContentType);

        ctx.Response.Body.Seek(0, SeekOrigin.Begin);
        string body = await new StreamReader(ctx.Response.Body).ReadToEndAsync();
        Assert.Contains("Upstream fetch blocked", body);
        Assert.Contains("\"status\":502", body);
        // Upstream internals (the blocked URL) are never leaked in the response body.
        Assert.DoesNotContain("169.254.169.254", body);
    }

    [Fact]
    public async Task SsrfBlocked_MapsTo502_DeterministicAcrossDistinctBlockedUrls()
    {
        // Two distinct blocked-URL instances (link-local metadata endpoint vs. a private-range
        // host) must map to the identical status/content-type — the mapping does not depend on
        // which host or range triggered the block.
        var middlewareMetadata = new SsrfBlockedExceptionMiddleware(
            _ => throw new SsrfBlockedException("http://169.254.169.254/latest/meta-data/"),
            NullLogger<SsrfBlockedExceptionMiddleware>.Instance);
        var middlewarePrivate = new SsrfBlockedExceptionMiddleware(
            _ => throw new SsrfBlockedException("http://10.0.0.5/internal"),
            NullLogger<SsrfBlockedExceptionMiddleware>.Instance);

        var ctx1 = BuildContext();
        await middlewareMetadata.InvokeAsync(ctx1);
        var ctx2 = BuildContext();
        await middlewarePrivate.InvokeAsync(ctx2);

        Assert.Equal(502, ctx1.Response.StatusCode);
        Assert.Equal(502, ctx2.Response.StatusCode);
        Assert.Equal(ctx1.Response.ContentType, ctx2.Response.ContentType);
    }

    [Fact]
    public async Task NoException_PassesThrough()
    {
        bool nextCalled = false;
        var middleware = new SsrfBlockedExceptionMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            NullLogger<SsrfBlockedExceptionMiddleware>.Instance);

        var ctx = BuildContext();
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
        Assert.Equal(200, ctx.Response.StatusCode);
    }
}
