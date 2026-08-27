using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Direct coverage for <see cref="TenantNotReadyResponseWriter"/>'s <c>/v2/</c> branch across
/// every <see cref="TenantNotReadyReason"/> — <see cref="TenantNotReadyExceptionMiddlewareTests"/>
/// only exercises the non-OCI problem+json path, leaving NotFound/ProvisioningPending/
/// ProvisioningFailed/the default arm on <c>/v2/</c> unpinned before this file.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantNotReadyResponseWriterTests
{
    private static DefaultHttpContext NewOciContext()
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.Request.Path = "/v2/team/app/blobs/uploads/";
        return ctx;
    }

    private static async Task<JsonElement> ReadOciErrorAsync(DefaultHttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        using var reader = new StreamReader(ctx.Response.Body);
        string body = await reader.ReadToEndAsync();
        return JsonDocument.Parse(body).RootElement.GetProperty("errors")[0].Clone();
    }

    [Fact]
    public async Task StatusInactive_Returns403Denied()
    {
        var ctx = NewOciContext();

        await TenantNotReadyResponseWriter.WriteAsync(ctx, TenantNotReadyReason.StatusInactive);

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.Equal("application/json", ctx.Response.ContentType);
        Assert.Equal("nosniff", ctx.Response.Headers.XContentTypeOptions.ToString());

        var error = await ReadOciErrorAsync(ctx);
        Assert.Equal("DENIED", error.GetProperty("code").GetString());
        // Covers suspended/archived/deleting alike — never names the specific status.
        Assert.Equal("Organization is not available.", error.GetProperty("message").GetString());
    }

    [Fact]
    public async Task NotFound_Returns404NameUnknown()
    {
        var ctx = NewOciContext();

        await TenantNotReadyResponseWriter.WriteAsync(ctx, TenantNotReadyReason.NotFound);

        Assert.Equal(StatusCodes.Status404NotFound, ctx.Response.StatusCode);
        Assert.Equal("nosniff", ctx.Response.Headers.XContentTypeOptions.ToString());

        var error = await ReadOciErrorAsync(ctx);
        Assert.Equal("NAME_UNKNOWN", error.GetProperty("code").GetString());
        Assert.Equal("Tenant not found.", error.GetProperty("message").GetString());
    }

    [Theory]
    [InlineData(TenantNotReadyReason.ProvisioningPending)]
    [InlineData(TenantNotReadyReason.ProvisioningFailed)]
    public async Task Provisioning_Returns503Unavailable(TenantNotReadyReason reason)
    {
        var ctx = NewOciContext();

        await TenantNotReadyResponseWriter.WriteAsync(ctx, reason);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, ctx.Response.StatusCode);
        Assert.Equal("nosniff", ctx.Response.Headers.XContentTypeOptions.ToString());

        var error = await ReadOciErrorAsync(ctx);
        Assert.Equal("UNAVAILABLE", error.GetProperty("code").GetString());
        Assert.Equal("Tenant registry is not ready.", error.GetProperty("message").GetString());
    }

    [Fact]
    public async Task UnknownReason_FallsBackToUnsupported500()
    {
        // Defence-in-depth: a future TenantNotReadyReason the switch forgets to wire in must
        // still produce a structured OCI error rather than an unhandled exception.
        var ctx = NewOciContext();

        await TenantNotReadyResponseWriter.WriteAsync(ctx, (TenantNotReadyReason)999);

        Assert.Equal(StatusCodes.Status500InternalServerError, ctx.Response.StatusCode);

        var error = await ReadOciErrorAsync(ctx);
        Assert.Equal("UNSUPPORTED", error.GetProperty("code").GetString());
        Assert.Equal("Tenant not ready.", error.GetProperty("message").GetString());
    }

    [Fact]
    public async Task StatusInactive_OciPath_PreservesSecurityAndCorsHeaders_ButNotTheAbortedContentType()
    {
        // The OCI branch calls Response.Clear() independently of the problem+json branch — pin
        // it separately so a regression confined to this branch is not masked by the other.
        var ctx = NewOciContext();
        ctx.Response.Headers.XContentTypeOptions = "nosniff";
        ctx.Response.Headers.XFrameOptions = "DENY";
        ctx.Response.Headers.ContentSecurityPolicy = "default-src 'none'";
        ctx.Response.Headers.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload";
        ctx.Response.Headers.AccessControlAllowOrigin = "https://spa.example.com";
        ctx.Response.Headers.AccessControlAllowCredentials = "true";
        ctx.Response.Headers.Vary = "Origin";
        ctx.Response.ContentType = "text/plain";
        ctx.Response.ContentLength = 4096;

        await TenantNotReadyResponseWriter.WriteAsync(ctx, TenantNotReadyReason.StatusInactive);

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.Equal("DENY", ctx.Response.Headers.XFrameOptions.ToString());
        Assert.Equal("default-src 'none'", ctx.Response.Headers.ContentSecurityPolicy.ToString());
        Assert.Equal(
            "max-age=31536000; includeSubDomains; preload",
            ctx.Response.Headers.StrictTransportSecurity.ToString());
        Assert.Equal("https://spa.example.com", ctx.Response.Headers.AccessControlAllowOrigin.ToString());
        Assert.Equal("true", ctx.Response.Headers.AccessControlAllowCredentials.ToString());
        Assert.Equal("Origin", ctx.Response.Headers.Vary.ToString());

        // The OCI error envelope's own shape, not the aborted response's.
        Assert.Equal("application/json", ctx.Response.ContentType);
        Assert.Null(ctx.Response.ContentLength);
    }

    [Fact]
    public async Task ResponseAlreadyStarted_DoesNotThrowOrClobber()
    {
        // TenantStatusEnforcementMiddleware calls this directly (no exception in flight), so
        // there is nothing to re-throw to if the response already started; the writer just
        // leaves it alone rather than let Response.Clear() fault.
        var ctx = NewOciContext();
        ctx.Features.Set<Microsoft.AspNetCore.Http.Features.IHttpResponseFeature>(
            new StartedResponseFeature { StatusCode = StatusCodes.Status200OK });

        await TenantNotReadyResponseWriter.WriteAsync(ctx, TenantNotReadyReason.StatusInactive);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    private sealed class StartedResponseFeature : Microsoft.AspNetCore.Http.Features.IHttpResponseFeature
    {
        public int StatusCode { get; set; } = 200;
        public string? ReasonPhrase { get; set; }
        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();
        public Stream Body { get; set; } = new MemoryStream();
        public bool HasStarted => true;
        public void OnStarting(Func<object, Task> callback, object state) { }
        public void OnCompleted(Func<object, Task> callback, object state) { }
    }
}
