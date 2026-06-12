using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class TenantNotReadyExceptionMiddlewareTests
{
    private static TenantNotReadyExceptionMiddleware BuildThrowing(TenantNotReadyException ex) =>
        new(_ => throw ex);

    private static DefaultHttpContext NewContext()
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    private static async Task<JsonElement> ReadBodyAsync(DefaultHttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        using var reader = new StreamReader(ctx.Response.Body);
        string body = await reader.ReadToEndAsync();
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    [Fact]
    public async Task NotFound_Returns404_WithReasonExtension()
    {
        var mw = BuildThrowing(new TenantNotReadyException(
            "t-missing", TenantNotReadyReason.NotFound, "tenant not found"));
        var ctx = NewContext();

        await mw.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status404NotFound, ctx.Response.StatusCode);
        Assert.Equal("application/problem+json", ctx.Response.ContentType);
        Assert.False(ctx.Response.Headers.ContainsKey("Retry-After"));

        var body = await ReadBodyAsync(ctx);
        Assert.Equal(404, body.GetProperty("status").GetInt32());
        Assert.Equal("NotFound", body.GetProperty("reason").GetString());
        Assert.Equal("t-missing", body.GetProperty("tenantId").GetString());
        Assert.Equal("tenant not found", body.GetProperty("detail").GetString());
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task StatusInactive_Returns423Locked_WithoutRetryAfter(string status)
    {
        // 423 Locked is the right semantic — the tenant exists but admin action is needed
        // to lift the state. No Retry-After: clients shouldn't keep polling.
        var mw = BuildThrowing(new TenantNotReadyException(
            "t-locked", TenantNotReadyReason.StatusInactive, $"status='{status}'"));
        var ctx = NewContext();

        await mw.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status423Locked, ctx.Response.StatusCode);
        Assert.False(ctx.Response.Headers.ContainsKey("Retry-After"));

        var body = await ReadBodyAsync(ctx);
        Assert.Equal("StatusInactive", body.GetProperty("reason").GetString());
        Assert.Contains(status, body.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task ProvisioningPending_Returns503_WithRetryAfter30()
    {
        var mw = BuildThrowing(new TenantNotReadyException(
            "t-pending", TenantNotReadyReason.ProvisioningPending, "provisioning state='creating'"));
        var ctx = NewContext();

        await mw.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, ctx.Response.StatusCode);
        Assert.Equal("30", ctx.Response.Headers.RetryAfter.ToString());

        var body = await ReadBodyAsync(ctx);
        Assert.Equal("ProvisioningPending", body.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task ProvisioningFailed_Returns503_WithRetryAfter60()
    {
        var mw = BuildThrowing(new TenantNotReadyException(
            "t-failed", TenantNotReadyReason.ProvisioningFailed, "provisioning state='failed'"));
        var ctx = NewContext();

        await mw.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, ctx.Response.StatusCode);
        // Longer retry for failed: ops needs to inspect, not just wait it out.
        Assert.Equal("60", ctx.Response.Headers.RetryAfter.ToString());

        var body = await ReadBodyAsync(ctx);
        Assert.Equal("ProvisioningFailed", body.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task NonTenantNotReadyException_DoesNotIntercept()
    {
        // Other exceptions must bubble — middleware is specific to TenantNotReadyException.
        var mw = new TenantNotReadyExceptionMiddleware(_ => throw new InvalidOperationException("nope"));
        var ctx = NewContext();

        await Assert.ThrowsAsync<InvalidOperationException>(() => mw.InvokeAsync(ctx));
    }

    [Fact]
    public async Task ResponseAlreadyStarted_RethrowsInsteadOfCorrupting()
    {
        // If the response has already started writing we can't change status/headers safely;
        // re-throw so the host loggers see the failure instead of silently writing garbage.
        // DefaultHttpContext + MemoryStream doesn't flip HasStarted on its own, so we inject
        // a response feature that reports HasStarted=true to simulate the post-flush state.
        var ctx = NewContext();
        ctx.Features.Set<IHttpResponseFeature>(new StartedResponseFeature
        {
            StatusCode = StatusCodes.Status200OK,
        });

        var mw = new TenantNotReadyExceptionMiddleware(_ =>
            throw new TenantNotReadyException("t", TenantNotReadyReason.NotFound, "after start"));

        await Assert.ThrowsAsync<TenantNotReadyException>(() => mw.InvokeAsync(ctx));
        // The pre-existing 200 was not clobbered.
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    private sealed class StartedResponseFeature : IHttpResponseFeature
    {
        public int StatusCode { get; set; } = 200;
        public string? ReasonPhrase { get; set; }
        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();
        public Stream Body { get; set; } = new MemoryStream();
        public bool HasStarted => true;
        public void OnStarting(Func<object, Task> callback, object state) { }
        public void OnCompleted(Func<object, Task> callback, object state) { }
    }

    [Fact]
    public async Task UnknownReason_FallsBackTo500_NoRetryAfter()
    {
        // Defence-in-depth: if someone adds a new TenantNotReadyReason and forgets to wire
        // it into Map, the middleware must still produce a structured response (500) rather
        // than crash. Cast an out-of-range value to exercise the default switch arm.
        var mw = BuildThrowing(new TenantNotReadyException(
            "t-unknown", (TenantNotReadyReason)999, "unmapped reason"));
        var ctx = NewContext();

        await mw.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status500InternalServerError, ctx.Response.StatusCode);
        Assert.Equal("application/problem+json", ctx.Response.ContentType);
        Assert.False(ctx.Response.Headers.ContainsKey("Retry-After"));

        var body = await ReadBodyAsync(ctx);
        Assert.Equal(500, body.GetProperty("status").GetInt32());
        Assert.Equal("Tenant not ready", body.GetProperty("title").GetString());
        Assert.Equal("t-unknown", body.GetProperty("tenantId").GetString());
    }

    [Fact]
    public async Task HappyPath_DoesNotTouchResponse()
    {
        // No exception → middleware is invisible.
        var mw = new TenantNotReadyExceptionMiddleware(ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status204NoContent;
            return Task.CompletedTask;
        });
        var ctx = NewContext();

        await mw.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status204NoContent, ctx.Response.StatusCode);
        Assert.Null(ctx.Response.ContentType);
    }
}
