using System.Net;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class MetricsAccessMiddlewareTests
{
    private static MetricsAccessMiddleware Build(RequestDelegate next, string allowedIps = "127.0.0.1")
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["METRICS_ALLOWED_IPS"] = allowedIps })
            .Build();
        return new MetricsAccessMiddleware(next, config);
    }

    private static DefaultHttpContext MetricsContext(IPAddress? ip)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/metrics";
        ctx.Connection.RemoteIpAddress = ip;
        return ctx;
    }

    [Fact]
    public async Task InvokeAsync_LocalhostIp_Allows()
    {
        var nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, "127.0.0.1");

        var ctx = MetricsContext(IPAddress.Parse("127.0.0.1"));
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_NonMetricsPath_CallsNextRegardlessOfIp()
    {
        var nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, "127.0.0.1");

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/api/v1/x";
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("192.168.99.99");

        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_NullRemoteIp_Returns403()
    {
        var nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, "127.0.0.1");

        var ctx = MetricsContext(null);
        await middleware.InvokeAsync(ctx);

        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.False(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_IPv4MappedIPv6_AllowedAfterMapping()
    {
        var nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, "127.0.0.1");

        var ctx = MetricsContext(IPAddress.Parse("::ffff:127.0.0.1"));
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_DisallowedIp_Returns403()
    {
        var nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, "127.0.0.1");

        var ctx = MetricsContext(IPAddress.Parse("192.168.1.1"));
        await middleware.InvokeAsync(ctx);

        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.False(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_ConfiguredCidrRange_AllowsMatchingIp()
    {
        var nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, "10.0.0.0/8");

        var ctx = MetricsContext(IPAddress.Parse("10.1.2.3"));
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
    }
}
