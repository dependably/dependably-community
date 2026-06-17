using System.Net;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class MetricsAccessMiddlewareTests
{
    private static MetricsAccessMiddleware Build(
        RequestDelegate next,
        string? allowedIps = "127.0.0.1",
        string? enabled = null)
    {
        var dict = new Dictionary<string, string?>();
        if (allowedIps is not null)
        {
            dict["METRICS_ALLOWED_IPS"] = allowedIps;
        }

        if (enabled is not null)
        {
            dict["METRICS_ENABLED"] = enabled;
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();

        // No-DB instance-setting reader: env vars cover the test cases here, so
        // the DB path is never exercised.
        static Task<string?> NoDb(string key, CancellationToken _) => Task.FromResult<string?>(null);

        var accessConfig = new MetricsAccessConfig(NoDb, config, TimeProvider.System);
        var diagnostics = new ScrapeDiagnostics(TimeProvider.System);
        return new MetricsAccessMiddleware(next, accessConfig, diagnostics);
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
        bool nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, allowedIps: "127.0.0.1");

        var ctx = MetricsContext(IPAddress.Parse("127.0.0.1"));
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_NonMetricsPath_CallsNextRegardlessOfIp()
    {
        bool nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, allowedIps: "127.0.0.1");

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/api/v1/x";
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("192.168.99.99");

        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_NullRemoteIp_Returns403()
    {
        bool nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, allowedIps: "127.0.0.1");

        var ctx = MetricsContext(null);
        await middleware.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.False(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_IPv4MappedIPv6_AllowedAfterMapping()
    {
        bool nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, allowedIps: "127.0.0.1");

        var ctx = MetricsContext(IPAddress.Parse("::ffff:127.0.0.1"));
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_DisallowedIp_Returns403()
    {
        bool nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, allowedIps: "127.0.0.1");

        var ctx = MetricsContext(IPAddress.Parse("192.168.1.1"));
        await middleware.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.False(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_ConfiguredCidrRange_AllowsMatchingIp()
    {
        bool nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, allowedIps: "10.0.0.0/8");

        var ctx = MetricsContext(IPAddress.Parse("10.1.2.3"));
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_DisabledViaEnv_Returns404()
    {
        bool nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, allowedIps: "127.0.0.1", enabled: "0");

        var ctx = MetricsContext(IPAddress.Parse("127.0.0.1"));
        await middleware.InvokeAsync(ctx);

        Assert.Equal(StatusCodes.Status404NotFound, ctx.Response.StatusCode);
        Assert.False(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_Loopback_AllowedByDefault()
    {
        // With no env vars set, MetricsAccessConfig falls back to the
        // hard-coded default of [127.0.0.1, ::1], so loopback callers
        // get through without any operator configuration.
        bool nextCalled = false;
        RequestDelegate next = ctx => { nextCalled = true; return Task.CompletedTask; };
        var middleware = Build(next, allowedIps: null);

        var ctx = MetricsContext(IPAddress.Parse("127.0.0.1"));
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);

        // ::1 also default-allowed.
        bool nextCalled2 = false;
        RequestDelegate next2 = ctx => { nextCalled2 = true; return Task.CompletedTask; };
        var middleware2 = Build(next2, allowedIps: null);
        var ctx2 = MetricsContext(IPAddress.IPv6Loopback);
        await middleware2.InvokeAsync(ctx2);

        Assert.True(nextCalled2);
    }
}
