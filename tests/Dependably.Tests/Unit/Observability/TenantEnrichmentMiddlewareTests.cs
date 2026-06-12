using System.Diagnostics;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Microsoft.AspNetCore.Http;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Verifies <see cref="TenantEnrichmentMiddleware"/> pushes the canonical
/// taxonomy properties (TenantId, OrgId, RequestId, TraceId, SpanId,
/// TenantSlug) into <c>LogContext</c> for the duration of the request.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantEnrichmentMiddlewareTests : IDisposable
{
    // Use a private Serilog logger instead of mutating the static Log.Logger:
    // xUnit runs test classes in parallel, and a WebApplicationFactory-based
    // test sharing the static would leak its request-logging events into this
    // sink. LogContext.PushProperty is AsyncLocal-scoped, so any Serilog
    // logger with Enrich.FromLogContext picks up the middleware's properties.
    private readonly CollectingSink _sink = new();
    private readonly Logger _logger;

    public TenantEnrichmentMiddlewareTests()
    {
        _logger = new LoggerConfiguration()
            .Enrich.FromLogContext()
            .WriteTo.Sink(_sink)
            .CreateLogger();
    }

    public void Dispose() => _logger.Dispose();

    [Fact]
    public async Task PushesRequestIdAlways()
    {
        var http = new DefaultHttpContext { TraceIdentifier = "req-abc" };

        var middleware = new TenantEnrichmentMiddleware(_ =>
        {
            _logger.Information("hi");
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(http);

        var evt = Assert.Single(_sink.Events);
        Assert.Equal("\"req-abc\"", evt.Properties["RequestId"].ToString());
    }

    [Fact]
    public async Task PushesTraceIdAndSpanIdWhenActivityPresent()
    {
        Activity.DefaultIdFormat = ActivityIdFormat.W3C;
        using var activity = new Activity("test-span").Start();
        var http = new DefaultHttpContext { TraceIdentifier = "req-1" };

        var middleware = new TenantEnrichmentMiddleware(_ =>
        {
            _logger.Information("hi");
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(http);

        var evt = Assert.Single(_sink.Events);
        Assert.True(evt.Properties.ContainsKey("TraceId"));
        Assert.True(evt.Properties.ContainsKey("SpanId"));
        Assert.Contains(activity.TraceId.ToString(), evt.Properties["TraceId"].ToString());
    }

    [Fact]
    public async Task PushesTenantPropertiesWhenContextIsTenant()
    {
        var http = new DefaultHttpContext { TraceIdentifier = "req-1" };
        http.Items[TenantContext.HttpItemsKey] =
            TenantContext.ForTenant(tenantId: "tnt_1", tenantSlug: "acme");

        var middleware = new TenantEnrichmentMiddleware(_ =>
        {
            _logger.Information("hi");
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(http);

        var evt = Assert.Single(_sink.Events);
        Assert.Equal("\"tnt_1\"", evt.Properties["TenantId"].ToString());
        Assert.Equal("\"tnt_1\"", evt.Properties["OrgId"].ToString());
        Assert.Equal("\"acme\"", evt.Properties["TenantSlug"].ToString());
    }

    [Fact]
    public async Task DoesNotPushTenantPropertiesOnApexRequest()
    {
        var http = new DefaultHttpContext { TraceIdentifier = "req-1" };
        http.Items[TenantContext.HttpItemsKey] = TenantContext.Apex;

        var middleware = new TenantEnrichmentMiddleware(_ =>
        {
            _logger.Information("hi");
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(http);

        var evt = Assert.Single(_sink.Events);
        Assert.False(evt.Properties.ContainsKey("TenantId"));
        Assert.False(evt.Properties.ContainsKey("OrgId"));
        Assert.False(evt.Properties.ContainsKey("TenantSlug"));
    }

    [Fact]
    public async Task DoesNotPushTenantPropertiesOnUninitializedRequest()
    {
        var http = new DefaultHttpContext { TraceIdentifier = "req-1" };
        http.Items[TenantContext.HttpItemsKey] = TenantContext.Uninitialized;

        var middleware = new TenantEnrichmentMiddleware(_ =>
        {
            _logger.Information("hi");
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(http);

        var evt = Assert.Single(_sink.Events);
        Assert.False(evt.Properties.ContainsKey("TenantId"));
    }

    [Fact]
    public async Task PropertiesAreScopedToRequest()
    {
        // After the middleware returns, LogContext should not carry the
        // properties anymore — proves the using-stack is disposed.
        var http = new DefaultHttpContext { TraceIdentifier = "req-scoped" };
        http.Items[TenantContext.HttpItemsKey] =
            TenantContext.ForTenant("tnt_x", "slug_x");

        var middleware = new TenantEnrichmentMiddleware(_ => Task.CompletedTask);
        await middleware.InvokeAsync(http);

        _logger.Information("outside");

        var evt = Assert.Single(_sink.Events);
        Assert.False(evt.Properties.ContainsKey("TenantId"));
        Assert.False(evt.Properties.ContainsKey("RequestId"));
    }

    private sealed class CollectingSink : ILogEventSink
    {
        public List<LogEvent> Events { get; } = new();
        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }
}
