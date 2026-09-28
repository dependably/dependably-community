using System.Diagnostics.Metrics;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The egress write path below the controllers: what the middleware turns a response into, and
/// how the writer carries events to the table. Each ecosystem's classification is covered by the
/// integration suite and by <c>MeteredEgressComplianceTests</c>.
/// </summary>
// One test asserts on dependably.usage_events.unclassified via a MeterListener, so the class runs
// alone against the process-wide static meter.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class EgressMeteringTests
{
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    [Fact]
    public async Task A_streamed_artifact_records_the_bytes_written_under_the_artifact_meter()
    {
        var writer = new UsageEventWriter(_clock);
        var context = MeteredContext(EgressKind.Artifact);

        await RunAsync(context, writer, async ctx =>
        {
            ctx.Response.StatusCode = 200;
            await ctx.Response.Body.WriteAsync(new byte[1234]);
        });

        var e = Assert.Single(Drain(writer));
        Assert.Equal(UsageMeters.EgressBytes, e.Meter);
        Assert.Equal(UsageDelivery.Streamed, e.Delivery);
        Assert.Equal(1234, e.Quantity);
        Assert.Equal("o1", e.OrgId);
        Assert.Equal("npm", e.Source);
    }

    [Fact]
    public async Task Bytes_written_through_the_pipe_writer_are_counted_too()
    {
        var writer = new UsageEventWriter(_clock);
        var context = MeteredContext(EgressKind.Metadata);

        await RunAsync(context, writer, async ctx =>
        {
            ctx.Response.StatusCode = 200;
            await ctx.Response.BodyWriter.WriteAsync(Encoding.UTF8.GetBytes("{\"name\":\"x\"}"));
            await ctx.Response.BodyWriter.FlushAsync();
        });

        var e = Assert.Single(Drain(writer));
        Assert.Equal(UsageMeters.EgressMetadataBytes, e.Meter);
        Assert.Equal(12, e.Quantity);
    }

    /// <summary>
    /// The wrapper must add no buffer of its own. Bytes a handler writes to the pipe and never
    /// flushes have to land in the server's pipe, where the server flushes them at the end of the
    /// request; parked in a wrapper-owned pipe they would never be sent, and a client waiting on
    /// the declared Content-Length would hang.
    /// </summary>
    [Fact]
    public async Task Unflushed_pipe_writes_land_in_the_servers_own_pipe()
    {
        var writer = new UsageEventWriter(_clock);
        var context = MeteredContext(EgressKind.Metadata);
        var serverBody = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpResponseBodyFeature>()!;

        await RunAsync(context, writer, ctx =>
        {
            ctx.Response.StatusCode = 200;
            var span = ctx.Response.BodyWriter.GetSpan(5);
            "hello"u8.CopyTo(span);
            ctx.Response.BodyWriter.Advance(5);
            return Task.CompletedTask;
        });

        Assert.Equal(5, serverBody.Writer.UnflushedBytes);
        Assert.Equal(5, Assert.Single(Drain(writer)).Quantity);
    }

    [Fact]
    public async Task A_sent_file_counts_its_length_from_the_offset()
    {
        var writer = new UsageEventWriter(_clock);
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, new byte[100]);

            await RunAsync(MeteredContext(EgressKind.Artifact), writer, async ctx =>
            {
                ctx.Response.StatusCode = 200;
                await ctx.Response.SendFileAsync(path, 30, null);
            });

            Assert.Equal(70, Assert.Single(Drain(writer)).Quantity);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(404)]
    [InlineData(403)]
    [InlineData(500)]
    [InlineData(304)]
    public async Task A_non_success_response_records_nothing(int status)
    {
        var writer = new UsageEventWriter(_clock);

        await RunAsync(MeteredContext(EgressKind.Artifact), writer, async ctx =>
        {
            ctx.Response.StatusCode = status;
            await ctx.Response.Body.WriteAsync(new byte[50]);
        });

        Assert.Empty(Drain(writer));
    }

    [Fact]
    public async Task An_empty_body_records_nothing()
    {
        var writer = new UsageEventWriter(_clock);

        await RunAsync(MeteredContext(EgressKind.Artifact), writer, ctx =>
        {
            ctx.Response.StatusCode = 200;
            return Task.CompletedTask;
        });

        Assert.Empty(Drain(writer));
    }

    [Fact]
    public async Task A_request_with_no_resolved_tenant_is_never_metered()
    {
        var writer = new UsageEventWriter(_clock);
        var context = MeteredContext(EgressKind.Artifact);
        context.Items.Remove(TenantContext.HttpItemsKey);

        await RunAsync(context, writer, async ctx => await ctx.Response.Body.WriteAsync(new byte[10]));

        Assert.Empty(Drain(writer));
    }

    [Fact]
    public async Task An_unmetered_endpoint_is_left_alone()
    {
        var writer = new UsageEventWriter(_clock);
        var context = TenantContextFor(new DefaultHttpContext());
        var originalBody = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpResponseBodyFeature>();

        await RunAsync(context, writer, async ctx =>
        {
            Assert.Same(originalBody, ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpResponseBodyFeature>());
            await ctx.Response.Body.WriteAsync(new byte[10]);
        });

        Assert.Empty(Drain(writer));
    }

    [Fact]
    public async Task A_redirect_records_the_objects_size_whatever_its_status()
    {
        var writer = new UsageEventWriter(_clock);

        await RunAsync(MeteredContext(EgressKind.PerResponse, "oci"), writer, ctx =>
        {
            ctx.RecordRedirectedEgress(987_654, "proxy/abc");
            ctx.Response.StatusCode = 307;
            return Task.CompletedTask;
        });

        var e = Assert.Single(Drain(writer));
        Assert.Equal(UsageMeters.EgressBytes, e.Meter);
        Assert.Equal(UsageDelivery.Redirect, e.Delivery);
        Assert.Equal(987_654, e.Quantity);
        Assert.Equal("proxy/abc", e.ObjectRef);
    }

    [Fact]
    public async Task A_handler_classification_overrides_the_attribute()
    {
        var writer = new UsageEventWriter(_clock);

        await RunAsync(MeteredContext(EgressKind.PerResponse, "maven"), writer, async ctx =>
        {
            ctx.ClassifyEgress(EgressKind.Artifact);
            await ctx.Response.Body.WriteAsync(new byte[7]);
        });

        Assert.Equal(UsageMeters.EgressBytes, Assert.Single(Drain(writer)).Meter);
    }

    [Fact]
    public async Task An_unclassified_per_response_body_records_as_metadata_and_is_counted()
    {
        var writer = new UsageEventWriter(_clock);
        long unclassified = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == DependablyMeter.MeterName && instrument.Name == "dependably.usage_events.unclassified")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, value, _, _) => Interlocked.Add(ref unclassified, value));
        listener.Start();

        await RunAsync(MeteredContext(EgressKind.PerResponse, "go"), writer, async ctx =>
            await ctx.Response.Body.WriteAsync(new byte[3]));

        Assert.Equal(UsageMeters.EgressMetadataBytes, Assert.Single(Drain(writer)).Meter);
        Assert.Equal(1, unclassified);
    }

    [Fact]
    public async Task A_body_aborted_mid_transfer_records_what_was_written_before_the_throw()
    {
        var writer = new UsageEventWriter(_clock);

        await Assert.ThrowsAsync<IOException>(() => RunAsync(MeteredContext(EgressKind.Artifact), writer, async ctx =>
        {
            await ctx.Response.Body.WriteAsync(new byte[400]);
            throw new IOException("client went away");
        }));

        Assert.Equal(400, Assert.Single(Drain(writer)).Quantity);
    }

    [Fact]
    public async Task The_original_body_feature_is_restored_after_the_request()
    {
        var writer = new UsageEventWriter(_clock);
        var context = MeteredContext(EgressKind.Artifact);
        var originalBody = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpResponseBodyFeature>();

        await RunAsync(context, writer, async ctx => await ctx.Response.Body.WriteAsync(new byte[1]));

        Assert.Same(originalBody, context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpResponseBodyFeature>());
    }

    [Fact]
    public async Task A_full_channel_sheds_after_its_bounded_wait_and_counts_the_drop()
    {
        var writer = new UsageEventWriter(_clock, capacity: 1, maxEnqueueWait: TimeSpan.Zero);

        Assert.True(await writer.EnqueueAsync(Event()));
        Assert.False(await writer.EnqueueAsync(Event()));
        Assert.Equal(1, writer.EnqueuedCount);
    }

    [Fact]
    public async Task The_drainer_commits_queued_events_and_a_replay_stores_nothing_twice()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();
        var writer = new UsageEventWriter(_clock);
        var service = new UsageEventWriterHostedService(
            writer, new UsageEventRepository(db), NullLogger<UsageEventWriterHostedService>.Instance, _clock);

        var e = Event();
        await writer.EnqueueAsync(e);
        await writer.EnqueueAsync(e);
        await service.DrainPendingAsync();

        await using var conn = await db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_events WHERE org_id = 'o1'"));
        Assert.Equal(2, service.FlushedCount);
    }

    private UsageEvent Event() =>
        UsageEvent.Create(Guid.CreateVersion7(_clock.GetUtcNow()), "o1", UsageMeters.EgressBytes,
            UsageDelivery.Streamed, 10, "npm", null, _clock.GetUtcNow());

    private static DefaultHttpContext MeteredContext(EgressKind kind, string ecosystem = "npm")
    {
        var context = new DefaultHttpContext();
        context.SetEndpoint(new Endpoint(
            null, new EndpointMetadataCollection(new MeteredEgressAttribute(kind, ecosystem)), "metered"));
        return TenantContextFor(context);
    }

    private static DefaultHttpContext TenantContextFor(DefaultHttpContext context)
    {
        context.Response.Body = new MemoryStream();
        context.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant("o1", "acme");
        return context;
    }

    private Task RunAsync(HttpContext context, UsageEventWriter writer, RequestDelegate endpoint) =>
        new EgressMeteringMiddleware(endpoint).InvokeAsync(context, writer, _clock);

    private static List<UsageEvent> Drain(UsageEventWriter writer)
    {
        var events = new List<UsageEvent>();
        while (writer.Reader.TryRead(out var e))
        {
            events.Add(e);
        }

        return events;
    }
}
