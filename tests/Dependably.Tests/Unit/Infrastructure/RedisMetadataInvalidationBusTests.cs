using System.Diagnostics.Metrics;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using StackExchange.Redis;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The Redis fan-out transport's failure posture: a broker that is down must degrade the system
/// to TTL-expiry convergence, never fail a push. Attaches a MeterListener filtered by
/// <see cref="DependablyMeter.MeterName"/>, so it runs in the MeterSensitive collection.
/// </summary>
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class RedisMetadataInvalidationBusTests
{
    private static readonly MetadataInvalidation Npm = MetadataInvalidation.ForNpm("org-a", "pkg");

    [Fact]
    public async Task PublishAsync_CountsSuccessAndSendsTheEncodedCoordinates()
    {
        var subscriber = Substitute.For<ISubscriber>();
        var bus = BuildBus(subscriber, out _);

        var measurements = new List<(long Value, string Outcome)>();
        using (PublishedListener(measurements))
        {
            await bus.PublishAsync(Npm);
        }

        await subscriber.Received(1).PublishAsync(
            Arg.Any<RedisChannel>(),
            Arg.Is<RedisValue>(v => Decodes(v, bus.Origin)),
            Arg.Any<CommandFlags>());

        Assert.Equal(new[] { (1L, "success") }, measurements);
    }

    /// <summary>
    /// Redis unreachable at publish time. The push path calls the void <c>Publish</c>, so the
    /// contract under test is: nothing propagates out, the failure is logged, and it is counted
    /// with <c>outcome=server_error</c> so an operator can see convergence has fallen back to TTL.
    /// </summary>
    [Fact]
    public async Task PublishAsync_SwallowsLogsAndCounts_WhenTheBrokerIsUnreachable()
    {
        var subscriber = Substitute.For<ISubscriber>();
        subscriber
            .PublishAsync(Arg.Any<RedisChannel>(), Arg.Any<RedisValue>(), Arg.Any<CommandFlags>())
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"));
        var bus = BuildBus(subscriber, out var logger);

        var measurements = new List<(long Value, string Outcome)>();
        Exception? thrown;
        using (PublishedListener(measurements))
        {
            thrown = await Record.ExceptionAsync(() => bus.PublishAsync(Npm));
        }

        Assert.Null(thrown);
        Assert.Equal(new[] { (1L, "server_error") }, measurements);
        logger.Received().Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    /// <summary>
    /// The fire-and-forget entry point the mutation path actually calls. It must return without
    /// throwing even when the transport is dead — a missed invalidation is a staleness bug, an
    /// exception here would be a failed publish.
    /// </summary>
    [Fact]
    public void Publish_NeverThrows_WhenTheBrokerIsUnreachable()
    {
        var subscriber = Substitute.For<ISubscriber>();
        subscriber
            .PublishAsync(Arg.Any<RedisChannel>(), Arg.Any<RedisValue>(), Arg.Any<CommandFlags>())
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"));

        var bus = BuildBus(subscriber, out _);

        Assert.Null(Record.Exception(() => bus.Publish(Npm)));
    }

    /// <summary>
    /// Even a synchronously-throwing client (no multiplexer at all) must not escape into the push
    /// path — <c>GetSubscriber()</c> itself throws before any await is reached.
    /// </summary>
    [Fact]
    public void Publish_NeverThrows_WhenTheClientCannotEvenProduceASubscriber()
    {
        var redis = Substitute.For<IRedisClient>();
        redis.ApplyPrefix(Arg.Any<string>()).Returns(call => "dependably:" + call.Arg<string>());
        redis.GetSubscriber().Throws(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"));
        var bus = new RedisMetadataInvalidationBus(
            redis,
            new MetadataInvalidationReceiver(
                TestMetadataInvalidation.Coordinator(),
                NullLogger<MetadataInvalidationReceiver>.Instance),
            NullLogger<RedisMetadataInvalidationBus>.Instance);

        Assert.Null(Record.Exception(() => bus.Publish(Npm)));
    }

    /// <summary>
    /// A replica that cannot subscribe keeps serving. Refusing to start over a cache-freshness
    /// optimisation would turn a degraded-but-correct deployment into an outage.
    /// </summary>
    [Fact]
    public async Task StartAsync_DoesNotThrow_WhenSubscribeFails()
    {
        var subscriber = Substitute.For<ISubscriber>();
        subscriber
            .SubscribeAsync(Arg.Any<RedisChannel>(), Arg.Any<Action<RedisChannel, RedisValue>>(), Arg.Any<CommandFlags>())
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"));
        var bus = BuildBus(subscriber, out _);

        Assert.Null(await Record.ExceptionAsync(() => bus.StartAsync(CancellationToken.None)));
    }

    /// <summary>
    /// The channel carries the deployment's configured Redis key prefix, so two deployments
    /// sharing one Redis instance never evict each other's caches.
    /// </summary>
    [Fact]
    public async Task ChannelCarriesTheConfiguredKeyPrefix()
    {
        var subscriber = Substitute.For<ISubscriber>();
        var bus = BuildBus(subscriber, out _, prefix: "tenant-x:");

        await bus.PublishAsync(Npm);

        await subscriber.Received(1).PublishAsync(
            Arg.Is<RedisChannel>(c => c.ToString() == "tenant-x:" + RedisMetadataInvalidationBus.ChannelName),
            Arg.Any<RedisValue>(),
            Arg.Any<CommandFlags>());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static RedisMetadataInvalidationBus BuildBus(
        ISubscriber subscriber, out ILogger<RedisMetadataInvalidationBus> logger, string prefix = "dependably:")
    {
        var redis = Substitute.For<IRedisClient>();
        redis.ApplyPrefix(Arg.Any<string>()).Returns(call => prefix + call.Arg<string>());
        redis.GetSubscriber().Returns(subscriber);
        logger = Substitute.For<ILogger<RedisMetadataInvalidationBus>>();
        return new RedisMetadataInvalidationBus(
            redis,
            new MetadataInvalidationReceiver(
                TestMetadataInvalidation.Coordinator(),
                NullLogger<MetadataInvalidationReceiver>.Instance),
            logger);
    }

    private static bool Decodes(RedisValue value, string expectedOrigin) =>
        MetadataInvalidationCodec.TryDecode(value.ToString(), out var decoded, out string origin)
        && decoded == Npm
        && origin == expectedOrigin;

    private static MeterListener PublishedListener(List<(long Value, string Outcome)> sink)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName
                    && instrument.Name == "dependably.metadata.invalidations_published")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            string outcome = "";
            foreach (var tag in tags)
            {
                if (tag.Key == "outcome")
                {
                    outcome = tag.Value?.ToString() ?? "";
                }
            }

            sink.Add((measurement, outcome));
        });
        listener.Start();
        return listener;
    }
}
