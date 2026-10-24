using System.Diagnostics.Metrics;
using Dependably.Infrastructure;
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
            () => new MetadataInvalidationReceiver(
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

    /// <summary>
    /// The receiver evicts through the coordinator, and the coordinator publishes through this
    /// bus. Constructing the bus must therefore not construct the receiver, or resolving the bus
    /// resolves the coordinator, which needs the bus: a loop the container deadlocks on. The
    /// receiver is built once, when the subscription opens.
    /// </summary>
    [Fact]
    public async Task Receiver_IsResolvedWhenTheSubscriptionOpens_NotWhenTheBusIsBuilt()
    {
        int resolutions = 0;
        var bus = new RedisMetadataInvalidationBus(
            RedisOver(Substitute.For<ISubscriber>()),
            () =>
            {
                resolutions++;
                return new MetadataInvalidationReceiver(
                    TestMetadataInvalidation.Coordinator(), NullLogger<MetadataInvalidationReceiver>.Instance);
            },
            NullLogger<RedisMetadataInvalidationBus>.Instance);

        bus.Publish(Npm);
        Assert.Equal(0, resolutions);

        await bus.StartAsync(CancellationToken.None);
        Assert.Equal(1, resolutions);
    }

    /// <summary>
    /// Delivery through the subscription the bus opens: a peer's message evicts on this replica,
    /// and this replica's own broadcast, echoed back by the broker, is dropped.
    /// </summary>
    [Fact]
    public async Task SubscribedHandler_EvictsOnAPeerMessage_AndDropsItsOwn()
    {
        var harness = TestMetadataInvalidation.Build();
        Action<RedisChannel, RedisValue>? handler = null;
        var subscriber = Substitute.For<ISubscriber>();
        subscriber
            .SubscribeAsync(
                Arg.Any<RedisChannel>(),
                Arg.Do<Action<RedisChannel, RedisValue>>(h => handler = h),
                Arg.Any<CommandFlags>())
            .Returns(Task.CompletedTask);
        var bus = new RedisMetadataInvalidationBus(
            RedisOver(subscriber),
            () => new MetadataInvalidationReceiver(
                harness.Coordinator, NullLogger<MetadataInvalidationReceiver>.Instance),
            NullLogger<RedisMetadataInvalidationBus>.Instance);
        await bus.StartAsync(CancellationToken.None);
        Assert.NotNull(handler);
        var key = new NpmPackumentKey("org-a", "pkg");
        var channel = RedisChannel.Literal("dependably:" + RedisMetadataInvalidationBus.ChannelName);

        harness.Npm.Set(key, [1], TimeSpan.FromMinutes(5));
        handler(channel, MetadataInvalidationCodec.Encode(Npm, bus.Origin));
        Assert.True(harness.Npm.TryGet(key, out _));

        handler(channel, MetadataInvalidationCodec.Encode(Npm, "peer-replica"));
        Assert.False(harness.Npm.TryGet(key, out _));
    }

    /// <summary>
    /// The org-wide message rides the same counters under the bounded <c>scope=org</c> attribute
    /// and carries no <c>ecosystem</c> attribute at all: <c>org</c> is a message kind, not an
    /// ecosystem, and the org id is never a label value.
    /// </summary>
    [Fact]
    public async Task PublishAsync_CountsAnOrgWideMessageUnderScopeOrg_WithNoEcosystem()
    {
        var subscriber = Substitute.For<ISubscriber>();
        var bus = BuildBus(subscriber, out _);
        string orgId = $"org-{Guid.NewGuid():N}";

        var measurements = new List<Measured>();
        using (PublishedListener(measurements))
        {
            await bus.PublishAsync(MetadataInvalidation.ForOrg(orgId));
        }

        var only = Assert.Single(measurements);
        Assert.Equal(1L, only.Value);
        Assert.Equal(
            new Dictionary<string, string> { ["scope"] = "org", ["outcome"] = "success" },
            only.Tags);
        Assert.DoesNotContain(orgId, only.Tags.Values);
    }

    [Fact]
    public void Receiver_CountsAnAppliedOrgWideMessageUnderScopeOrg_WithNoEcosystem()
    {
        var receiver = new MetadataInvalidationReceiver(
            TestMetadataInvalidation.Coordinator(), NullLogger<MetadataInvalidationReceiver>.Instance);
        string orgId = $"org-{Guid.NewGuid():N}";
        string payload = MetadataInvalidationCodec.Encode(MetadataInvalidation.ForOrg(orgId), origin: "peer");

        var measurements = new List<Measured>();
        using (ReceivedListener(measurements))
        {
            Assert.True(receiver.Apply(payload, selfOrigin: "self"));
        }

        // Other test classes apply invalidations concurrently, so this listener may also see
        // their measurements; every one of them must keep "org" out of the ecosystem attribute
        // and the tenant id out of every attribute.
        var snapshot = Snapshot(measurements);
        Assert.Contains(snapshot, m => m.Tags.Count == 1 && m.Tags.GetValueOrDefault("scope") == "org");
        Assert.DoesNotContain(snapshot, m => m.Tags.GetValueOrDefault("ecosystem") == "org");
        Assert.DoesNotContain(snapshot, m => m.Tags.Values.Contains(orgId));
    }

    public static TheoryData<string> EcosystemKinds() =>
        new(MetadataInvalidationEcosystems.All.Where(k => k != MetadataInvalidationEcosystems.Org));

    /// <summary>
    /// A message naming one ecosystem's caches counts under <c>scope=ecosystem</c> with that
    /// ecosystem — RPM's tenant-wide message included, since it still clears RPM caches only.
    /// </summary>
    [Theory]
    [MemberData(nameof(EcosystemKinds))]
    public async Task PublishAsync_CountsAnEcosystemMessageUnderScopeEcosystem(string kind)
    {
        var subscriber = Substitute.For<ISubscriber>();
        var bus = BuildBus(subscriber, out _);

        var measurements = new List<Measured>();
        using (PublishedListener(measurements))
        {
            await bus.PublishAsync(MessageOfKind(kind, "org-a"));
        }

        var only = Assert.Single(measurements);
        Assert.Equal(
            new Dictionary<string, string> { ["scope"] = "ecosystem", ["ecosystem"] = kind, ["outcome"] = "success" },
            only.Tags);
    }

    [Theory]
    [MemberData(nameof(EcosystemKinds))]
    public void Receiver_CountsAnAppliedEcosystemMessageUnderScopeEcosystem(string kind)
    {
        var receiver = new MetadataInvalidationReceiver(
            TestMetadataInvalidation.Coordinator(), NullLogger<MetadataInvalidationReceiver>.Instance);
        string payload = MetadataInvalidationCodec.Encode(MessageOfKind(kind, "org-a"), origin: "peer");

        var measurements = new List<Measured>();
        using (ReceivedListener(measurements))
        {
            Assert.True(receiver.Apply(payload, selfOrigin: "self"));
        }

        Assert.Contains(Snapshot(measurements), m =>
            m.Tags.Count == 2
            && m.Tags.GetValueOrDefault("scope") == "ecosystem"
            && m.Tags.GetValueOrDefault("ecosystem") == kind);
    }

    /// <summary>
    /// Every value the invalidation counters can put in the <c>ecosystem</c> attribute belongs to
    /// the shared ecosystem vocabulary every other plane uses. Drives one message of every wire
    /// kind through both counters and reads the vocabulary from its list of record, so a new wire
    /// kind that is not an ecosystem fails here unless it is counted under its own scope.
    /// </summary>
    [Fact]
    public async Task InvalidationCounters_EmitOnlyTaxonomyEcosystemIds()
    {
        var vocabulary = Dependably.Tests.Compliance.EcosystemHardcodedListComplianceTests.ParseEcosystemVocabulary();
        var bus = BuildBus(Substitute.For<ISubscriber>(), out _);
        var receiver = new MetadataInvalidationReceiver(
            TestMetadataInvalidation.Coordinator(), NullLogger<MetadataInvalidationReceiver>.Instance);

        var published = new List<Measured>();
        var received = new List<Measured>();
        using (PublishedListener(published))
        using (ReceivedListener(received))
        {
            foreach (string kind in MetadataInvalidationEcosystems.All)
            {
                var message = MessageOfKind(kind, "org-a");
                await bus.PublishAsync(message);
                Assert.True(receiver.Apply(MetadataInvalidationCodec.Encode(message, "peer"), selfOrigin: "self"));
            }
        }

        var emitted = Snapshot(published).Concat(Snapshot(received))
            .Select(m => m.Tags.GetValueOrDefault("ecosystem"))
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(emitted);
        var outside = emitted.Where(e => !vocabulary.Contains(e)).ToList();
        Assert.True(
            outside.Count == 0,
            $"Invalidation counters emitted ecosystem values outside ECOSYSTEMS: [{string.Join(", ", outside)}]");
        Assert.All(
            Snapshot(published).Concat(Snapshot(received)),
            m => Assert.Contains(m.Tags.GetValueOrDefault("scope"), MetadataInvalidationScopes.All));
    }

    /// <summary>
    /// The broadcast-failure log names the scope, and the ecosystem only for a message that has
    /// one: an org-wide failure must not log <c>Ecosystem=org</c>.
    /// </summary>
    [Theory]
    [InlineData(MetadataInvalidationEcosystems.Org, "org", null)]
    [InlineData(MetadataInvalidationEcosystems.Rpm, "ecosystem", "rpm")]
    [InlineData(MetadataInvalidationEcosystems.Npm, "ecosystem", "npm")]
    public async Task PublishAsync_FailureLogNamesTheScope_AndTheEcosystemOnlyWhenScoped(
        string kind, string expectedScope, string? expectedEcosystem)
    {
        var subscriber = Substitute.For<ISubscriber>();
        subscriber
            .PublishAsync(Arg.Any<RedisChannel>(), Arg.Any<RedisValue>(), Arg.Any<CommandFlags>())
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"));
        var bus = BuildBus(subscriber, out var logger);
        var properties = new List<IReadOnlyDictionary<string, object?>>();
        logger
            .When(l => l.Log(
                LogLevel.Warning,
                Arg.Any<EventId>(),
                Arg.Any<object>(),
                Arg.Any<Exception?>(),
                Arg.Any<Func<object, Exception?, string>>()))
            .Do(call =>
            {
                if (call.ArgAt<object>(2) is IEnumerable<KeyValuePair<string, object?>> state)
                {
                    properties.Add(state.ToDictionary(kv => kv.Key, kv => kv.Value));
                }
            });

        await bus.PublishAsync(MessageOfKind(kind, "org-a"));

        var logged = Assert.Single(properties);
        Assert.Equal(expectedScope, logged["Scope"]);
        if (expectedEcosystem is null)
        {
            Assert.False(logged.ContainsKey("Ecosystem"));
        }
        else
        {
            Assert.Equal(expectedEcosystem, logged["Ecosystem"]);
        }
    }

    /// <summary>
    /// A reservation change with the broker down: the request still succeeds and this replica's
    /// own caches are still cleared, the broadcast is counted as dropped, and peers fall back to
    /// their TTLs. The broadcast is fire-and-forget, so the drop is awaited through the counter.
    /// </summary>
    [Fact]
    public async Task ReservationChange_Succeeds_AndClearsLocally_WhenTheBrokerIsUnreachable()
    {
        var subscriber = Substitute.For<ISubscriber>();
        subscriber
            .PublishAsync(Arg.Any<RedisChannel>(), Arg.Any<RedisValue>(), Arg.Any<CommandFlags>())
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"));
        var redis = Substitute.For<IRedisClient>();
        redis.ApplyPrefix(Arg.Any<string>()).Returns(call => "dependably:" + call.Arg<string>());
        redis.GetSubscriber().Returns(subscriber);

        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();
        string orgId = await Dependably.Tests.Infrastructure.Seeding.OrgSeeder.InsertAsync(db, "broker-down");
        var memory = new Microsoft.Extensions.Caching.Memory.MemoryCache(
            new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions());
        var list = new Dependably.Protocol.ReservedNamespaceListCache(memory);
        var epoch = new OrgCacheEpochStore();
        var orgWide = new OrgWideCacheEviction(list, epoch: epoch);
        TestInvalidationHarness harness = null!;
        var bus = new RedisMetadataInvalidationBus(
            redis,
            () => new MetadataInvalidationReceiver(harness.Coordinator, NullLogger<MetadataInvalidationReceiver>.Instance),
            NullLogger<RedisMetadataInvalidationBus>.Instance);
        harness = TestMetadataInvalidation.Build(memory, bus, orgWide, epoch);
        var reserved = new Dependably.Protocol.ReservedNamespaceService(
            db, memory, TimeProvider.System, epoch, lookupCache: null, list, harness.Coordinator);
        Assert.Empty(await reserved.ListAsync(orgId));
        var epochToken = epoch.GetToken(orgId);

        var measurements = new List<Measured>();
        var dropped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Exception? thrown;
        using (PublishedListener(measurements, onMeasured: () => dropped.TrySetResult()))
        {
            thrown = await Record.ExceptionAsync(
                () => reserved.AddAsync(orgId, "maven", "com.acme", createdBy: null));
            await dropped.Task.WaitAsync(TimeSpan.FromSeconds(10));
        }

        Assert.Null(thrown);
        Assert.True(epochToken.HasChanged);
        Assert.True(await reserved.IsReservedAsync(orgId, "maven", "com.acme"));
        var only = Assert.Single(measurements);
        Assert.Equal(
            new Dictionary<string, string> { ["scope"] = "org", ["outcome"] = "server_error" },
            only.Tags);
    }

    /// <summary>
    /// A message reaching a bus whose receiver was never bound cannot be applied. StartAsync's
    /// ordering makes that unreachable, which is exactly why it must not be silent if a reordering
    /// ever makes it reachable: the peer's change would be missed with nothing in the log.
    /// </summary>
    [Fact]
    public void OnMessage_LogsAWarning_WhenTheReceiverIsNotYetBound()
    {
        int resolutions = 0;
        var logger = Substitute.For<ILogger<RedisMetadataInvalidationBus>>();
        var bus = new RedisMetadataInvalidationBus(
            RedisOver(Substitute.For<ISubscriber>()),
            () =>
            {
                resolutions++;
                return new MetadataInvalidationReceiver(
                    TestMetadataInvalidation.Coordinator(), NullLogger<MetadataInvalidationReceiver>.Instance);
            },
            logger);

        var thrown = Record.Exception(() => bus.OnMessage(
            RedisChannel.Literal("dependably:" + RedisMetadataInvalidationBus.ChannelName),
            MetadataInvalidationCodec.Encode(Npm, "peer-replica")));

        Assert.Null(thrown);
        Assert.Equal(0, resolutions);
        logger.Received(1).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
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
            () => new MetadataInvalidationReceiver(
                TestMetadataInvalidation.Coordinator(),
                NullLogger<MetadataInvalidationReceiver>.Instance),
            logger);
    }

    private static IRedisClient RedisOver(ISubscriber subscriber)
    {
        var redis = Substitute.For<IRedisClient>();
        redis.ApplyPrefix(Arg.Any<string>()).Returns(call => "dependably:" + call.Arg<string>());
        redis.GetSubscriber().Returns(subscriber);
        return redis;
    }

    private static bool Decodes(RedisValue value, string expectedOrigin) =>
        MetadataInvalidationCodec.TryDecode(value.ToString(), out var decoded, out string origin)
        && decoded == Npm
        && origin == expectedOrigin;

    /// <summary>One wire message of each <see cref="MetadataInvalidationEcosystems"/> kind.</summary>
    private static MetadataInvalidation MessageOfKind(string kind, string orgId) => kind switch
    {
        MetadataInvalidationEcosystems.Npm => MetadataInvalidation.ForNpm(orgId, "pkg"),
        MetadataInvalidationEcosystems.PyPi => MetadataInvalidation.ForPyPi(orgId, "pkg"),
        MetadataInvalidationEcosystems.NuGet => MetadataInvalidation.ForNuGet(orgId, "Pkg"),
        MetadataInvalidationEcosystems.Maven => MetadataInvalidation.ForMaven(orgId, "com.acme", "lib"),
        MetadataInvalidationEcosystems.Rpm => MetadataInvalidation.ForRpm(orgId),
        MetadataInvalidationEcosystems.Org => MetadataInvalidation.ForOrg(orgId),
        _ => throw new ArgumentOutOfRangeException(
            nameof(kind), kind, "A new wire kind needs a factory here so the counter tests cover it."),
    };

    private sealed record Measured(long Value, IReadOnlyDictionary<string, string> Tags);

    private static List<Measured> Snapshot(List<Measured> sink)
    {
        lock (sink)
        {
            return sink.ToList();
        }
    }

    private static MeterListener PublishedListener(List<(long Value, string Outcome)> sink)
    {
        var full = new List<Measured>();
        return PublishedListener(
            full, onMeasured: () => sink.Add((full[^1].Value, full[^1].Tags.GetValueOrDefault("outcome", ""))));
    }

    private static MeterListener PublishedListener(List<Measured> sink, Action? onMeasured = null) =>
        Listen("dependably.metadata.invalidations_published", sink, onMeasured);

    private static MeterListener ReceivedListener(List<Measured> sink) =>
        Listen("dependably.metadata.invalidations_received", sink, onMeasured: null);

    private static MeterListener Listen(string instrumentName, List<Measured> sink, Action? onMeasured)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName && instrument.Name == instrumentName)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            var captured = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var tag in tags)
            {
                captured[tag.Key] = tag.Value?.ToString() ?? "";
            }

            lock (sink)
            {
                sink.Add(new Measured(measurement, captured));
            }

            onMeasured?.Invoke();
        });
        listener.Start();
        return listener;
    }
}
