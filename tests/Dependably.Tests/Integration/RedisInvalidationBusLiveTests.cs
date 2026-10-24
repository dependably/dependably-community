using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Redis;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Dependably.Tests.Integration;

/// <summary>
/// Two replicas' invalidation buses over a real Redis broker. The unit tests drive the bus through
/// a fake subscriber, which proves what the bus does with a delivered message but not that a
/// message published by one process is delivered to another: the channel name, the key prefix,
/// the subscription and the self-origin check only meet on a real broker.
///
/// <para>Each replica is a bus over its own multiplexer plus a coordinator over its own caches,
/// the shape two hosts have. Every test uses a fresh key prefix, so its channel is its own.</para>
/// </summary>
[Trait("Category", LiveRedis.Category)]
[Collection("LiveRedis")]
public sealed class RedisInvalidationBusLiveTests : IAsyncLifetime
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    // Delivery on a quiet local broker takes milliseconds; the budget is for a loaded CI runner.
    private static readonly TimeSpan DeliveryBudget = TimeSpan.FromSeconds(15);

    private readonly string _prefix = LiveRedis.UniquePrefix("bus");
    private readonly List<Replica> _replicas = new();
    private ConnectionMultiplexer _raw = null!;

    private RedisChannel Channel => RedisChannel.Literal(_prefix + RedisMetadataInvalidationBus.ChannelName);

    public async Task InitializeAsync()
    {
        _raw = await ConnectionMultiplexer.ConnectAsync(LiveRedis.ConnectionString);
    }

    public async Task DisposeAsync()
    {
        foreach (var replica in _replicas)
        {
            await replica.DisposeAsync();
        }

        await _raw.DisposeAsync();
    }

    [Fact]
    public async Task PublishOnA_EvictsOnB_ForAPackageAndForAnOrgWideMessage()
    {
        var a = await StartReplicaAsync();
        var b = await StartReplicaAsync();

        // Package scope: both npm variants of the package are evicted on B by A's broadcast.
        var plain = new NpmPackumentKey("org-a", "pkg");
        var proxy = new NpmPackumentKey("org-a", "pkg") { IsProxy = true };
        foreach (var replica in new[] { a, b })
        {
            replica.Caches.Npm.Set(plain, [1], Ttl);
            replica.Caches.Npm.Set(proxy, [1], Ttl);
        }

        a.Caches.Coordinator.Invalidate(MetadataInvalidation.ForNpm("org-a", "pkg"));

        Assert.False(a.Caches.Npm.TryGet(plain, out _));
        Assert.False(a.Caches.Npm.TryGet(proxy, out _));
        Assert.True(
            await LiveRedis.UntilAsync(
                () => !b.Caches.Npm.TryGet(plain, out _) && !b.Caches.Npm.TryGet(proxy, out _), DeliveryBudget),
            "B kept the npm packument variants A invalidated: the broadcast did not reach B's subscription.");

        // Org scope: an org-wide message bumps B's org epoch, which expires every rendered entry
        // B holds for that org, and leaves another org's entries alone.
        var orgA = new NpmPackumentKey("org-a", "other");
        var orgB = new NpmPackumentKey("org-b", "other");
        b.Caches.Npm.Set(orgA, [1], Ttl);
        b.Caches.Npm.Set(orgB, [1], Ttl);
        var epochToken = b.Epoch.GetToken("org-a");

        a.Caches.Coordinator.InvalidateOrg("org-a");

        Assert.True(
            await LiveRedis.UntilAsync(() => epochToken.HasChanged, DeliveryBudget),
            "B's org epoch did not change: the org-wide broadcast did not reach B.");
        Assert.False(b.Caches.Npm.TryGet(orgA, out _));
        Assert.True(b.Caches.Npm.TryGet(orgB, out _), "An org-wide message for org-a evicted org-b's entry on B.");
    }

    [Fact]
    public async Task AMessageStampedWithAsOrigin_EvictsOnB_AndIsDroppedOnA()
    {
        var a = await StartReplicaAsync();
        var b = await StartReplicaAsync();
        var key = new NpmPackumentKey("org-a", "self");
        a.Caches.Npm.Set(key, [1], Ttl);
        b.Caches.Npm.Set(key, [1], Ttl);

        await _raw.GetSubscriber().PublishAsync(
            Channel, MetadataInvalidationCodec.Encode(MetadataInvalidation.ForNpm("org-a", "self"), a.Bus.Origin));

        Assert.True(
            await LiveRedis.UntilAsync(() => !b.Caches.Npm.TryGet(key, out _), DeliveryBudget),
            "B did not evict on a message stamped with A's origin.");
        await BarrierAsync(a);
        Assert.True(a.Caches.Npm.TryGet(key, out _), "A applied a message stamped with its own origin.");
    }

    /// <summary>
    /// The ordering the self-origin drop exists for: A evicts locally, publishes, and re-renders
    /// the document before its own broadcast comes back from the broker. The echo must not evict
    /// that fresh render, or every local push would cost the publishing replica a second render.
    /// </summary>
    [Fact]
    public async Task AsOwnEcho_DoesNotEvictADocumentReRenderedAfterThePublish()
    {
        var a = await StartReplicaAsync();
        var b = await StartReplicaAsync();
        var key = new NpmPackumentKey("org-a", "echo");
        a.Caches.Npm.Set(key, [1], Ttl);
        b.Caches.Npm.Set(key, [1], Ttl);

        a.Caches.Coordinator.Invalidate(MetadataInvalidation.ForNpm("org-a", "echo"));
        Assert.False(a.Caches.Npm.TryGet(key, out _));
        a.Caches.Npm.Set(key, [2], Ttl);

        // B evicting proves the broadcast reached the broker, so A's subscription has it queued;
        // the barrier then proves A has worked through it.
        Assert.True(
            await LiveRedis.UntilAsync(() => !b.Caches.Npm.TryGet(key, out _), DeliveryBudget),
            "A's broadcast never reached B.");
        await BarrierAsync(a);

        Assert.True(a.Caches.Npm.TryGet(key, out byte[]? body), "A's own echo evicted the re-rendered document.");
        Assert.Equal(new byte[] { 2 }, body);
    }

    // Publishes a peer-origin message for a sentinel key A holds and waits for A to evict it.
    // Redis delivers one channel's messages to a subscriber in publish order, so once A has
    // applied the sentinel it has received everything published before it. The client may run
    // callback handlers concurrently, but an earlier message dispatched first and handled by a
    // decode-and-compare has finished long before the poll observes the sentinel's eviction.
    private async Task BarrierAsync(Replica a)
    {
        string name = "barrier-" + Guid.NewGuid().ToString("N");
        var sentinel = new NpmPackumentKey("org-a", name);
        a.Caches.Npm.Set(sentinel, [1], Ttl);
        await _raw.GetSubscriber().PublishAsync(
            Channel, MetadataInvalidationCodec.Encode(MetadataInvalidation.ForNpm("org-a", name), "barrier-peer"));
        Assert.True(
            await LiveRedis.UntilAsync(() => !a.Caches.Npm.TryGet(sentinel, out _), DeliveryBudget),
            "A did not apply the barrier message.");
    }

    private async Task<Replica> StartReplicaAsync()
    {
        var options = new RedisOptions { ConnectionString = LiveRedis.ConnectionString, KeyPrefix = _prefix };
        var mux = await ConnectionMultiplexer.ConnectAsync(options.BuildConfigurationOptions());
        var memory = new MemoryCache(new MemoryCacheOptions { SizeLimit = 8 * 1024 * 1024 });
        var epoch = new OrgCacheEpochStore();
        var orgWide = new OrgWideCacheEviction(new ReservedNamespaceListCache(memory), epoch: epoch);
        TestInvalidationHarness caches = null!;
        var bus = new RedisMetadataInvalidationBus(
            new RedisClient(mux, Options.Create(options)),
            () => new MetadataInvalidationReceiver(caches.Coordinator, NullLogger<MetadataInvalidationReceiver>.Instance),
            NullLogger<RedisMetadataInvalidationBus>.Instance);
        caches = TestMetadataInvalidation.Build(memory, bus, orgWide, epoch);

        var replica = new Replica(mux, memory, bus, caches, epoch);
        _replicas.Add(replica);
        await bus.StartAsync(CancellationToken.None);

        // The subscription is acknowledged before StartAsync returns, but assert it on the broker
        // itself: a test whose replica never subscribed would fail later with a misleading message.
        var subscribers = (RedisValue[])(await _raw.GetDatabase().ExecuteAsync(
            "PUBSUB", "NUMSUB", Channel.ToString()))!;
        Assert.Equal(_replicas.Count, (int)subscribers[1]);
        return replica;
    }

    private sealed record Replica(
        ConnectionMultiplexer Mux,
        MemoryCache Memory,
        RedisMetadataInvalidationBus Bus,
        TestInvalidationHarness Caches,
        OrgCacheEpochStore Epoch) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await Bus.StopAsync(CancellationToken.None);
            await Mux.DisposeAsync();
            Memory.Dispose();
        }
    }
}
