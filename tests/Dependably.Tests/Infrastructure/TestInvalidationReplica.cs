using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// An in-memory stand-in for the Redis pub/sub channel. Every published message is encoded with
/// the production codec and delivered synchronously to every joined replica's receiver,
/// including the publisher's own, exactly as a Redis subscriber hears its own publish; the
/// receiver's origin check is what drops that copy.
/// </summary>
internal sealed class InMemoryInvalidationChannel
{
    private readonly List<Endpoint> _endpoints = new();

    /// <summary>Every payload that crossed the channel, in publish order.</summary>
    internal List<string> Payloads { get; } = new();

    internal Endpoint Join()
    {
        var endpoint = new Endpoint(this);
        _endpoints.Add(endpoint);
        return endpoint;
    }

    private void Deliver(string payload)
    {
        Payloads.Add(payload);
        foreach (var endpoint in _endpoints)
        {
            endpoint.Receive(payload);
        }
    }

    /// <summary>One replica's connection: its bus for publishing and its receiver for delivery.</summary>
    internal sealed class Endpoint(InMemoryInvalidationChannel channel) : IMetadataInvalidationBus
    {
        internal string Origin { get; } = Guid.NewGuid().ToString("N");

        internal MetadataInvalidationReceiver? Receiver { get; set; }

        /// <summary>How many delivered messages this replica's receiver applied.</summary>
        internal int Applied { get; private set; }

        public void Publish(MetadataInvalidation invalidation) =>
            channel.Deliver(MetadataInvalidationCodec.Encode(invalidation, Origin));

        internal void Receive(string payload)
        {
            if (Receiver?.Apply(payload, Origin) == true)
            {
                Applied++;
            }
        }
    }
}

/// <summary>
/// One full-host replica's per-process caches, composed the way the host composes them: its own
/// memory cache, org epoch, lookup cache, reservation list and settings cache, an
/// <see cref="OrgWideCacheEviction"/> over them, a coordinator and receiver on a shared
/// <see cref="InMemoryInvalidationChannel"/>, and a <see cref="ReservedNamespaceService"/> that
/// reads through the same list cache. Two replicas built over one store are two hosts sharing
/// one database.
/// </summary>
internal sealed class TestInvalidationReplica
{
    private TestInvalidationReplica(
        IMemoryCache memory,
        OrgCacheEpochStore epoch,
        PackageLookupCache lookups,
        ReservedNamespaceListCache reservationList,
        OrgRepository orgs,
        TestInvalidationHarness harness,
        InMemoryInvalidationChannel.Endpoint endpoint,
        ReservedNamespaceService reserved)
    {
        Memory = memory;
        Epoch = epoch;
        Lookups = lookups;
        ReservationList = reservationList;
        Orgs = orgs;
        Harness = harness;
        Endpoint = endpoint;
        Reserved = reserved;
    }

    internal IMemoryCache Memory { get; }
    internal OrgCacheEpochStore Epoch { get; }
    internal PackageLookupCache Lookups { get; }
    internal ReservedNamespaceListCache ReservationList { get; }
    internal OrgRepository Orgs { get; }
    internal TestInvalidationHarness Harness { get; }
    internal InMemoryInvalidationChannel.Endpoint Endpoint { get; }
    internal ReservedNamespaceService Reserved { get; }

    internal MetadataInvalidationCoordinator Coordinator => Harness.Coordinator;

    /// <summary>The Maven metadata cache, bound to this replica's org epoch.</summary>
    internal RenderedResponseCache<MavenMetadataKey> Maven => Harness.Maven;

    /// <param name="channel">The channel shared by every replica of the deployment.</param>
    /// <param name="db">The database shared by every replica.</param>
    /// <param name="time">
    /// Clock for the lookup cache, the reservation timestamps, and the memory cache's own expiry,
    /// so a settings entry's one-second TTL cannot lapse mid-test on a slow machine.
    /// </param>
    internal static TestInvalidationReplica Join(
        InMemoryInvalidationChannel channel, IMetadataStore db, TimeProvider time)
    {
        var memory = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 8 * 1024 * 1024,
            Clock = new TimeProviderSystemClock(time),
        });
        var epoch = new OrgCacheEpochStore();
        var lookups = new PackageLookupCache(time);
        var reservationList = new ReservedNamespaceListCache(memory);
        var orgs = new OrgRepository(db, memory, time);
        var orgWide = new OrgWideCacheEviction(reservationList, orgs, epoch, lookups);
        var endpoint = channel.Join();
        var harness = TestMetadataInvalidation.Build(memory, endpoint, orgWide, epoch);
        endpoint.Receiver = new MetadataInvalidationReceiver(
            harness.Coordinator, NullLogger<MetadataInvalidationReceiver>.Instance);
        var reserved = new ReservedNamespaceService(
            db, memory, time, epoch, lookups, reservationList, harness.Coordinator);
        return new TestInvalidationReplica(
            memory, epoch, lookups, reservationList, orgs, harness, endpoint, reserved);
    }

    /// <summary>Whether this replica holds a cached reservation list for <paramref name="orgId"/>.</summary>
    internal bool HasCachedReservationList(string orgId) =>
        Memory.TryGetValue(ReservedNamespaceListCache.CacheKey(orgId), out _);

    /// <summary>Whether this replica holds a cached settings record for <paramref name="orgId"/>.</summary>
    internal bool HasCachedSettings(string orgId) =>
        Memory.TryGetValue("org-settings:" + orgId, out _);

    // Bridges a TimeProvider into MemoryCache's own expiry checks.
    private sealed class TimeProviderSystemClock(TimeProvider time) : Microsoft.Extensions.Internal.ISystemClock
    {
        public DateTimeOffset UtcNow => time.GetUtcNow();
    }
}
