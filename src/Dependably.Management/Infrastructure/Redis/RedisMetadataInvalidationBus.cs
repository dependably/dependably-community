using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Observability;
using StackExchange.Redis;

namespace Dependably.Infrastructure.Redis;

/// <summary>
/// Redis pub/sub fan-out for rendered-metadata invalidations, used in HA (multi-replica) mode.
/// Publishing replica: <see cref="Publish"/> encodes the coordinates and fires them at the
/// channel. Receiving replicas: <see cref="StartAsync"/> subscribes and hands each payload to
/// <see cref="MetadataInvalidationReceiver"/>, which evicts through the same coordinator the
/// local mutation path uses.
///
/// <para><b>Failure posture — degrade to TTL, never to an outage.</b> Redis being unreachable
/// must not fail a push. <see cref="Publish"/> is <see langword="void"/> and dispatches the
/// send without awaiting it; every failure path (broker down, timeout, serialization) is caught,
/// logged at warning, and counted on
/// <see cref="DependablyMeter.MetadataInvalidationsPublished"/> with
/// <c>outcome=server_error</c>. The peers then converge exactly as they did before the channel existed:
/// on their entries' TTL. Subscribe failures are logged the same way, leaving this replica
/// TTL-only rather than crashing the host.</para>
///
/// <para>The channel name carries the configured Redis key prefix so two deployments sharing one
/// Redis instance do not cross-evict each other, and each message carries this process's
/// <see cref="Origin"/> so a replica ignores its own broadcast (it evicted before publishing).</para>
/// </summary>
public sealed class RedisMetadataInvalidationBus : IMetadataInvalidationBus, IHostedService
{
    /// <summary>Bare channel name; the Redis key prefix is applied on top.</summary>
    public const string ChannelName = "metadata-invalidation";

    private readonly IRedisClient _redis;
    private readonly MetadataInvalidationReceiver _receiver;
    private readonly ILogger<RedisMetadataInvalidationBus> _logger;

    public RedisMetadataInvalidationBus(
        IRedisClient redis,
        MetadataInvalidationReceiver receiver,
        ILogger<RedisMetadataInvalidationBus> logger)
    {
        _redis = redis;
        _receiver = receiver;
        _logger = logger;
    }

    /// <summary>
    /// This process's identity on the channel. Regenerated per process so a restarted replica is
    /// never mistaken for its predecessor.
    /// </summary>
    public string Origin { get; } = Guid.NewGuid().ToString("N");

    private RedisChannel Channel => RedisChannel.Literal(_redis.ApplyPrefix(ChannelName));

    /// <inheritdoc />
    public void Publish(MetadataInvalidation invalidation)
    {
        // Fire-and-forget by contract: the push path has already evicted locally and committed
        // its write, and a broker round-trip must not be on its critical path or in its failure
        // envelope. PublishAsync never throws, so the discarded task cannot become unobserved.
        _ = PublishAsync(invalidation);
    }

    /// <summary>
    /// Sends one invalidation and records the outcome. Never throws — the awaitable form exists
    /// so the failure accounting is directly testable.
    /// </summary>
    public async Task PublishAsync(MetadataInvalidation invalidation)
    {
        var ecosystem = new KeyValuePair<string, object?>("ecosystem", invalidation.Ecosystem);
        try
        {
            string payload = MetadataInvalidationCodec.Encode(invalidation, Origin);
            await _redis.GetSubscriber().PublishAsync(Channel, payload);
            DependablyMeter.MetadataInvalidationsPublished.Add(
                1, ecosystem, new KeyValuePair<string, object?>("outcome", "success"));
        }
        catch (Exception ex)
        {
            DependablyMeter.MetadataInvalidationsPublished.Add(
                1, ecosystem, new KeyValuePair<string, object?>("outcome", "server_error"));
            _logger.LogWarning(ex,
                "Metadata-invalidation broadcast failed for {Ecosystem}: {ExceptionType}. Peer replicas "
                + "fall back to metadata TTL expiry for this change.",
                invalidation.Ecosystem, ex.GetType().Name);
        }
    }

    /// <summary>
    /// Subscribes this replica to the channel. A subscribe failure is logged and swallowed: the
    /// replica keeps serving, converging on TTL expiry, rather than refusing to start over a
    /// cache-freshness optimisation.
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _redis.GetSubscriber().SubscribeAsync(Channel, OnMessage);
            _logger.LogInformation(
                "Subscribed to the cross-replica metadata-invalidation channel as replica {Origin}.", Origin);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not subscribe to the metadata-invalidation channel: {ExceptionType}. This replica "
                + "falls back to metadata TTL expiry for peer-originated changes.",
                ex.GetType().Name);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _redis.GetSubscriber().UnsubscribeAsync(Channel);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex,
                "Unsubscribing from the metadata-invalidation channel failed during shutdown: {ExceptionType}.",
                ex.GetType().Name);
        }
    }

    // Subscriber callback. Runs on a StackExchange.Redis message-pump thread, so it must never
    // throw: an escaping exception there tears down the pump for every subscriber in the process.
    private void OnMessage(RedisChannel _, RedisValue message)
    {
        try
        {
            _receiver.Apply(message.ToString(), Origin);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Applying a received metadata invalidation failed: {ExceptionType}. The affected entries "
                + "expire on their TTL instead.",
                ex.GetType().Name);
        }
    }
}
