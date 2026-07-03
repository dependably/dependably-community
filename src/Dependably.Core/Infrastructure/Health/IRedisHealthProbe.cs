namespace Dependably.Infrastructure.Health;

/// <summary>
/// Core-side readiness probe for the optional Redis backing store. The full <c>IRedisClient</c>
/// abstraction exposes StackExchange.Redis types (<c>IDatabase</c>, <c>ISubscriber</c>) and lives
/// in Dependably.Management with the Redis client package; a protocol-only edge host has no Redis
/// dependency and never registers it.
///
/// <see cref="ReadinessAggregator"/> ships in Core (it backs both <c>/ready</c> and the edge-allowed
/// HealthcheckPinger), so it depends on this StackExchange-free probe instead of the concrete client:
/// the Redis-backed implementation is registered by the management wiring when a connection string
/// is configured, and its absence simply means the readiness check omits the "redis" entry.
/// </summary>
public interface IRedisHealthProbe
{
    /// <summary>Pings the Redis endpoint; throws on failure so the caller can record it.</summary>
    Task PingAsync(CancellationToken ct);
}
