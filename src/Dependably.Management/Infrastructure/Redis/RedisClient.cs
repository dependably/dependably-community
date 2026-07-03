using Dependably.Infrastructure.Health;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Dependably.Infrastructure.Redis;

public sealed class RedisClient : IRedisClient, IRedisHealthProbe
{
    private readonly IConnectionMultiplexer _mux;
    private readonly string _prefix;

    public RedisClient(IConnectionMultiplexer mux, IOptions<RedisOptions> opts)
    {
        _mux = mux;
        _prefix = opts.Value.KeyPrefix;
    }

    public IDatabase GetDatabase() => _mux.GetDatabase();

    public ISubscriber GetSubscriber() => _mux.GetSubscriber();

    public string ApplyPrefix(string key) => _prefix + key;

    public bool IsConnected => _mux.IsConnected;

    // Core-side readiness probe. ReadinessAggregator (Core) depends on IRedisHealthProbe rather
    // than IRedisClient so it carries no StackExchange.Redis dependency; the management wiring
    // registers this instance as the probe when Redis is configured.
    public async Task PingAsync(CancellationToken ct) => await GetDatabase().PingAsync();
}
