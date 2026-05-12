using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Dependably.Infrastructure.Redis;

public sealed class RedisClient : IRedisClient
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
}
