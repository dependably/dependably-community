using StackExchange.Redis;

namespace Dependably.Infrastructure.Redis;

public interface IRedisClient
{
    IDatabase GetDatabase();
    ISubscriber GetSubscriber();

    /// <summary>Applies the configured key prefix to a bare key name.</summary>
    string ApplyPrefix(string key);

    /// <summary>True when the underlying multiplexer is connected.</summary>
    bool IsConnected { get; }
}
