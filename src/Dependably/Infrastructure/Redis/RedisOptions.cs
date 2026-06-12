using StackExchange.Redis;

namespace Dependably.Infrastructure.Redis;

public sealed class RedisOptions
{
    /// <summary>
    /// StackExchange.Redis connection string.
    /// Plain: "localhost:6379"
    /// Sentinel: "sentinel-1:26379,sentinel-2:26379,sentinel-3:26379,serviceName=dependably-master"
    /// </summary>
    public string? ConnectionString { get; set; }

    /// <summary>Optional password — injected at runtime so it does not appear in process listings.</summary>
    public string? Password { get; set; }

    public bool Ssl { get; set; } = false;

    public int Database { get; set; } = 0;

    /// <summary>Prefix applied to every Redis key via <see cref="IRedisClient.ApplyPrefix"/>.</summary>
    public string KeyPrefix { get; set; } = "dependably:";

    public bool IsConfigured => !string.IsNullOrWhiteSpace(ConnectionString);

    public ConfigurationOptions BuildConfigurationOptions()
    {
        if (!IsConfigured)
        {
            throw new InvalidOperationException("Redis is not configured (REDIS_CONNECTION_STRING is not set).");
        }

        var opts = ConfigurationOptions.Parse(ConnectionString!);

        if (!string.IsNullOrWhiteSpace(Password))
        {
            opts.Password = Password;
        }

        opts.Ssl = Ssl;
        opts.DefaultDatabase = Database;
        opts.AbortOnConnectFail = false;
        opts.ConnectRetry = 5;
        opts.ReconnectRetryPolicy = new ExponentialRetry(500, 10_000);

        return opts;
    }
}
