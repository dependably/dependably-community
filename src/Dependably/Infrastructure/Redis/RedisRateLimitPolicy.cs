using System.Threading.RateLimiting;
using Dependably.Security;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Infrastructure.Redis;

/// <summary>
/// IRateLimiterPolicy that creates Redis-backed fixed-window rate limiters.
/// The limit configuration is keyed by policy name to match the in-process defaults.
/// Buckets by client IP address.
/// </summary>
public sealed class RedisRateLimitPolicy : IRateLimiterPolicy<string>
{
    // Fallback rate limit applied when the endpoint's policy name is not in PolicyConfig.
    private const int DefaultRateLimitPermits = 100;
    private const int DefaultRateLimitWindowSeconds = 60;

    private static readonly Dictionary<string, (int Limit, int WindowSeconds)> PolicyConfig = new()
    {
        ["login"] = (10, 60),       // 10 requests / min
        ["invite"] = (20, 3600),     // 20 requests / hour
        ["token-create"] = (60, 3600),     // 60 requests / hour
    };

    private readonly IRedisClient _redis;
    private readonly TimeProvider _time;

    public RedisRateLimitPolicy(IRedisClient redis, TimeProvider time)
    {
        _redis = redis;
        _time = time;
    }

    public Func<OnRejectedContext, CancellationToken, ValueTask>? OnRejected => null;

    public RateLimitPartition<string> GetPartition(HttpContext httpContext)
    {
        // Determine policy name from the endpoint metadata (set by [EnableRateLimiting("name")]).
        string policyName = httpContext.GetEndpoint()
            ?.Metadata.GetMetadata<EnableRateLimitingAttribute>()
            ?.PolicyName ?? "unknown";

        string ip = httpContext.GetNormalizedRemoteIp() ?? "unknown";
        string bucket = $"{ip}:{policyName}";

        if (!PolicyConfig.TryGetValue(policyName, out var cfg))
        {
            cfg = (DefaultRateLimitPermits, DefaultRateLimitWindowSeconds); // safe default
        }

        var db = _redis.GetDatabase();
        string prefix = _redis.ApplyPrefix("");

        return RateLimitPartition.Get(bucket, key =>
            new RedisFixedWindowRateLimiter(db, prefix, policyName, key, cfg.Limit, cfg.WindowSeconds, _time));
    }
}
