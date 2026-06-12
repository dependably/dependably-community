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
    private static readonly Dictionary<string, (int Limit, int WindowSeconds)> PolicyConfig = new()
    {
        ["login"] = (10, 60),       // 10 requests / min
        ["invite"] = (20, 3600),     // 20 requests / hour
        ["token-create"] = (60, 3600),     // 60 requests / hour
    };

    private readonly IRedisClient _redis;

    public RedisRateLimitPolicy(IRedisClient redis) => _redis = redis;

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
            cfg = (100, 60); // safe default
        }

        var db = _redis.GetDatabase();
        string prefix = _redis.ApplyPrefix("");

        return RateLimitPartition.Get(bucket, key =>
            new RedisFixedWindowRateLimiter(db, prefix, policyName, key, cfg.Limit, cfg.WindowSeconds));
    }
}
