using System.Threading.RateLimiting;
using Dependably.Security;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Dependably.Infrastructure.Redis;

/// <summary>
/// IRateLimiterPolicy that creates Redis-backed fixed-window rate limiters.
/// The limit configuration is keyed by policy name and reads the same environment variables as
/// the in-process limiters (<c>LOGIN_RATE_LIMIT_PERMITS</c>, <c>INVITE_RATE_LIMIT_PERMITS</c>,
/// <c>TOKEN_CREATE_RATE_LIMIT_PERMITS</c>), falling back to the same defaults, so an operator's
/// tuning has the same effect in standalone and HA (<c>DEPENDABLY_DEPLOYMENT_MODE=ha</c>) modes.
/// Only the permit count is configurable — the window length (one minute for login, one hour for
/// invite/token-create) is fixed in both modes, matching <c>AddInProcessLimiters</c>.
/// Buckets by client IP address.
/// </summary>
public sealed class RedisRateLimitPolicy : IRateLimiterPolicy<string>
{
    // Fallback rate limit applied when the endpoint's policy name is not in PolicyConfig.
    private const int DefaultRateLimitPermits = 100;
    private const int DefaultRateLimitWindowSeconds = 60;

    // Hardcoded fallback permit counts, used when the corresponding environment variable is
    // unset or unparsable. These match the in-process limiters' defaults
    // (AuthStartupExtensions.AddInProcessLimiters) so standalone and HA agree when an operator
    // has not tuned either.
    private const int LoginPermitsDefault = 10;
    private const int InvitePermitsDefault = 20;
    private const int TokenCreatePermitsDefault = 60;

    // Window lengths are not operator-configurable in either mode — the in-process limiters
    // (AddInProcessLimiters) hardcode the same TimeSpans, so this stays symmetric with them
    // rather than introducing a knob the in-process path lacks.
    private const int LoginWindowSeconds = 60;
    private const int InviteWindowSeconds = 3600;
    private const int TokenCreateWindowSeconds = 3600;

    private readonly IRedisClient _redis;
    private readonly TimeProvider _time;
    private readonly ILogger<RedisFixedWindowRateLimiter> _logger;
    private readonly int _ipv6Prefix;
    private readonly bool _failOpen;
    private readonly Dictionary<string, (int Limit, int WindowSeconds)> _policyConfig;

    public RedisRateLimitPolicy(
        IRedisClient redis, TimeProvider time, IConfiguration cfg,
        ILogger<RedisFixedWindowRateLimiter> logger)
    {
        _redis = redis;
        _time = time;
        _logger = logger;
        // Posture when Redis cannot answer: grant (default, preserves availability) or deny.
        // Resolved once here so every partition limiter this policy mints shares it.
        _failOpen = RateLimitFailureMode.ResolveFailOpen(cfg);
        // Collapse IPv6 sources to their /64 (or the operator override) for the partition key, the
        // same as the in-process limiters — otherwise the per-IP login/invite/token-create budgets
        // stay evadable from a routed /64 even in Redis mode.
        _ipv6Prefix = int.TryParse(cfg["RATE_LIMIT_IPV6_PREFIX"], out int p) && p is >= 1 and <= 128
            ? p
            : IpAddressExtensions.DefaultIpv6PartitionPrefixBits;

        // Read the same permit env vars the in-process limiters read
        // (AuthStartupExtensions.AddInProcessLimiters) so an operator's tuning is honoured
        // identically whether the process ends up on the in-process or the Redis-backed path.
        int loginLimit = int.TryParse(cfg["LOGIN_RATE_LIMIT_PERMITS"], out int lp) ? lp : LoginPermitsDefault;
        int inviteLimit = int.TryParse(cfg["INVITE_RATE_LIMIT_PERMITS"], out int inv) ? inv : InvitePermitsDefault;
        int tokenCreateLimit = int.TryParse(cfg["TOKEN_CREATE_RATE_LIMIT_PERMITS"], out int tp)
            ? tp
            : TokenCreatePermitsDefault;

        _policyConfig = new Dictionary<string, (int Limit, int WindowSeconds)>
        {
            ["login"] = (loginLimit, LoginWindowSeconds),
            ["invite"] = (inviteLimit, InviteWindowSeconds),
            ["token-create"] = (tokenCreateLimit, TokenCreateWindowSeconds),
        };
    }

    public Func<OnRejectedContext, CancellationToken, ValueTask>? OnRejected => null;

    public RateLimitPartition<string> GetPartition(HttpContext httpContext)
    {
        // Determine policy name from the endpoint metadata (set by [EnableRateLimiting("name")]).
        string policyName = httpContext.GetEndpoint()
            ?.Metadata.GetMetadata<EnableRateLimitingAttribute>()
            ?.PolicyName ?? "unknown";

        string ip = httpContext.GetRateLimitPartitionIp(_ipv6Prefix) ?? "unknown";
        string bucket = $"{ip}:{policyName}";

        if (!_policyConfig.TryGetValue(policyName, out var cfg))
        {
            cfg = (DefaultRateLimitPermits, DefaultRateLimitWindowSeconds); // safe default
        }

        var db = _redis.GetDatabase();
        string prefix = _redis.ApplyPrefix("");

        return RateLimitPartition.Get(bucket, key =>
            new RedisFixedWindowRateLimiter(
                db,
                new RedisFixedWindowRateLimiter.Settings(
                    prefix, policyName, key, cfg.Limit, cfg.WindowSeconds, _failOpen),
                _time,
                _logger));
    }
}
