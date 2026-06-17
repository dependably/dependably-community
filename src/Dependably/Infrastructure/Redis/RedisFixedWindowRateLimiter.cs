using System.Threading.RateLimiting;
using StackExchange.Redis;

namespace Dependably.Infrastructure.Redis;

/// <summary>
/// Redis-backed fixed-window rate limiter.
///
/// Algorithm: INCR key; on first INCR, EXPIRE key to window length.
/// If counter exceeds limit, deny. TTL is used to compute Retry-After.
///
/// Key format: {prefix}ratelimit:{scope}:{bucket}:{window_id}
/// where window_id = floor(unix_seconds / window_seconds)
/// </summary>
public sealed class RedisFixedWindowRateLimiter : RateLimiter
{
    private readonly IDatabase _db;
    private readonly string _keyPrefix;
    private readonly string _scope;
    private readonly string _bucket;
    private readonly int _permitLimit;
    private readonly int _windowSeconds;
    private readonly TimeProvider _time;

    private static readonly RedisScript IncrScript = new(
        """
        local key = KEYS[1]
        local window = tonumber(ARGV[1])
        local count = redis.call('INCR', key)
        if count == 1 then
            redis.call('EXPIRE', key, window)
        end
        local ttl = redis.call('TTL', key)
        return {count, ttl}
        """);

    public RedisFixedWindowRateLimiter(
        IDatabase db, string keyPrefix, string scope, string bucket,
        int permitLimit, int windowSeconds, TimeProvider time)
    {
        _db = db;
        _keyPrefix = keyPrefix;
        _scope = scope;
        _bucket = bucket;
        _permitLimit = permitLimit;
        _windowSeconds = windowSeconds;
        _time = time;
    }

    public override RateLimiterStatistics? GetStatistics() => null;

    protected override ValueTask<RateLimitLease> AcquireAsyncCore(int permitCount, CancellationToken cancellationToken)
        => new(AcquireAsync());

    protected override RateLimitLease AttemptAcquireCore(int permitCount)
        // Synchronous path not used by ASP.NET middleware — fire async and block.
        => AcquireAsync().GetAwaiter().GetResult();

    // No CancellationToken — StackExchange.Redis honors its own command timeout, not CTs.
    private async Task<RateLimitLease> AcquireAsync()
    {
        long windowId = _time.GetUtcNow().ToUnixTimeSeconds() / _windowSeconds;
        string key = $"{_keyPrefix}ratelimit:{_scope}:{_bucket}:{windowId}";

        RedisResult result;
        try
        {
            result = await _db.ScriptEvaluateAsync(
                IncrScript.Script,
                new RedisKey[] { key },
                new RedisValue[] { _windowSeconds });
        }
        catch
        {
            // Redis unavailable — fail open to avoid denying legitimate requests.
            return new SuccessLease();
        }

        var values = (RedisResult[])result!;
        long count = (long)values[0];
        long ttl = (long)values[1];

        if (count <= _permitLimit)
        {
            return new SuccessLease();
        }

        var retryAfter = ttl > 0 ? TimeSpan.FromSeconds(ttl) : TimeSpan.FromSeconds(_windowSeconds);
        return new RejectedLease(retryAfter);
    }

    public override TimeSpan? IdleDuration => null;
    protected override void Dispose(bool disposing)
    {
        // No unmanaged resources — Redis connection lifetime is managed by DI.
    }
    protected override ValueTask DisposeAsyncCore() => ValueTask.CompletedTask;

    private sealed class SuccessLease : RateLimitLease
    {
        public override bool IsAcquired => true;
        public override IEnumerable<string> MetadataNames => [];
        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            metadata = null;
            return false;
        }
        protected override void Dispose(bool disposing)
        {
            // Stateless lease — nothing to release.
        }
    }

    private sealed class RejectedLease : RateLimitLease
    {
        private readonly TimeSpan _retryAfter;

        public RejectedLease(TimeSpan retryAfter) => _retryAfter = retryAfter;

        public override bool IsAcquired => false;

        public override IEnumerable<string> MetadataNames =>
            [MetadataName.RetryAfter.Name];

        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            if (metadataName == MetadataName.RetryAfter.Name)
            {
                metadata = _retryAfter;
                return true;
            }
            metadata = null;
            return false;
        }

        protected override void Dispose(bool disposing)
        {
            // Stateless lease — nothing to release.
        }
    }

    private sealed class RedisScript(string script)
    {
        public string Script => script;
    }
}
