using System.Threading.RateLimiting;
using Dependably.Infrastructure.Observability;
using Microsoft.Extensions.Logging;
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
///
/// When Redis is unreachable there is no counter to decide with, so the request is resolved by
/// the operator-configured posture (<see cref="RateLimitFailureMode"/>): grant by default, deny
/// under <c>closed</c>. Either way the decision is logged at Warning and counted on
/// <c>dependably.rate_limit.backend_unavailable</c> — a limiter that silently stops limiting is
/// indistinguishable from one that is working.
/// </summary>
public sealed class RedisFixedWindowRateLimiter : RateLimiter
{
    /// <summary>
    /// Per-partition limiter configuration: the key components, the window shape, and the
    /// posture to take when the backend cannot be reached.
    /// </summary>
    /// <param name="KeyPrefix">Redis key prefix applied to every key this limiter writes.</param>
    /// <param name="Scope">Rate-limit policy name (login|invite|token-create|unknown).</param>
    /// <param name="Bucket">Partition key — the caller's IP plus policy name.</param>
    /// <param name="PermitLimit">Requests permitted per window.</param>
    /// <param name="WindowSeconds">Fixed-window length in seconds.</param>
    /// <param name="FailOpen">Grant (true) or deny (false) when Redis is unreachable.</param>
    public sealed record Settings(
        string KeyPrefix,
        string Scope,
        string Bucket,
        int PermitLimit,
        int WindowSeconds,
        bool FailOpen);

    private readonly IDatabase _db;
    private readonly string _keyPrefix;
    private readonly string _scope;
    private readonly string _bucket;
    private readonly int _permitLimit;
    private readonly int _windowSeconds;
    private readonly bool _failOpen;
    private readonly TimeProvider _time;
    private readonly ILogger<RedisFixedWindowRateLimiter> _logger;

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
        IDatabase db, Settings settings, TimeProvider time, ILogger<RedisFixedWindowRateLimiter> logger)
    {
        _db = db;
        _keyPrefix = settings.KeyPrefix;
        _scope = settings.Scope;
        _bucket = settings.Bucket;
        _permitLimit = settings.PermitLimit;
        _windowSeconds = settings.WindowSeconds;
        _failOpen = settings.FailOpen;
        _time = time;
        _logger = logger;
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

        // The reply parse lives inside the same guard as the round-trip: a null reply (cast
        // yields null, then NullReferenceException on element access), a non-array reply
        // (InvalidCastException), a short array (IndexOutOfRangeException), or an array whose
        // elements are present but non-numeric or out of Int64 range (FormatException /
        // OverflowException from the (long) conversion) are all shapes a misbehaving or
        // incompatible Redis server can return, and must take the configured fail-open/fail-closed
        // posture exactly like an unreachable connection rather than throwing an unhandled
        // exception out of the rate limiter.
        try
        {
            var result = await _db.ScriptEvaluateAsync(
                IncrScript.Script,
                new RedisKey[] { key },
                new RedisValue[] { _windowSeconds });

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
        catch (Exception ex) when (ex is InvalidCastException or NullReferenceException
            or IndexOutOfRangeException or FormatException or OverflowException)
        {
            // Thrown by parsing a reply that came back from Redis but isn't shaped as the
            // two-element {count, ttl} array of integers the script always returns — distinct
            // from a connection failure, which never reaches the parse.
            return BackendUnavailable(ex, cause: "malformed_reply");
        }
        catch (Exception ex)
        {
            return BackendUnavailable(ex, cause: "connection");
        }
    }

    /// <summary>
    /// Resolves a request the backend could not decide. The posture is the operator's choice —
    /// fail-open keeps legitimate traffic flowing while the abuse budget is unenforced,
    /// fail-closed keeps the budget enforced while denying everyone. Both branches emit the same
    /// Warning log and counter increment, tagged with the policy name and the cause (connection
    /// failure vs. a malformed reply), so an outage that disables login rate limiting is
    /// observable while it is happening rather than only reconstructable afterwards.
    /// </summary>
    private RateLimitLease BackendUnavailable(Exception ex, string cause)
    {
        string decision = _failOpen ? "allowed" : "denied";

        DependablyMeter.RateLimitBackendUnavailable.Add(1,
            new KeyValuePair<string, object?>("policy", _scope),
            new KeyValuePair<string, object?>("decision", decision),
            new KeyValuePair<string, object?>("cause", cause));

        _logger.LogWarning(ex,
            "Rate-limit backend unavailable for policy {Policy} ({Cause}); request {Decision} by "
            + "the configured failure posture: {ExceptionType}",
            _scope, cause, decision, ex.GetType().Name);

        return _failOpen
            ? new SuccessLease()
            : new RejectedLease(TimeSpan.FromSeconds(_windowSeconds));
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
