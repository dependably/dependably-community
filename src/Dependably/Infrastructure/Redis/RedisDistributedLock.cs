using StackExchange.Redis;

namespace Dependably.Infrastructure.Redis;

/// <summary>
/// Redis-backed distributed lock using SET NX PX with Lua compare-and-delete for release.
/// Safe for single-instance Redis and acceptable for Sentinel/Cluster (we do not implement
/// RedLock; consumers are designed to be idempotent under the small risk of dual acquisition
/// during a primary failover).
/// </summary>
public sealed class RedisDistributedLock : IDistributedLock
{
    private static readonly RedisScript ReleaseScript = new(
        """
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("DEL", KEYS[1])
        else
            return 0
        end
        """);

    private static readonly RedisScript ExtendScript = new(
        """
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("PEXPIRE", KEYS[1], ARGV[2])
        else
            return 0
        end
        """);

    private readonly IRedisClient _redis;

    public RedisDistributedLock(IRedisClient redis) => _redis = redis;

    public async Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
    {
        string key = _redis.ApplyPrefix($"lock:{name}");
        string token = Guid.NewGuid().ToString("N");
        var db = _redis.GetDatabase();

        bool acquired = await db.StringSetAsync(key, token, ttl, When.NotExists);
        return !acquired ? null : (ILockHandle)new LockHandle(db, key, token, name, ReleaseScript, ExtendScript);
    }

    public async Task<ILockHandle> AcquireAsync(
        string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default)
    {
        var deadline = DateTimeOffset.UtcNow + wait;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var handle = await TryAcquireAsync(name, ttl, ct);
            if (handle is not null)
            {
                return handle;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException($"Could not acquire distributed lock '{name}' within {wait}.");
            }

            await Task.Delay(retryInterval, ct);
        }
    }

    private sealed class LockHandle : ILockHandle
    {
        private readonly IDatabase _db;
        private readonly RedisKey _key;
        private readonly string _token;
        private readonly RedisScript _releaseScript;
        private readonly RedisScript _extendScript;
        private bool _released;

        public string Name { get; }
        public DateTimeOffset AcquiredAt { get; } = DateTimeOffset.UtcNow;

        public LockHandle(IDatabase db, RedisKey key, string token, string name,
            RedisScript releaseScript, RedisScript extendScript)
        {
            _db = db;
            _key = key;
            _token = token;
            Name = name;
            _releaseScript = releaseScript;
            _extendScript = extendScript;
        }

        public async Task<bool> ExtendAsync(TimeSpan additional, CancellationToken ct = default)
        {
            if (_released)
            {
                return false;
            }

            long result = (long)await _db.ScriptEvaluateAsync(
                _extendScript.Script,
                new RedisKey[] { _key },
                new RedisValue[] { _token, (long)additional.TotalMilliseconds });
            return result == 1;
        }

        public async ValueTask DisposeAsync()
        {
            if (_released)
            {
                return;
            }

            _released = true;
            try
            {
                await _db.ScriptEvaluateAsync(
                    _releaseScript.Script,
                    new RedisKey[] { _key },
                    new RedisValue[] { _token });
            }
            catch
            {
                // Best-effort release; TTL expiry handles cleanup on failure.
            }
        }
    }

    private sealed class RedisScript(string script)
    {
        public string Script => script;
    }
}
