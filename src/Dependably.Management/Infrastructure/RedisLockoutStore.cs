using Dependably.Infrastructure.Redis;
using StackExchange.Redis;

namespace Dependably.Infrastructure;

/// <summary>
/// Redis-backed lockout store — used in HA mode.
///
/// Keys per identifier (sha256 of email):
///   lockout:attempts:{hash}  — INCR counter, expires after lockout window
///   lockout:locked:{hash}    — present and non-empty while the account is locked; TTL = remaining lockout
/// </summary>
public sealed class RedisLockoutStore : ILockoutStore
{
    private const int LockoutSeconds = 15 * 60;

    // Increments the attempts counter and, in the same Lua invocation, sets the lock key once
    // the threshold is reached. Redis executes a script as a single atomic unit — no other
    // command from another caller can interleave between the INCR and the threshold check — so
    // N concurrent failures for the same key always advance the counter by exactly N, unlike a
    // caller-computed StringSetAsync(newCount) which can lose an update under a race.
    private const string RecordFailureScript =
        """
        local count = redis.call('INCR', KEYS[1])
        redis.call('EXPIRE', KEYS[1], ARGV[2])
        local locked = 0
        if count >= tonumber(ARGV[1]) then
            redis.call('SET', KEYS[2], '1', 'EX', ARGV[2])
            locked = 1
        end
        return {count, locked}
        """;

    private readonly IRedisClient _redis;
    private readonly TimeProvider _time;

    public RedisLockoutStore(IRedisClient redis, TimeProvider time)
    {
        _redis = redis;
        _time = time;
    }

    public async Task<(int FailedCount, DateTimeOffset? LockedUntil)> GetAsync(
        string emailHash, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        string lockedKey = _redis.ApplyPrefix($"lockout:locked:{emailHash}");
        string attemptsKey = _redis.ApplyPrefix($"lockout:attempts:{emailHash}");

        var locked = await db.StringGetWithExpiryAsync(lockedKey);
        if (locked.Value.HasValue)
        {
            var remaining = locked.Expiry ?? TimeSpan.FromSeconds(LockoutSeconds);
            return (0, _time.GetUtcNow() + remaining);
        }

        var count = await db.StringGetAsync(attemptsKey);
        return (count.HasValue ? (int)count : 0, null);
    }

    public async Task<(int NewCount, DateTimeOffset? LockedUntil)> RecordFailureAsync(
        string emailHash, int maxFailedAttempts, TimeSpan lockoutDuration, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        string attemptsKey = _redis.ApplyPrefix($"lockout:attempts:{emailHash}");
        string lockedKey = _redis.ApplyPrefix($"lockout:locked:{emailHash}");
        int lockoutSeconds = Math.Max(1, (int)lockoutDuration.TotalSeconds);

        var reply = (RedisResult[])(await db.ScriptEvaluateAsync(
            RecordFailureScript,
            new RedisKey[] { attemptsKey, lockedKey },
            new RedisValue[] { maxFailedAttempts, lockoutSeconds }))!;

        long newCount = (long)reply[0];
        bool locked = (long)reply[1] == 1;
        DateTimeOffset? lockedUntil = locked ? _time.GetUtcNow().Add(lockoutDuration) : null;

        return ((int)newCount, lockedUntil);
    }

    public async Task ClearAsync(string emailHash, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        var batch = db.CreateBatch();
        var deletes = new[]
        {
            batch.KeyDeleteAsync(_redis.ApplyPrefix($"lockout:attempts:{emailHash}")),
            batch.KeyDeleteAsync(_redis.ApplyPrefix($"lockout:locked:{emailHash}")),
        };
        batch.Execute();
        await Task.WhenAll(deletes);
    }
}
