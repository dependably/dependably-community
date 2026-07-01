using Dependably.Infrastructure.Redis;

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

    public async Task RecordFailureAsync(
        string emailHash, int newCount, DateTimeOffset? lockedUntil, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        string attemptsKey = _redis.ApplyPrefix($"lockout:attempts:{emailHash}");
        string lockedKey = _redis.ApplyPrefix($"lockout:locked:{emailHash}");

        // Pipeline the writes to minimize round trips, but await their completion: a dropped
        // lockout write must surface, not vanish as an unobserved task. Silently losing the
        // attempt count would under-count failures (a lockout-bypass risk under Redis trouble).
        var batch = db.CreateBatch();
        var writes = new List<Task>
        {
            batch.StringSetAsync(attemptsKey, newCount, TimeSpan.FromSeconds(LockoutSeconds)),
        };

        if (lockedUntil.HasValue)
        {
            var ttl = lockedUntil.Value - _time.GetUtcNow();
            if (ttl > TimeSpan.Zero)
            {
                writes.Add(batch.StringSetAsync(lockedKey, "1", ttl));
            }
        }

        batch.Execute();
        await Task.WhenAll(writes);
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
