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

    private readonly IRedisClient _redis;

    public RedisLockoutStore(IRedisClient redis) => _redis = redis;

    public async Task<(int FailedCount, DateTimeOffset? LockedUntil)> GetAsync(
        string emailHash, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        var lockedKey = _redis.ApplyPrefix($"lockout:locked:{emailHash}");
        var attemptsKey = _redis.ApplyPrefix($"lockout:attempts:{emailHash}");

        var locked = await db.StringGetWithExpiryAsync(lockedKey);
        if (locked.Value.HasValue)
        {
            var remaining = locked.Expiry ?? TimeSpan.FromSeconds(LockoutSeconds);
            return (0, DateTimeOffset.UtcNow + remaining);
        }

        var count = await db.StringGetAsync(attemptsKey);
        return (count.HasValue ? (int)count : 0, null);
    }

    public async Task RecordFailureAsync(
        string emailHash, int newCount, DateTimeOffset? lockedUntil, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        var attemptsKey = _redis.ApplyPrefix($"lockout:attempts:{emailHash}");
        var lockedKey = _redis.ApplyPrefix($"lockout:locked:{emailHash}");

        // Use a pipeline to minimize round trips.
        var batch = db.CreateBatch();
        _ = batch.StringSetAsync(attemptsKey, newCount, TimeSpan.FromSeconds(LockoutSeconds));

        if (lockedUntil.HasValue)
        {
            var ttl = lockedUntil.Value - DateTimeOffset.UtcNow;
            if (ttl > TimeSpan.Zero)
                _ = batch.StringSetAsync(lockedKey, "1", ttl);
        }

        batch.Execute();
    }

    public async Task ClearAsync(string emailHash, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        var batch = db.CreateBatch();
        _ = batch.KeyDeleteAsync(_redis.ApplyPrefix($"lockout:attempts:{emailHash}"));
        _ = batch.KeyDeleteAsync(_redis.ApplyPrefix($"lockout:locked:{emailHash}"));
        batch.Execute();
        await Task.CompletedTask;
    }
}
