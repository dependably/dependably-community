using Dependably.Infrastructure.Redis;
using NSubstitute;
using StackExchange.Redis;

namespace Dependably.Tests.Unit.Infrastructure.Redis;

/// <summary>
/// Behavioral tests for the Redis-backed distributed lock. Mocks <see cref="IRedisClient"/> +
/// <see cref="IDatabase"/> via NSubstitute and drives the lock through acquire / contention /
/// release / extend scenarios.
///
/// Fail-closed contract: Redis errors on the acquire path propagate to the caller (better to
/// deny the lock than risk dual acquisition). Documented in
/// <see cref="RedisDistributedLock"/> and enforced by <see cref="TryAcquire_RedisThrows_PropagatesException"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RedisDistributedLockTests
{
    private readonly IRedisClient _redis = Substitute.For<IRedisClient>();
    private readonly IDatabase _db = Substitute.For<IDatabase>();

    public RedisDistributedLockTests()
    {
        _redis.GetDatabase().Returns(_db);
        _redis.ApplyPrefix(Arg.Any<string>()).Returns(c => "prefix:" + c.Arg<string>());
    }

    [Fact]
    public async Task TryAcquire_FirstCallSucceeds_SecondCallContests()
    {
        // Sequence the underlying SET NX response: first attempt true (acquired), second false.
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns(true, false);

        var sut = new RedisDistributedLock(_redis, TimeProvider.System);

        var first = await sut.TryAcquireAsync("a-lock", TimeSpan.FromSeconds(5));
        var second = await sut.TryAcquireAsync("a-lock", TimeSpan.FromSeconds(5));

        Assert.NotNull(first);
        Assert.Null(second);
        Assert.Equal("a-lock", first!.Name);
    }

    [Fact]
    public async Task TryAcquire_AppliesKeyPrefix()
    {
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns(true);

        var sut = new RedisDistributedLock(_redis, TimeProvider.System);
        await sut.TryAcquireAsync("my-name", TimeSpan.FromSeconds(5));

        // The actual key passed to Redis must be prefix:lock:my-name.
        await _db.Received(1).StringSetAsync(
            (RedisKey)"prefix:lock:my-name",
            Arg.Any<RedisValue>(),
            TimeSpan.FromSeconds(5),
            When.NotExists);
    }

    [Fact]
    public async Task ExtendAsync_LockHeldByUs_Returns1_ScriptReturnsTrue()
    {
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns(true);
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(RedisResult.Create(1));

        var handle = await new RedisDistributedLock(_redis, TimeProvider.System).TryAcquireAsync("k", TimeSpan.FromSeconds(5));

        Assert.True(await handle!.ExtendAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task ExtendAsync_AfterRelease_ShortCircuitsToFalse()
    {
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns(true);
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(RedisResult.Create(1));

        var handle = await new RedisDistributedLock(_redis, TimeProvider.System).TryAcquireAsync("k", TimeSpan.FromSeconds(5));
        await handle!.DisposeAsync();

        // ExtendAsync returns false post-release without touching Redis again.
        Assert.False(await handle.ExtendAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task DisposeAsync_AttemptsCompareAndDeleteScript()
    {
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns(true);
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(RedisResult.Create(1));

        var handle = await new RedisDistributedLock(_redis, TimeProvider.System).TryAcquireAsync("k", TimeSpan.FromSeconds(5));
        await handle!.DisposeAsync();

        await _db.Received(1).ScriptEvaluateAsync(
            Arg.Is<string>(s => s.Contains("DEL", StringComparison.Ordinal)),
            Arg.Any<RedisKey[]>(),
            Arg.Any<RedisValue[]>());
    }

    [Fact]
    public async Task DisposeAsync_ScriptThrows_Swallowed_BestEffortRelease()
    {
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns(true);
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns<Task<RedisResult>>(_ => throw new RedisConnectionException(ConnectionFailureType.SocketFailure, "boom"));

        var handle = await new RedisDistributedLock(_redis, TimeProvider.System).TryAcquireAsync("k", TimeSpan.FromSeconds(5));
        Assert.NotNull(handle);
        // Must not propagate — TTL cleans up on its own.
        Assert.Null(await Record.ExceptionAsync(() => handle.DisposeAsync().AsTask()));
    }

    [Fact]
    public async Task TryAcquire_RedisThrows_PropagatesException()
    {
        // Fail-closed contract — better to deny than risk dual acquisition.
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns<Task<bool>>(_ => throw new RedisConnectionException(ConnectionFailureType.SocketFailure, "down"));

        await Assert.ThrowsAsync<RedisConnectionException>(() =>
            new RedisDistributedLock(_redis, TimeProvider.System).TryAcquireAsync("k", TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task AcquireAsync_WithinDeadline_ReturnsHandle()
    {
        // First two SET-NX calls fail (contention), third succeeds.
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns(false, false, true);

        var handle = await new RedisDistributedLock(_redis, TimeProvider.System).AcquireAsync(
            "k", ttl: TimeSpan.FromSeconds(5),
            wait: TimeSpan.FromSeconds(2),
            retryInterval: TimeSpan.FromMilliseconds(10));
        Assert.NotNull(handle);
    }

    [Fact]
    public async Task AcquireAsync_PastDeadline_Throws()
    {
        _db.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>())
            .Returns(false);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            new RedisDistributedLock(_redis, TimeProvider.System).AcquireAsync(
                "k", ttl: TimeSpan.FromSeconds(5),
                wait: TimeSpan.FromMilliseconds(50),
                retryInterval: TimeSpan.FromMilliseconds(10)));
    }
}
