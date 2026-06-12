using System.Threading.RateLimiting;
using Dependably.Infrastructure.Redis;
using NSubstitute;
using StackExchange.Redis;

namespace Dependably.Tests.Unit.Infrastructure.Redis;

/// <summary>
/// Behavioral tests for the Redis fixed-window rate limiter.
///
/// Fail-open contract: a Redis exception MUST yield an acquired lease so legitimate traffic
/// doesn't get denied during a Redis outage. Pinned by
/// <see cref="Acquire_RedisThrows_FailsOpen_AcquiresLease"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RedisFixedWindowRateLimiterTests
{
    private readonly IDatabase _db = Substitute.For<IDatabase>();

    private RedisFixedWindowRateLimiter NewSut(int permitLimit = 5, int windowSeconds = 60)
        => new(_db, keyPrefix: "p:", scope: "login", bucket: "ip-1.2.3.4",
               permitLimit: permitLimit, windowSeconds: windowSeconds);

    private static RedisResult Pair(long count, long ttl) =>
        RedisResult.Create(new[] { RedisResult.Create(count), RedisResult.Create(ttl) });

    [Fact]
    public async Task UnderLimit_AcquiresLease()
    {
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 1, ttl: 60));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync(permitCount: 1);
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task AtLimit_StillAcquires()
    {
        // count == permitLimit is "the Nth permitted call", not the rejection boundary.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 5, ttl: 60));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync();
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task OverLimit_RejectsWithRetryAfterFromTtl()
    {
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 6, ttl: 42));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync();
        Assert.False(lease.IsAcquired);
        Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter.Name, out object? meta));
        Assert.Equal(TimeSpan.FromSeconds(42), Assert.IsType<TimeSpan>(meta));
    }

    [Fact]
    public async Task OverLimit_TtlMissing_FallsBackToWindowLength()
    {
        // If TTL is -1 / 0 (key persisted somehow), the retry-after defaults to a full window.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 7, ttl: 0));

        using var lease = await NewSut(permitLimit: 5, windowSeconds: 90).AcquireAsync();
        Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter.Name, out object? meta));
        Assert.Equal(TimeSpan.FromSeconds(90), Assert.IsType<TimeSpan>(meta));
    }

    [Fact]
    public async Task Acquire_RedisThrows_FailsOpen_AcquiresLease()
    {
        // Fail-open contract — a Redis outage must not deny legitimate traffic.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns<Task<RedisResult>>(_ => throw new RedisConnectionException(ConnectionFailureType.SocketFailure, "down"));

        using var lease = await NewSut().AcquireAsync();
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task KeyIncludesScope_Bucket_AndWindowId()
    {
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(1, 60));

        await NewSut(windowSeconds: 60).AcquireAsync();

        await _db.Received(1).ScriptEvaluateAsync(
            Arg.Any<string>(),
            Arg.Is<RedisKey[]>(keys =>
                keys.Length == 1 &&
                keys[0].ToString().StartsWith("p:ratelimit:login:ip-1.2.3.4:", StringComparison.Ordinal)),
            Arg.Any<RedisValue[]>());
    }

    [Fact]
    public async Task SynchronousAttemptAcquire_DefersToAsync()
    {
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(1, 60));
        using var lease = NewSut().AttemptAcquire();   // covers the AttemptAcquireCore branch
        await Task.Yield();
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public void GetStatistics_ReturnsNull_UntilBacklogIsModeled()
    {
        Assert.Null(NewSut().GetStatistics());
    }

    [Fact]
    public async Task AcquireAsync_WithPermitCountGreaterThanOne_AcquiresLease()
    {
        // permitCount > 1 still routes through the same AcquireAsync() path — count stays under limit.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 3, ttl: 55));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync(permitCount: 3);
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task SuccessLease_Dispose_DoesNotThrow()
    {
        // Exercises the SuccessLease.Dispose(bool) path — stateless, nothing to release.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 1, ttl: 60));

        var lease = await NewSut().AcquireAsync();
        Assert.True(lease.IsAcquired);
        var ex = Record.Exception(() => lease.Dispose());
        Assert.Null(ex);
    }

    [Fact]
    public async Task RejectedLease_TryGetMetadata_UnknownKey_ReturnsFalse()
    {
        // Drive the limiter over limit to obtain a RejectedLease, then probe an unknown key.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 10, ttl: 30));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync();
        Assert.False(lease.IsAcquired);
        bool found = lease.TryGetMetadata("unknown_key", out object? meta);
        Assert.False(found);
        Assert.Null(meta);
    }

    [Fact]
    public void Dispose_Limiter_DoesNotThrow()
    {
        // Exercises the protected Dispose(bool) override — no unmanaged resources to release.
        var sut = NewSut();
        var ex = Record.Exception(() => sut.Dispose());
        Assert.Null(ex);
    }
}
