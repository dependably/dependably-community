using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the atomic-increment contract on <see cref="ILockoutStore.RecordFailureAsync"/>: the
/// store — not the caller — computes the post-failure count, so concurrent failures against the
/// same account can never lose an update the way a caller-computed
/// <c>currentFailedCount + 1</c> written back with an absolute SET could.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SqliteLockoutStoreConcurrencyTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public SqliteLockoutStoreConcurrencyTests(InMemoryDbFixture fixture) => _fixture = fixture;

    /// <summary>
    /// Two failed logins against the same account, released together so their store calls race
    /// rather than run back-to-back. Both must be counted: a caller-computed increment that reads
    /// a stale value before either write lands only advances the counter by one, understating a
    /// distributed attacker's real guess count by however many attempts collided.
    /// </summary>
    [Fact]
    public async Task RecordFailureAsync_TwoConcurrentFailures_BothCounted()
    {
        var store = new SqliteLockoutStore(_fixture.Store, TestTime.Frozen());
        string hash = $"concurrency-{Guid.NewGuid():N}";

        using var start = new SemaphoreSlim(0, 2);

        async Task<(int NewCount, DateTimeOffset? LockedUntil)> RecordAsync()
        {
            await start.WaitAsync();
            return await store.RecordFailureAsync(hash, maxFailedAttempts: 10, TimeSpan.FromMinutes(15), CancellationToken.None);
        }

        var t1 = RecordAsync();
        var t2 = RecordAsync();
        start.Release(2);
        var results = await Task.WhenAll(t1, t2);

        // Each concurrent call must observe its own distinct post-increment count — {1, 2} in
        // some order — never the same value twice, which is what a lost update looks like.
        Assert.Equal(new[] { 1, 2 }, results.Select(r => r.NewCount).OrderBy(n => n));

        var (finalCount, _) = await store.GetAsync(hash, CancellationToken.None);
        Assert.Equal(2, finalCount);
    }

    /// <summary>
    /// A higher-contention version of the same race: five concurrent failures must all be
    /// counted with no duplicate or skipped post-increment value.
    /// </summary>
    [Fact]
    public async Task RecordFailureAsync_FiveConcurrentFailures_AllCountedWithDistinctValues()
    {
        var store = new SqliteLockoutStore(_fixture.Store, TestTime.Frozen());
        string hash = $"concurrency-{Guid.NewGuid():N}";

        using var start = new SemaphoreSlim(0, 5);

        async Task<int> RecordAsync()
        {
            await start.WaitAsync();
            var (newCount, _) = await store.RecordFailureAsync(hash, maxFailedAttempts: 100, TimeSpan.FromMinutes(15), CancellationToken.None);
            return newCount;
        }

        var tasks = Enumerable.Range(0, 5).Select(_ => RecordAsync()).ToArray();
        start.Release(5);
        int[] counts = await Task.WhenAll(tasks);

        Assert.Equal(new[] { 1, 2, 3, 4, 5 }, counts.OrderBy(n => n));

        var (finalCount, _) = await store.GetAsync(hash, CancellationToken.None);
        Assert.Equal(5, finalCount);
    }

    /// <summary>
    /// Mixed outcome: some of the concurrent failures cross the lockout threshold and some do
    /// not. Every caller must still see a count that is consistent with the real, atomic total —
    /// the lock decision is made from the same authoritative value the counter converges on, not
    /// a value guessed independently by each caller.
    /// </summary>
    [Fact]
    public async Task RecordFailureAsync_ConcurrentFailuresCrossingThreshold_LockDecisionMatchesRealCount()
    {
        var store = new SqliteLockoutStore(_fixture.Store, TestTime.Frozen());
        string hash = $"concurrency-{Guid.NewGuid():N}";
        const int maxFailedAttempts = 3;

        using var start = new SemaphoreSlim(0, 4);

        async Task<(int NewCount, DateTimeOffset? LockedUntil)> RecordAsync()
        {
            await start.WaitAsync();
            return await store.RecordFailureAsync(hash, maxFailedAttempts, TimeSpan.FromMinutes(15), CancellationToken.None);
        }

        var tasks = Enumerable.Range(0, 4).Select(_ => RecordAsync()).ToArray();
        start.Release(4);
        var results = await Task.WhenAll(tasks);

        Assert.Equal(new[] { 1, 2, 3, 4 }, results.Select(r => r.NewCount).OrderBy(n => n));

        // Exactly the calls whose authoritative count reached the threshold report a lock —
        // never more, never fewer, and never a call below threshold reporting locked.
        foreach (var (newCount, lockedUntil) in results)
        {
            if (newCount >= maxFailedAttempts)
            {
                Assert.NotNull(lockedUntil);
            }
            else
            {
                Assert.Null(lockedUntil);
            }
        }

        var (finalCount, finalLockedUntil) = await store.GetAsync(hash, CancellationToken.None);
        Assert.Equal(4, finalCount);
        Assert.NotNull(finalLockedUntil);
    }
}
