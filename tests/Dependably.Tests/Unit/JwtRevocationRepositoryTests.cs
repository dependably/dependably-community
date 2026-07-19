using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class JwtRevocationRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly MemoryCache _cache = new(new MemoryCacheOptions());

    public async Task InitializeAsync() =>
        await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync()
    {
        _cache.Dispose();
        await _db.DisposeAsync();
    }

    // Acceptance check: lookup by jti must be index-served, not a full table scan.
    // jti is PRIMARY KEY, so SQLite backs it with sqlite_autoindex_jwt_revocations_1.
    [Fact]
    public async Task IsRevokedQuery_UsesIndex_NotTableScan()
    {
        await using var conn = await _db.OpenAsync();
        var plan = (await conn.QueryAsync<(int Id, int Parent, int NotUsed, string Detail)>(
            """
            EXPLAIN QUERY PLAN
            SELECT COUNT(*) FROM jwt_revocations WHERE jti = @jti AND expires_at > @now
            """,
            new { jti = "x", now = "2026-01-01T00:00:00Z" })).ToList();

        Assert.NotEmpty(plan);
        string detail = string.Join("\n", plan.Select(p => p.Detail));
        Assert.Contains("SEARCH", detail);
        Assert.DoesNotContain("SCAN jwt_revocations", detail);
    }

    [Fact]
    public async Task IsRevokedAsync_CachesNegativeResult()
    {
        var repo = new JwtRevocationRepository(_db, _cache, TestTime.Frozen());

        // First call: cache miss, DB returns false, populates negative cache.
        Assert.False(await repo.IsRevokedAsync("jti-1"));

        // Insert a revocation directly bypassing the repository so the cache stays warm.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO jwt_revocations (jti, expires_at) VALUES (@jti, @exp)",
                new { jti = "jti-1", exp = TestTime.KnownNow.AddHours(1).ToString("yyyy-MM-ddTHH:mm:ssZ") });
        }

        // Second call: cache hit, still returns false (proves we actually cached).
        Assert.False(await repo.IsRevokedAsync("jti-1"));
    }

    [Fact]
    public async Task RevokeAsync_EvictsNegativeCacheEntry()
    {
        var repo = new JwtRevocationRepository(_db, _cache, TestTime.Frozen());

        // Warm the negative cache.
        Assert.False(await repo.IsRevokedAsync("jti-2"));

        // Revoke through the repository — must invalidate the cache entry.
        await repo.RevokeAsync("jti-2", TestTime.KnownNow.AddHours(1));

        // Next check goes to the DB and reflects the revocation.
        Assert.True(await repo.IsRevokedAsync("jti-2"));
    }

    [Fact]
    public async Task IsRevokedAsync_DoesNotCachePositiveResult()
    {
        var repo = new JwtRevocationRepository(_db, _cache, TestTime.Frozen());
        await repo.RevokeAsync("jti-3", TestTime.KnownNow.AddHours(1));

        Assert.True(await repo.IsRevokedAsync("jti-3"));

        // Manually expire the row to simulate the cleanup window — if the positive
        // answer were cached we'd still see "revoked" after the row is gone.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE jwt_revocations SET expires_at = @past WHERE jti = @jti",
                new { jti = "jti-3", past = TestTime.KnownNow.AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ssZ") });
        }

        Assert.False(await repo.IsRevokedAsync("jti-3"));
    }

    [Fact]
    public async Task IsRevokedAsync_WorksWithoutCache()
    {
        var repo = new JwtRevocationRepository(_db, time: TestTime.Frozen());

        Assert.False(await repo.IsRevokedAsync("jti-4"));
        await repo.RevokeAsync("jti-4", TestTime.KnownNow.AddHours(1));
        Assert.True(await repo.IsRevokedAsync("jti-4"));
    }

    [Fact]
    public async Task RevokeThatRacesAnInFlightNegativeFill_DoesNotCacheTheStaleNotRevokedAnswer()
    {
        // Fill-after-invalidate race: request B checks IsRevokedAsync and its DB read returns
        // count=0 (not yet revoked); concurrently request A logs out, committing the revocation
        // INSERT and evicting the cache key. B then completes its fill. On the pre-guard code B
        // caches revoked=false AFTER A's eviction, so the logged-out token authenticates for a
        // full 60s TTL. The hook fires the racing RevokeAsync in the window between B's scalar
        // read and its cache write — this fails on the old code and passes on the guard-token fix.
        var hooked = new AfterDbReadHookStore(_db);
        var repo = new JwtRevocationRepository(hooked, _cache, TestTime.Frozen());

        hooked.AfterRead = async () =>
            await repo.RevokeAsync("jti-race", TestTime.KnownNow.AddHours(1));

        // B's fill: reads count=0, then the hook revokes+evicts, then B writes the negative entry.
        Assert.False(await repo.IsRevokedAsync("jti-race")); // B legitimately read the pre-revoke state

        // Killer assertion: a subsequent check must observe the revocation, not a stale cached
        // "not revoked" left behind by B's post-eviction write.
        Assert.True(await repo.IsRevokedAsync("jti-race"));
    }

    [Fact]
    public async Task NaturallyExpiringToken_DoesNotRetainItsFillGuard()
    {
        // A cache MISS mints a per-jti generation guard so a racing RevokeAsync can cancel an
        // in-flight fill. Naturally-expiring JWTs never call RevokeAsync, so unless the guard's
        // lifetime is tied to the cache entry its generation lives for the whole process — one
        // CancellationTokenSource per distinct token ever seen, an unbounded leak on a long-lived
        // node.
        var repo = new JwtRevocationRepository(_db, _cache, TestTime.Frozen());

        Assert.False(await repo.IsRevokedAsync("jti-leak"));
        Assert.Equal(1, repo.FillGuardCount);

        // Evict the negative entry the way a TTL expiry or capacity trim would — not RevokeAsync,
        // which retires the guard directly. The entry's post-eviction callback must retire it.
        _cache.Compact(1.0);

        await WaitForFillGuardsToDrain(() => repo.FillGuardCount);
        Assert.Equal(0, repo.FillGuardCount);
    }

    [Fact]
    public async Task RevokedJtiLookup_DoesNotRetainItsFillGuard()
    {
        // Not-cached terminal branch: a cache MISS mints a per-jti generation guard before the DB
        // read, but a revoked (positive) result is intentionally never cached, so the guard is
        // never tied to a cache entry. IsRevokedAsync runs on EVERY JWT request, so a repeatedly
        // presented logged-out token would leak one CancellationTokenSource per distinct revoked
        // jti — monotonic over the process lifetime. The terminal branch must retire the guard.
        var repo = new JwtRevocationRepository(_db, _cache, TestTime.Frozen());

        // Insert the revocation directly so the guard we observe is the one IsRevokedAsync mints,
        // not the one RevokeAsync retires on its own path.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO jwt_revocations (jti, expires_at) VALUES (@jti, @exp)",
                new { jti = "jti-revoked-leak", exp = TestTime.KnownNow.AddHours(1).ToString("yyyy-MM-ddTHH:mm:ssZ") });
        }

        Assert.True(await repo.IsRevokedAsync("jti-revoked-leak"));

        // The retire is synchronous on the terminal branch (no cache entry, so no post-eviction
        // callback to await). On the pre-fix code the guard leaks and this reads 1.
        Assert.Equal(0, repo.FillGuardCount);
    }

    // MemoryCache fires post-eviction callbacks on a thread-pool task, so poll briefly for the
    // asynchronous retire rather than assuming it has already run.
    private static async Task WaitForFillGuardsToDrain(Func<int> count)
    {
        for (int i = 0; i < 200 && count() != 0; i++)
        {
            await Task.Delay(10);
        }
    }
}
