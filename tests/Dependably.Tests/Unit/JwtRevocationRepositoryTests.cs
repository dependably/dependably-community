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
}
