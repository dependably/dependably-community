using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for <see cref="SystemAdminTokenVersionStore"/>. Exercises the null-for-missing,
/// cached-read, and post-Invalidate re-read paths.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemAdminTokenVersionStoreTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly MemoryCache _cache = new(new MemoryCacheOptions { SizeLimit = 1000 });

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO system_admins (id, email, password_hash, token_version) " +
            "VALUES ('sa1','admin@example.com','$2b$12$hash',7)");
    }

    public async Task DisposeAsync()
    {
        _cache.Dispose();
        await _db.DisposeAsync();
    }

    private SystemAdminTokenVersionStore Store() => new(_db, _cache);

    // ── null for missing id ───────────────────────────────────────────────────

    [Fact]
    public async Task GetCurrentVersionAsync_MissingId_ReturnsNull()
    {
        long? version = await Store().GetCurrentVersionAsync("no-such-id");
        Assert.Null(version);
    }

    // ── returns stored version ────────────────────────────────────────────────

    [Fact]
    public async Task GetCurrentVersionAsync_ExistingId_ReturnsStoredVersion()
    {
        long? version = await Store().GetCurrentVersionAsync("sa1");
        Assert.Equal(7L, version);
    }

    // ── caching ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetCurrentVersionAsync_SecondCall_ReturnsCachedValue()
    {
        var store = Store();

        long? first = await store.GetCurrentVersionAsync("sa1");

        // Bump the version out-of-band — the cache should still serve the old value.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_admins SET token_version = 99 WHERE id = 'sa1'");
        }

        long? second = await store.GetCurrentVersionAsync("sa1");

        Assert.Equal(7L, first);
        Assert.Equal(7L, second); // still cached
    }

    // ── invalidation forces re-read ───────────────────────────────────────────

    [Fact]
    public async Task Invalidate_ForcesDbReRead_OnNextCall()
    {
        var store = Store();

        long? first = await store.GetCurrentVersionAsync("sa1");
        Assert.Equal(7L, first);

        // Bump the version out-of-band, then invalidate the cache entry.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_admins SET token_version = 42 WHERE id = 'sa1'");
        }

        store.Invalidate("sa1");

        long? second = await store.GetCurrentVersionAsync("sa1");
        Assert.Equal(42L, second);
    }

    // ── mixed partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task GetCurrentVersionAsync_MultipleAdmins_ReturnsCorrectVersionPerAdmin()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO system_admins (id, email, password_hash, token_version) " +
                "VALUES ('sa2','other@example.com','$2b$12$hash',3)");
        }

        var store = Store();

        long? v1 = await store.GetCurrentVersionAsync("sa1");
        long? v2 = await store.GetCurrentVersionAsync("sa2");

        Assert.Equal(7L, v1);
        Assert.Equal(3L, v2);

        // Invalidate only sa1; sa2 should still be served from cache.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_admins SET token_version = 100 WHERE id = 'sa1'");
            await conn.ExecuteAsync(
                "UPDATE system_admins SET token_version = 200 WHERE id = 'sa2'");
        }

        store.Invalidate("sa1");

        long? v1After = await store.GetCurrentVersionAsync("sa1");
        long? v2After = await store.GetCurrentVersionAsync("sa2");

        Assert.Equal(100L, v1After); // re-read
        Assert.Equal(3L, v2After);   // still cached
    }
}
