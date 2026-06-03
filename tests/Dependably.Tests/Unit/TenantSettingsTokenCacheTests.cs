using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance tests for the slug → tenant context cache, tenant id → OrgSettings cache,
/// and the unified UNION-ALL token lookup. Each test exercises both the cached path and
/// the invalidation/eviction guarantees.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantSettingsTokenCacheTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly MemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync()
    {
        _cache.Dispose();
        await _db.DisposeAsync();
    }

    // ── OrgRepository settings cache ────────────────────────────────────────

    [Fact]
    public async Task GetSettingsAsync_CachesResult_AcrossCalls()
    {
        var repo = new OrgRepository(_db, _cache);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, anonymous_pull, allowlist_mode) VALUES ('o1', 1, 0)");
        }

        var first = await repo.GetSettingsAsync("o1");
        Assert.NotNull(first);
        Assert.True(first!.AnonymousPull);

        // Mutate the row out-of-band — without invalidation, the cache should still
        // serve the prior value.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = 'o1'");
        }

        var cached = await repo.GetSettingsAsync("o1");
        Assert.NotNull(cached);
        Assert.True(cached!.AnonymousPull); // still cached
    }

    [Fact]
    public async Task InvalidateSettingsCache_ForcesFreshRead()
    {
        var repo = new OrgRepository(_db, _cache);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, anonymous_pull, allowlist_mode) VALUES ('o1', 1, 0)");
        }

        _ = await repo.GetSettingsAsync("o1");

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = 'o1'");
        }

        repo.InvalidateSettingsCache("o1");
        var fresh = await repo.GetSettingsAsync("o1");
        Assert.NotNull(fresh);
        Assert.False(fresh!.AnonymousPull); // DB now wins
    }

    [Fact]
    public async Task UpsertSettings_InvalidatesOrgRepositoryCache()
    {
        // End-to-end: OrgSettingsRepository write path must invalidate OrgRepository cache
        // so admin policy changes take effect on the very next hot-path read.
        var orgs = new OrgRepository(_db, _cache);
        var settingsRepo = new OrgSettingsRepository(_db, orgs);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, anonymous_pull, allowlist_mode) VALUES ('o1', 1, 0)");
        }

        // Warm cache.
        _ = await orgs.GetSettingsAsync("o1");

        // UpsertSettingsAsync writes a fresh row + must invalidate.
        var instanceMax = (long?)null;
        await settingsRepo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: "o1",
            AnonymousPull: false,
            AllowlistMode: false,
            MaxUploadBytes: null,
            MaxUploadBytesPyPi: null,
            MaxUploadBytesNpm: null,
            MaxUploadBytesNuGet: null,
            InstanceMaxUploadBytes: instanceMax,
            DefaultLanguage: "en",
            AllowVersionOverwrite: false));

        var fresh = await orgs.GetSettingsAsync("o1");
        Assert.NotNull(fresh);
        Assert.False(fresh!.AnonymousPull);
    }

    // ── SubdomainTenantResolver cache ───────────────────────────────────────

    [Fact]
    public async Task SubdomainResolver_CachesTenantContext()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["APEX_HOST"] = "apex.test" })
            .Build();
        var resolver = new SubdomainTenantResolver(_db, config, _cache);

        var ctx1 = await ResolveAsync(resolver, "acme.apex.test");
        Assert.Equal("o1", ctx1.TenantId);

        // Drop the row — without cache invalidation the resolver must still serve the
        // cached value (until TTL elapses) so the perf win is observable.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE orgs SET deleted_at = '2026-01-01T00:00:00Z' WHERE id = 'o1'");
        }

        var ctx2 = await ResolveAsync(resolver, "acme.apex.test");
        Assert.Equal("o1", ctx2.TenantId); // still cached
    }

    private static async Task<TenantContext> ResolveAsync(SubdomainTenantResolver resolver, string host)
    {
        var ctx = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        ctx.Request.Host = new Microsoft.AspNetCore.Http.HostString(host);
        return await resolver.ResolveAsync(ctx);
    }

    // ── TokenRepository unified lookup ──────────────────────────────────────

    [Fact]
    public async Task ResolveAsync_FindsUserTokenViaUnifiedQuery()
    {
        var tokens = new TokenRepository(_db);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO users (id, tenant_id, email, password_hash, role, created_at)
                VALUES ('u1', 'o1', 'a@b', '', 'admin', '2026-01-01T00:00:00Z');
                INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, created_at)
                VALUES ('t1', 'o1', 'u1', @hash, '["read:metadata"]', '2026-01-01T00:00:00Z')
                """, new { hash = TokenRepository.HashToken("user-token-raw") });
        }

        var resolved = await tokens.ResolveAsync("user-token-raw");
        Assert.NotNull(resolved);
        Assert.Equal(TokenSource.User, resolved!.Source);
        Assert.Equal("u1", resolved.UserId);
    }

    [Fact]
    public async Task ResolveAsync_FindsServiceTokenViaUnifiedQuery()
    {
        var tokens = new TokenRepository(_db);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
                VALUES ('t2', 'o1', 'ci', @hash, '["publish:npm"]', '2026-01-01T00:00:00Z')
                """, new { hash = TokenRepository.HashToken("service-token-raw") });
        }

        var resolved = await tokens.ResolveAsync("service-token-raw");
        Assert.NotNull(resolved);
        Assert.Equal(TokenSource.Service, resolved!.Source);
        Assert.Null(resolved.UserId);
    }

    [Fact]
    public async Task ResolveAsync_UnknownToken_ReturnsNull()
    {
        var tokens = new TokenRepository(_db);
        Assert.Null(await tokens.ResolveAsync("never-issued"));
    }

    [Fact]
    public async Task ResolveAsync_ExpiredToken_ReturnsNull()
    {
        var tokens = new TokenRepository(_db);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO users (id, tenant_id, email, password_hash, role, created_at)
                VALUES ('u2', 'o1', 'c@d', '', 'member', '2026-01-01T00:00:00Z');
                INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, created_at, expires_at)
                VALUES ('t3', 'o1', 'u2', @hash, '["read:metadata"]', '2026-01-01T00:00:00Z', '2020-01-01T00:00:00Z')
                """, new { hash = TokenRepository.HashToken("expired-raw") });
        }

        Assert.Null(await tokens.ResolveAsync("expired-raw"));
    }
}
