using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;

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
    private readonly MemoryCache _cache = new(new MemoryCacheOptions());

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
        long? instanceMax = (long?)null;
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
            .AddInMemoryCollection(new Dictionary<string, string?> { ["BASE_URL"] = "https://apex.test" })
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
        var tokens = new TokenRepository(_db, TimeProvider.System);

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
        var tokens = new TokenRepository(_db, TimeProvider.System);

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
        var tokens = new TokenRepository(_db, TimeProvider.System);
        Assert.Null(await tokens.ResolveAsync("never-issued"));
    }

    [Fact]
    public async Task ResolveAsync_ExpiredToken_ReturnsNull()
    {
        var tokens = new TokenRepository(_db, TimeProvider.System);

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

    // ── TokenRepository resolve cache ───────────────────────────────────────

    [Fact]
    public async Task ResolveAsync_CachesResult_WithinTtl_HitsStoreOnce()
    {
        var counting = new CountingMetadataStore(_db);
        var tokens = new TokenRepository(counting, TimeProvider.System, _cache);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
                VALUES ('t-cache-hit', 'o1', 'ci', @hash, '["publish:npm"]', '2026-01-01T00:00:00Z')
                """, new { hash = TokenRepository.HashToken("cache-hit-raw") });
        }

        var first = await tokens.ResolveAsync("cache-hit-raw");
        var second = await tokens.ResolveAsync("cache-hit-raw");

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal("t-cache-hit", second!.Id);
        // The resolve query opens exactly one connection — the second call is served
        // entirely from the in-memory cache without touching the store.
        Assert.Equal(1, counting.OpenCount);
    }

    [Fact]
    public async Task ResolveAsync_CachesResult_UntilOutOfBandMutation_ObservedAfterInvalidation()
    {
        var tokens = new TokenRepository(_db, TimeProvider.System, _cache);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
                VALUES ('t-cache-stale', 'o1', 'ci', @hash, '["publish:npm"]', '2026-01-01T00:00:00Z')
                """, new { hash = TokenRepository.HashToken("cache-stale-raw") });
        }

        var first = await tokens.ResolveAsync("cache-stale-raw");
        Assert.Contains("publish:npm", first!.CapabilitySet);

        // Revoke the capability out-of-band (e.g. a concurrent admin edit). Without the
        // resolve cache this would be visible on the very next request; the 1-second TTL
        // is the accepted revocation-lag trade-off documented on TokenRepository.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE service_tokens SET capabilities = '[]' WHERE id = 't-cache-stale'");
        }

        var cached = await tokens.ResolveAsync("cache-stale-raw");
        Assert.Contains("publish:npm", cached!.CapabilitySet); // still serving the cached resolution
    }

    [Fact]
    public async Task ResolveAsync_DistinctTokensAcrossOrgs_NeverShareCacheEntry()
    {
        var tokens = new TokenRepository(_db, TimeProvider.System, _cache);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'other')");
            await conn.ExecuteAsync("""
                INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
                VALUES ('svc-o1', 'o1', 'ci-o1', @hashA, '["publish:npm"]', '2026-01-01T00:00:00Z');
                INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
                VALUES ('svc-o2', 'o2', 'ci-o2', @hashB, '["publish:npm"]', '2026-01-01T00:00:00Z')
                """,
                new { hashA = TokenRepository.HashToken("org1-raw"), hashB = TokenRepository.HashToken("org2-raw") });
        }

        var first = await tokens.ResolveAsync("org1-raw");
        var second = await tokens.ResolveAsync("org2-raw");
        // Re-resolving the first token must still land on org1 — a distinct raw token can
        // never be served from another tenant's cache entry (the cache key is the token's
        // own SHA-256 hash, unique per token).
        var firstAgain = await tokens.ResolveAsync("org1-raw");

        Assert.Equal("o1", first!.OrgId);
        Assert.Equal("o2", second!.OrgId);
        Assert.Equal("o1", firstAgain!.OrgId);
    }

    [Fact]
    public async Task ResolveAsync_NeverCachesMiss_ForUnknownToken()
    {
        var counting = new CountingMetadataStore(_db);
        var tokens = new TokenRepository(counting, TimeProvider.System, _cache);

        Assert.Null(await tokens.ResolveAsync("still-never-issued"));
        Assert.Null(await tokens.ResolveAsync("still-never-issued"));

        // A miss is never cached — an account-disabled or removed user token also resolves
        // to null, and caching that would delay the reactivation/removal tests' expected
        // same-request recovery just as badly as caching a stale hit would.
        Assert.Equal(2, counting.OpenCount);
    }

    [Fact]
    public async Task ResolveAsync_NeverCachesUserTokenResolution()
    {
        var counting = new CountingMetadataStore(_db);
        var tokens = new TokenRepository(counting, TimeProvider.System, _cache);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO users (id, tenant_id, email, password_hash, role, created_at)
                VALUES ('u-cache', 'o1', 'cache@example.com', '', 'member', '2026-01-01T00:00:00Z');
                INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, created_at)
                VALUES ('t-user-cache', 'o1', 'u-cache', @hash, '["read:metadata"]', '2026-01-01T00:00:00Z')
                """, new { hash = TokenRepository.HashToken("user-cache-raw") });
        }

        var first = await tokens.ResolveAsync("user-cache-raw");
        var second = await tokens.ResolveAsync("user-cache-raw");

        Assert.NotNull(first);
        Assert.NotNull(second);
        // User-token resolutions are never cached — every call re-queries so an account
        // lock/disable or a password-change token revocation takes effect on the very next
        // request rather than lagging by the cache TTL.
        Assert.Equal(2, counting.OpenCount);
    }

    // Wraps an IMetadataStore and counts OpenAsync calls, so cache-hit tests can assert the
    // store was (or wasn't) actually queried rather than inferring it from timing.
    private sealed class CountingMetadataStore(IMetadataStore inner) : IMetadataStore
    {
        public int OpenCount { get; private set; }

        public DbProvider Provider => inner.Provider;

        public async Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            OpenCount++;
            return await inner.OpenAsync(ct);
        }
    }
}
