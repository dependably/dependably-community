using Dependably.Infrastructure.Caching;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit coverage for the per-org policy-invalidation epoch — the mechanism a proxy-settings
/// PUT uses to bulk-expire every rendered-cache entry for its org without enumerating package
/// names. Mirrors <see cref="UserTokenVersionStoreTests"/>'s coverage of the same
/// generation-guard shape (per-key <c>CancellationTokenSource</c>, retired-and-replaced on
/// invalidation), adapted to a bind-many/cancel-once fan-out instead of a single cached value.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgCacheEpochStoreTests
{
    [Fact]
    public void Invalidate_ExpiresEveryEntryBoundToTheOrgsEpoch()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new OrgCacheEpochStore();

        var options = new MemoryCacheEntryOptions();
        options.AddExpirationToken(store.GetToken("org1"));
        cache.Set("entry-a", "value-a", options);

        var options2 = new MemoryCacheEntryOptions();
        options2.AddExpirationToken(store.GetToken("org1"));
        cache.Set("entry-b", "value-b", options2);

        Assert.True(cache.TryGetValue("entry-a", out _));
        Assert.True(cache.TryGetValue("entry-b", out _));

        store.Invalidate("org1");

        // Both entries were bound to the same org epoch and must both expire from one call —
        // the whole point of a shared change token over per-key eviction.
        Assert.False(cache.TryGetValue("entry-a", out _));
        Assert.False(cache.TryGetValue("entry-b", out _));
    }

    [Fact]
    public void Invalidate_DoesNotAffectAnotherOrgsEntries()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new OrgCacheEpochStore();

        var optionsA = new MemoryCacheEntryOptions();
        optionsA.AddExpirationToken(store.GetToken("org-a"));
        cache.Set("entry-a", "value-a", optionsA);

        var optionsB = new MemoryCacheEntryOptions();
        optionsB.AddExpirationToken(store.GetToken("org-b"));
        cache.Set("entry-b", "value-b", optionsB);

        store.Invalidate("org-a");

        Assert.False(cache.TryGetValue("entry-a", out _));
        // Tenant isolation: invalidating org-a's epoch must never expire org-b's entries.
        Assert.True(cache.TryGetValue("entry-b", out _));
    }

    [Fact]
    public void Invalidate_ThenNewWrite_SurvivesUntilTheNextInvalidate()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new OrgCacheEpochStore();

        var options = new MemoryCacheEntryOptions();
        options.AddExpirationToken(store.GetToken("org1"));
        cache.Set("entry", "before", options);
        store.Invalidate("org1");
        Assert.False(cache.TryGetValue("entry", out _));

        // A write that binds to the token minted AFTER Invalidate must not be immediately
        // expired by the retired token — the store must mint a fresh, live epoch.
        var freshOptions = new MemoryCacheEntryOptions();
        freshOptions.AddExpirationToken(store.GetToken("org1"));
        cache.Set("entry", "after", freshOptions);
        Assert.True(cache.TryGetValue("entry", out object? value));
        Assert.Equal("after", value);
    }

    [Fact]
    public void InvalidateThatRacesAnInFlightWrite_DoesNotLetTheStaleWriteSurvive()
    {
        // The exact race the finding describes: a rebuild captures the org's epoch token before
        // it reads policy-dependent state (or, on the proxy path, holds a multi-second upstream
        // fetch open), then a concurrent proxy-settings PUT commits and calls Invalidate. If the
        // rebuild's Set happened after Invalidate cancelled the token, a naive cache would still
        // accept the write and resurrect the pre-flip snapshot for a full TTL. Binding the entry
        // to the token captured up front means the write is accepted by IMemoryCache but expires
        // immediately because its expiration token is already cancelled.
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new OrgCacheEpochStore();

        // Simulates a rebuild capturing the token before its (policy-dependent) read.
        var tokenCapturedBeforeRead = store.GetToken("org1");

        // Concurrent proxy-settings PUT lands and invalidates mid-rebuild.
        store.Invalidate("org1");

        // The rebuild finishes and writes its (now-stale) snapshot, bound to the token it
        // captured before the invalidation.
        var options = new MemoryCacheEntryOptions();
        options.AddExpirationToken(tokenCapturedBeforeRead);
        cache.Set("entry", "stale-pre-flip-value", options);

        // The stale write must not be observably cached — the next read must miss and force a
        // fresh rebuild against the new policy state.
        Assert.False(cache.TryGetValue("entry", out _));
    }
}
