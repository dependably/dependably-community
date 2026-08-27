using System.Data.Common;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class BlocklistRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public BlocklistRepositoryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private BlocklistRepository NewRepo() => new(_fixture.Store, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);

    [Fact]
    public async Task ListAsync_FiltersByOrg_OrderedByPattern()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgA, "z");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgA, "b");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgA, "a");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgB, "should-not-leak");

        var entries = await NewRepo().ListAsync(orgA);

        Assert.Equal(3, entries.Count);
        Assert.Equal("a", entries[0].Pattern);
        Assert.Equal("b", entries[1].Pattern);
        Assert.Equal("z", entries[2].Pattern);
    }

    [Fact]
    public async Task IsBlockedAsync_AnchoredPatternScopesByEcosystem()
    {
        // With ecosystem dropped, scoping is the operator's job: anchor the pattern to the
        // PURL prefix to keep enforcement confined to one ecosystem.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgId, "^pkg:npm/evil-.*");

        var repo = NewRepo();
        Assert.True(await repo.IsBlockedAsync(orgId, "pkg:npm/evil-pkg@1.0.0"));
        Assert.False(await repo.IsBlockedAsync(orgId, "pkg:npm/good-pkg@1.0.0"));
        Assert.False(await repo.IsBlockedAsync(orgId, "pkg:pypi/evil-pkg@1.0.0"));
    }

    [Fact]
    public async Task IsBlockedAsync_LoosePatternMatchesAllEcosystems()
    {
        // Documents the intentional behaviour: a pattern without the
        // `pkg:<eco>/` anchor matches the substring anywhere in the PURL, including
        // ecosystems the operator may not have intended.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgId, "evil-.*");

        var repo = NewRepo();
        Assert.True(await repo.IsBlockedAsync(orgId, "pkg:npm/evil-pkg@1.0.0"));
        Assert.True(await repo.IsBlockedAsync(orgId, "pkg:pypi/evil-pkg@1.0.0"));
    }

    [Fact]
    public async Task IsBlockedAsync_MalformedRegex_DoesNotThrow_AndDoesNotBlock()
    {
        // Hostile blocklist entry shouldn't poison the whole gate — bad pattern → no match.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgId, "[unclosed-bracket");

        Assert.False(await NewRepo().IsBlockedAsync(orgId, "pkg:npm/anything@1.0.0"));
    }

    [Fact]
    public async Task AddAsync_OnDuplicate_IsIgnored_AndInvalidatesCache()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();

        await repo.AddAsync(orgId, "pkg:npm/foo");
        int beforeDup = (await repo.ListAsync(orgId)).Count;
        await repo.AddAsync(orgId, "pkg:npm/foo");  // identical pattern → ignored
        int afterDup = (await repo.ListAsync(orgId)).Count;

        Assert.Equal(beforeDup, afterDup);
    }

    [Fact]
    public async Task DeleteAsync_RemovesEntry_AndIsIdempotent()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string id = await BlocklistSeeder.InsertAsync(_fixture.Store, orgId, "pkg:npm/x");
        var repo = NewRepo();

        await repo.DeleteAsync(orgId, id);
        await repo.DeleteAsync(orgId, id);   // delete-of-missing → safe no-op

        Assert.Empty(await repo.ListAsync(orgId));
    }

    [Fact]
    public async Task AddThatRacesAnInFlightListFill_DoesNotServeThePreBlockListForATtl()
    {
        // Fill-after-invalidate race on the hot proxy/publish gate: IsBlockedAsync reads the DB
        // (no matching pattern yet); concurrently an operator adds a block, whose INSERT +
        // cache-eviction lands mid-fill. The fill then caches the pre-block list AFTER the
        // eviction, so a package the operator just blocked stays installable for a full 60s TTL.
        // The hook fires the racing AddAsync between the list read and its cache write — fails on
        // the pre-guard code, passes on the generation-token fix.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var hooked = new AfterDbReadHookStore(_fixture.Store);
        var repo = new BlocklistRepository(hooked, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);

        hooked.AfterRead = async () => await repo.AddAsync(orgId, "^pkg:npm/evil-.*");

        // The fill reads the empty list, then the hook adds the block + evicts, then the fill caches.
        Assert.False(await repo.IsBlockedAsync(orgId, "pkg:npm/evil-x@1.0.0")); // read pre-block list

        // Killer assertion: the next check must enforce the newly-added block, not serve a stale
        // pre-block list cached by the racing fill.
        Assert.True(await repo.IsBlockedAsync(orgId, "pkg:npm/evil-x@1.0.0"));
    }

    [Fact]
    public async Task DbOpenThrowsAfterGuardIsMinted_DoesNotRetainItsFillGuard()
    {
        // GuardFor mints the guard BEFORE the DB open/read. BlocklistRepository is registered
        // Singleton, so the guard map is process-lifetime — if the open or read throws with no
        // cache entry ever installed to tie the guard's lifetime to, the guard must not survive
        // the throw. Fails on the pre-fix code (no try/finally around the read), passes once the
        // throwing branch retires the just-minted guard.
        var repo = new BlocklistRepository(
            new ThrowingAfterGuardStore(), new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => repo.ListAsync($"org-{Guid.NewGuid():N}"));

        Assert.Equal(0, repo.FillGuardCount);
    }

    [Fact]
    public async Task RacingFillReusesAboutToRetireGuard_ItsInstalledEntryDoesNotSurviveTheDelayedEviction()
    {
        // Async post-eviction-callback race: MemoryCache dispatches TieToEntryLifetime's callback
        // on a thread-pool task, not synchronously with eviction, so a concurrent fill can call
        // GuardFor and receive the about-to-retire generation before that callback ever runs. The
        // hook fires the FIRST entry's captured eviction callback (simulating that delayed
        // dispatch, deterministically rather than by timing) between the SECOND fill's DB read and
        // its cache write. Fails on a callback that only compare-removes from the map; passes once
        // it also cancels the generation, which is what lets the SECOND (racing) entry's own
        // already-cancelled expiration token keep it from ever installing.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var wrappedCache = new PostEvictionCallbackCapturingMemoryCache(new MemoryCache(new MemoryCacheOptions()));
        var hooked = new AfterDbReadHookStore(_fixture.Store);
        var repo = new BlocklistRepository(hooked, wrappedCache, TimeProvider.System);
        string cacheKey = "blocklist:" + orgId;

        // Entry 1: a normal fill installs a real cache entry bound to G1 and captures its
        // post-eviction callback — not fired yet, simulating "logically expired, physical
        // eviction still pending" the way a naturally-elapsed TTL would leave it.
        await repo.ListAsync(orgId);

        hooked.AfterRead = () =>
        {
            wrappedCache.FireCapturedEvictionCallbacks(cacheKey);
            return Task.CompletedTask;
        };

        // Force the second fill to observe a cache miss; G1 is still in the repo's own
        // _fillGuards map (nothing has retired it yet), so GuardFor hands back the SAME instance.
        wrappedCache.Remove(cacheKey);
        await repo.ListAsync(orgId);

        // Killer assertion: entry 2 — installed by the racing fill, bound to the same G1 the hook
        // cancelled mid-read — must not survive; MemoryCache installs it as expired-on-insert.
        Assert.False(wrappedCache.TryGetValue(cacheKey, out _));
    }

    private sealed class ThrowingAfterGuardStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException(
                "Simulates a cancelled/refused/exhausted DB open after ListAsync has already minted the fill guard.");
    }
}
