using System.Data.Common;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Fill-after-invalidate race coverage for <see cref="ReservedNamespaceService"/>'s per-org read
/// cache — the same generation-token guard the sibling <c>BlocklistRepository</c> carries.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ReservedNamespaceServiceRaceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public ReservedNamespaceServiceRaceTests(InMemoryDbFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task AddThatRacesAnInFlightListFill_DoesNotServeThePreReservationListForATtl()
    {
        // IsReservedAsync reads the DB (no reservation yet); concurrently an operator reserves a
        // namespace, whose INSERT + cache-eviction lands mid-fill. On the pre-guard code the fill
        // caches the pre-reservation list AFTER the eviction, so a namespace just reserved can
        // still be claimed by a proxy fetch for a full 60s TTL. The hook fires the racing AddAsync
        // between the list read and its cache write — fails on the old code, passes on the fix.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rns-race-{Guid.NewGuid():N}");
        var hooked = new AfterDbReadHookStore(_fixture.Store);
        var sut = new ReservedNamespaceService(
            hooked, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);

        hooked.AfterRead = async () => await sut.AddAsync(orgId, "npm", "@acme/*", null);

        // The fill reads the empty list, then the hook reserves + evicts, then it caches.
        Assert.False(await sut.IsReservedAsync(orgId, "npm", "@acme/http-client")); // pre-reservation read

        // Killer assertion: the next check must enforce the reservation, not a stale pre-reservation
        // list cached by the racing fill.
        Assert.True(await sut.IsReservedAsync(orgId, "npm", "@acme/http-client"));
    }

    [Fact]
    public async Task DbOpenThrowsAfterGuardIsMinted_DoesNotRetainItsFillGuard()
    {
        // GuardFor mints the guard BEFORE the DB open/read. ReservedNamespaceService is registered
        // Singleton, so the guard map is process-lifetime — if the open or read throws with no
        // cache entry ever installed to tie the guard's lifetime to, the guard must not survive
        // the throw. Fails on the pre-fix code (no try/finally around the read), passes once the
        // throwing branch retires the just-minted guard.
        var sut = new ReservedNamespaceService(
            new ThrowingAfterGuardStore(), new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => sut.ListAsync($"org-{Guid.NewGuid():N}"));

        Assert.Equal(0, sut.FillGuardCount);
    }

    private sealed class ThrowingAfterGuardStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException(
                "Simulates a cancelled/refused/exhausted DB open after ListAsync has already " +
                "minted the fill guard.");
    }
}
