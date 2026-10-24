using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The last-active system admin guard holds when two operators act at the same moment. The race
/// is made deterministic by <see cref="LockstepOpenStore"/>: a guard that counts on one connection
/// and writes on another lets both requests count before either writes, so both see one other
/// active admin and both succeed. The guard has to be atomic with the write for exactly one of
/// the pair to win.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemAdminLastActiveRaceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _store = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_store).InitializeAsync();

    public async Task DisposeAsync() => await _store.DisposeAsync();

    [Theory]
    [InlineData("disabled", "disabled")]
    [InlineData("locked", "locked")]
    [InlineData("disabled", "locked")]
    public async Task MutualStatusChange_OfTheLastTwoActiveAdmins_LeavesExactlyOneActive(
        string statusForB, string statusForA)
    {
        string a = await SystemAdminSeeder.InsertAsync(_store, $"a-{Guid.NewGuid():N}@x.test");
        string b = await SystemAdminSeeder.InsertAsync(_store, $"b-{Guid.NewGuid():N}@x.test");

        var (byA, byB) = await LastActiveAdminRace.MutualAsync(_store, a, b, statusForB, statusForA);

        int[] statuses = [byA.Status, byB.Status];
        Assert.Single(statuses, s => s == StatusCodes.Status204NoContent);
        var refused = Assert.Single(new[] { byA, byB }, r => r.Status == StatusCodes.Status409Conflict);
        Assert.Equal("last_active_admin", refused.Reason);

        var active = await LastActiveAdminRace.ActiveIdsAsync(_store);
        string survivor = Assert.Single(active);
        // The admin whose request succeeded is the one left standing.
        Assert.Equal(byA.Status == StatusCodes.Status204NoContent ? a : b, survivor);
    }

    [Fact]
    public async Task MutualDisable_WithAThirdActiveAdmin_BothSucceed()
    {
        // Mixed scenario: the guard refuses only the change that would empty the active set. With
        // a third admin active, both concurrent disables are legitimate and both land.
        string a = await SystemAdminSeeder.InsertAsync(_store, $"a-{Guid.NewGuid():N}@x.test");
        string b = await SystemAdminSeeder.InsertAsync(_store, $"b-{Guid.NewGuid():N}@x.test");
        string c = await SystemAdminSeeder.InsertAsync(_store, $"c-{Guid.NewGuid():N}@x.test");

        var (byA, byB) = await LastActiveAdminRace.MutualAsync(_store, a, b, "disabled", "disabled");

        Assert.Equal(StatusCodes.Status204NoContent, byA.Status);
        Assert.Equal(StatusCodes.Status204NoContent, byB.Status);
        Assert.Equal([c], await LastActiveAdminRace.ActiveIdsAsync(_store));
    }

    [Fact]
    public async Task ConcurrentReactivationAndDisable_NeitherIsRefused()
    {
        // B is disabled. A re-activates B while C disables A at the same moment. C's change
        // leaves C active either way, and the re-activation only raises the count, so neither
        // change may be refused, whichever commits first.
        string a = await SystemAdminSeeder.InsertAsync(_store, $"a-{Guid.NewGuid():N}@x.test");
        string b = await SystemAdminSeeder.InsertAsync(_store, $"b-{Guid.NewGuid():N}@x.test");
        string c = await SystemAdminSeeder.InsertAsync(_store, $"c-{Guid.NewGuid():N}@x.test");
        await using (var conn = await _store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE system_admins SET account_status = 'disabled' WHERE id = @b", new { b });
        }

        var lockstep = new LockstepOpenStore(_store);
        var byA = LastActiveAdminRace.Controller(lockstep, _store, actorId: a);
        var byC = LastActiveAdminRace.Controller(lockstep, _store, actorId: c);
        var results = await Task.WhenAll(
            lockstep.RunAsAsync(0, () => byA.SetAdminAccountStatus(
                b, new Dependably.Api.SetAdminAccountStatusRequest("active"), CancellationToken.None)),
            lockstep.RunAsAsync(1, () => byC.SetAdminAccountStatus(
                a, new Dependably.Api.SetAdminAccountStatusRequest("disabled"), CancellationToken.None)));

        Assert.All(results, r => Assert.Equal(StatusCodes.Status204NoContent, LastActiveAdminRace.Describe(r).Status));
        var active = await LastActiveAdminRace.ActiveIdsAsync(_store);
        Assert.Equal(new[] { b, c }.Order(), active.Order());
    }

    [Fact]
    public async Task DeleteAdmin_TargetReactivatedAfterTheControllerRead_DeletesNothing()
    {
        // Delete path: the controller reads the target as disabled, then another operator
        // re-activates it before the delete runs. The disabled condition lives in the DELETE
        // itself, so the now-active admin is not removed and the active count never drops.
        string actor = await SystemAdminSeeder.InsertAsync(_store, $"actor-{Guid.NewGuid():N}@x.test");
        string target = await SystemAdminSeeder.InsertAsync(_store, $"target-{Guid.NewGuid():N}@x.test");
        var direct = LastActiveAdminRace.Controller(_store, _store, actorId: actor);
        Assert.Equal(StatusCodes.Status204NoContent, LastActiveAdminRace.Describe(await direct.SetAdminAccountStatus(
            target, new Dependably.Api.SetAdminAccountStatusRequest("disabled"), CancellationToken.None)).Status);

        var hooked = new AfterDbReadHookStore(_store);
        var deleting = LastActiveAdminRace.Controller(hooked, _store, actorId: actor);
        hooked.AfterRead = async () =>
        {
            await using var conn = await _store.OpenAsync();
            await conn.ExecuteAsync(
                "UPDATE system_admins SET account_status = 'active' WHERE id = @target", new { target });
        };

        var response = LastActiveAdminRace.Describe(await deleting.DeleteAdmin(target, CancellationToken.None));

        Assert.Equal(StatusCodes.Status404NotFound, response.Status);
        var active = await LastActiveAdminRace.ActiveIdsAsync(_store);
        Assert.Equal(new[] { actor, target }.Order(), active.Order());
    }
}
