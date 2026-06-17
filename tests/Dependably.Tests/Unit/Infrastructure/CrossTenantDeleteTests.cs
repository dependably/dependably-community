using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Regression guard for the cross-tenant BOLA class: the allowlist / blocklist / invite
/// <c>DeleteAsync</c> methods are keyed on a GLOBAL primary key, so without an org_id predicate a
/// tenant admin could delete another tenant's row by supplying its id. Each repo now requires the
/// caller's org and the delete must affect 0 rows for a foreign id. These tests fail if the org
/// scope is ever dropped again.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CrossTenantDeleteTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public CrossTenantDeleteTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private async Task<(string OrgA, string OrgB)> TwoOrgsAsync()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        return (orgA, orgB);
    }

    [Fact]
    public async Task Allowlist_DeleteWithForeignOrg_RemovesNothing_OwnOrgRemoves()
    {
        var (orgA, orgB) = await TwoOrgsAsync();
        var repo = new AllowlistRepository(_fixture.Store, TimeProvider.System);
        var entry = await repo.AddAsync(orgA, "pkg:npm/owned-by-a");

        // Tenant B cannot delete tenant A's entry by id.
        Assert.Equal(0, await repo.DeleteAsync(orgB, entry.Id));
        Assert.Contains(await repo.ListAsync(orgA), e => e.Id == entry.Id);

        // The owning tenant can.
        Assert.Equal(1, await repo.DeleteAsync(orgA, entry.Id));
        Assert.DoesNotContain(await repo.ListAsync(orgA), e => e.Id == entry.Id);
    }

    [Fact]
    public async Task Blocklist_DeleteWithForeignOrg_RemovesNothing_OwnOrgRemoves()
    {
        var (orgA, orgB) = await TwoOrgsAsync();
        var repo = new BlocklistRepository(_fixture.Store, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var entry = await repo.AddAsync(orgA, "pkg:npm/blocked-by-a");

        Assert.Equal(0, await repo.DeleteAsync(orgB, entry.Id));
        Assert.Contains(await repo.ListAsync(orgA), e => e.Id == entry.Id);

        Assert.Equal(1, await repo.DeleteAsync(orgA, entry.Id));
        Assert.DoesNotContain(await repo.ListAsync(orgA), e => e.Id == entry.Id);
    }

    [Fact]
    public async Task Invite_DeleteWithForeignOrg_RemovesNothing_OwnOrgRemoves()
    {
        var (orgA, orgB) = await TwoOrgsAsync();
        // invites.created_by is a NOT NULL FK to users(id), so seed a real inviter in org A.
        string inviter = await UserSeeder.InsertAsync(_fixture.Store, orgA, $"inviter-{Guid.NewGuid():N}@x.test", "admin");
        var repo = new InviteRepository(_fixture.Store, TimeProvider.System);
        var (_, invite) = await repo.CreateAsync(orgA, $"invitee-{Guid.NewGuid():N}@x.test", inviter);

        Assert.Equal(0, await repo.DeleteAsync(orgB, invite.Id));
        Assert.Contains(await repo.ListAsync(orgA), i => i.Id == invite.Id);

        Assert.Equal(1, await repo.DeleteAsync(orgA, invite.Id));
        Assert.DoesNotContain(await repo.ListAsync(orgA), i => i.Id == invite.Id);
    }
}
