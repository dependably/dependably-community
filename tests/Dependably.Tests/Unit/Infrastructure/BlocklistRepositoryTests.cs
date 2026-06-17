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
}
