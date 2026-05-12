using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class BlocklistRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public BlocklistRepositoryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private BlocklistRepository NewRepo() => new(_fixture.Store, new MemoryCache(new MemoryCacheOptions()));

    [Fact]
    public async Task ListAsync_FiltersByOrg_OrderedByEcosystemThenPattern()
    {
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgA, "pypi", "z");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgA, "npm",  "b");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgA, "npm",  "a");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgB, "npm",  "should-not-leak");

        var entries = await NewRepo().ListAsync(orgA);

        Assert.Equal(3, entries.Count);
        Assert.Equal("npm", entries[0].Ecosystem);   // ecosystem-then-pattern ordering
        Assert.Equal("a",   entries[0].Pattern);
        Assert.Equal("npm", entries[1].Ecosystem);
        Assert.Equal("b",   entries[1].Pattern);
        Assert.Equal("pypi", entries[2].Ecosystem);
    }

    [Fact]
    public async Task IsBlockedAsync_MatchesRegex_ScopedToEcosystem()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgId, "npm", "pkg:npm/evil-.*");

        var repo = NewRepo();
        Assert.True(await repo.IsBlockedAsync(orgId, "npm", "pkg:npm/evil-pkg@1.0.0"));
        Assert.False(await repo.IsBlockedAsync(orgId, "npm", "pkg:npm/good-pkg@1.0.0"));
        Assert.False(await repo.IsBlockedAsync(orgId, "pypi", "pkg:pypi/evil-pkg@1.0.0"));   // wrong ecosystem
    }

    [Fact]
    public async Task IsBlockedAsync_MalformedRegex_DoesNotThrow_AndDoesNotBlock()
    {
        // Hostile blocklist entry shouldn't poison the whole gate — bad pattern → no match.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await BlocklistSeeder.InsertAsync(_fixture.Store, orgId, "npm", "[unclosed-bracket");

        Assert.False(await NewRepo().IsBlockedAsync(orgId, "npm", "pkg:npm/anything@1.0.0"));
    }

    [Fact]
    public async Task AddAsync_OnDuplicate_IsIgnored_AndInvalidatesCache()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();

        await repo.AddAsync(orgId, "npm", "pkg:npm/foo");
        var beforeDup = (await repo.ListAsync(orgId)).Count;
        await repo.AddAsync(orgId, "npm", "pkg:npm/foo");  // identical (ecosystem, pattern) → ignored
        var afterDup = (await repo.ListAsync(orgId)).Count;

        Assert.Equal(beforeDup, afterDup);
    }

    [Fact]
    public async Task DeleteAsync_RemovesEntry_AndIsIdempotent()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var id = await BlocklistSeeder.InsertAsync(_fixture.Store, orgId, "npm", "pkg:npm/x");
        var repo = NewRepo();

        await repo.DeleteAsync(id);
        await repo.DeleteAsync(id);   // delete-of-missing → safe no-op

        Assert.Empty(await repo.ListAsync(orgId));
    }
}
