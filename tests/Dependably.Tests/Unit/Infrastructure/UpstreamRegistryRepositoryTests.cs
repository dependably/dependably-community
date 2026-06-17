using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class UpstreamRegistryRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public UpstreamRegistryRepositoryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private UpstreamRegistryRepository NewRepo() => new(_fixture.Store, TimeProvider.System);

    [Fact]
    public async Task Add_AppendsInPriorityOrder_AndListFiltersByOrg()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        var repo = NewRepo();

        var first = await repo.AddAsync(orgA, "pypi", "https://pypi.org", null);
        var second = await repo.AddAsync(orgA, "pypi", "https://mirror.example/pypi", "mirror");
        await repo.AddAsync(orgB, "pypi", "https://should-not-leak.example", null);

        var urls = await repo.ListUrlsForEcosystemAsync(orgA, "pypi");
        Assert.Equal(["https://pypi.org", "https://mirror.example/pypi"], urls);
        Assert.True(first.Position < second.Position);

        // Org isolation — orgA never sees orgB's entry.
        var all = await repo.ListAsync(orgA);
        Assert.All(all, e => Assert.Equal(orgA, e.OrgId));
    }

    [Fact]
    public async Task ListUrls_IsScopedPerEcosystem()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();
        await repo.AddAsync(org, "pypi", "https://pypi.org", null);
        await repo.AddAsync(org, "npm", "https://registry.npmjs.org", null);

        Assert.Equal(["https://pypi.org"], await repo.ListUrlsForEcosystemAsync(org, "pypi"));
        Assert.Equal(["https://registry.npmjs.org"], await repo.ListUrlsForEcosystemAsync(org, "npm"));
        Assert.Empty(await repo.ListUrlsForEcosystemAsync(org, "nuget"));
    }

    [Fact]
    public async Task Reorder_RewritesPositions_InRequestedOrder()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();
        var a = await repo.AddAsync(org, "npm", "https://a.example", null);
        var b = await repo.AddAsync(org, "npm", "https://b.example", null);
        var c = await repo.AddAsync(org, "npm", "https://c.example", null);

        await repo.ReorderAsync(org, "npm", [c.Id, a.Id, b.Id]);

        Assert.Equal(
            ["https://c.example", "https://a.example", "https://b.example"],
            await repo.ListUrlsForEcosystemAsync(org, "npm"));
    }

    [Fact]
    public async Task Reorder_PartialList_KeepsOmittedEntriesAfterSuppliedOnes()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();
        _ = await repo.AddAsync(org, "npm", "https://a.example", null);
        _ = await repo.AddAsync(org, "npm", "https://b.example", null);
        var c = await repo.AddAsync(org, "npm", "https://c.example", null);

        // Only name c — a and b should retain their relative order after c.
        await repo.ReorderAsync(org, "npm", [c.Id]);

        var urls = await repo.ListUrlsForEcosystemAsync(org, "npm");
        Assert.Equal("https://c.example", urls[0]);
        Assert.Contains("https://a.example", urls);
        Assert.Contains("https://b.example", urls);
        Assert.Equal(3, urls.Count);
    }

    [Fact]
    public async Task Delete_IsOrgScoped_CrossOrgDeleteIsNoOp()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        var repo = NewRepo();
        var entry = await repo.AddAsync(orgA, "maven", "https://repo1.maven.org/maven2", null);

        // orgB attempting to delete orgA's entry must not remove it (BOLA-safe).
        await repo.DeleteAsync(orgB, entry.Id);
        Assert.Single(await repo.ListUrlsForEcosystemAsync(orgA, "maven"));

        // Correct owner deletes successfully; repeat is a safe no-op.
        await repo.DeleteAsync(orgA, entry.Id);
        await repo.DeleteAsync(orgA, entry.Id);
        Assert.Empty(await repo.ListUrlsForEcosystemAsync(orgA, "maven"));
    }

    [Fact]
    public async Task Add_DuplicateUrlForEcosystem_IsIgnored()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();
        await repo.AddAsync(org, "pypi", "https://pypi.org", null);
        await repo.AddAsync(org, "pypi", "https://pypi.org", "dup");

        Assert.Single(await repo.ListUrlsForEcosystemAsync(org, "pypi"));
    }
}
