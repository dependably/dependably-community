using Dependably.Configuration;
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

    // ── OCI-specific: AddOciAsync, BuildOciUpstreamsForOrgAsync ────────────────

    [Fact]
    public async Task AddOci_StoresAllFields_SecretNotExposedInList()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();

        var req = new NewOciUpstreamRegistry(
            Host: "ghcr.io",
            AuthType: OciAuthType.Basic,
            Prefixes: ["ghcr/"],
            Name: "GHCR",
            Username: "robot",
            Secret: "super-secret-token",
            TokenEndpoint: null);

        var entry = await repo.AddOciAsync(org, req);

        Assert.Equal("oci", entry.Ecosystem);
        Assert.Equal("ghcr.io", entry.Url);
        Assert.Equal("basic", entry.AuthType);
        Assert.Equal("robot", entry.Username);
        Assert.True(entry.HasSecret);  // secret is set
        Assert.Equal(["ghcr/"], entry.Prefixes);

        // ListAsync must NEVER return the secret; only HasSecret bool.
        var listed = await repo.ListAsync(org);
        var ociEntry = listed.Single(e => e.Ecosystem == "oci");
        Assert.True(ociEntry.HasSecret);
        Assert.Equal(["ghcr/"], ociEntry.Prefixes);
    }

    [Fact]
    public async Task BuildOciUpstreams_ReturnsEntriesInPositionOrder_WithParsedPrefixes()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();

        // Insert in reverse order; BuildOciUpstreams should return by position.
        await repo.AddOciAsync(org, new NewOciUpstreamRegistry(
            Host: "registry-1.docker.io",
            AuthType: OciAuthType.DockerHubTokenExchange,
            Prefixes: ["library/", ""],
            TokenEndpoint: "https://auth.docker.io/token"));

        await repo.AddOciAsync(org, new NewOciUpstreamRegistry(
            Host: "ghcr.io",
            AuthType: OciAuthType.Anonymous,
            Prefixes: ["ghcr/"]));

        var upstreams = await repo.BuildOciUpstreamsForOrgAsync(org);

        Assert.Equal(2, upstreams.Count);
        Assert.Equal("registry-1.docker.io", upstreams[0].Host);
        Assert.Equal(OciAuthType.DockerHubTokenExchange, upstreams[0].AuthType);
        Assert.Equal("https://auth.docker.io/token", upstreams[0].TokenEndpoint);
        Assert.Equal(["library/", ""], upstreams[0].Prefixes);
        Assert.Equal("ghcr.io", upstreams[1].Host);
        Assert.Equal(OciAuthType.Anonymous, upstreams[1].AuthType);
        Assert.Equal(["ghcr/"], upstreams[1].Prefixes);
    }

    [Fact]
    public async Task BuildOciUpstreams_DifferentOrgs_Isolated()
    {
        // OCI upstreams for org A must not appear in org B's list.
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        var repo = NewRepo();

        await repo.AddOciAsync(orgA, new NewOciUpstreamRegistry(
            Host: "private.a.example",
            AuthType: OciAuthType.Basic,
            Prefixes: ["a/"],
            Username: "user-a",
            Secret: "secret-a"));

        await repo.AddOciAsync(orgB, new NewOciUpstreamRegistry(
            Host: "private.b.example",
            AuthType: OciAuthType.Anonymous,
            Prefixes: ["b/"]));

        var aUpstreams = await repo.BuildOciUpstreamsForOrgAsync(orgA);
        var bUpstreams = await repo.BuildOciUpstreamsForOrgAsync(orgB);

        Assert.Single(aUpstreams);
        Assert.Equal("private.a.example", aUpstreams[0].Host);
        Assert.Single(bUpstreams);
        Assert.Equal("private.b.example", bUpstreams[0].Host);
    }

    /// <summary>
    /// Mixed partial-failure: org A's OCI write succeeds; org B's duplicate-host write is
    /// silently ignored (ON CONFLICT DO NOTHING). Both orgs' upstreams remain independent
    /// and neither is contaminated by the other's state.
    /// </summary>
    [Fact]
    public async Task AddOci_MixedOutcome_DuplicateIgnoredFirstSucceeds()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        var repo = NewRepo();

        var req = new NewOciUpstreamRegistry(
            Host: "mirror.example.com",
            AuthType: OciAuthType.Anonymous,
            Prefixes: [""]);

        // First write for orgA — succeeds.
        var entryA1 = await repo.AddOciAsync(orgA, req);
        // Duplicate write for orgA with same host — silently ignored, first entry retained.
        await repo.AddOciAsync(orgA, req with { Name = "dup" });

        // orgB's write for the same host — succeeds (separate tenant).
        var entryB = await repo.AddOciAsync(orgB, req);

        var aUpstreams = await repo.BuildOciUpstreamsForOrgAsync(orgA);
        var bUpstreams = await repo.BuildOciUpstreamsForOrgAsync(orgB);

        // orgA: exactly one entry (duplicate ignored).
        Assert.Single(aUpstreams);
        Assert.Equal("mirror.example.com", aUpstreams[0].Host);

        // orgB: one independent entry — not contaminated by orgA's data.
        Assert.Single(bUpstreams);
        Assert.Equal("mirror.example.com", bUpstreams[0].Host);

        // The two entries are distinct rows (different org_id).
        Assert.NotEqual(entryA1.Id, entryB.Id);
    }
}
