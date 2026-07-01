using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class TrustAnchorRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TrustAnchorRepositoryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private TrustAnchorRepository NewRepo() => new(_fixture.Store, TimeProvider.System);

    // ── Add / List ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Add_PersistsRow_ListReturnsWithoutMaterial()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();

        var entry = await repo.AddAsync(org, new NewTrustAnchor(
            Ecosystem: "rpm",
            AnchorKind: "pgp",
            Material: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END PGP PUBLIC KEY BLOCK-----",
            KeyId: "AABBCCDD",
            Label: "Test key",
            CreatedBy: "user-1"));

        Assert.NotEmpty(entry.Id);
        Assert.Equal(org, entry.OrgId);
        Assert.Equal("rpm", entry.Ecosystem);
        Assert.Equal("pgp", entry.AnchorKind);
        Assert.Equal("AABBCCDD", entry.KeyId);
        Assert.Equal("Test key", entry.Label);
        Assert.Equal("user-1", entry.CreatedBy);

        // List returns the row without material.
        var listed = await repo.ListAsync(org);
        var found = Assert.Single(listed);
        Assert.Equal(entry.Id, found.Id);
        Assert.Equal("rpm", found.Ecosystem);
        Assert.Equal("pgp", found.AnchorKind);
        Assert.Equal("AABBCCDD", found.KeyId);
    }

    [Fact]
    public async Task ListForEcosystem_ReturnsMatchingRows_WithMaterial()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();

        await repo.AddAsync(org, new NewTrustAnchor("rpm", "pgp", "KEY1", null, "label1", null));
        await repo.AddAsync(org, new NewTrustAnchor("npm", "spki", "SPKI1", null, "npm-key", null));

        var rpmRows = await repo.ListForEcosystemAsync(org, "rpm");
        Assert.Single(rpmRows);
        Assert.Equal("KEY1", rpmRows[0].Material);
        Assert.Equal("pgp", rpmRows[0].AnchorKind);

        var npmRows = await repo.ListForEcosystemAsync(org, "npm");
        Assert.Single(npmRows);
        Assert.Equal("SPKI1", npmRows[0].Material);

        // nuget has no rows.
        Assert.Empty(await repo.ListForEcosystemAsync(org, "nuget"));
    }

    [Fact]
    public async Task AnyAsync_ReturnsTrueWhenRowExists_FalseOtherwise()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();

        Assert.False(await repo.AnyAsync(org, "maven"));
        await repo.AddAsync(org, new NewTrustAnchor("maven", "pgp", "MAVENKEY", null, null, null));
        Assert.True(await repo.AnyAsync(org, "maven"));
        // Different ecosystem stays false.
        Assert.False(await repo.AnyAsync(org, "npm"));
    }

    // ── Org isolation ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ListAsync_IsOrgScoped_NeverLeaksAcrossOrgs()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        var repo = NewRepo();

        await repo.AddAsync(orgA, new NewTrustAnchor("rpm", "pgp", "KEYA", null, null, null));
        await repo.AddAsync(orgB, new NewTrustAnchor("rpm", "pgp", "KEYB", null, null, null));

        var aList = await repo.ListAsync(orgA);
        var bList = await repo.ListAsync(orgB);

        Assert.All(aList, e => Assert.Equal(orgA, e.OrgId));
        Assert.All(bList, e => Assert.Equal(orgB, e.OrgId));
        Assert.Single(aList);
        Assert.Single(bList);
    }

    // ── Delete / BOLA safety ──────────────────────────────────────────────────

    [Fact]
    public async Task Delete_IsOrgScoped_CrossOrgDeleteIsNoOp()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        var repo = NewRepo();

        var entry = await repo.AddAsync(orgA, new NewTrustAnchor("rpm", "pgp", "ORGAKEY", null, null, null));

        // orgB attempting to delete orgA's anchor must not remove it (BOLA-safe).
        await repo.DeleteAsync(orgB, entry.Id);
        Assert.Single(await repo.ListAsync(orgA));

        // Correct owner deletes successfully; repeat is a safe no-op.
        await repo.DeleteAsync(orgA, entry.Id);
        await repo.DeleteAsync(orgA, entry.Id);
        Assert.Empty(await repo.ListAsync(orgA));
    }

    // ── Multiple anchors per ecosystem ─────────────────────────────────────────

    [Fact]
    public async Task MultipleAnchors_SameEcosystem_AllReturned()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = NewRepo();

        await repo.AddAsync(org, new NewTrustAnchor("maven", "pgp", "KEY1", "AAAA", "Project key", null));
        await repo.AddAsync(org, new NewTrustAnchor("maven", "pgp", "KEY2", "BBBB", "Mirror key", null));

        var rows = await repo.ListAsync(org);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal("maven", r.Ecosystem));

        var materials = await repo.ListForEcosystemAsync(org, "maven");
        Assert.Equal(2, materials.Count);
    }

    // ── Mixed partial-failure scenario ─────────────────────────────────────────

    /// <summary>
    /// OrgA adds a RPM and an NPM key (both succeed). OrgB adds a RPM key (succeeds).
    /// OrgA deletes its RPM key — NPM key and OrgB's RPM key are unaffected.
    /// This ensures cross-org and cross-ecosystem partial mutations don't corrupt state.
    /// </summary>
    [Fact]
    public async Task PartialMutation_DeleteOneKey_OtherKeysAndOrgsUnaffected()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        var repo = NewRepo();

        var aRpm = await repo.AddAsync(orgA, new NewTrustAnchor("rpm", "pgp", "A_RPM_KEY", null, null, null));
        var aNpm = await repo.AddAsync(orgA, new NewTrustAnchor("npm", "spki", "A_NPM_KEY", null, null, null));
        var bRpm = await repo.AddAsync(orgB, new NewTrustAnchor("rpm", "pgp", "B_RPM_KEY", null, null, null));

        // OrgA deletes its RPM key.
        await repo.DeleteAsync(orgA, aRpm.Id);

        // OrgA's NPM key survives.
        var aList = await repo.ListAsync(orgA);
        Assert.Single(aList);
        Assert.Equal(aNpm.Id, aList[0].Id);

        // OrgB's RPM key is completely unaffected.
        var bList = await repo.ListAsync(orgB);
        Assert.Single(bList);
        Assert.Equal(bRpm.Id, bList[0].Id);

        // AnyAsync reflects the deletion correctly.
        Assert.False(await repo.AnyAsync(orgA, "rpm"));
        Assert.True(await repo.AnyAsync(orgA, "npm"));
        Assert.True(await repo.AnyAsync(orgB, "rpm"));
    }
}
