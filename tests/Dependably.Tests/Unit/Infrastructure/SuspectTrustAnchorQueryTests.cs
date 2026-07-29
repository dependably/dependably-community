using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Coverage for <see cref="TrustAnchorRepository.ListSuspectAsync"/> — the cross-tenant read
/// behind the system-admin integrity audit and the instance health count. Asserts the selection
/// (exactly the unregistered pairs, across every tenant), the projected fields, and the
/// write-only-material contract the whole trust-anchor API upholds.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SuspectTrustAnchorQueryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public SuspectTrustAnchorQueryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private TrustAnchorRepository NewRepo() => new(_fixture.Store, _clock);

    [Fact]
    public async Task ListSuspect_ReturnsOnlyUnregisteredPairs_AcrossEveryTenant()
    {
        var repo = NewRepo();
        string slugA = $"sus-a-{Guid.NewGuid():N}";
        string slugB = $"sus-b-{Guid.NewGuid():N}";
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, slugA);
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, slugB);

        // Org A: one registered pair, one unregistered.
        var okA = await repo.AddAsync(orgA, new NewTrustAnchor("rpm", "pgp", "PGPMAT", "FPR-A", "prod rpm", "u-a"));
        var badA = await repo.AddAsync(orgA, new NewTrustAnchor("npm", "pgp", "GARBAGE", "kid-a", "oops", "u-a"));

        // Org B: two registered pairs, one unregistered — the mixed shape a real instance has.
        var okB1 = await repo.AddAsync(orgB, new NewTrustAnchor("pypi", "sigstore_root", "PEM", "thumb-b", null, "u-b"));
        var okB2 = await repo.AddAsync(orgB, new NewTrustAnchor("apk", "rsa", "PEMRSA", "SHA256:b", null, "u-b"));
        var badB = await repo.AddAsync(orgB, new NewTrustAnchor("nuget", "rsa", "GARBAGE", null, null, null));

        var suspects = await repo.ListSuspectAsync();
        var mine = suspects.Where(s => s.OrgId == orgA || s.OrgId == orgB).ToList();

        Assert.Equal(2, mine.Count);
        Assert.Contains(mine, s => s.Id == badA.Id);
        Assert.Contains(mine, s => s.Id == badB.Id);
        Assert.DoesNotContain(mine, s => s.Id == okA.Id || s.Id == okB1.Id || s.Id == okB2.Id);
    }

    [Fact]
    public async Task ListSuspect_ProjectsEveryAuditField_IncludingTheJoinedOrgSlug()
    {
        var repo = NewRepo();
        string slug = $"sus-fields-{Guid.NewGuid():N}";
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, slug);

        var seeded = await repo.AddAsync(orgId, new NewTrustAnchor(
            Ecosystem: "maven",
            AnchorKind: "x509",
            Material: "GARBAGE",
            KeyId: "kid-42",
            Label: "pasted by mistake",
            CreatedBy: "operator-7"));

        var row = Assert.Single(await repo.ListSuspectAsync(), s => s.Id == seeded.Id);

        Assert.Equal(orgId, row.OrgId);
        Assert.Equal(slug, row.OrgSlug);
        Assert.Equal("maven", row.Ecosystem);
        Assert.Equal("x509", row.AnchorKind);
        Assert.Equal("kid-42", row.KeyId);
        Assert.Equal("pasted by mistake", row.Label);
        Assert.Equal("operator-7", row.CreatedBy);
        Assert.Equal(_clock.GetUtcNow(), row.CreatedAt);
    }

    /// <summary>
    /// The projection carries no material property at all, so there is no way for a caller — or a
    /// future serializer change — to leak key material through this surface.
    /// </summary>
    [Fact]
    public void SuspectTrustAnchor_HasNoMaterialProperty()
    {
        Assert.DoesNotContain(
            typeof(SuspectTrustAnchor).GetProperties(),
            p => p.Name.Contains("material", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ListSuspect_NeverSerializesMaterial_EvenWhenTheRowHoldsSecretLookingBytes()
    {
        var repo = NewRepo();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sus-mat-{Guid.NewGuid():N}");
        const string Sentinel = "SENTINEL-MATERIAL-MUST-NOT-LEAK";
        await repo.AddAsync(orgId, new NewTrustAnchor("npm", "x509", Sentinel, "kid", null, null));

        var rows = (await repo.ListSuspectAsync()).Where(s => s.OrgId == orgId).ToList();
        Assert.Single(rows);

        string json = System.Text.Json.JsonSerializer.Serialize(rows);
        Assert.DoesNotContain(Sentinel, json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListSuspect_SkipsSoftDeletedTenants()
    {
        var repo = NewRepo();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sus-del-{Guid.NewGuid():N}");
        await repo.AddAsync(orgId, new NewTrustAnchor("npm", "pgp", "GARBAGE", null, null, null));

        Assert.Contains(await repo.ListSuspectAsync(), s => s.OrgId == orgId);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @at WHERE id = @orgId",
                new { at = _clock.GetUtcNow().ToUtcIso(), orgId });
        }

        Assert.DoesNotContain(await repo.ListSuspectAsync(), s => s.OrgId == orgId);
    }

    [Fact]
    public async Task CountSuspect_MatchesTheListLength()
    {
        var repo = NewRepo();
        int before = await repo.CountSuspectAsync();

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sus-count-{Guid.NewGuid():N}");
        await repo.AddAsync(orgId, new NewTrustAnchor("npm", "pgp", "GARBAGE", null, null, null));
        await repo.AddAsync(orgId, new NewTrustAnchor("apk", "spki", "GARBAGE", null, null, null));
        await repo.AddAsync(orgId, new NewTrustAnchor("apk", "rsa", "PEMRSA", null, null, null));

        Assert.Equal(before + 2, await repo.CountSuspectAsync());
        Assert.Equal((await repo.ListSuspectAsync()).Count, await repo.CountSuspectAsync());
    }

    // ── The per-row flag on the tenant-facing list ─────────────────────────────

    [Fact]
    public async Task ListAsync_FlagsUnregisteredPairs_AndLeavesRegisteredOnesAlone()
    {
        var repo = NewRepo();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sus-flag-{Guid.NewGuid():N}");
        var ok = await repo.AddAsync(orgId, new NewTrustAnchor("nuget", "x509", "PEM", "thumb", null, null));
        var bad = await repo.AddAsync(orgId, new NewTrustAnchor("nuget", "spki", "GARBAGE", null, null, null));

        var entries = await repo.ListAsync(orgId);

        Assert.True(Assert.Single(entries, e => e.Id == ok.Id).IsRegisteredPair);
        Assert.False(Assert.Single(entries, e => e.Id == bad.Id).IsRegisteredPair);
    }
}
