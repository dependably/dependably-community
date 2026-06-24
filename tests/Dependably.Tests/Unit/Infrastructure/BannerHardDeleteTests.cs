using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Verifies that <see cref="TenantHardDeleteService"/> explicitly removes banner rows for a
/// hard-deleted tenant. Because <c>banners.org_id</c> carries no FK to <c>orgs</c>, the
/// DELETE FROM orgs cascade does not clean them up — the service must call
/// <c>BannerRepository.DeleteForOrgAsync</c> first.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BannerHardDeleteTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public BannerHardDeleteTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);

    private BannerRepository BannerRepo() => new(_fixture.Store, TestTime.Frozen(KnownNow));

    private static BannerCreateRequest ActiveReq() =>
        new("info", "Test body", null, null, "all",
            KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            KnownNow.AddDays(+30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            true);

    private TenantHardDeleteService BuildService(IMetadataStore db)
    {
        var clock = TestTime.Frozen(KnownNow);
        var orgs = new OrgRepository(db, null, clock);
        var audit = new AuditRepository(db, null, clock);
        var banners = new BannerRepository(db, clock);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TENANT_HARD_DELETE_GRACE_DAYS"] = "0"
            })
            .Build();
        return new TenantHardDeleteService(
            orgs, audit, db, banners, config,
            NullLogger<TenantHardDeleteService>.Instance,
            clock);
    }

    [Fact]
    public async Task HardDelete_RemovesBanners_ForDeletedOrg()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"del-org-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"u-{Guid.NewGuid():N}@test.invalid");
        var bannerRepo = BannerRepo();
        var banner = await bannerRepo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        // Soft-delete the org (set deleted_at in the past so grace period is elapsed).
        await using var conn0 = await _fixture.Store.OpenAsync();
        await conn0.ExecuteAsync(
            "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
            new { dt = KnownNow.AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ssZ"), id = orgId });

        // Confirm banner exists before hard-delete.
        var listBefore = await bannerRepo.ListTenantAsync(orgId);
        Assert.Contains(listBefore, b => b.Id == banner.Id);

        var svc = BuildService(_fixture.Store);
        await svc.RunPassAsync(CancellationToken.None);

        // The org row is gone (cascade path).
        await using var conn = await _fixture.Store.OpenAsync();
        int orgCount = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId });
        Assert.Equal(0, orgCount);

        // The banner row must also be gone (explicit BannerRepository.DeleteForOrgAsync path).
        int bannerCount = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM banners WHERE id = @id", new { id = banner.Id });
        Assert.Equal(0, bannerCount);
    }

    [Fact]
    public async Task HardDelete_OtherTenantBanners_AreNotAffected()
    {
        // Org A is deleted; org B is not.
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"del-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"keep-b-{Guid.NewGuid():N}");
        string userA = await UserSeeder.InsertAsync(_fixture.Store, orgA, $"ua-{Guid.NewGuid():N}@test.invalid");
        string userB = await UserSeeder.InsertAsync(_fixture.Store, orgB, $"ub-{Guid.NewGuid():N}@test.invalid");

        var bannerRepo = BannerRepo();
        var bannerA = await bannerRepo.CreateTenantAsync(orgA, userA, ActiveReq(), CancellationToken.None);
        var bannerB = await bannerRepo.CreateTenantAsync(orgB, userB, ActiveReq(), CancellationToken.None);

        await using var conn0 = await _fixture.Store.OpenAsync();
        await conn0.ExecuteAsync(
            "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
            new { dt = KnownNow.AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ssZ"), id = orgA });

        var svc = BuildService(_fixture.Store);
        await svc.RunPassAsync(CancellationToken.None);

        await using var conn = await _fixture.Store.OpenAsync();
        int countA = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM banners WHERE id = @id", new { id = bannerA.Id });
        int countB = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM banners WHERE id = @id", new { id = bannerB.Id });

        Assert.Equal(0, countA);
        Assert.Equal(1, countB);
    }
}
