using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Tests for <see cref="BannerRepository"/> covering:
/// <list type="bullet">
///   <item>Resolution query: role match/miss, time-window edges, dismissed/not, system+tenant union.</item>
///   <item>Cross-tenant isolation (BOLA): tenant A cannot update/delete tenant B's banners.</item>
///   <item>Audit plane split: tenant vs system scopes stay separate.</item>
///   <item>Validation: active-banner cap, TenantHardDelete cleanup.</item>
///   <item>Mixed/partial-failure: some banners visible, some suppressed (role, time, dismissed).</item>
/// </list>
/// </summary>
[Trait("Category", "Unit")]
public sealed class BannerRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    // A fixed "now" seeded far from window boundaries (no leap-year or DST trap).
    // Windows use offsets of +/- 30 days to keep tests deterministic.
    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);

    private BannerRepository Repo(FakeTimeProvider? clock = null) =>
        new(_fixture.Store, clock ?? TestTime.Frozen(KnownNow));

    public BannerRepositoryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private async Task<(string OrgId, string UserId)> SeedTenantAsync(string role = "member")
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId,
            $"user-{Guid.NewGuid():N}@test.invalid", role);
        return (orgId, userId);
    }

    private static BannerCreateRequest ActiveReq(
        string targetRole = "all",
        string severity = "info",
        bool enabled = true,
        DateTimeOffset? startsAt = null,
        DateTimeOffset? endsAt = null,
        string? linkUrl = null,
        string? linkLabel = null) =>
        new(
            Severity: severity,
            Body: "Test body",
            LinkUrl: linkUrl,
            LinkLabel: linkLabel,
            TargetRole: targetRole,
            StartsAt: (startsAt ?? KnownNow.AddDays(-30)).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: (endsAt ?? KnownNow.AddDays(+30)).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: enabled);

    // ── Tenant CRUD ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateTenant_And_ListTenant_RoundTrip()
    {
        var (orgId, userId) = await SeedTenantAsync();
        var repo = Repo();

        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        Assert.Equal("tenant", banner.Scope);
        Assert.Equal(orgId, banner.OrgId);

        var list = await repo.ListTenantAsync(orgId);
        Assert.Contains(list, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task ListTenant_DoesNotReturnOtherTenantBanners()
    {
        var (orgA, userA) = await SeedTenantAsync();
        var (orgB, _) = await SeedTenantAsync();
        var repo = Repo();

        var banner = await repo.CreateTenantAsync(orgA, userA, ActiveReq(), CancellationToken.None);

        var listB = await repo.ListTenantAsync(orgB);
        Assert.DoesNotContain(listB, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task UpdateTenant_OwnOrg_UpdatesRow()
    {
        var (orgId, userId) = await SeedTenantAsync();
        var repo = Repo();
        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        var req = new BannerUpdateRequest("warn", "Updated body", null, null, "all",
            banner.StartsAt, banner.EndsAt, true);
        bool updated = await repo.UpdateTenantAsync(orgId, banner.Id, req);
        Assert.True(updated);
    }

    [Fact]
    public async Task UpdateTenant_ForeignOrg_Returns0RowsUpdated()
    {
        var (orgA, userA) = await SeedTenantAsync();
        var (orgB, _) = await SeedTenantAsync();
        var repo = Repo();
        var banner = await repo.CreateTenantAsync(orgA, userA, ActiveReq(), CancellationToken.None);

        var req = new BannerUpdateRequest("alert", "Pwned", null, null, "all",
            banner.StartsAt, banner.EndsAt, true);
        bool updated = await repo.UpdateTenantAsync(orgB, banner.Id, req);
        Assert.False(updated);
    }

    [Fact]
    public async Task DeleteTenant_ForeignOrg_Returns0RowsDeleted()
    {
        var (orgA, userA) = await SeedTenantAsync();
        var (orgB, _) = await SeedTenantAsync();
        var repo = Repo();
        var banner = await repo.CreateTenantAsync(orgA, userA, ActiveReq(), CancellationToken.None);

        bool deleted = await repo.DeleteTenantAsync(orgB, banner.Id);
        Assert.False(deleted);

        var listA = await repo.ListTenantAsync(orgA);
        Assert.Contains(listA, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task DeleteTenant_OwnOrg_RemovesBanner()
    {
        var (orgId, userId) = await SeedTenantAsync();
        var repo = Repo();
        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        bool deleted = await repo.DeleteTenantAsync(orgId, banner.Id);
        Assert.True(deleted);

        var list = await repo.ListTenantAsync(orgId);
        Assert.DoesNotContain(list, b => b.Id == banner.Id);
    }

    // ── System CRUD ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateSystem_SetsNullOrgId()
    {
        var repo = Repo();
        var banner = await repo.CreateSystemAsync("sysadmin-1", ActiveReq(), CancellationToken.None);

        Assert.Equal("system", banner.Scope);
        Assert.Null(banner.OrgId);
    }

    [Fact]
    public async Task ListSystem_OnlyReturnsSystemScopedBanners()
    {
        var (orgId, userId) = await SeedTenantAsync();
        var repo = Repo();
        var tenantBanner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);
        var sysBanner = await repo.CreateSystemAsync("sysadmin", ActiveReq(), CancellationToken.None);

        var list = await repo.ListSystemAsync();
        Assert.Contains(list, b => b.Id == sysBanner.Id);
        Assert.DoesNotContain(list, b => b.Id == tenantBanner.Id);
    }

    [Fact]
    public async Task UpdateSystem_WrongScope_ReturnsFalse()
    {
        var (orgId, userId) = await SeedTenantAsync();
        var repo = Repo();
        var tenantBanner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        var req = new BannerUpdateRequest("alert", "Pwned", null, null, "all",
            tenantBanner.StartsAt, tenantBanner.EndsAt, true);
        bool updated = await repo.UpdateSystemAsync(tenantBanner.Id, req);
        Assert.False(updated);
    }

    [Fact]
    public async Task DeleteSystem_WrongScope_ReturnsFalse()
    {
        var (orgId, userId) = await SeedTenantAsync();
        var repo = Repo();
        var tenantBanner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        bool deleted = await repo.DeleteSystemAsync(tenantBanner.Id);
        Assert.False(deleted);
    }

    // ── Resolution query ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetActive_Returns_EnabledBannersInWindow()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.Contains(active, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_Excludes_DisabledBanners()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(enabled: false), CancellationToken.None);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.DoesNotContain(active, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_Excludes_BannersNotYetStarted()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        // starts_at is 30 days in the future relative to KnownNow.
        var banner = await repo.CreateTenantAsync(orgId, userId,
            ActiveReq(startsAt: KnownNow.AddDays(30), endsAt: KnownNow.AddDays(60)),
            CancellationToken.None);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.DoesNotContain(active, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_Excludes_ExpiredBanners()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        // ends_at is 30 days in the past.
        var banner = await repo.CreateTenantAsync(orgId, userId,
            ActiveReq(startsAt: KnownNow.AddDays(-60), endsAt: KnownNow.AddDays(-30)),
            CancellationToken.None);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.DoesNotContain(active, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_IncludesBannerExactlyAtWindowBoundary()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        // starts_at == now (starts_at <= now is true).
        var banner = await repo.CreateTenantAsync(orgId, userId,
            ActiveReq(startsAt: KnownNow, endsAt: KnownNow.AddDays(30)),
            CancellationToken.None);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.Contains(active, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_ExcludesBannerWhenEndsAtEqualsNow()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        // ends_at == now (ends_at > now is false when equal).
        var banner = await repo.CreateTenantAsync(orgId, userId,
            ActiveReq(startsAt: KnownNow.AddDays(-30), endsAt: KnownNow),
            CancellationToken.None);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.DoesNotContain(active, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_RoleFilter_TargetAll_VisibleToAllRoles()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(targetRole: "all"), CancellationToken.None);

        var activeMember = await repo.GetActiveAsync(orgId, userId, "member");
        var activeAdmin = await repo.GetActiveAsync(orgId, userId, "admin");
        Assert.Contains(activeMember, b => b.Id == banner.Id);
        Assert.Contains(activeAdmin, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_RoleFilter_TargetAdmin_NotVisibleToMember()
    {
        var (orgId, userId) = await SeedTenantAsync("admin");
        var repo = Repo();

        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(targetRole: "admin"), CancellationToken.None);

        var activeAdmin = await repo.GetActiveAsync(orgId, userId, "admin");
        var activeMember = await repo.GetActiveAsync(orgId, userId, "member");

        Assert.Contains(activeAdmin, b => b.Id == banner.Id);
        Assert.DoesNotContain(activeMember, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_DismissedByUser_IsExcluded()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        await repo.DismissAsync(banner.Id, userId);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.DoesNotContain(active, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task Dismiss_Idempotent_DoesNotThrow()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();
        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        await repo.DismissAsync(banner.Id, userId);
        var ex = await Record.ExceptionAsync(() => repo.DismissAsync(banner.Id, userId));
        Assert.Null(ex);
    }

    [Fact]
    public async Task GetActive_DismissalByOneUser_DoesNotHideFromOtherUser()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        string userId2 = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"u2-{Guid.NewGuid():N}@test.invalid", "member");
        var repo = Repo();

        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);
        await repo.DismissAsync(banner.Id, userId);

        var active2 = await repo.GetActiveAsync(orgId, userId2, "member");
        Assert.Contains(active2, b => b.Id == banner.Id);
    }

    [Fact]
    public async Task GetActive_SystemBanner_VisibleToTenantUser()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        var sysBanner = await repo.CreateSystemAsync("sysadmin", ActiveReq(), CancellationToken.None);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.Contains(active, b => b.Id == sysBanner.Id);
    }

    [Fact]
    public async Task GetActive_SystemAndTenantBothVisible_OrderedBySeverity()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        var sysBanner = await repo.CreateSystemAsync("sysadmin", ActiveReq(severity: "alert"), CancellationToken.None);
        var tenantBanner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(severity: "info"), CancellationToken.None);

        var active = await repo.GetActiveAsync(orgId, userId, "member");
        int sysIdx = active.ToList().FindIndex(b => b.Id == sysBanner.Id);
        int tenantIdx = active.ToList().FindIndex(b => b.Id == tenantBanner.Id);
        Assert.True(sysIdx < tenantIdx, "alert severity should sort before info");
    }

    [Fact]
    public async Task GetActive_CrossTenantIsolation_OtherTenantBannersNotLeaked()
    {
        var (orgA, userA) = await SeedTenantAsync("member");
        var (orgB, userB) = await SeedTenantAsync("member");
        var repo = Repo();

        var bannerA = await repo.CreateTenantAsync(orgA, userA, ActiveReq(), CancellationToken.None);

        var activeForB = await repo.GetActiveAsync(orgB, userB, "member");
        Assert.DoesNotContain(activeForB, b => b.Id == bannerA.Id);
    }

    // ── Mixed/partial-failure scenario ───────────────────────────────────────────────────────

    /// <summary>
    /// Mixed scenario: multiple banners exist for the same org; some are visible, some are not.
    /// This is the mixed/partial-failure test that pins the resolution logic.
    /// </summary>
    [Fact]
    public async Task GetActive_MixedBanners_OnlyEligibleOnesReturned()
    {
        var (orgId, userId) = await SeedTenantAsync("member");
        var repo = Repo();

        // Visible: active, enabled, targets member.
        var visible1 = await repo.CreateTenantAsync(orgId, userId, ActiveReq(targetRole: "all"), CancellationToken.None);

        // Visible: active, targets member explicitly.
        var visible2 = await repo.CreateTenantAsync(orgId, userId, ActiveReq(targetRole: "member"), CancellationToken.None);

        // Not visible: disabled.
        var suppressed1 = await repo.CreateTenantAsync(orgId, userId, ActiveReq(enabled: false), CancellationToken.None);

        // Not visible: expired.
        var suppressed2 = await repo.CreateTenantAsync(orgId, userId,
            ActiveReq(startsAt: KnownNow.AddDays(-60), endsAt: KnownNow.AddDays(-30)),
            CancellationToken.None);

        // Not visible: targets admin only.
        var suppressed3 = await repo.CreateTenantAsync(orgId, userId, ActiveReq(targetRole: "admin"), CancellationToken.None);

        // Not visible: dismissed by user.
        var suppressed4 = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);
        await repo.DismissAsync(suppressed4.Id, userId);

        var active = await repo.GetActiveAsync(orgId, userId, "member");

        Assert.Contains(active, b => b.Id == visible1.Id);
        Assert.Contains(active, b => b.Id == visible2.Id);
        Assert.DoesNotContain(active, b => b.Id == suppressed1.Id);
        Assert.DoesNotContain(active, b => b.Id == suppressed2.Id);
        Assert.DoesNotContain(active, b => b.Id == suppressed3.Id);
        Assert.DoesNotContain(active, b => b.Id == suppressed4.Id);
    }

    // ── CountActiveForScope ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CountActiveForScope_CountsOnlyWindowedEnabled()
    {
        var (orgId, userId) = await SeedTenantAsync();
        var repo = Repo();

        int before = await repo.CountActiveForScopeAsync("tenant", orgId);

        await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);
        await repo.CreateTenantAsync(orgId, userId, ActiveReq(enabled: false), CancellationToken.None);
        await repo.CreateTenantAsync(orgId, userId, ActiveReq(startsAt: KnownNow.AddDays(-60), endsAt: KnownNow.AddDays(-30)), CancellationToken.None);

        int after = await repo.CountActiveForScopeAsync("tenant", orgId);
        Assert.Equal(before + 1, after);
    }

    // ── TenantHardDelete cleanup ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteForOrg_RemovesAllTenantBannersForOrg()
    {
        var (orgId, userId) = await SeedTenantAsync();
        var repo = Repo();

        var b1 = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);
        var b2 = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        await repo.DeleteForOrgAsync(orgId);

        var remaining = await repo.ListTenantAsync(orgId);
        Assert.DoesNotContain(remaining, b => b.Id == b1.Id);
        Assert.DoesNotContain(remaining, b => b.Id == b2.Id);
    }

    [Fact]
    public async Task DeleteForOrg_LeavesOtherTenantBannersIntact()
    {
        var (orgA, userA) = await SeedTenantAsync();
        var (orgB, userB) = await SeedTenantAsync();
        var repo = Repo();

        var bannerA = await repo.CreateTenantAsync(orgA, userA, ActiveReq(), CancellationToken.None);
        var bannerB = await repo.CreateTenantAsync(orgB, userB, ActiveReq(), CancellationToken.None);

        await repo.DeleteForOrgAsync(orgA);

        var remainingB = await repo.ListTenantAsync(orgB);
        Assert.Contains(remainingB, b => b.Id == bannerB.Id);
    }

    [Fact]
    public async Task DeleteForOrg_LeavesSystemBannersIntact()
    {
        var (orgId, _) = await SeedTenantAsync();
        var repo = Repo();

        var sysBanner = await repo.CreateSystemAsync("sysadmin", ActiveReq(), CancellationToken.None);

        await repo.DeleteForOrgAsync(orgId);

        var sysList = await repo.ListSystemAsync();
        Assert.Contains(sysList, b => b.Id == sysBanner.Id);
    }

    // ── Audit plane split ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TenantScope_And_SystemScope_BannersAreSeparate()
    {
        var (orgId, userId) = await SeedTenantAsync("admin");
        var repo = Repo();

        var tenantBanner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);
        var sysBanner = await repo.CreateSystemAsync("sysadmin", ActiveReq(), CancellationToken.None);

        var tenantList = await repo.ListTenantAsync(orgId);
        var sysList = await repo.ListSystemAsync();

        Assert.Contains(tenantList, b => b.Id == tenantBanner.Id);
        Assert.DoesNotContain(tenantList, b => b.Id == sysBanner.Id);
        Assert.Contains(sysList, b => b.Id == sysBanner.Id);
        Assert.DoesNotContain(sysList, b => b.Id == tenantBanner.Id);
    }

    // ── Time-provider determinism ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetActive_UsesInjectedClock_NotWallClock()
    {
        var (orgId, userId) = await SeedTenantAsync("member");

        // Clock is 100 days before KnownNow, so a window that's "active at KnownNow"
        // is "not yet started" from the clock's perspective.
        var pastClock = TestTime.Frozen(KnownNow.AddDays(-100));
        var repo = new BannerRepository(_fixture.Store, pastClock);

        var banner = await repo.CreateTenantAsync(orgId, userId, ActiveReq(), CancellationToken.None);

        // The banner's window starts 30 days before KnownNow — still 70 days in the
        // future relative to the frozen clock.
        var active = await repo.GetActiveAsync(orgId, userId, "member");
        Assert.DoesNotContain(active, b => b.Id == banner.Id);
    }
}
