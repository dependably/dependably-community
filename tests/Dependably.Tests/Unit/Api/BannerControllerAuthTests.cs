using System.Security.Claims;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Resources;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Verifies that <see cref="BannersController.GetActive"/> and
/// <see cref="BannersController.Dismiss"/> enforce org membership for ALL four tenant roles
/// and reject callers who are not members of the target tenant with 404 (BOLA invariant).
///
/// These endpoints require membership only — no capability comparison — so an auditor
/// (whose cap set is {read:audit, tokens:manage_own} and does NOT include read:packages)
/// must still receive 200/204, not 403.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BannerControllerAuthTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private string _orgId = null!;
    private string _otherOrgId = null!;
    private string _sharedBannerId = null!;
    private readonly Dictionary<string, string> _userIds = new();

    // A fixed "now" seeded far from window boundaries.
    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        _orgId = Guid.NewGuid().ToString("N");
        _otherOrgId = Guid.NewGuid().ToString("N");

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _orgId, slug = "test-org" });
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _otherOrgId, slug = "other-org" });

        foreach (string role in new[] { "member", "admin", "owner", "auditor" })
        {
            string uid = Guid.NewGuid().ToString("N");
            _userIds[role] = uid;
            await conn.ExecuteAsync(
                "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @tenant, @email, '', @role)",
                new { id = uid, tenant = _orgId, email = $"{role}@test.invalid", role });
        }

        // A user who belongs to a different org — must get 404 on our org's routes.
        string outsiderId = Guid.NewGuid().ToString("N");
        _userIds["outsider"] = outsiderId;
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @tenant, @email, '', @role)",
            new { id = outsiderId, tenant = _otherOrgId, email = "outsider@other.invalid", role = "owner" });

        // Seed a shared active banner so Dismiss tests can pass a real banner_id (FK enforced).
        _sharedBannerId = Guid.NewGuid().ToString("N");
        string createdAt = KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(
            """
            INSERT INTO banners (id, scope, org_id, severity, body, link_url, link_label,
                                 target_role, starts_at, ends_at, enabled, created_by, created_at)
            VALUES (@id, 'tenant', @orgId, 'info', 'Shared test banner', NULL, NULL,
                    'all', @starts, @ends, 1, @createdBy, @now)
            """,
            new
            {
                id = _sharedBannerId,
                orgId = _orgId,
                starts = KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ends = KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
                createdBy = _userIds["owner"],
                now = createdAt,
            });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private BannersController BuildController(string userId, string role)
    {
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "test-org");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim("sub", userId),
                new Claim("role", role),
                new Claim("tid", _orgId),
            ],
            authenticationType: "test"));
        return BuildControllerWithContext(http);
    }

    private BannersController BuildControllerForOutsider(string userId, string role)
    {
        // The route resolves to our primary org, but the JWT identifies a user in another org.
        // TenantContext is for the primary org; the claims carry the outsider's real org.
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "test-org");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim("sub", userId),
                new Claim("role", role),
                new Claim("tid", _otherOrgId),
            ],
            authenticationType: "test"));
        return BuildControllerWithContext(http);
    }

    private BannersController BuildControllerWithContext(DefaultHttpContext http)
    {
        var guard = new OrgAccessGuard(_db);
        var audit = new AuditRepository(_db);
        var banners = new BannerRepository(_db, TestTime.Frozen(KnownNow));
        var problems = new ProblemResults(new EchoLocalizer());

        return new BannersController(banners, guard, audit, problems)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    // ── GetActive: all four roles receive 200 ───────────────────────────────────────────────

    [Theory]
    [InlineData("member")]
    [InlineData("admin")]
    [InlineData("owner")]
    [InlineData("auditor")]
    public async Task GetActive_AllTenantRoles_Return200(string role)
    {
        var ctrl = BuildController(_userIds[role], role);
        var result = await ctrl.GetActive(CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    // ── GetActive: non-member receives 404 (BOLA invariant) ────────────────────────────────

    [Fact]
    public async Task GetActive_NonMember_Returns404_NotForbidden()
    {
        // The outsider holds a valid JWT but is not a member of the target org.
        var ctrl = BuildControllerForOutsider(_userIds["outsider"], "owner");
        var result = await ctrl.GetActive(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Dismiss: all four roles receive 204 ────────────────────────────────────────────────

    [Theory]
    [InlineData("member")]
    [InlineData("admin")]
    [InlineData("owner")]
    [InlineData("auditor")]
    public async Task Dismiss_AllTenantRoles_Return204(string role)
    {
        var ctrl = BuildController(_userIds[role], role);
        // Dismiss records the dismissal against a real banner. ON CONFLICT DO NOTHING makes
        // the call idempotent; each theory call uses the same shared banner so later calls
        // simply no-op on the existing row.
        var result = await ctrl.Dismiss(_sharedBannerId, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }

    // ── Dismiss: non-member receives 404 (BOLA invariant) ──────────────────────────────────

    [Fact]
    public async Task Dismiss_NonMember_Returns404_NotForbidden()
    {
        var ctrl = BuildControllerForOutsider(_userIds["outsider"], "owner");
        // The guard rejects non-members before touching BannerRepository.
        var result = await ctrl.Dismiss(_sharedBannerId, CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Mixed partial: auditor sees non-dismissed banners, skips dismissed ones ───────────

    [Fact]
    public async Task GetActive_Auditor_SeesBannersTargetingAuditor_NotDismissed()
    {
        // Seed one banner targeting "auditor" role and one already-dismissed by the auditor.
        var repo = new BannerRepository(_db, TestTime.Frozen(KnownNow));
        string userId = _userIds["auditor"];

        var visibleBanner = await repo.CreateTenantAsync(_orgId, userId, new BannerCreateRequest(
            Severity: "info",
            Body: "Auditor banner",
            LinkUrl: null,
            LinkLabel: null,
            TargetRole: "auditor",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true), CancellationToken.None);

        var dismissedBanner = await repo.CreateTenantAsync(_orgId, userId, new BannerCreateRequest(
            Severity: "warn",
            Body: "Already dismissed",
            LinkUrl: null,
            LinkLabel: null,
            TargetRole: "auditor",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true), CancellationToken.None);

        await repo.DismissAsync(dismissedBanner.Id, userId, CancellationToken.None);

        var ctrl = BuildController(userId, "auditor");
        var okResult = Assert.IsType<OkObjectResult>(await ctrl.GetActive(CancellationToken.None));

        var active = Assert.IsAssignableFrom<IEnumerable<Banner>>(okResult.Value);
        var activeList = active.ToList();

        Assert.Contains(activeList, b => b.Id == visibleBanner.Id);
        Assert.DoesNotContain(activeList, b => b.Id == dismissedBanner.Id);
    }

    // ── Dismiss: non-existent banner id returns 404 (FK-safe) ─────────────────────────────

    /// <summary>
    /// Regression: a made-up banner id must return 404, not 500 (previously the INSERT into
    /// banner_dismissals triggered an FK violation against the banners table).
    /// </summary>
    [Fact]
    public async Task Dismiss_NonExistentBannerId_Returns404()
    {
        var ctrl = BuildController(_userIds["member"], "member");
        string nonExistentId = Guid.NewGuid().ToString("N");
        var result = await ctrl.Dismiss(nonExistentId, CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Dismiss_ExistingBanner_FirstCall_Returns204()
    {
        // Seeds a fresh banner so this test is independent of _sharedBannerId dismissal state.
        var repo = new BannerRepository(_db, TestTime.Frozen(KnownNow));
        string userId = _userIds["member"];
        var banner = await repo.CreateTenantAsync(_orgId, userId, new BannerCreateRequest(
            Severity: "info",
            Body: "Fresh dismiss test banner",
            LinkUrl: null,
            LinkLabel: null,
            TargetRole: "all",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true), CancellationToken.None);

        var ctrl = BuildController(userId, "member");
        var result = await ctrl.Dismiss(banner.Id, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task Dismiss_ExistingBanner_ReDismiss_Returns204_Idempotent()
    {
        // First dismiss then re-dismiss — both should return 204.
        var repo = new BannerRepository(_db, TestTime.Frozen(KnownNow));
        string userId = _userIds["admin"];
        var banner = await repo.CreateTenantAsync(_orgId, userId, new BannerCreateRequest(
            Severity: "warn",
            Body: "Idempotent dismiss test banner",
            LinkUrl: null,
            LinkLabel: null,
            TargetRole: "all",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true), CancellationToken.None);

        var ctrl = BuildController(userId, "admin");
        // First call: banner exists and is not yet dismissed.
        var firstResult = await ctrl.Dismiss(banner.Id, CancellationToken.None);
        Assert.IsType<NoContentResult>(firstResult);

        // Second call: ON CONFLICT DO NOTHING makes the dismissal idempotent.
        var secondResult = await ctrl.Dismiss(banner.Id, CancellationToken.None);
        Assert.IsType<NoContentResult>(secondResult);
    }

    // ── Dismiss: mixed partial — some banners exist, some do not ──────────────────────────

    /// <summary>
    /// Mixed partial-failure: in a batch of dismiss attempts, some banners exist (204) and
    /// some do not (404), confirming each is evaluated independently.
    /// </summary>
    [Fact]
    public async Task Dismiss_MixedExistentAndNonExistent_IndependentResults()
    {
        var repo = new BannerRepository(_db, TestTime.Frozen(KnownNow));
        string userId = _userIds["owner"];
        var realBanner = await repo.CreateTenantAsync(_orgId, userId, new BannerCreateRequest(
            Severity: "info",
            Body: "Mixed-partial real banner",
            LinkUrl: null,
            LinkLabel: null,
            TargetRole: "all",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true), CancellationToken.None);

        string fakeBannerId = Guid.NewGuid().ToString("N");
        var ctrl = BuildController(userId, "owner");

        // Existing banner → 204.
        var existResult = await ctrl.Dismiss(realBanner.Id, CancellationToken.None);
        Assert.IsType<NoContentResult>(existResult);

        // Non-existent banner → 404 (not 500).
        var notFoundResult = await ctrl.Dismiss(fakeBannerId, CancellationToken.None);
        Assert.IsType<NotFoundResult>(notFoundResult);
    }

    // ── CRUD guards are unchanged: List requires ReadTenant, not membership-only ───────────

    [Fact]
    public async Task List_Auditor_Forbidden_ReadTenantRequired()
    {
        var ctrl = BuildController(_userIds["auditor"], "auditor");
        var result = await ctrl.List(CancellationToken.None);
        // Auditor lacks read:tenant — must 403, not 200.
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Create_Auditor_Forbidden_TenantConfigureRequired()
    {
        var ctrl = BuildController(_userIds["auditor"], "auditor");
        var result = await ctrl.Create(new BannerCreateRequest(
            Severity: "info", Body: "Test", LinkUrl: null, LinkLabel: null,
            TargetRole: "all",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true), CancellationToken.None);
        Assert.IsType<ForbidResult>(result);
    }

    // ── Create: owner can create, invalid payloads are rejected ────────────────────────────

    private static BannerCreateRequest ValidCreateRequest(string severity = "info", string targetRole = "all") => new(
        Severity: severity,
        Body: "Tenant banner body",
        LinkUrl: null,
        LinkLabel: null,
        TargetRole: targetRole,
        StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        Enabled: true);

    [Fact]
    public async Task Create_Owner_Valid_Returns201WithTenantScope()
    {
        var ctrl = BuildController(_userIds["owner"], "owner");
        var result = Assert.IsType<CreatedResult>(await ctrl.Create(ValidCreateRequest(), CancellationToken.None));
        var banner = Assert.IsType<Banner>(result.Value);
        Assert.Equal("tenant", banner.Scope);
        Assert.Equal(_orgId, banner.OrgId);
    }

    [Fact]
    public async Task Create_InvalidSeverity_Returns422()
    {
        var ctrl = BuildController(_userIds["owner"], "owner");
        var req = ValidCreateRequest(severity: "critical");
        var result = await ctrl.Create(req, CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Create_EmptyBody_Returns422()
    {
        var ctrl = BuildController(_userIds["owner"], "owner");
        var req = ValidCreateRequest() with { Body = "" };
        var result = await ctrl.Create(req, CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Create_AtMaxActiveBanners_Returns422()
    {
        var ctrl = BuildController(_userIds["owner"], "owner");
        // The shared banner seeded in InitializeAsync already counts toward the tenant's active
        // total, so top up to the max from there.
        for (int i = 1; i < BannerRepository.MaxActiveBannersPerScope; i++)
        {
            var created = await ctrl.Create(ValidCreateRequest(), CancellationToken.None);
            Assert.IsType<CreatedResult>(created);
        }

        var overflow = await ctrl.Create(ValidCreateRequest(), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)overflow).StatusCode);
    }

    // ── Update: owner can update an existing tenant banner ─────────────────────────────────

    [Fact]
    public async Task Update_Existing_Returns204AndPersists()
    {
        var repo = new BannerRepository(_db, TestTime.Frozen(KnownNow));
        string userId = _userIds["owner"];
        var banner = await repo.CreateTenantAsync(_orgId, userId, ValidCreateRequest(), CancellationToken.None);

        var ctrl = BuildController(userId, "owner");
        var updateReq = new BannerUpdateRequest(
            Severity: "warn",
            Body: "Updated tenant banner body",
            LinkUrl: null,
            LinkLabel: null,
            TargetRole: "all",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true);

        var result = await ctrl.Update(banner.Id, updateReq, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        var list = await repo.ListTenantAsync(_orgId, CancellationToken.None);
        Assert.Equal("warn", list.Single(b => b.Id == banner.Id).Severity);
    }

    [Fact]
    public async Task Update_NonExistent_Returns404()
    {
        var ctrl = BuildController(_userIds["owner"], "owner");
        var result = await ctrl.Update(Guid.NewGuid().ToString("N"), new BannerUpdateRequest(
            Severity: "warn", Body: "x", LinkUrl: null, LinkLabel: null, TargetRole: "all",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true), CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Update_Auditor_Forbidden_TenantConfigureRequired()
    {
        var ctrl = BuildController(_userIds["auditor"], "auditor");
        var result = await ctrl.Update(_sharedBannerId, new BannerUpdateRequest(
            Severity: "warn", Body: "x", LinkUrl: null, LinkLabel: null, TargetRole: "all",
            StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Enabled: true), CancellationToken.None);
        Assert.IsType<ForbidResult>(result);
    }

    // ── Delete: owner can delete an existing tenant banner ─────────────────────────────────

    [Fact]
    public async Task Delete_Existing_Returns204()
    {
        var repo = new BannerRepository(_db, TestTime.Frozen(KnownNow));
        string userId = _userIds["owner"];
        var banner = await repo.CreateTenantAsync(_orgId, userId, ValidCreateRequest(), CancellationToken.None);

        var ctrl = BuildController(userId, "owner");
        var result = await ctrl.Delete(banner.Id, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task Delete_NonExistent_Returns404()
    {
        var ctrl = BuildController(_userIds["owner"], "owner");
        var result = await ctrl.Delete(Guid.NewGuid().ToString("N"), CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Delete_Auditor_Forbidden_TenantConfigureRequired()
    {
        var ctrl = BuildController(_userIds["auditor"], "auditor");
        var result = await ctrl.Delete(_sharedBannerId, CancellationToken.None);
        Assert.IsType<ForbidResult>(result);
    }

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(System.Globalization.CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
