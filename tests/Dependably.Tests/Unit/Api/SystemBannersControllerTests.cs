using System.Security.Claims;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Resources;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Covers <see cref="SystemBannersController"/> CRUD: list, create (success + validation
/// errors + the max-active-per-scope guard), update (success + 404 + validation), and
/// delete (success + 404). Authorization for the <c>/api/v1/system</c> prefix is enforced
/// upstream by <see cref="Dependably.Security.RouteScopeFilter"/>, not by this controller, so
/// these tests exercise the handlers directly against a system-admin-shaped principal.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemBannersControllerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);
    private string _actorId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _actorId = Guid.NewGuid().ToString("N");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private SystemBannersController BuildController()
    {
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, _actorId),
                    new Claim("sub", _actorId),
                    new Claim("scope", "system"),
                ],
                authenticationType: "test")),
        };

        var banners = new BannerRepository(_db, TestTime.Frozen(KnownNow));
        var audit = new AuditRepository(_db);
        var problems = new ProblemResults(new EchoLocalizer());

        return new SystemBannersController(banners, audit, problems)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private static BannerCreateRequest ValidCreateRequest(string severity = "info", string targetRole = "all") => new(
        Severity: severity,
        Body: "System-wide maintenance window",
        LinkUrl: null,
        LinkLabel: null,
        TargetRole: targetRole,
        StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        Enabled: true);

    private static BannerUpdateRequest ValidUpdateRequest(string severity = "warn") => new(
        Severity: severity,
        Body: "Updated system banner body",
        LinkUrl: null,
        LinkLabel: null,
        TargetRole: "all",
        StartsAt: KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        EndsAt: KnownNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        Enabled: true);

    // ── List ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_Empty_ReturnsEmptyOk()
    {
        var ctrl = BuildController();
        var result = Assert.IsType<OkObjectResult>(await ctrl.List(CancellationToken.None));
        var list = Assert.IsAssignableFrom<IReadOnlyList<Banner>>(result.Value);
        Assert.Empty(list);
    }

    [Fact]
    public async Task List_AfterCreate_ReturnsCreatedBanner()
    {
        var ctrl = BuildController();
        await ctrl.Create(ValidCreateRequest(), CancellationToken.None);

        var result = Assert.IsType<OkObjectResult>(await ctrl.List(CancellationToken.None));
        var list = Assert.IsAssignableFrom<IReadOnlyList<Banner>>(result.Value);
        Assert.Single(list);
        Assert.Equal("system", list[0].Scope);
    }

    // ── Create ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Create_Valid_Returns201WithSystemScope()
    {
        var ctrl = BuildController();
        var result = Assert.IsType<CreatedResult>(await ctrl.Create(ValidCreateRequest(), CancellationToken.None));
        var banner = Assert.IsType<Banner>(result.Value);
        Assert.Equal("system", banner.Scope);
        Assert.Null(banner.OrgId);
        Assert.Equal(_actorId, banner.CreatedBy);
    }

    [Fact]
    public async Task Create_EmptyBody_Returns422()
    {
        var ctrl = BuildController();
        var req = ValidCreateRequest() with { Body = "   " };
        var result = await ctrl.Create(req, CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Create_InvalidSeverity_Returns422()
    {
        var ctrl = BuildController();
        var req = ValidCreateRequest(severity: "critical");
        var result = await ctrl.Create(req, CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Create_InvalidTargetRole_Returns422()
    {
        var ctrl = BuildController();
        var req = ValidCreateRequest(targetRole: "superadmin");
        var result = await ctrl.Create(req, CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Create_EndsBeforeStarts_Returns422()
    {
        var ctrl = BuildController();
        var req = ValidCreateRequest() with
        {
            StartsAt = KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EndsAt = KnownNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        };
        var result = await ctrl.Create(req, CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Create_InvalidLinkUrlScheme_Returns422()
    {
        var ctrl = BuildController();
        var req = ValidCreateRequest() with { LinkUrl = "ftp://example.com/file" };
        var result = await ctrl.Create(req, CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Create_AtMaxActiveBanners_Returns422()
    {
        var ctrl = BuildController();
        for (int i = 0; i < BannerRepository.MaxActiveBannersPerScope; i++)
        {
            var created = await ctrl.Create(ValidCreateRequest(), CancellationToken.None);
            Assert.IsType<CreatedResult>(created);
        }

        var overflow = await ctrl.Create(ValidCreateRequest(), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)overflow).StatusCode);
    }

    // ── Update ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Update_Existing_Returns204AndPersists()
    {
        var ctrl = BuildController();
        var created = Assert.IsType<CreatedResult>(await ctrl.Create(ValidCreateRequest(), CancellationToken.None));
        var banner = Assert.IsType<Banner>(created.Value);

        var result = await ctrl.Update(banner.Id, ValidUpdateRequest(), CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        var list = Assert.IsType<OkObjectResult>(await ctrl.List(CancellationToken.None));
        var updated = Assert.IsAssignableFrom<IReadOnlyList<Banner>>(list.Value).Single(b => b.Id == banner.Id);
        Assert.Equal("warn", updated.Severity);
    }

    [Fact]
    public async Task Update_NonExistent_Returns404()
    {
        var ctrl = BuildController();
        var result = await ctrl.Update(Guid.NewGuid().ToString("N"), ValidUpdateRequest(), CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Update_InvalidPayload_Returns422_BeforeLookup()
    {
        var ctrl = BuildController();
        var req = ValidUpdateRequest() with { Severity = "bogus" };
        var result = await ctrl.Update(Guid.NewGuid().ToString("N"), req, CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    // ── Delete ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Delete_Existing_Returns204AndRemovesFromList()
    {
        var ctrl = BuildController();
        var created = Assert.IsType<CreatedResult>(await ctrl.Create(ValidCreateRequest(), CancellationToken.None));
        var banner = Assert.IsType<Banner>(created.Value);

        var result = await ctrl.Delete(banner.Id, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        var list = Assert.IsType<OkObjectResult>(await ctrl.List(CancellationToken.None));
        Assert.Empty(Assert.IsAssignableFrom<IReadOnlyList<Banner>>(list.Value));
    }

    [Fact]
    public async Task Delete_NonExistent_Returns404()
    {
        var ctrl = BuildController();
        var result = await ctrl.Delete(Guid.NewGuid().ToString("N"), CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Mixed partial: batch of deletes, some hit some miss ────────────────────────────────

    [Fact]
    public async Task Delete_MixedExistentAndNonExistent_IndependentResults()
    {
        var ctrl = BuildController();
        var created = Assert.IsType<CreatedResult>(await ctrl.Create(ValidCreateRequest(), CancellationToken.None));
        var banner = Assert.IsType<Banner>(created.Value);
        string fakeId = Guid.NewGuid().ToString("N");

        Assert.IsType<NoContentResult>(await ctrl.Delete(banner.Id, CancellationToken.None));
        Assert.IsType<NotFoundResult>(await ctrl.Delete(fakeId, CancellationToken.None));
    }

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(System.Globalization.CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
