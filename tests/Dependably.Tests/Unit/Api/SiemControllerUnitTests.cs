using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// SiemController has manual auth (JWT or Bearer token with read:audit) and serves both
/// JSON and NDJSON / CEF. The scenario seeds an owner with full capabilities; auth-deny
/// cases use the anonymous + member roles. Note: tests don't authenticate via Bearer token
/// — that path runs through TokenAuthExtensions which needs the full middleware pipeline.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SiemControllerUnitTests
{
    // ── GetAuthEvents ────────────────────────────────────────────────────────

    [Fact]
    public async Task GetAuthEvents_Owner_Returns200_WithItemsAndCursor()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: null, limit: 100, cursor: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_Anonymous_ReturnsUnauthorized()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        // Either UnauthorizedObjectResult or ObjectResult with 401.
        int? status = result switch
        {
            ObjectResult o => o.StatusCode,
            UnauthorizedResult => 401,
            _ => null
        };
        Assert.Equal(401, status);
    }

    [Fact]
    public async Task GetAuthEvents_Member_Forbidden_NoReadAuditCapability()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    [Theory]
    [InlineData("not-a-date", "2026-01-01T00:00:00Z")]
    [InlineData("2026-01-01T00:00:00Z", "garbage")]
    public async Task GetAuthEvents_InvalidIsoDates_Returns400(string since, string until)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(since, until, null, null, 100, null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_SinceAfterUntil_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(
            since: "2026-12-31T00:00:00Z", until: "2026-01-01T00:00:00Z",
            org: null, action: null, limit: 100, cursor: null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_AtTheTotalCap_IsServedAndOneValuePastItIs400()
    {
        // Every filter costs one bind parameter, so the repeatable action= filter is bounded.
        // A rejection is the honest answer — dropping the overflow would return a feed quietly
        // missing events the caller asked for. The largest legitimate subscription is every
        // declared action plus every implied family, which is exactly the published total cap.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string[] atTheCap = [.. AuditActions.All, .. AuditActions.ImpliedFamilyPrefixes];
        Assert.Equal(AuditRepository.MaxAuthEventActionFilters, atTheCap.Length);

        var served = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: atTheCap, limit: 100, cursor: null);
        Assert.IsType<OkObjectResult>(served);

        var refused = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null,
            action: [.. atTheCap, "zzz_one_past_the_composition"], limit: 100, cursor: null);
        Assert.IsType<BadRequestObjectResult>(refused);
    }

    [Fact]
    public async Task GetAuthEvents_MoreFamilyFiltersThanTheFamilyCap_Returns400()
    {
        // The half with a cost: one unindexable LIKE per family or undeclared name, evaluated
        // against every candidate row of the window. Well under the total cap, so this is the
        // family bound answering and not the other one.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string[] filters = [.. Enumerable
            .Range(0, AuditRepository.MaxAuthEventFamilyFilters + 1)
            .Select(i => $"family{i}")];
        Assert.True(filters.Length <= AuditRepository.MaxAuthEventActionFilters);

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: filters, limit: 100, cursor: null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_EveryDeclaredActionNamedExplicitly_IsServed()
    {
        // A collector that pins the vocabulary it understands rather than inheriting a widening
        // default sends exactly this. It must not read as abuse — declared names cost an IN entry
        // each and no LIKE at all.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: [.. AuditActions.All],
            limit: 100, cursor: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_RepeatedIdenticalActionPrefixesPastTheCap_AreFoldedAndServed()
    {
        // The bound is on distinct prefixes: a client repeating one filter is not asking for more
        // parameters than the statement can carry, so it must not read as abuse.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string[] prefixes = [.. Enumerable.Repeat("login", AuditRepository.MaxAuthEventActionFilters + 50)];

        var result = await b.SiemController.GetAuthEvents(
            since: null, until: null, org: null, action: prefixes, limit: 100, cursor: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_TenantUser_OrgFilterIgnored_AlwaysScopedToOwnTenant()
    {
        // Auth model: tenant-scoped JWTs are pinned to their own org by TokenOrgId regardless
        // of the ?org= query param. The Forbid path only fires for platform admins (who have
        // no TokenOrgId) asking with an unparseable slug — covered separately.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetAuthEvents(
            null, null, org: "ignored-by-tenant-scope", null, 100, null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAuthEvents_NdjsonAcceptHeader_ReturnsNdjsonContentType()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.Request.Headers.Accept = "application/x-ndjson";

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        var content = Assert.IsType<ContentResult>(result);
        Assert.StartsWith("application/x-ndjson", content.ContentType);
    }

    [Fact]
    public async Task GetAuthEvents_CefAcceptHeader_ReturnsCefContentType()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.SiemController.Request.Headers.Accept = "application/x-cef";

        var result = await b.SiemController.GetAuthEvents(null, null, null, null, 100, null);
        var content = Assert.IsType<ContentResult>(result);
        Assert.StartsWith("application/x-cef", content.ContentType);
    }

    // ── GetVulnSummary ───────────────────────────────────────────────────────

    [Fact]
    public async Task GetVulnSummary_Owner_Returns200_WithByEcosystemShape()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetVulnSummary(org: null, ecosystem: null);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);
        // Response is anonymous { by_ecosystem, packages_total, packages_affected }; just
        // verify it's an object with by_ecosystem key.
        Assert.NotNull(ok.Value!.GetType().GetProperty("by_ecosystem"));
    }

    [Fact]
    public async Task GetVulnSummary_Anonymous_ReturnsUnauthorized()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetVulnSummary(null, null);
        int? status = result switch
        {
            ObjectResult o => o.StatusCode,
            UnauthorizedResult => 401,
            _ => null
        };
        Assert.Equal(401, status);
    }

    [Fact]
    public async Task GetVulnSummary_TenantUser_OrgFilterIgnored_AlwaysScopedToOwnTenant()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetVulnSummary(org: "ignored", ecosystem: null);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetVulnSummary_Member_Forbidden_NoReadAuditCapability()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.SiemController.GetVulnSummary(null, null);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }
}
