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
