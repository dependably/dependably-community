using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;
using Dependably.Infrastructure;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// SystemController is the apex-only operator surface. Auth scope ("system" + apex) is
/// enforced by RouteScopeFilter globally, so these tests don't need to fake that filter —
/// they exercise the lifecycle and validation paths against real repos + in-memory SQLite.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemControllerUnitTests
{
    [Fact]
    public async Task ListTenants_ReturnsAllTenants_WithPagination()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme");
        await s.WithUserAsync(role: "owner");
        await OrgSeeder.InsertAsync(s.Store, $"second-{Guid.NewGuid():N}".Substring(0, 16));
        await OrgSeeder.InsertAsync(s.Store, $"third-{Guid.NewGuid():N}".Substring(0, 16));
        var b = await s.BuildAsync();

        var result = await b.SystemController.ListTenants(limit: 50, page: 1);
        var ok = Assert.IsType<OkObjectResult>(result);
        var total = (int)ok.Value!.GetType().GetProperty("total")!.GetValue(ok.Value)!;
        Assert.True(total >= 3);
    }

    [Fact]
    public async Task ListTenants_ClampsLimitToMax200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = (OkObjectResult)await b.SystemController.ListTenants(limit: 1000, page: 1);
        var limit = (int)result.Value!.GetType().GetProperty("limit")!.GetValue(result.Value)!;
        Assert.Equal(200, limit);
    }

    [Fact]
    public async Task CreateTenant_NullBody_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.CreateTenant(null!, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Theory]
    [InlineData("admin", "owner@example.com")]
    [InlineData("",      "owner@example.com")]
    [InlineData("Bad Slug!", "owner@example.com")]
    public async Task CreateTenant_InvalidSlug_Returns422(string slug, string email)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.CreateTenant(
            new CreateTenantRequest(slug, email), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Theory]
    [InlineData("notanemail")]
    [InlineData("")]
    [InlineData("   ")]
    public async Task CreateTenant_InvalidEmail_Returns422(string email)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var slug = $"valid-{Guid.NewGuid():N}".Substring(0, 18);
        var result = await b.SystemController.CreateTenant(
            new CreateTenantRequest(slug, email), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task SoftDeleteTenant_StampsDeletedAt_AndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var targetSlug = $"target-{Guid.NewGuid():N}".Substring(0, 18);
        await OrgSeeder.InsertAsync(s.Store, targetSlug);
        var b = await s.BuildAsync();

        var result = await b.SystemController.SoftDeleteTenant(targetSlug, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        // Read back via repo so the date type-handler applies — raw string read can race
        // SQLite's default text representation across SDK versions.
        var orgs = new Dependably.Infrastructure.OrgRepository(b.Db);
        var org = await orgs.GetBySlugAsync(targetSlug, includeDeleted: true);
        Assert.NotNull(org);
        Assert.NotNull(org!.DeletedAt);

        await using var conn = await b.Db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'tenant.deleted'");
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task SoftDeleteTenant_UnknownSlug_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.SoftDeleteTenant("ghost-tenant", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task RestoreTenant_PreviouslyDeleted_ClearsTombstone_AndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var slug = $"restore-{Guid.NewGuid():N}".Substring(0, 18);
        var orgId = await OrgSeeder.InsertAsync(s.Store, slug);
        await using (var conn = await s.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @id",
                new { id = orgId });
        }
        var b = await s.BuildAsync();

        var result = await b.SystemController.RestoreTenant(slug, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        var orgs = new Dependably.Infrastructure.OrgRepository(b.Db);
        var restored = await orgs.GetBySlugAsync(slug, includeDeleted: true);
        Assert.NotNull(restored);
        Assert.Null(restored!.DeletedAt);

        await using var verify = await b.Db.OpenAsync();
        var auditCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'tenant.restored'");
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task RestoreTenant_AlreadyActive_Returns409()
    {
        // Restoring a tenant that isn't currently soft-deleted is a 409 Conflict (per the
        // controller's "Tenant is already active." path). Tenants that don't exist at all
        // would return 404 — that branch is covered separately.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var slug = $"alive-{Guid.NewGuid():N}".Substring(0, 18);
        await OrgSeeder.InsertAsync(s.Store, slug);
        var b = await s.BuildAsync();

        var result = await b.SystemController.RestoreTenant(slug, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, obj.StatusCode);
    }

    [Fact]
    public async Task RestoreTenant_UnknownSlug_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.RestoreTenant("ghost-tenant", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task GetSettings_ReturnsInstanceConfig()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.GetSettings(CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    // ── LookupUsers ────────────────────────────────────────────────────────

    [Fact]
    public async Task LookupUsers_NeitherEmailNorSlug_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.LookupUsers(
            email: null, tenantSlug: null, limit: 50);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task LookupUsers_ByEmail_Returns200WithResults()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("lookup-org");
        await s.WithUserAsync(email: "find@lookup-org.test", role: "owner", org: "lookup-org");
        var b = await s.BuildAsync();

        var result = await b.SystemController.LookupUsers(
            email: "find@lookup-org.test", tenantSlug: null, limit: 50);
        var ok = Assert.IsType<OkObjectResult>(result);
        var items = ok.Value!.GetType().GetProperty("items")!.GetValue(ok.Value);
        Assert.NotNull(items);
    }

    // ── UpdateSettings ─────────────────────────────────────────────────────

    [Fact]
    public async Task UpdateSettings_UnknownKey_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var payload = new Dictionary<string, string> { ["unknown_key"] = "value" };
        var result = await b.SystemController.UpdateSettings(payload, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task UpdateSettings_KnownKey_Returns204()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var payload = new Dictionary<string, string> { ["max_upload_bytes"] = "52428800" };
        var result = await b.SystemController.UpdateSettings(payload, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }

    // ── SetAccountStatus ───────────────────────────────────────────────────

    [Fact]
    public async Task SetAccountStatus_InvalidStatus_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var req = new SetAccountStatusRequest("unknown_status", "acme");
        var result = await b.SystemController.SetAccountStatus(
            "owner@acme.test", req, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── ChangeMyPassword ───────────────────────────────────────────────────

    [Fact]
    public async Task ChangeMyPassword_ShortNewPassword_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var req = new ChangePasswordRequest("OldPassword123", "short");
        var result = await b.SystemController.ChangeMyPassword(req, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task ChangeMyPassword_SameAsCurrentPassword_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        const string password = "SamePassword123!";
        var req = new ChangePasswordRequest(password, password);
        var result = await b.SystemController.ChangeMyPassword(req, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }
}
