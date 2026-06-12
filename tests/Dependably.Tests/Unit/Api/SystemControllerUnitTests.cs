using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

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
        await OrgSeeder.InsertAsync(s.Store, $"second-{Guid.NewGuid():N}"[..16]);
        await OrgSeeder.InsertAsync(s.Store, $"third-{Guid.NewGuid():N}"[..16]);
        var b = await s.BuildAsync();

        var result = await b.SystemController.ListTenants(limit: 50, page: 1);
        var ok = Assert.IsType<OkObjectResult>(result);
        int total = (int)ok.Value!.GetType().GetProperty("total")!.GetValue(ok.Value)!;
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
        int limit = (int)result.Value!.GetType().GetProperty("limit")!.GetValue(result.Value)!;
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
    [InlineData("", "owner@example.com")]
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

        string slug = $"valid-{Guid.NewGuid():N}"[..18];
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
        string targetSlug = $"target-{Guid.NewGuid():N}"[..18];
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
        long auditCount = await conn.ExecuteScalarAsync<long>(
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
        string slug = $"restore-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);
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
        long auditCount = await verify.ExecuteScalarAsync<long>(
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
        string slug = $"alive-{Guid.NewGuid():N}"[..18];
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

    // ── Storage quota ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task SetTenantStorageQuota_PositiveBytes_PersistsAndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string slug = $"quota-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);
        var b = await s.BuildAsync();

        var result = await b.SystemController.SetTenantStorageQuota(
            slug, new Dependably.Api.SetStorageQuotaRequest(1_000_000_000),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        var orgs = new Dependably.Infrastructure.OrgRepository(b.Db);
        var org = await orgs.GetByIdAsync(orgId);
        Assert.NotNull(org);
        Assert.Equal(1_000_000_000L, org!.StorageQuotaBytes);

        await using var conn = await b.Db.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'tenant.quota_changed'");
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task SetTenantStorageQuota_NullBytes_ClearsTheCap()
    {
        // null = unlimited. Round-trip through the controller and assert the column is
        // NULL after the call.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string slug = $"qclear-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);
        var orgs = new Dependably.Infrastructure.OrgRepository(s.Store);
        await orgs.SetStorageQuotaBytesAsync(orgId, 500);
        var b = await s.BuildAsync();

        var result = await b.SystemController.SetTenantStorageQuota(
            slug, new Dependably.Api.SetStorageQuotaRequest(null),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        var after = await orgs.GetByIdAsync(orgId);
        Assert.NotNull(after);
        Assert.Null(after!.StorageQuotaBytes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-1_000_000)]
    public async Task SetTenantStorageQuota_ZeroOrNegative_Returns422(long bytes)
    {
        // Zero would never reject a publish; negative is nonsensical. Both must 422 so
        // the caller can't accidentally lock a tenant out by mis-typing a sign.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string slug = $"qbad-{Guid.NewGuid():N}"[..18];
        await OrgSeeder.InsertAsync(s.Store, slug);
        var b = await s.BuildAsync();

        var result = await b.SystemController.SetTenantStorageQuota(
            slug, new Dependably.Api.SetStorageQuotaRequest(bytes),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task SetTenantStorageQuota_UnknownSlug_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.SetTenantStorageQuota(
            "ghost-tenant", new Dependably.Api.SetStorageQuotaRequest(1_000),
            CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task SetTenantStorageQuota_NullBody_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string slug = $"qnull-{Guid.NewGuid():N}"[..18];
        await OrgSeeder.InsertAsync(s.Store, slug);
        var b = await s.BuildAsync();

        var result = await b.SystemController.SetTenantStorageQuota(slug, null, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task ListTenants_ExposesStorageQuotaBytes()
    {
        // The UI keys its display + edit form off this field; the list response must
        // include it (null for unset, the byte value when set).
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string slug = $"qlist-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);
        var orgs = new Dependably.Infrastructure.OrgRepository(s.Store);
        await orgs.SetStorageQuotaBytesAsync(orgId, 2_500);
        var b = await s.BuildAsync();

        var result = await b.SystemController.ListTenants();
        var ok = Assert.IsType<OkObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(ok.Value);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var items = doc.RootElement.GetProperty("items");
        var match = items.EnumerateArray()
            .FirstOrDefault(i => i.GetProperty("slug").GetString() == slug);
        Assert.True(match.ValueKind != System.Text.Json.JsonValueKind.Undefined,
            "Seeded tenant must appear in the list.");
        Assert.Equal(2_500L, match.GetProperty("storageQuotaBytes").GetInt64());
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
        object? items = ok.Value!.GetType().GetProperty("items")!.GetValue(ok.Value);
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

    // ── system_admin CRUD on /admins ───────────────────────────────────────
    // Tests exercise the three controller-level guards (no-self, last-active,
    // delete-requires-disabled) and the audit emission for each happy path.
    // RouteScopeFilter (which enforces scope=system+apex globally) is bypassed
    // because these tests invoke the controller method directly.

    /// <summary>Rebinds <c>HttpContext.User</c> on the controller to a system_admin actor id.</summary>
    private static void SetSystemActor(ControllerScenarioResult b, string actorId)
    {
        b.SystemController.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
                [
                    new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, actorId),
                    new System.Security.Claims.Claim("sub", actorId),
                    new System.Security.Claims.Claim("scope", "system"),
                ],
                authenticationType: "test"));
    }

    [Fact]
    public async Task ListAdmins_NeverIncludesPasswordHash()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        await SystemAdminSeeder.InsertAsync(s.Store, "ops1@example.test");
        await SystemAdminSeeder.InsertAsync(s.Store, "ops2@example.test");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListAdmins(CancellationToken.None));
        var items = (System.Collections.IEnumerable)ok.Value!;
        object first = items.Cast<object>().First();
        var props = first.GetType().GetProperties().Select(p => p.Name).ToHashSet();
        Assert.DoesNotContain("passwordHash", props);
        Assert.DoesNotContain("password_hash", props);
        Assert.Contains("email", props);
        Assert.Contains("accountStatus", props);
    }

    [Fact]
    public async Task CreateAdmin_ReturnsTempPassword_PersistsActiveAndMustChange()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.CreateAdmin(
            new CreateAdminRequest("new-ops@example.test"), CancellationToken.None);
        var created = Assert.IsType<CreatedAtActionResult>(result);
        object value = created.Value!;
        string temp = (string)value.GetType().GetProperty("temporaryPassword")!.GetValue(value)!;
        Assert.False(string.IsNullOrWhiteSpace(temp));

        await using var conn = await b.Db.OpenAsync();
        var (Email, Status, Mcp, Hash) = await conn.QuerySingleAsync<(string Email, string Status, int Mcp, string Hash)>(
            "SELECT email AS Email, account_status AS Status, must_change_password AS Mcp, password_hash AS Hash FROM system_admins WHERE email = 'new-ops@example.test'");
        Assert.Equal("active", Status);
        Assert.Equal(1, Mcp);
        Assert.True(BCrypt.Net.BCrypt.Verify(temp, Hash));
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'system_admin.admin_created'");
        Assert.Equal(1, auditCount);
    }

    [Fact]
    public async Task CreateAdmin_DuplicateEmail_Returns409()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        await SystemAdminSeeder.InsertAsync(s.Store, "dup@example.test");
        var b = await s.BuildAsync();

        var result = await b.SystemController.CreateAdmin(
            new CreateAdminRequest("dup@example.test"), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, obj.StatusCode);
    }

    [Fact]
    public async Task CreateAdmin_MissingEmail_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.CreateAdmin(
            new CreateAdminRequest(""), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task SetAdminAccountStatus_DisableSelf_Returns403()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string selfId = await SystemAdminSeeder.InsertAsync(s.Store, "self@example.test");
        await SystemAdminSeeder.InsertAsync(s.Store, "other@example.test");
        var b = await s.BuildAsync();
        SetSystemActor(b, selfId);

        var result = await b.SystemController.SetAdminAccountStatus(
            selfId, new SetAdminAccountStatusRequest("disabled"), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    [Fact]
    public async Task SetAdminAccountStatus_DisableLastActiveAdmin_Returns409()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        // Only one admin exists; another actor (caller) is needed to satisfy no-self.
        string aloneId = await SystemAdminSeeder.InsertAsync(s.Store, "alone@example.test");
        string callerId = Guid.NewGuid().ToString("N"); // synthetic caller id; no row in system_admins
        var b = await s.BuildAsync();
        SetSystemActor(b, callerId);

        var result = await b.SystemController.SetAdminAccountStatus(
            aloneId, new SetAdminAccountStatusRequest("disabled"), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, obj.StatusCode);
    }

    [Fact]
    public async Task SetAdminAccountStatus_DisableWithAnotherActiveAdmin_Succeeds_AndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string targetId = await SystemAdminSeeder.InsertAsync(s.Store, "target@example.test");
        string otherId = await SystemAdminSeeder.InsertAsync(s.Store, "stays-active@example.test");
        var b = await s.BuildAsync();
        SetSystemActor(b, otherId);

        var result = await b.SystemController.SetAdminAccountStatus(
            targetId, new SetAdminAccountStatusRequest("disabled"), CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        string? status = await conn.ExecuteScalarAsync<string>(
            "SELECT account_status FROM system_admins WHERE id = @id", new { id = targetId });
        Assert.Equal("disabled", status);
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'system_admin.admin_account_status_changed'");
        Assert.Equal(1, auditCount);
    }

    [Fact]
    public async Task SetAdminAccountStatus_InvalidStatus_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string targetId = await SystemAdminSeeder.InsertAsync(s.Store, "t@example.test");
        var b = await s.BuildAsync();
        SetSystemActor(b, Guid.NewGuid().ToString("N"));

        var result = await b.SystemController.SetAdminAccountStatus(
            targetId, new SetAdminAccountStatusRequest("frozen"), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task ResetAdminPassword_OnSelf_Returns403()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string selfId = await SystemAdminSeeder.InsertAsync(s.Store, "self2@example.test");
        var b = await s.BuildAsync();
        SetSystemActor(b, selfId);

        var result = await b.SystemController.ResetAdminPassword(selfId, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    [Fact]
    public async Task ResetAdminPassword_OnOther_IssuesNewPassword_AndForcesRotation()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string targetId = await SystemAdminSeeder.InsertAsync(s.Store, "reset-me@example.test", password: "OldPassword123");
        var b = await s.BuildAsync();
        SetSystemActor(b, Guid.NewGuid().ToString("N"));

        var result = await b.SystemController.ResetAdminPassword(targetId, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        string temp = (string)ok.Value!.GetType().GetProperty("temporaryPassword")!.GetValue(ok.Value)!;
        Assert.False(string.IsNullOrWhiteSpace(temp));

        await using var conn = await b.Db.OpenAsync();
        var (Hash, Mcp, Issued) = await conn.QuerySingleAsync<(string Hash, int Mcp, string? Issued)>(
            "SELECT password_hash AS Hash, must_change_password AS Mcp, password_reset_issued_at AS Issued FROM system_admins WHERE id = @id",
            new { id = targetId });
        Assert.True(BCrypt.Net.BCrypt.Verify(temp, Hash));
        Assert.False(BCrypt.Net.BCrypt.Verify("OldPassword123", Hash));
        Assert.Equal(1, Mcp);
        Assert.False(string.IsNullOrEmpty(Issued));
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'system_admin.admin_password_reset'");
        Assert.Equal(1, auditCount);
    }

    [Fact]
    public async Task DeleteAdmin_OnSelf_Returns403()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string selfId = await SystemAdminSeeder.InsertAsync(s.Store, "self3@example.test");
        var b = await s.BuildAsync();
        SetSystemActor(b, selfId);

        var result = await b.SystemController.DeleteAdmin(selfId, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
    }

    [Fact]
    public async Task DeleteAdmin_WhenActive_Returns409_MustDisableFirst()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string targetId = await SystemAdminSeeder.InsertAsync(s.Store, "still-active@example.test");
        var b = await s.BuildAsync();
        SetSystemActor(b, Guid.NewGuid().ToString("N"));

        var result = await b.SystemController.DeleteAdmin(targetId, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, obj.StatusCode);
    }

    [Fact]
    public async Task DeleteAdmin_WhenDisabled_Succeeds_AndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string targetId = await SystemAdminSeeder.InsertAsync(s.Store, "delete-me@example.test");
        // Pre-disable the target so DELETE proceeds.
        await using (var conn = await s.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_admins SET account_status = 'disabled' WHERE id = @id", new { id = targetId });
        }
        var b = await s.BuildAsync();
        SetSystemActor(b, Guid.NewGuid().ToString("N"));

        var result = await b.SystemController.DeleteAdmin(targetId, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var verify = await b.Db.OpenAsync();
        long count = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM system_admins WHERE id = @id", new { id = targetId });
        Assert.Equal(0, count);
        long auditCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'system_admin.admin_deleted'");
        Assert.Equal(1, auditCount);
    }

    // ── GetAdmin(id) ───────────────────────────────────────────────────────

    [Fact]
    public async Task GetAdmin_UnknownId_ReturnsNotFound()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.GetAdmin("not-real-id", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task GetAdmin_KnownId_ReturnsProjection()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string adminId = await SystemAdminSeeder.InsertAsync(s.Store, $"ops-{Guid.NewGuid():N}@example.test");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(
            await b.SystemController.GetAdmin(adminId, CancellationToken.None));
        string id = (string)ok.Value!.GetType().GetProperty("id")!.GetValue(ok.Value)!;
        string? email = (string?)ok.Value.GetType().GetProperty("email")!.GetValue(ok.Value);
        Assert.Equal(adminId, id);
        Assert.False(string.IsNullOrEmpty(email));
    }

    // ── Me() ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Me_NoSubClaim_ReturnsUnauthorized()
    {
        // Strip both NameIdentifier and "sub" — the lookup helper inside Me() returns null
        // and the endpoint must reject with 401 before touching the systemAdmins repo.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        b.SystemController.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("scope", "system")],
                authenticationType: "test"));

        var result = await b.SystemController.Me(CancellationToken.None);
        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task Me_UnknownAdmin_ReturnsNotFound()
    {
        // Sub claim points to a system_admin row that doesn't exist — the lookup returns null
        // and the endpoint returns 404 rather than producing a hollow projection.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        SetSystemActor(b, "missing-admin-id");

        var result = await b.SystemController.Me(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Me_WithStoredLanguage_ReturnsLanguageField()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string adminId = await SystemAdminSeeder.InsertAsync(s.Store, $"ops-{Guid.NewGuid():N}@example.test");
        await using (var seed = await s.Store.OpenAsync())
        {
            await seed.ExecuteAsync(
                "UPDATE system_admins SET language = 'fr' WHERE id = @id", new { id = adminId });
        }
        var b = await s.BuildAsync();
        SetSystemActor(b, adminId);

        var ok = Assert.IsType<OkObjectResult>(
            await b.SystemController.Me(CancellationToken.None));
        string? lang = (string?)ok.Value!.GetType().GetProperty("language")!.GetValue(ok.Value);
        Assert.Equal("fr", lang);
    }

    [Fact]
    public async Task Me_NullLanguage_FallsBackToDefault()
    {
        // When the admin row has no language preference, the response surfaces the default —
        // the IsNullOrEmpty true-branch of the ternary fires.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string adminId = await SystemAdminSeeder.InsertAsync(s.Store, $"ops-{Guid.NewGuid():N}@example.test");
        var b = await s.BuildAsync();
        SetSystemActor(b, adminId);

        var ok = Assert.IsType<OkObjectResult>(
            await b.SystemController.Me(CancellationToken.None));
        string? lang = (string?)ok.Value!.GetType().GetProperty("language")!.GetValue(ok.Value);
        Assert.Equal(Dependably.Infrastructure.LanguageCodes.Default, lang);
    }

    // ── UpdateMyLanguage ───────────────────────────────────────────────────

    [Fact]
    public async Task UpdateMyLanguage_UnsupportedCode_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.UpdateMyLanguage(
            new UpdateLanguageRequest("zz"), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task UpdateMyLanguage_BlankCode_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.UpdateMyLanguage(
            new UpdateLanguageRequest("   "), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task UpdateMyLanguage_NoSubClaim_ReturnsUnauthorized()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        b.SystemController.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("scope", "system")],
                authenticationType: "test"));

        var result = await b.SystemController.UpdateMyLanguage(
            new UpdateLanguageRequest("en"), CancellationToken.None);
        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task UpdateMyLanguage_Valid_PersistsAndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        string adminId = await SystemAdminSeeder.InsertAsync(s.Store, $"ops-{Guid.NewGuid():N}@example.test");
        var b = await s.BuildAsync();
        SetSystemActor(b, adminId);

        var result = await b.SystemController.UpdateMyLanguage(
            new UpdateLanguageRequest("fr"), CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var verify = await b.Db.OpenAsync();
        string? stored = await verify.ExecuteScalarAsync<string?>(
            "SELECT language FROM system_admins WHERE id = @id", new { id = adminId });
        Assert.Equal("fr", stored);
        long auditCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'system_admin.language_changed' AND actor_id = @id",
            new { id = adminId });
        Assert.True(auditCount >= 1);
    }

    // ── ChangeMyPassword: sub-claim fallback ───────────────────────────────

    [Fact]
    public async Task ChangeMyPassword_NoSubClaim_ReturnsUnauthorized()
    {
        // The validation guards (current/new password rules) all pass, but the sub-claim
        // lookup returns null and the endpoint must reject with 401.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        b.SystemController.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("scope", "system")],
                authenticationType: "test"));

        var req = new ChangePasswordRequest("OldPassword123!", "BrandNewPassword456!");
        var result = await b.SystemController.ChangeMyPassword(req, CancellationToken.None);
        Assert.IsType<UnauthorizedResult>(result);
    }

    // ── SetAccountStatus / IssuePasswordReset null-body ────────────────────

    [Fact]
    public async Task SetAccountStatus_NullBody_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.SetAccountStatus(
            "user@acme.test", null!, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task IssuePasswordReset_NullBody_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.IssuePasswordReset(
            "user@acme.test", null!, CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── UpdateMetricsAccess: env-locked conflict branches ─────────────────

    [Fact]
    public async Task UpdateMetricsAccess_EnabledLockedByEnv_ReturnsConflict()
    {
        // METRICS_ENABLED env is set; updating the enabled flag must surface the
        // env-locked conflict instead of writing through to instance_settings.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["METRICS_ENABLED"] = "1" })
            .Build();
        static Task<string?> Reader(string _, CancellationToken __) => Task.FromResult<string?>(null);
        var access = new Dependably.Security.MetricsAccessConfig(Reader, config);

        var result = await b.SystemController.UpdateMetricsAccess(
            new UpdateMetricsAccessRequest(Enabled: false, AllowedIps: null),
            access,
            CancellationToken.None);
        var obj = Assert.IsType<ConflictObjectResult>(result);
        Assert.NotNull(obj.Value);
    }

    [Fact]
    public async Task UpdateMetricsAccess_AllowlistLockedByEnv_ReturnsConflict()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["METRICS_ALLOWED_IPS"] = "10.0.0.0/8" })
            .Build();
        static Task<string?> Reader(string _, CancellationToken __) => Task.FromResult<string?>(null);
        var access = new Dependably.Security.MetricsAccessConfig(Reader, config);

        var result = await b.SystemController.UpdateMetricsAccess(
            new UpdateMetricsAccessRequest(Enabled: null, AllowedIps: new[] { "192.168.0.0/16" }),
            access,
            CancellationToken.None);
        Assert.IsType<ConflictObjectResult>(result);
    }

    [Fact]
    public async Task IssuePasswordReset_MissingTenantSlug_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.SystemController.IssuePasswordReset(
            "user@acme.test", new PasswordResetRequest(""), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }
}
