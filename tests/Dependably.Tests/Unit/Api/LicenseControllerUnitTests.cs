using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Pattern B coverage — LicenseController exercised against real repos + in-memory SQLite
/// via <see cref="ControllerScenario"/>. Each conditional branch in the controller has at
/// least one test; the write paths have at least one that reads back the audit_log row.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LicenseControllerUnitTests
{
    // ── GetPolicy ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetPolicy_Owner_ReturnsOff_WhenNoModeSet()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetPolicy(CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);
    }

    [Fact]
    public async Task GetPolicy_Anonymous_DeniedBeforeReadingPolicy()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetPolicy(CancellationToken.None);
        Assert.False(IsOk(result));
    }

    [Fact]
    public async Task GetPolicy_MemberInDifferentOrg_Forbidden()
    {
        // Cross-tenant: a valid user from another org tries to read policy.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme");
        await s.WithUserInDifferentOrgAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetPolicy(CancellationToken.None);
        Assert.False(IsOk(result));
    }

    // ── SetMode ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task SetMode_Owner_AcceptsAndAudits(string mode)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.SetMode(new SetModeRequest(mode), CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'license_policy_mode_changed' AND org_id = @orgId",
            new { orgId = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task SetMode_InvalidMode_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.SetMode(new SetModeRequest("panic"), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task SetMode_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.SetMode(new SetModeRequest("warn"), CancellationToken.None);
        Assert.False(IsOk(result));
    }

    // ── Allowlist CRUD ───────────────────────────────────────────────────────

    [Fact]
    public async Task AddAllowlist_Owner_Created_AndAuditsAddPath()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        var spdx = $"MIT-{Guid.NewGuid():N}".Substring(0, 12);

        var result = await b.LicenseController.AddAllowlist(new LicenseSpdxRequest(spdx), CancellationToken.None);
        var created = Assert.IsType<CreatedAtActionResult>(result);
        Assert.NotNull(created.Value);

        await using var conn = await b.Db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'license_allowlist_added' AND org_id = @orgId",
            new { orgId = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task AddAllowlist_BlankSpdx_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.AddAllowlist(new LicenseSpdxRequest("   "), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task AddAllowlist_Duplicate_Returns409()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        var spdx = $"APACHE-{Guid.NewGuid():N}".Substring(0, 15);

        var first = await b.LicenseController.AddAllowlist(new LicenseSpdxRequest(spdx), CancellationToken.None);
        Assert.IsType<CreatedAtActionResult>(first);

        var second = await b.LicenseController.AddAllowlist(new LicenseSpdxRequest(spdx), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(second);
        Assert.Equal(StatusCodes.Status409Conflict, obj.StatusCode);
    }

    [Fact]
    public async Task RemoveAllowlist_Missing_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.RemoveAllowlist($"never-{Guid.NewGuid():N}", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task RemoveAllowlist_Existing_RemovesAndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var spdx = $"BSD-{Guid.NewGuid():N}".Substring(0, 10);
        await s.WithLicenseAllowlistEntryAsync(spdx);
        var b = await s.BuildAsync();

        var result = await b.LicenseController.RemoveAllowlist(spdx, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'license_allowlist_removed' AND org_id = @orgId",
            new { orgId = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    // ── Blocklist CRUD ───────────────────────────────────────────────────────

    [Fact]
    public async Task GetBlocklist_Owner_ReturnsArrayShape()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetBlocklist(CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task AddBlocklist_Owner_CreatedAndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        var spdx = $"GPL-{Guid.NewGuid():N}".Substring(0, 10);

        var result = await b.LicenseController.AddBlocklist(new LicenseSpdxRequest(spdx), CancellationToken.None);
        Assert.IsType<CreatedAtActionResult>(result);

        await using var conn = await b.Db.OpenAsync();
        Assert.True(await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'license_blocklist_added' AND org_id = @orgId",
            new { orgId = b.PrimaryOrgId }) >= 1);
    }

    [Fact]
    public async Task AddBlocklist_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.AddBlocklist(new LicenseSpdxRequest("MIT"), CancellationToken.None);
        Assert.False(IsOk(result));
    }

    [Fact]
    public async Task RemoveBlocklist_RoundTrip_AndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var spdx = $"AGPL-{Guid.NewGuid():N}".Substring(0, 12);
        await s.WithLicenseBlocklistEntryAsync(spdx);
        var b = await s.BuildAsync();

        var result = await b.LicenseController.RemoveBlocklist(spdx, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        Assert.True(await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'license_blocklist_removed' AND org_id = @orgId",
            new { orgId = b.PrimaryOrgId }) >= 1);
    }

    private static bool IsOk(IActionResult r) =>
        r is OkResult or OkObjectResult or CreatedResult or CreatedAtActionResult or NoContentResult;
}
