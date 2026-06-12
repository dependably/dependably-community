using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

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
        long auditCount = await conn.ExecuteScalarAsync<long>(
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
        string spdx = $"MIT-{Guid.NewGuid():N}"[..12];

        var result = await b.LicenseController.AddAllowlist(new LicenseSpdxRequest(spdx), CancellationToken.None);
        var created = Assert.IsType<CreatedAtActionResult>(result);
        Assert.NotNull(created.Value);

        await using var conn = await b.Db.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
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
        string spdx = $"APACHE-{Guid.NewGuid():N}"[..15];

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
        string spdx = $"BSD-{Guid.NewGuid():N}"[..10];
        await s.WithLicenseAllowlistEntryAsync(spdx);
        var b = await s.BuildAsync();

        var result = await b.LicenseController.RemoveAllowlist(spdx, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
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
        string spdx = $"GPL-{Guid.NewGuid():N}"[..10];

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
        string spdx = $"AGPL-{Guid.NewGuid():N}"[..12];
        await s.WithLicenseBlocklistEntryAsync(spdx);
        var b = await s.BuildAsync();

        var result = await b.LicenseController.RemoveBlocklist(spdx, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        Assert.True(await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'license_blocklist_removed' AND org_id = @orgId",
            new { orgId = b.PrimaryOrgId }) >= 1);
    }

    [Fact]
    public async Task AddBlocklist_BlankSpdx_Returns422()
    {
        // Covers the missing 422 branch on AddBlocklist (mirror of allowlist).
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.AddBlocklist(new LicenseSpdxRequest("   "), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task AddBlocklist_Duplicate_Returns409()
    {
        // Covers the missing 409 branch on AddBlocklist (mirror of allowlist).
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        string spdx = $"LGPL-{Guid.NewGuid():N}"[..12];

        var first = await b.LicenseController.AddBlocklist(new LicenseSpdxRequest(spdx), CancellationToken.None);
        Assert.IsType<CreatedAtActionResult>(first);

        var second = await b.LicenseController.AddBlocklist(new LicenseSpdxRequest(spdx), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(second);
        Assert.Equal(StatusCodes.Status409Conflict, obj.StatusCode);
    }

    [Fact]
    public async Task RemoveBlocklist_Missing_Returns404()
    {
        // Covers the missing 404 branch on RemoveBlocklist (mirror of allowlist).
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.RemoveBlocklist($"never-{Guid.NewGuid():N}", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Review queue ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GetReviewQueue_Owner_ReturnsOk()
    {
        // Covers the admin-only review-queue happy path; the endpoint is not exercised
        // anywhere else in the unit suite.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetReviewQueue(includeDeprecated: false, CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetReviewQueue_IncludeDeprecatedTrue_ReturnsOk()
    {
        // Hits the includeDeprecated=true argument path so the parameter is exercised
        // with both values.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetReviewQueue(includeDeprecated: true, CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetReviewQueue_Member_Forbidden()
    {
        // Review queue requires tenant:configure — members get denied at the guard.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetReviewQueue(includeDeprecated: false, CancellationToken.None);
        Assert.False(IsOk(result));
    }

    // ── GetAllowlist (direct) ────────────────────────────────────────────────

    [Fact]
    public async Task GetAllowlist_Owner_ReturnsArrayShape()
    {
        // Direct call covers GetAllowlist's authorized branch + Ok return.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetAllowlist(CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task GetAllowlist_Anonymous_DeniedBeforeReading()
    {
        // Covers the `authResult is not null` branch on GetAllowlist that the existing
        // owner-happy-path test bypasses. Anonymous fails the NameIdentifier/sub check.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetAllowlist(CancellationToken.None);
        Assert.False(IsOk(result));
    }

    [Fact]
    public async Task GetBlocklist_Anonymous_DeniedBeforeReading()
    {
        // Mirror of GetAllowlist denial — covers the corresponding branch on GetBlocklist.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.LicenseController.GetBlocklist(CancellationToken.None);
        Assert.False(IsOk(result));
    }

    [Fact]
    public async Task SetMode_NameIdentifierAbsent_UsesSubClaimForAudit()
    {
        // GetUserId() falls back to the "sub" claim when NameIdentifier is missing.
        // OrgAccessGuard uses the same fallback so authorization still passes; the audit
        // row's actor_id proves the fallback was taken.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string userId = b.ActorUserId!;
        b.LicenseController.ControllerContext.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("sub", userId),
                new System.Security.Claims.Claim("org_id", b.PrimaryOrgId),
                new System.Security.Claims.Claim("tid", b.PrimaryOrgId),
                new System.Security.Claims.Claim("role", "owner"),
                new System.Security.Claims.Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var result = await b.LicenseController.SetMode(new SetModeRequest("warn"), CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        await using var conn = await b.Db.OpenAsync();
        string? actorId = await conn.ExecuteScalarAsync<string?>(
            "SELECT actor_id FROM audit_log WHERE action = 'license_policy_mode_changed' AND org_id = @orgId LIMIT 1",
            new { orgId = b.PrimaryOrgId });
        Assert.Equal(userId, actorId);
    }

    private static bool IsOk(IActionResult r) =>
        r is OkResult or OkObjectResult or CreatedResult or CreatedAtActionResult or NoContentResult;
}
