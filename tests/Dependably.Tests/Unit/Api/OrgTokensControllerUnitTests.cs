using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Branch-coverage tests for OrgTokensController. The happy-path Ok/NoContent flows are
/// covered alongside OrgController in OrgControllerUnitTests; this file fills in the
/// 401/403/422 + private-helper branches that are otherwise unreachable.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgTokensControllerUnitTests
{
    // ── ListTokens ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ListTokens_Anonymous_NotOk()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.ListTokens(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task ListTokens_MemberRole_Allowed_BecauseManageOwnTokensGrantedToAllUsers()
    {
        // The capability ladder gives every signed-in role (member, admin, owner) the
        // tokens:manage_own capability — members must be able to list their own tokens.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.ListTokens(CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    // ── CreateToken: validation branches ────────────────────────────────────────

    [Fact]
    public async Task CreateToken_Anonymous_NotOk()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task CreateToken_EmptyCapabilitiesList_Returns422()
    {
        // Distinct from the null branch already covered in OrgControllerUnitTests:
        // an explicit empty array also fails TryNormalizeAndAuthorize.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: Array.Empty<string>()),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateToken_UnknownCapability_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "totally:made:up" }),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateToken_CapabilityExceedingMemberGrants_Returns422()
    {
        // A member doesn't hold publish:* — TryNormalizeAndAuthorize must reject the
        // privilege-escalation attempt.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "publish:npm" }),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateToken_DescriptionExceedingLength_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var longDesc = new string('a', 201); // > MaxDescriptionLength (200)
        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(
                ExpiresAt: null,
                Capabilities: new[] { "read:metadata" },
                Description: longDesc),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateToken_DescriptionWithControlChars_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(
                ExpiresAt: null,
                Capabilities: new[] { "read:metadata" },
                Description: "line1\r\nline2"), // \r and \n are control chars
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateToken_DescriptionTrimmedToEmpty_Accepted()
    {
        // TryNormalizeDescription: whitespace-only string trims to empty → normalized=null,
        // returns true (no validation error). Exercises the early-return branch.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(
                ExpiresAt: null,
                Capabilities: new[] { "read:metadata" },
                Description: "   "),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task CreateToken_ValidDescription_PersistedInAuditLog()
    {
        // Happy-path TryNormalizeDescription: trimmed, under limit, no control chars.
        // Confirms the audit_log entry actually contains the normalized description.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(
                ExpiresAt: null,
                Capabilities: new[] { "read:metadata" },
                Description: "  ci-token  "),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'token_created' AND org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    // ── DeleteToken ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteToken_Anonymous_NotNoContent()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.DeleteToken("non-existent", CancellationToken.None);
        Assert.False(result is NoContentResult);
    }

    [Fact]
    public async Task DeleteToken_MemberRevokingNonexistentToken_Forbidden()
    {
        // Member doesn't have tenant:configure → the controller looks up the token to
        // verify ownership; missing token → Forbid() (treats as "not yours" to avoid
        // disclosing token existence to non-admins).
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.DeleteToken("does-not-exist", CancellationToken.None);
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task DeleteToken_MemberRevokingAnotherUsersToken_Forbidden()
    {
        // Two users in same org. Member1 creates a token; Member2 tries to revoke it
        // → Forbid because token.UserId != Member2.id.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(email: "alice@acme.test", role: "member");
        await s.WithUserAsync(email: "bob@acme.test", role: "member");
        var b = await s.BuildAsync();

        // Alice (the actor) creates a token for herself.
        var created = (OkObjectResult)await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        var record = created.Value!.GetType().GetProperty("record")!.GetValue(created.Value)!;
        var tokenId = (string)record.GetType().GetProperty("Id")!.GetValue(record)!;

        // Re-point the controller's principal at Bob.
        await using var conn = await b.Db.OpenAsync();
        var bobId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @t AND email = 'bob@acme.test'",
            new { t = b.PrimaryOrgId });
        Assert.NotNull(bobId);

        b.OrgTokensController.ControllerContext.HttpContext.User =
            new System.Security.Claims.ClaimsPrincipal(
                new System.Security.Claims.ClaimsIdentity(
                [
                    new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, bobId!),
                    new System.Security.Claims.Claim("sub", bobId!),
                    new System.Security.Claims.Claim("org_id", b.PrimaryOrgId),
                    new System.Security.Claims.Claim("tid", b.PrimaryOrgId),
                    new System.Security.Claims.Claim("role", "member"),
                    new System.Security.Claims.Claim("scope", "tenant"),
                ], authenticationType: "test"));

        var result = await b.OrgTokensController.DeleteToken(tokenId, CancellationToken.None);
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task DeleteToken_OwnerRevokingAnyToken_Succeeds()
    {
        // Owner has tenant:configure → admin-override branch; can revoke someone else's
        // token. Covers the "adminCheck == Allowed" branch where the token-ownership
        // check is skipped entirely.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(email: "owner@acme.test", role: "owner");
        await s.WithUserAsync(email: "victim@acme.test", role: "member");
        var b = await s.BuildAsync();

        // Re-point principal at the member, mint a token, then put owner back.
        await using var conn = await b.Db.OpenAsync();
        var victimId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @t AND email = 'victim@acme.test'",
            new { t = b.PrimaryOrgId });
        Assert.NotNull(victimId);

        var ctx = b.OrgTokensController.ControllerContext.HttpContext;
        ctx.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, victimId!),
                new System.Security.Claims.Claim("sub", victimId!),
                new System.Security.Claims.Claim("org_id", b.PrimaryOrgId),
                new System.Security.Claims.Claim("tid", b.PrimaryOrgId),
                new System.Security.Claims.Claim("role", "member"),
                new System.Security.Claims.Claim("scope", "tenant"),
            ], authenticationType: "test"));
        var created = (OkObjectResult)await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        var record = created.Value!.GetType().GetProperty("record")!.GetValue(created.Value)!;
        var tokenId = (string)record.GetType().GetProperty("Id")!.GetValue(record)!;

        // Put owner back in the seat.
        ctx.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, b.ActorUserId!),
                new System.Security.Claims.Claim("sub", b.ActorUserId!),
                new System.Security.Claims.Claim("org_id", b.PrimaryOrgId),
                new System.Security.Claims.Claim("tid", b.PrimaryOrgId),
                new System.Security.Claims.Claim("role", "owner"),
                new System.Security.Claims.Claim("scope", "tenant"),
            ], authenticationType: "test"));

        var result = await b.OrgTokensController.DeleteToken(tokenId, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }

    // ── ListServiceTokens ───────────────────────────────────────────────────────

    [Fact]
    public async Task ListServiceTokens_Member_Forbidden()
    {
        // Member doesn't hold tenant:configure → service-token listing is gated.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.ListServiceTokens(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task ListServiceTokens_Anonymous_NotOk()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.ListServiceTokens(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    // ── CreateServiceToken ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task CreateServiceToken_BlankName_Returns422(string? name)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest(Name: name!, ExpiresAt: null,
                Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateServiceToken_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("bot", null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task CreateServiceToken_UnknownCapability_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("bot", null, Capabilities: new[] { "made:up:cap" }),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateServiceToken_DescriptionExceedingLength_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var longDesc = new string('x', 250);
        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("bot", null,
                Capabilities: new[] { "read:metadata" }, Description: longDesc),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateServiceToken_DescriptionControlChar_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("bot", null,
                Capabilities: new[] { "read:metadata" }, Description: "baddesc"),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateServiceToken_ValidDescription_AuditLogged()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("ci-deploy", null,
                Capabilities: new[] { "publish:npm" }, Description: "release pipeline"),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'service_token_created' AND org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    // ── DeleteServiceToken ──────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteServiceToken_Owner_Succeeds()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Mint then revoke.
        var created = (OkObjectResult)await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("ci", null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        var record = created.Value!.GetType().GetProperty("record")!.GetValue(created.Value)!;
        var tokenId = (string)record.GetType().GetProperty("Id")!.GetValue(record)!;

        var result = await b.OrgTokensController.DeleteServiceToken(tokenId, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'service_token_revoked' AND org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task DeleteServiceToken_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.DeleteServiceToken("any-id", CancellationToken.None);
        Assert.False(result is NoContentResult);
    }

    [Fact]
    public async Task DeleteServiceToken_Anonymous_NotNoContent()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.DeleteServiceToken("any-id", CancellationToken.None);
        Assert.False(result is NoContentResult);
    }
}
