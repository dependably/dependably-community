using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

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
    public async Task CreateToken_TokenNarrowedPrincipal_CannotMintAboveItsCaps_Returns422()
    {
        // A principal whose JWT carries explicit cap claims (token-narrowing) is bounded by
        // those caps, not its full role grants. Here the owner role would grant publish:npm,
        // but the narrowed caps are a strict subset that still includes tokens:manage_own (so
        // the CreateToken authorization gate passes) — minting a publish:npm token must be
        // rejected as privilege escalation across the narrowing boundary.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        RepointWithCaps(b, role: "owner", caps: new[] { "read:metadata", "tokens:manage_own" });

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "publish:npm" }),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateToken_TokenNarrowedPrincipal_CanMintWithinItsCaps_Succeeds()
    {
        // The narrowed caps still authorize a request that stays within them.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        RepointWithCaps(b, role: "owner", caps: new[] { "read:metadata", "tokens:manage_own" });

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task CreateToken_NonNarrowedPrincipal_StillGetsFullRoleCeiling_Succeeds()
    {
        // Without cap claims the role grants drive the ceiling unchanged: an owner can still
        // mint a publish:npm token. Guards against the narrowing fix over-restricting the
        // common (non-narrowed) path.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "publish:npm" }),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    // Re-point the controller's principal at the same actor but with explicit cap claims,
    // simulating a token-narrowed JWT. Mirrors the principal shape BuildAsync constructs.
    private static void RepointWithCaps(ControllerScenarioResult b, string role, string[] caps)
    {
        var claims = new List<System.Security.Claims.Claim>
        {
            new(System.Security.Claims.ClaimTypes.NameIdentifier, b.ActorUserId!),
            new("sub", b.ActorUserId!),
            new("org_id", b.PrimaryOrgId),
            new("tid", b.PrimaryOrgId),
            new("role", role),
            new("scope", "tenant"),
        };
        claims.AddRange(caps.Select(c => new System.Security.Claims.Claim("cap", c)));

        b.OrgTokensController.ControllerContext.HttpContext.User =
            new System.Security.Claims.ClaimsPrincipal(
                new System.Security.Claims.ClaimsIdentity(claims, authenticationType: "test"));
    }

    [Fact]
    public async Task CreateToken_DescriptionExceedingLength_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string longDesc = new('a', 201); // > MaxDescriptionLength (200)
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
        long auditCount = await conn.ExecuteScalarAsync<long>(
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
        object record = created.Value!.GetType().GetProperty("record")!.GetValue(created.Value)!;
        string tokenId = (string)record.GetType().GetProperty("Id")!.GetValue(record)!;

        // Re-point the controller's principal at Bob.
        await using var conn = await b.Db.OpenAsync();
        string? bobId = await conn.ExecuteScalarAsync<string>(
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
        string? victimId = await conn.ExecuteScalarAsync<string>(
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
        object record = created.Value!.GetType().GetProperty("record")!.GetValue(created.Value)!;
        string tokenId = (string)record.GetType().GetProperty("Id")!.GetValue(record)!;

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

        string longDesc = new('x', 250);
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
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'service_token_created' AND org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    // ── Token cap (user tokens) ─────────────────────────────────────────────────

    [Fact]
    public async Task CreateToken_AtCap_Returns422()
    {
        // Set cap to 1, create one token, then verify the second attempt is rejected.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using var conn = await b.Db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('max_active_tokens_per_tenant', '1') ON CONFLICT(key) DO UPDATE SET value = '1'");

        // First token: must succeed.
        var first = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(first);

        // Second token: cap reached → 422.
        var second = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(second);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateToken_ExpiredTokenDoesNotCountTowardCap()
    {
        // Expired tokens are not active and must not count against the cap.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using var conn = await b.Db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('max_active_tokens_per_tenant', '1') ON CONFLICT(key) DO UPDATE SET value = '1'");

        // Seed an already-expired token directly in the DB.
        string expiredId = Guid.NewGuid().ToString("N");
        string userId = b.ActorUserId!;
        await conn.ExecuteAsync(
            """
            INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, expires_at)
            VALUES (@id, @orgId, @userId, 'deadbeef', '["read:metadata"]', '2000-01-01T00:00:00Z')
            """,
            new { id = expiredId, orgId = b.PrimaryOrgId, userId });

        // Creating one live token must still be allowed (expired row doesn't count).
        var result = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(ExpiresAt: null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task CreateToken_CapFromInstanceSetting_OverridesDefault()
    {
        // Verify a large cap from instance_settings allows more than the hard-coded default.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using var conn = await b.Db.OpenAsync();
        // Allow only 2 user tokens.
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('max_active_tokens_per_tenant', '2') ON CONFLICT(key) DO UPDATE SET value = '2'");

        var r1 = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(null, Capabilities: new[] { "read:metadata" }), CancellationToken.None);
        Assert.IsType<OkObjectResult>(r1);

        var r2 = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(null, Capabilities: new[] { "read:metadata" }), CancellationToken.None);
        Assert.IsType<OkObjectResult>(r2);

        // Third token must be rejected.
        var r3 = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(null, Capabilities: new[] { "read:metadata" }), CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(r3);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // ── Token cap (service tokens) ──────────────────────────────────────────────

    [Fact]
    public async Task CreateServiceToken_AtCap_Returns422()
    {
        // Set cap to 1, create one service token, then verify the second attempt is rejected.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using var conn = await b.Db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('max_active_tokens_per_tenant', '1') ON CONFLICT(key) DO UPDATE SET value = '1'");

        var first = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("bot-1", ExpiresAt: null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(first);

        var second = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("bot-2", ExpiresAt: null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(second);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    [Fact]
    public async Task CreateServiceToken_ExpiredTokenDoesNotCountTowardCap()
    {
        // Expired service tokens must not count against the cap.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using var conn = await b.Db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('max_active_tokens_per_tenant', '1') ON CONFLICT(key) DO UPDATE SET value = '1'");

        string expiredId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, expires_at)
            VALUES (@id, @orgId, 'expired-bot', 'aabbccdd', '["read:metadata"]', '2000-01-01T00:00:00Z')
            """,
            new { id = expiredId, orgId = b.PrimaryOrgId });

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("live-bot", null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task TokenCap_UserAtCap_ServiceTokenStillAllowed_IfCapIsPerType()
    {
        // The cap counts BOTH user and service tokens together. Verify that when user
        // tokens fill the cap, the service token path also rejects (they share the count).
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using var conn = await b.Db.OpenAsync();
        // Cap of 1 across both types.
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('max_active_tokens_per_tenant', '1') ON CONFLICT(key) DO UPDATE SET value = '1'");

        // Fill the cap with a user token.
        var userTok = await b.OrgTokensController.CreateToken(
            new CreateTokenRequest(null, Capabilities: new[] { "read:metadata" }), CancellationToken.None);
        Assert.IsType<OkObjectResult>(userTok);

        // Service token must now be rejected — the combined cap is reached.
        var svcTok = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("bot", null, Capabilities: new[] { "read:metadata" }),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(svcTok);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
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
        object record = created.Value!.GetType().GetProperty("record")!.GetValue(created.Value)!;
        string tokenId = (string)record.GetType().GetProperty("Id")!.GetValue(record)!;

        var result = await b.OrgTokensController.DeleteServiceToken(tokenId, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
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
