using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Pins the weak-password-policy-context bug: <c>AcceptInvite</c> and <c>ChangePassword</c>
/// must evaluate <see cref="Dependably.Security.PasswordPolicy"/> with the caller's own
/// email/tenant slug, not an always-empty <c>PasswordContext</c>. Both candidate passwords
/// below score 4/4 on zxcvbn in isolation (verified directly against
/// <c>Zxcvbn.Core.EvaluatePassword</c>) — the only thing that can reject them is the
/// context-dictionary check, so a pass on the old (empty-context) code and a reject on the
/// fixed code isolates exactly the bug described.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuthControllerPasswordPolicyContextTests : IAsyncLifetime
{
    private readonly InMemoryDbFixture _fixture = new();

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        // Both actions issue/re-issue a session JWT past the policy check — a signing secret
        // must exist so a rejected-vs-accepted password produces a clean Ok/BadRequest
        // assertion instead of an unrelated "secret missing" exception on the old code.
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', @secret) ON CONFLICT(key) DO NOTHING",
            new { secret = "unit-test-secret-min-32-chars-xxxxxx" });
    }

    public Task DisposeAsync() => _fixture.DisposeAsync();

    private AuthController BuildController(out InviteRepository invites)
    {
        var db = _fixture.Store;
        var clock = TestTime.Frozen();
        var orgs = new OrgRepository(db);
        var users = new UserService(db, orgs);
        var audit = new AuditRepository(db);
        var admins = new SystemAdminRepository(db);
        invites = new InviteRepository(db, clock);
        var revocations = new JwtRevocationRepository(db);
        var login = new LoginService(new LoginService.Dependencies(
            Db: db,
            Orgs: orgs,
            SystemAdmins: admins,
            Lockout: Substitute.For<ILockoutStore>(),
            Audit: audit,
            ExternalIdentities: new ExternalIdentityRepository(db, clock),
            AuditEmitter: Substitute.For<Dependably.Infrastructure.Audit.IAuditEmitter>(),
            Time: clock,
            Mfa: Substitute.For<IMfaEnrollmentService>(),
            SystemMfa: Substitute.For<ISystemMfaEnrollmentService>()));

        var urls = Substitute.For<IPublicUrlBuilder>();
        urls.SessionCookieOptions(Arg.Any<HttpContext>(), Arg.Any<SameSiteMode>()).Returns(new CookieOptions());

        var controller = new AuthController(
            login, users, revocations, audit, urls, clock, orgs,
            Substitute.For<IRequireMfaMode>(), admins);

        var http = new DefaultHttpContext { Request = { Scheme = "https", Host = new HostString("acme.example.test") } };
        controller.ControllerContext = new ControllerContext { HttpContext = http };
        return controller;
    }

    // ── AcceptInvite: password contains the invite's own tenant slug ────────────

    [Fact]
    public async Task AcceptInvite_PasswordContainsTenantSlug_RejectedByPolicy_AndInviteNotConsumed()
    {
        var controller = BuildController(out var invites);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, "acme");
        string ownerId = await UserSeeder.InsertAsync(_fixture.Store, orgId, "owner@acme.test", role: "owner");
        var (rawToken, _) = (await invites.CreateAsync(orgId, "invitee@acme.test", ownerId, role: "member"))!;

        // High zxcvbn entropy (score 4/4 in isolation) but contains the org's own slug "acme" —
        // only the context-dictionary check (fed by the tenant slug) can reject this.
        const string weakInContextOnly = "Xk7$pQwacmeuTz2v9Lm";

        var result = await controller.AcceptInvite(
            new AcceptInviteRequest(rawToken, weakInContextOnly), invites, CancellationToken.None);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(bad.Value);
        Assert.Contains("\"field\":\"password\"", json);

        // The invite must still be usable — a rejected password never burns the single-use token.
        var stillPending = await invites.PeekPendingAsync(rawToken, CancellationToken.None);
        Assert.NotNull(stillPending);
    }

    // ── ChangePassword: new password contains the caller's own email local-part ────

    [Fact]
    public async Task ChangePassword_NewPasswordContainsOwnEmailLocalPart_RejectedByPolicy()
    {
        var controller = BuildController(out _);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, "acme");
        string userId = await UserSeeder.InsertAsync(
            _fixture.Store, orgId, "quinlan.vega@acme.test", role: "member", password: "Password12345");

        controller.ControllerContext.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("sub", userId),
                new System.Security.Claims.Claim("tid", orgId),
                new System.Security.Claims.Claim("org_id", orgId),
                new System.Security.Claims.Claim("role", "member"),
            ], authenticationType: "test"));

        // High zxcvbn entropy (score 4/4 in isolation) but contains the caller's own email
        // local-part "quinlan.vega" — only the context-dictionary check (fed by the caller's
        // own email) can reject this.
        const string weakInContextOnly = "Quinlan.Vega2027!TidalWave99";

        var result = await controller.ChangePassword(
            new ChangePasswordRequest("Password12345", weakInContextOnly), null!, CancellationToken.None);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        string json = System.Text.Json.JsonSerializer.Serialize(bad.Value);
        Assert.Contains("\"field\":\"newPassword\"", json);
    }
}
