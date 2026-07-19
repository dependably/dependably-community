using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Pins the logout revocation-failure bug: <c>Logout</c> must not report "Logged out." (200)
/// when the jwt_revocations write actually fails — the malformed-token catch is narrow, and a
/// revocation-store failure propagates instead of being swallowed as success.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuthControllerLogoutRevocationTests
{
    private static string BuildSessionJwt(string jti)
    {
        var handler = new JwtSecurityTokenHandler();
        var claims = new[] { new Claim(JwtRegisteredClaimNames.Jti, jti) };
        // A fixed future instant — only the cookie's parseability and jti matter to
        // TryRevokeSessionCookieAsync, never wall-clock "now".
        var expires = TestTime.KnownNow.AddHours(8).UtcDateTime;
        var token = new JwtSecurityToken(claims: claims, expires: expires);
        return handler.WriteToken(token);
    }

    private static AuthController BuildController(JwtRevocationRepository revocations)
    {
        // None of Logout's other dependencies are exercised by the code path under test, so
        // they're wired against a harmless real (non-throwing) in-memory store.
        var harmlessDb = Substitute.For<IMetadataStore>();
        var orgs = new OrgRepository(harmlessDb);
        var users = new UserService(harmlessDb, orgs);
        var audit = new AuditRepository(harmlessDb);
        var admins = new SystemAdminRepository(harmlessDb);
        var login = new LoginService(new LoginService.Dependencies(
            Db: harmlessDb,
            Orgs: orgs,
            SystemAdmins: admins,
            Lockout: Substitute.For<ILockoutStore>(),
            Audit: audit,
            ExternalIdentities: new ExternalIdentityRepository(harmlessDb, TimeProvider.System),
            AuditEmitter: Substitute.For<Dependably.Infrastructure.Audit.IAuditEmitter>(),
            Time: TimeProvider.System,
            Mfa: Substitute.For<IMfaEnrollmentService>(),
            SystemMfa: Substitute.For<ISystemMfaEnrollmentService>()));

        var controller = new AuthController(
            login, users, revocations, audit,
            Substitute.For<IPublicUrlBuilder>(), TimeProvider.System, orgs,
            Substitute.For<IRequireMfaMode>(), admins);

        var http = new DefaultHttpContext();
        controller.ControllerContext = new ControllerContext { HttpContext = http };
        return controller;
    }

    private static void SetSessionCookie(AuthController controller, string token) =>
        controller.ControllerContext.HttpContext.Request.Headers.Append(
            "Cookie", new StringValues($"dependably_session={token}"));

    // ── Revocation-store failure must not be swallowed as success ──────────────

    [Fact]
    public async Task Logout_RevocationStoreThrows_DoesNotReturnLoggedOut()
    {
        // A DB that always throws on OpenAsync simulates "DB locked/unavailable" for RevokeAsync.
        var throwingDb = Substitute.For<IMetadataStore>();
        throwingDb.OpenAsync(Arg.Any<CancellationToken>())
            .Returns<Task<System.Data.Common.DbConnection>>(_ => throw new InvalidOperationException("db unavailable"));
        var revocations = new JwtRevocationRepository(throwingDb);

        var controller = BuildController(revocations);
        SetSessionCookie(controller, BuildSessionJwt("jti-" + Guid.NewGuid().ToString("N")));

        // On the old (buggy) code, the blanket catch around RevokeAsync swallows this and
        // Logout returns Ok(new { message = "Logged out." }) — a false success while the
        // session JWT's jti was never revoked. The fix lets the failure propagate.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => controller.Logout(CancellationToken.None));
    }

    // ── Malformed cookie still logs out cleanly (unchanged behavior) ────────────

    [Fact]
    public async Task Logout_MalformedCookie_StillReturnsLoggedOut()
    {
        var throwingDb = Substitute.For<IMetadataStore>();
        throwingDb.OpenAsync(Arg.Any<CancellationToken>())
            .Returns<Task<System.Data.Common.DbConnection>>(_ => throw new InvalidOperationException("should not be reached"));
        var revocations = new JwtRevocationRepository(throwingDb);

        var controller = BuildController(revocations);
        SetSessionCookie(controller, "not-a-jwt");

        var result = await controller.Logout(CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
    }
}
