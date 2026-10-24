using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Refusal and edge paths of <c>/api/v1/auth</c> and the self-service <c>/api/v1/users/me</c>
/// routes: invite acceptance, password reset and change, email-change confirmation, logout with
/// a damaged cookie, language and timezone preferences, and the second-factor lockout reached
/// with a challenge issued before the account locked. Each refusal is paired with a check that
/// the credential or preference it guards was not changed.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AuthControllerCoverageTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    // Fixture credentials: strong enough to satisfy the password policy, not real secrets.
    private const string StrongPassword = "Xm9#kLp2$vRq8nTs!";
    private const string OtherStrongPassword = "Qz7!wNd4%hYc6bGe#";

    private readonly DependablyFactory _factory;
    public AuthControllerCoverageTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private HttpClient CookielessClient() =>
        _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
        });

    private async Task<(string UserId, HttpClient Client)> NewUserClientAsync(string password = StrongPassword)
    {
        string email = $"auth-cov-{Guid.NewGuid():N}@test.local";
        string id = await _factory.CreateUser(email, password);
        return (id, _factory.CreateClientWithBearer(await _factory.CreateUserJwt(id, "member")));
    }

    private async Task<string> OwnerIdAsync()
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT u.id FROM users u JOIN orgs o ON o.id = u.tenant_id WHERE o.slug = 'default' AND u.role = 'owner' LIMIT 1")
            ?? throw new InvalidOperationException("Bootstrap owner not found.");
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    // ── Second-factor lockout reached with a pre-lockout challenge ───────────────────────────

    [Fact]
    public async Task LoginTotp_GarbledChallengeCookie_IsUnauthorized()
    {
        using var c = CookielessClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login/totp")
        {
            Content = JsonContent.Create(new { code = "123456" }),
        };
        req.Headers.Add("Cookie", "dependably_mfa=not.a.jwt");

        var resp = await c.SendAsync(req);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.False(resp.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(h => h.StartsWith("dependably_session=", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task LoginTotp_ChallengeIssuedBeforeLockout_GetsRetryAfterEvenWithTheRightCode()
    {
        string email = $"auth-cov-mfa-{Guid.NewGuid():N}@test.local";
        string userId = await _factory.CreateUser(email, StrongPassword);
        string manualKey = await EnrollAsync(userId);
        using var c = CookielessClient();

        var step1 = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = StrongPassword });
        Assert.Equal(HttpStatusCode.OK, step1.StatusCode);
        string challenge = CookieValue(step1, "dependably_mfa")!;

        // Exhaust the shared failure budget with wrong passwords; the challenge stays unrevoked.
        for (int i = 0; i < 12; i++)
        {
            var wrong = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "WrongPassword9!" });
            if (wrong.StatusCode == HttpStatusCode.TooManyRequests)
            {
                break;
            }
        }

        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login/totp")
        {
            Content = JsonContent.Create(new { code = TotpTestHelper.Compute(manualKey) }),
        };
        req.Headers.Add("Cookie", $"dependably_mfa={challenge}");
        var locked = await c.SendAsync(req);

        Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
        Assert.True(locked.Headers.Contains("Retry-After"));
        Assert.Null(CookieValue(locked, "dependably_session"));
    }

    private async Task<string> EnrollAsync(string userId)
    {
        using var client = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(userId, "member"));
        var begin = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        begin.EnsureSuccessStatusCode();
        string key = (await ProblemBody.ReadAsync(begin)).GetProperty("manualKey").GetString()!;
        foreach (string code in TotpTestHelper.ComputeWindow(key))
        {
            if ((await client.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code })).IsSuccessStatusCode)
            {
                return key;
            }
        }

        throw new InvalidOperationException("Could not enrol MFA.");
    }

    private static string? CookieValue(HttpResponseMessage resp, string name)
    {
        if (!resp.Headers.TryGetValues("Set-Cookie", out var headers))
        {
            return null;
        }

        foreach (string header in headers)
        {
            string pair = header.Split(';')[0].Trim();
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if (eq > 0 && pair[..eq] == name && pair.Length > eq + 1)
            {
                return pair[(eq + 1)..];
            }
        }

        return null;
    }

    // ── Invite acceptance ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AcceptInvite_BlankToken_IsBadRequest()
    {
        using var c = _factory.CreateClient();

        var resp = await c.PostAsJsonAsync("/api/v1/invites/accept", new { token = "  ", password = StrongPassword });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task AcceptInvite_WeakPassword_IsRefusedWithoutSpendingTheInvite()
    {
        var invites = _factory.Services.GetRequiredService<InviteRepository>();
        string email = $"invitee-{Guid.NewGuid():N}@test.local";
        var (raw, _) = (await invites.CreateAsync(await DefaultOrgIdAsync(), email, await OwnerIdAsync(), "member"))!;
        using var c = _factory.CreateClient();

        var weak = await c.PostAsJsonAsync("/api/v1/invites/accept", new { token = raw, password = "password" });

        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
        Assert.Equal("password", (await ProblemBody.ReadAsync(weak)).GetProperty("field").GetString());
        // The same link still works with an acceptable password: the failed check did not burn it.
        var good = await c.PostAsJsonAsync("/api/v1/invites/accept", new { token = raw, password = StrongPassword });
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
    }

    [Fact]
    public async Task AcceptInvite_UnknownToken_IsGone()
    {
        using var c = _factory.CreateClient();

        var resp = await c.PostAsJsonAsync("/api/v1/invites/accept", new { token = "no-such-invite-token", password = StrongPassword });

        Assert.Equal(HttpStatusCode.Gone, resp.StatusCode);
    }

    [Fact]
    public async Task AcceptInvite_EmailThatAlreadyHasAnAccount_ConflictsAndCreatesNoSecondUser()
    {
        var invites = _factory.Services.GetRequiredService<InviteRepository>();
        string email = $"dup-{Guid.NewGuid():N}@test.local";
        var (raw, _) = (await invites.CreateAsync(await DefaultOrgIdAsync(), email, await OwnerIdAsync(), "member"))!;
        await _factory.CreateUser(email.ToUpperInvariant(), StrongPassword);
        using var c = _factory.CreateClient();

        var resp = await c.PostAsJsonAsync("/api/v1/invites/accept", new { token = raw, password = OtherStrongPassword });

        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
        await using var conn = await Db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM users WHERE LOWER(email) = @email", new { email }));
    }

    // ── Forgot / reset password ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ForgotPassword_BlankEmail_IsBadRequest()
    {
        using var c = _factory.CreateClient();

        var resp = await c.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = " " });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task ResetPassword_BlankToken_IsBadRequest_AndUnknownTokenIsGone()
    {
        using var c = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.BadRequest,
            (await c.PostAsJsonAsync("/api/v1/auth/reset-password", new { token = "", newPassword = StrongPassword })).StatusCode);
        Assert.Equal(HttpStatusCode.Gone,
            (await c.PostAsJsonAsync("/api/v1/auth/reset-password", new { token = "unknown-reset-token", newPassword = StrongPassword })).StatusCode);
    }

    [Fact]
    public async Task ResetPassword_WeakPassword_IsRefusedAndTheLinkSurvives()
    {
        string email = $"reset-weak-{Guid.NewGuid():N}@test.local";
        string userId = await _factory.CreateUser(email, StrongPassword);
        var tokens = _factory.Services.GetRequiredService<PasswordResetTokenRepository>();
        string raw = await tokens.IssueAsync(userId, await DefaultOrgIdAsync());
        using var c = _factory.CreateClient();

        var weak = await c.PostAsJsonAsync("/api/v1/auth/reset-password", new { token = raw, newPassword = "short" });

        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
        Assert.Equal("newPassword", (await ProblemBody.ReadAsync(weak)).GetProperty("field").GetString());
        var good = await c.PostAsJsonAsync("/api/v1/auth/reset-password", new { token = raw, newPassword = OtherStrongPassword });
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        var login = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = OtherStrongPassword });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    // ── Email-change confirmation ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ConfirmEmailChange_BlankOrUnknownToken_IsRefused()
    {
        using var c = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.BadRequest,
            (await c.PostAsJsonAsync("/api/v1/auth/confirm-email-change", new { token = " " })).StatusCode);
        Assert.Equal(HttpStatusCode.Gone,
            (await c.PostAsJsonAsync("/api/v1/auth/confirm-email-change", new { token = "unknown-change-token" })).StatusCode);
    }

    [Fact]
    public async Task ConfirmEmailChange_AddressTakenSinceTheRequest_ConflictsAndLeavesTheEmailAlone()
    {
        string original = $"mover-{Guid.NewGuid():N}@test.local";
        string target = $"taken-{Guid.NewGuid():N}@test.local";
        string userId = await _factory.CreateUser(original, StrongPassword);
        var changes = _factory.Services.GetRequiredService<EmailChangeTokenRepository>();
        string raw = await changes.IssueAsync(userId, await DefaultOrgIdAsync(), target);
        await _factory.CreateUser(target, StrongPassword);
        using var c = _factory.CreateClient();

        var resp = await c.PostAsJsonAsync("/api/v1/auth/confirm-email-change", new { token = raw });

        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
        await using var conn = await Db.OpenAsync();
        Assert.Equal(original, await conn.ExecuteScalarAsync<string>(
            "SELECT email FROM users WHERE id = @userId", new { userId }));
    }

    // ── Password change ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ChangePassword_RefusalsLeaveTheCredentialUnchanged_AndASuccessRotatesIt()
    {
        string email = $"chg-{Guid.NewGuid():N}@test.local";
        string userId = await _factory.CreateUser(email, StrongPassword);
        using var user = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(userId, "member"));
        const string Path = "/api/v1/users/me/password";

        Assert.Equal(HttpStatusCode.BadRequest,
            (await user.PostAsJsonAsync(Path, new { currentPassword = " ", newPassword = OtherStrongPassword })).StatusCode);
        var weak = await user.PostAsJsonAsync(Path, new { currentPassword = StrongPassword, newPassword = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
        Assert.Equal("newPassword", (await ProblemBody.ReadAsync(weak)).GetProperty("field").GetString());
        var wrong = await user.PostAsJsonAsync(Path, new { currentPassword = "NotMyPassword9!", newPassword = OtherStrongPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        var same = await user.PostAsJsonAsync(Path, new { currentPassword = StrongPassword, newPassword = StrongPassword });
        Assert.Equal(HttpStatusCode.BadRequest, same.StatusCode);

        using var anon = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK,
            (await anon.PostAsJsonAsync("/api/v1/auth/login", new { email, password = StrongPassword })).StatusCode);

        var changed = await user.PostAsJsonAsync(Path, new { currentPassword = StrongPassword, newPassword = OtherStrongPassword });
        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anon.PostAsJsonAsync("/api/v1/auth/login", new { email, password = StrongPassword })).StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await anon.PostAsJsonAsync("/api/v1/auth/login", new { email, password = OtherStrongPassword })).StatusCode);
    }

    [Fact]
    public async Task ChangePassword_ForAUserDeletedMidSession_IsUnauthorized()
    {
        var (userId, client) = await NewUserClientAsync();
        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM users WHERE id = @userId", new { userId });
        }

        var resp = await client.PostAsJsonAsync(
            "/api/v1/users/me/password", new { currentPassword = StrongPassword, newPassword = OtherStrongPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Logout ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Logout_WithAMalformedSessionCookie_StillSucceedsAndClearsIt()
    {
        using var c = CookielessClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", "dependably_session=%%%not-a-jwt%%%");

        var resp = await c.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(h => h.StartsWith("dependably_session=;", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Logout_WithACookieThatLooksLikeAJwtButDoesNotDecode_StillSucceedsAndClearsIt()
    {
        using var c = CookielessClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", "dependably_session=e30.bm90LWpzb24.c2ln");

        var resp = await c.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(h => h.StartsWith("dependably_session=;", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("", "somePassword1!")]
    [InlineData("someone@test.local", "")]
    [InlineData("   ", "   ")]
    public async Task Login_BlankEmailOrPassword_IsBadRequest_AndSetsNoCookie(string email, string password)
    {
        using var c = CookielessClient();

        var resp = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.False(resp.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Logout_WithARealSession_RevokesItsJti_SoTheTokenStopsWorking()
    {
        string userId = await _factory.CreateUser($"logout-{Guid.NewGuid():N}@test.local", StrongPassword);
        string jwt = await _factory.CreateUserJwt(userId, "member");
        string jti = new JwtSecurityTokenHandler().ReadJwtToken(jwt).Id;
        using var viaHeader = _factory.CreateClientWithBearer(jwt);
        Assert.Equal(HttpStatusCode.OK, (await viaHeader.GetAsync("/api/v1/auth/me")).StatusCode);

        using var cookieClient = CookielessClient();
        using var logout = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        logout.Headers.Add("Cookie", $"dependably_session={jwt}");
        Assert.Equal(HttpStatusCode.OK, (await cookieClient.SendAsync(logout)).StatusCode);

        var revocations = _factory.Services.GetRequiredService<JwtRevocationRepository>();
        Assert.True(await revocations.IsRevokedAsync(jti));
        Assert.Equal(HttpStatusCode.Unauthorized, (await viaHeader.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    // ── Language and timezone preferences ────────────────────────────────────────────────────

    [Fact]
    public async Task UpdateLanguage_UnsupportedCode_IsRefusedAndThePreferenceStays()
    {
        var (_, client) = await NewUserClientAsync();
        Assert.Equal(HttpStatusCode.NoContent,
            (await client.PostAsJsonAsync("/api/v1/users/me/language", new { language = "fr" })).StatusCode);

        foreach (string bad in new[] { "xx", "", "  ", "EN" })
        {
            var resp = await client.PostAsJsonAsync("/api/v1/users/me/language", new { language = bad });
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        }

        var me = await ProblemBody.ReadAsync(await client.GetAsync("/api/v1/auth/me"));
        Assert.Equal("fr", me.GetProperty("language").GetString());
    }

    [Fact]
    public async Task UpdateTimezone_SetsAnIanaZone_RefusesUnknownOnes_AndBlankClearsTheOverride()
    {
        var (_, client) = await NewUserClientAsync();
        const string Path = "/api/v1/users/me/timezone";

        Assert.Equal(HttpStatusCode.NoContent,
            (await client.PostAsJsonAsync(Path, new { timezone = "America/Toronto" })).StatusCode);
        var me = await ProblemBody.ReadAsync(await client.GetAsync("/api/v1/auth/me"));
        Assert.Equal("America/Toronto", me.GetProperty("timezone").GetString());
        Assert.Equal("America/Toronto", me.GetProperty("resolvedTimezone").GetString());

        var bad = await client.PostAsJsonAsync(Path, new { timezone = "Mars/Olympus_Mons" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Contains("Mars/Olympus_Mons", await bad.Content.ReadAsStringAsync());
        me = await ProblemBody.ReadAsync(await client.GetAsync("/api/v1/auth/me"));
        Assert.Equal("America/Toronto", me.GetProperty("timezone").GetString());

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync(Path, new { timezone = "  " })).StatusCode);
        me = await ProblemBody.ReadAsync(await client.GetAsync("/api/v1/auth/me"));
        Assert.Equal(JsonValueKind.Null, me.GetProperty("timezone").ValueKind);
        await using var conn = await Db.OpenAsync();
        Assert.True(await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'user.timezone_changed'") >= 2);
    }

    [Fact]
    public async Task ExportMyData_ForAUserDeletedMidSession_IsUnauthorized_AndForALiveUserCoversOnlyThatUser()
    {
        var (userId, client) = await NewUserClientAsync();
        var export = await client.GetAsync("/api/v1/users/me/export");
        Assert.Equal(HttpStatusCode.OK, export.StatusCode);
        Assert.DoesNotContain(
            await OwnerIdAsync(), await export.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM users WHERE id = @userId", new { userId });
        }

        var gone = await client.GetAsync("/api/v1/users/me/export");
        Assert.Equal(HttpStatusCode.Unauthorized, gone.StatusCode);
    }

    [Fact]
    public async Task Me_ForAPatLackingReadTenant_IsForbidden_AndForTheOwnerSessionIsOk()
    {
        using var pat = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));

        var denied = await pat.GetAsync("/api/v1/auth/me");

        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        using var owner = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        Assert.Equal(HttpStatusCode.OK, (await owner.GetAsync("/api/v1/auth/me")).StatusCode);
    }
}

/// <summary>
/// Multi-tenant host edges of the auth surface: the apex answers the login-methods probe with
/// forms only, refuses password reset (a system admin has no tenant user store), and a system
/// second factor reached with a pre-lockout challenge gets the same Retry-After a tenant does.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AuthControllerApexTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private const string AdminPassword = "SysTestMfa1!";

    private readonly DependablyMultiFactory _factory;
    public AuthControllerApexTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private HttpClient ApexClient(bool cookies = true)
    {
        var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = cookies,
        });
        client.DefaultRequestHeaders.Host = DependablyMultiFactory.ApexHost;
        return client;
    }

    [Fact]
    public async Task Methods_OnTheApex_OffersFormsOnly()
    {
        using var c = ApexClient();

        var body = await ProblemBody.ReadAsync(await c.GetAsync("/api/v1/auth/methods"));

        Assert.True(body.GetProperty("forms").GetBoolean());
        Assert.False(body.GetProperty("saml").GetBoolean());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("samlButtonLabel").ValueKind);
    }

    [Fact]
    public async Task ForgotPassword_OnTheApex_IsNotFound_AndIssuesNothing()
    {
        using var c = ApexClient();

        var resp = await c.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = "system@dependably.local" });

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM password_reset_tokens"));
    }

    [Fact]
    public async Task Login_OnAnUnknownTenantSubdomain_IsNotFound()
    {
        using var c = _factory.CreateClientForHost($"no-such-tenant.{DependablyMultiFactory.ApexHost}");

        var resp = await c.PostAsJsonAsync("/api/v1/auth/login", new { email = "a@b.test", password = "irrelevant" });

        Assert.True(resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task SystemLoginTotp_ChallengeIssuedBeforeLockout_GetsRetryAfterEvenWithTheRightCode()
    {
        var admins = _factory.Services.GetRequiredService<SystemAdminRepository>();
        string email = $"sys-lock-{Guid.NewGuid():N}@test.local";
        string id = await admins.CreateAsync(
            email, BCrypt.Net.BCrypt.HashPassword(AdminPassword, workFactor: 4), mustChangePassword: false);
        using var enroller = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        enroller.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateSystemAdminJwtForUser(id));
        var begin = await enroller.PostAsync("/api/v1/system/mfa/setup/begin", null);
        string key = (await ProblemBody.ReadAsync(begin)).GetProperty("manualKey").GetString()!;
        bool enrolled = false;
        foreach (string code in TotpTestHelper.ComputeWindow(key))
        {
            if ((await enroller.PostAsJsonAsync("/api/v1/system/mfa/setup/verify", new { code })).IsSuccessStatusCode)
            {
                enrolled = true;
                break;
            }
        }

        Assert.True(enrolled);
        using var c = ApexClient(cookies: false);
        var step1 = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = AdminPassword });
        Assert.Equal(HttpStatusCode.OK, step1.StatusCode);
        string challenge = step1.Headers.GetValues("Set-Cookie")
            .Select(h => h.Split(';')[0].Trim())
            .Single(p => p.StartsWith("dependably_mfa=", StringComparison.Ordinal))["dependably_mfa=".Length..];

        for (int i = 0; i < 12; i++)
        {
            var wrong = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "WrongPassword9!" });
            if (wrong.StatusCode == HttpStatusCode.TooManyRequests)
            {
                break;
            }
        }

        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login/totp")
        {
            Content = JsonContent.Create(new { code = TotpTestHelper.Compute(key) }),
        };
        req.Headers.Add("Cookie", $"dependably_mfa={challenge}");
        var locked = await c.SendAsync(req);

        Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
        Assert.True(locked.Headers.Contains("Retry-After"));
    }
}
