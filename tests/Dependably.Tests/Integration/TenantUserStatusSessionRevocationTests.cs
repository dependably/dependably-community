using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end session revocation when an operator locks, disables or re-activates a tenant user
/// (<c>PATCH /api/v1/system/users/account-status</c>), through the real JwtBearer pipeline
/// (signature, <c>tver</c> check, token-version cache), plus the tenant second factor's live
/// re-check. Each session test first proves the target's session works, which also fills the
/// token-version cache the way a live session does, so a revocation that leaves the cached
/// version in place shows up as a 200 rather than passing by accident.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantUserStatusSessionRevocationTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    // test-only placeholder password
    private const string TestPassword = "TenantStatusPass1!";

    private readonly DependablyMultiFactory _factory;

    public TenantUserStatusSessionRevocationTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private sealed record TenantUser(string UserId, string OrgId, string Slug, string Email)
    {
        public string Host => $"{Slug}.{DependablyMultiFactory.ApexHost}";
    }

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private async Task<TenantUser> SeedTenantUserAsync(string? slug = null, string? orgId = null)
    {
        slug ??= $"tss-{Guid.NewGuid():N}"[..20];
        orgId ??= await OrgSeeder.InsertAsync(Db, slug);
        string email = $"user-{Guid.NewGuid():N}@test.local";
        string userId = await UserSeeder.InsertAsync(Db, orgId, email, password: TestPassword);
        return new TenantUser(userId, orgId, slug, email);
    }

    private HttpClient CreateClient(string host)
    {
        var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
        });
        client.DefaultRequestHeaders.Host = host;
        return client;
    }

    private async Task<HttpClient> SessionClientAsync(TenantUser user)
    {
        var client = CreateClient(user.Host);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateTenantJwt(user.UserId, user.OrgId, "member"));
        return client;
    }

    private static Task<HttpResponseMessage> CallTenantApiAsync(HttpClient session) =>
        session.GetAsync("/api/v1/auth/me");

    private async Task SetStatusAsync(TenantUser user, string status)
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var resp = await sys.PatchAsJsonAsync("/api/v1/system/users/account-status",
            new { email = user.Email, tenantSlug = user.Slug, accountStatus = status });
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    // ── Sessions ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("disabled")]
    [InlineData("locked")]
    public async Task StatusChangeToNonActive_RejectsTheTargetsExistingSession_AndLeavesAColleagueAlone(string status)
    {
        // Mixed scenario: the target and a colleague in the same tenant both hold live sessions;
        // only the target's ends.
        var target = await SeedTenantUserAsync();
        var colleague = await SeedTenantUserAsync(target.Slug, target.OrgId);
        using var targetSession = await SessionClientAsync(target);
        using var colleagueSession = await SessionClientAsync(colleague);
        Assert.Equal(HttpStatusCode.OK, (await CallTenantApiAsync(targetSession)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await CallTenantApiAsync(colleagueSession)).StatusCode);

        await SetStatusAsync(target, status);

        Assert.Equal(HttpStatusCode.Unauthorized, (await CallTenantApiAsync(targetSession)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await CallTenantApiAsync(colleagueSession)).StatusCode);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("locked")]
    public async Task Reactivation_DoesNotReviveTheOldSession_ButAFreshLoginWorks(string status)
    {
        var user = await SeedTenantUserAsync();
        using (var session = await SessionClientAsync(user))
        {
            Assert.Equal(HttpStatusCode.OK, (await CallTenantApiAsync(session)).StatusCode);

            await SetStatusAsync(user, status);
            await SetStatusAsync(user, "active");

            Assert.Equal(HttpStatusCode.Unauthorized, (await CallTenantApiAsync(session)).StatusCode);
        }

        using var client = CreateClient(user.Host);
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new { email = user.Email, password = TestPassword });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        string? sessionCookie = ExtractCookieValue(login, "dependably_session");
        Assert.NotNull(sessionCookie);
        using var fresh = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me");
        fresh.Headers.Add("Cookie", $"dependably_session={sessionCookie}");
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(fresh)).StatusCode);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("locked")]
    public async Task StatusWrittenWithoutABump_EndsTheSessionWithinOneCacheTtl(string status)
    {
        var user = await SeedTenantUserAsync();
        using var session = await SessionClientAsync(user);
        Assert.Equal(HttpStatusCode.OK, (await CallTenantApiAsync(session)).StatusCode);

        // A status write that neither bumps token_version nor evicts the cached version, so the
        // session's tver still matches. Evicting the entry stands in for its TTL expiring.
        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET account_status = @status WHERE id = @userId AND tenant_id = @orgId",
                new { status, userId = user.UserId, orgId = user.OrgId });
        }

        _factory.Services.GetRequiredService<UserTokenVersionStore>().Invalidate(user.UserId);

        Assert.Equal(HttpStatusCode.Unauthorized, (await CallTenantApiAsync(session)).StatusCode);
    }

    // ── Second factor: a challenge straddling a status change issues nothing ──

    private async Task<string> EnrollMfaAsync(TenantUser user)
    {
        using var client = await SessionClientAsync(user);
        var beginResp = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        string manualKey = JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var vr = await client.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code });
            if (vr.IsSuccessStatusCode)
            {
                return manualKey;
            }
        }

        throw new InvalidOperationException("Could not enroll tenant MFA — TOTP window exhausted.");
    }

    private static async Task<HttpResponseMessage> PostLoginTotpAsync(
        HttpClient client, string mfaCookieValue, string code, bool rememberDevice)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login/totp");
        req.Content = JsonContent.Create(new { code, rememberDevice });
        req.Headers.Add("Cookie", $"dependably_mfa={mfaCookieValue}");
        return await client.SendAsync(req);
    }

    private sealed record LoginTrace(
        long Devices, long LoginSuccesses, string? LastLoginAt, long StaleRefusals, long FailureEvents);

    private async Task<LoginTrace> ReadLoginTraceAsync(TenantUser user)
    {
        await using var conn = await Db.OpenAsync();
        long devices = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId AND realm = 'tenant' AND tenant_id = @orgId",
            new { userId = user.UserId, orgId = user.OrgId });
        long logins = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE org_id = @orgId AND actor_id = @userId AND action = 'login.success'",
            new { userId = user.UserId, orgId = user.OrgId });
        string? lastLogin = await conn.ExecuteScalarAsync<string?>(
            "SELECT last_login_at FROM users WHERE id = @userId AND tenant_id = @orgId",
            new { userId = user.UserId, orgId = user.OrgId });
        long staleRefusals = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE org_id = @orgId AND action = 'login.failure'
              AND detail LIKE '%"reason":"stale_challenge"%' AND detail LIKE '%"realm":"tenant"%'
            """,
            new { orgId = user.OrgId });
        long failureEvents = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM audit_event
            WHERE org_id = @orgId AND event_type = 'auth.login.failure' AND outcome = 'rejected'
              AND payload LIKE @emailHash
            """,
            new { orgId = user.OrgId, emailHash = "%" + LoginService.HashEmail(user.Email) + "%" });
        return new LoginTrace(devices, logins, lastLogin, staleRefusals, failureEvents);
    }

    private static async Task<string> PassFirstFactorAsync(HttpClient client, TenantUser user)
    {
        var step1 = await client.PostAsJsonAsync("/api/v1/auth/login", new { email = user.Email, password = TestPassword });
        Assert.Equal(HttpStatusCode.OK, step1.StatusCode);
        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);
        return mfaCookie!;
    }

    /// <summary>
    /// The challenge carries the user id, tenant and token version from the first factor. A user
    /// locked, disabled, or disabled and re-activated after the first factor must not complete the
    /// second: no session, no remembered device, no login.success or last_login_at, and the same
    /// 401 a wrong code gets. Each refusal is audited with its reason and emitted as a login
    /// failure, and none is charged against the lockout budget.
    /// </summary>
    [Theory]
    [InlineData("disabled", false)]
    [InlineData("locked", false)]
    [InlineData("disabled", true)]
    public async Task StatusChangedBetweenFactors_SecondFactorIssuesNothing(string status, bool reactivate)
    {
        var user = await SeedTenantUserAsync();
        string manualKey = await EnrollMfaAsync(user);

        using var client = CreateClient(user.Host);
        string mfaCookie = await PassFirstFactorAsync(client, user);

        await SetStatusAsync(user, status);
        if (reactivate)
        {
            await SetStatusAsync(user, "active");
        }

        var codes = TotpTestHelper.ComputeWindow(manualKey).ToList();
        foreach (string code in codes)
        {
            var step2 = await PostLoginTotpAsync(client, mfaCookie, code, rememberDevice: true);
            Assert.Equal(HttpStatusCode.Unauthorized, step2.StatusCode);
            Assert.Null(ExtractCookieValue(step2, "dependably_session"));
            Assert.Null(ExtractCookieValue(step2, "dependably_device"));
            using var body = JsonDocument.Parse(await step2.Content.ReadAsStringAsync());
            Assert.Equal("Invalid credentials.", body.RootElement.GetProperty("detail").GetString());
        }

        var trace = await ReadLoginTraceAsync(user);
        Assert.Equal(0, trace.Devices);
        Assert.Equal(0, trace.LoginSuccesses);
        Assert.Null(trace.LastLoginAt);
        Assert.Equal(codes.Count, trace.StaleRefusals);
        Assert.Equal(codes.Count, trace.FailureEvents);

        var lockout = _factory.Services.GetRequiredService<ILockoutStore>();
        var (failedCount, lockedUntil) = await lockout.GetAsync(
            LoginService.HashLockoutKey("tenant", user.OrgId, user.Email), CancellationToken.None);
        Assert.Equal(0, failedCount);
        Assert.Null(lockedUntil);
    }

    [Fact]
    public async Task UnchangedAccount_SecondFactorStillSucceeds_AndRecordsNoStaleRefusal()
    {
        // Control for the theory above: with nothing changed between the factors, the same flow
        // mints a session and remembers the device.
        var user = await SeedTenantUserAsync();
        string manualKey = await EnrollMfaAsync(user);

        using var client = CreateClient(user.Host);
        string mfaCookie = await PassFirstFactorAsync(client, user);

        HttpResponseMessage? success = null;
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var step2 = await PostLoginTotpAsync(client, mfaCookie, code, rememberDevice: true);
            if (step2.StatusCode == HttpStatusCode.OK)
            {
                success = step2;
                break;
            }
        }

        Assert.NotNull(success);
        Assert.NotNull(ExtractCookieValue(success!, "dependably_session"));
        var trace = await ReadLoginTraceAsync(user);
        Assert.Equal(1, trace.Devices);
        Assert.Equal(1, trace.LoginSuccesses);
        Assert.Equal(0, trace.StaleRefusals);
    }

    /// <summary>
    /// A remembered device that exists when a user is re-activated (for example one written while
    /// the user was disabled) is dropped by the re-activation, so the next login asks for the
    /// second factor again.
    /// </summary>
    [Fact]
    public async Task Reactivation_DropsRememberedDevices_SoTheNextLoginNeedsTheSecondFactor()
    {
        var user = await SeedTenantUserAsync();
        await EnrollMfaAsync(user);

        await SetStatusAsync(user, "disabled");
        var devices = _factory.Services.GetRequiredService<TrustedDeviceService>();
        string deviceCookie = await devices.CreateAsync(user.UserId, "tenant", user.OrgId, "test-agent");
        Assert.Equal(1, (await ReadLoginTraceAsync(user)).Devices);

        await SetStatusAsync(user, "active");

        Assert.Equal(0, (await ReadLoginTraceAsync(user)).Devices);
        using var client = CreateClient(user.Host);
        using var login = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login");
        login.Content = JsonContent.Create(new { email = user.Email, password = TestPassword });
        login.Headers.Add("Cookie", $"dependably_device={deviceCookie}");
        var resp = await client.SendAsync(login);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("mfaRequired", out var mfaRequired) && mfaRequired.GetBoolean(),
            "the remembered device must not skip the second factor after re-activation");
        Assert.Null(ExtractCookieValue(resp, "dependably_session"));
    }

    private static string? ExtractCookieValue(HttpResponseMessage resp, string cookieName)
    {
        if (!resp.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
        {
            return null;
        }

        foreach (string header in setCookieHeaders)
        {
            string nameValue = header.Split(';')[0].Trim();
            int eq = nameValue.IndexOf('=', StringComparison.Ordinal);
            if (eq < 0)
            {
                continue;
            }

            string name = nameValue[..eq].Trim();
            string value = nameValue[(eq + 1)..].Trim();
            if (string.Equals(name, cookieName, StringComparison.OrdinalIgnoreCase) && value.Length > 0)
            {
                return value;
            }
        }

        return null;
    }
}
