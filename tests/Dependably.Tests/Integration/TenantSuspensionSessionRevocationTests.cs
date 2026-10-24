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
/// End-to-end revocation when a system operator locks a tenant out (suspends or soft-deletes it)
/// and later restores it, through the real JwtBearer pipeline (signature, <c>tver</c> check,
/// token-version cache) and the real login endpoints. Each session is proven to work before the
/// lockout, which also fills the token-version cache the way a live session does, so a
/// revocation that leaves the cached version in place shows up as a 200 rather than passing by
/// accident. A bystander in another tenant holds a session and a remembered device throughout.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantSuspensionSessionRevocationTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    // test-only placeholder password
    private const string TestPassword = "TenantSuspendPass1!";

    private readonly DependablyMultiFactory _factory;

    public TenantSuspensionSessionRevocationTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private sealed record TenantUser(string UserId, string OrgId, string Slug, string Email)
    {
        public string Host => $"{Slug}.{DependablyMultiFactory.ApexHost}";
    }

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private async Task<TenantUser> SeedTenantUserAsync(string? slug = null, string? orgId = null)
    {
        slug ??= $"tsr-{Guid.NewGuid():N}"[..20];
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

    private async Task<HttpClient> BearerClientAsync(TenantUser user)
    {
        var client = CreateClient(user.Host);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateTenantJwt(user.UserId, user.OrgId, "member"));
        return client;
    }

    private async Task<HttpStatusCode> CallWithSessionCookieAsync(TenantUser user, string sessionCookie)
    {
        using var client = CreateClient(user.Host);
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me");
        req.Headers.Add("Cookie", $"dependably_session={sessionCookie}");
        return (await client.SendAsync(req)).StatusCode;
    }

    private static async Task<HttpStatusCode> CallMeAsync(HttpClient session) =>
        (await session.GetAsync("/api/v1/auth/me")).StatusCode;

    // ── Operator lifecycle actions ────────────────────────────────────────────

    private async Task SetTenantStatusAsync(TenantUser user, string status)
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var resp = await sys.PatchAsJsonAsync($"/api/v1/system/tenants/{user.Slug}/status", new { status });
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    private async Task LockOutAsync(TenantUser user, string lockout)
    {
        if (lockout == "soft-deleted")
        {
            using var sys = await _factory.CreateSystemAdminClient();
            var resp = await sys.DeleteAsync($"/api/v1/system/tenants/{user.Slug}");
            Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        }
        else
        {
            await SetTenantStatusAsync(user, lockout);
        }
    }

    private async Task RestoreAsync(TenantUser user, string lockout, string restoredTo)
    {
        if (lockout == "soft-deleted")
        {
            using var sys = await _factory.CreateSystemAdminClient();
            var resp = await sys.PatchAsync($"/api/v1/system/tenants/{user.Slug}/restore", null);
            Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        }
        else
        {
            await SetTenantStatusAsync(user, restoredTo);
        }
    }

    // ── MFA and remembered devices ────────────────────────────────────────────

    private async Task<string> EnrollMfaAsync(TenantUser user)
    {
        using var client = await BearerClientAsync(user);
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

    /// <summary>
    /// Signs an MFA user in through both factors with "remember this device", returning the
    /// session and device cookies the browser would hold.
    /// </summary>
    private async Task<(string Session, string Device)> SignInRememberingDeviceAsync(TenantUser user, string manualKey)
    {
        using var client = CreateClient(user.Host);
        var step1 = await client.PostAsJsonAsync("/api/v1/auth/login", new { email = user.Email, password = TestPassword });
        Assert.Equal(HttpStatusCode.OK, step1.StatusCode);
        string mfaCookie = ExtractCookieValue(step1, "dependably_mfa")
            ?? throw new InvalidOperationException("first factor issued no MFA challenge");

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login/totp");
            req.Content = JsonContent.Create(new { code, rememberDevice = true });
            req.Headers.Add("Cookie", $"dependably_mfa={mfaCookie}");
            var step2 = await client.SendAsync(req);
            if (step2.StatusCode == HttpStatusCode.OK)
            {
                return (ExtractCookieValue(step2, "dependably_session")!, ExtractCookieValue(step2, "dependably_device")!);
            }
        }

        throw new InvalidOperationException("Could not complete the tenant second factor — TOTP window exhausted.");
    }

    /// <summary>
    /// Presents the password with the remembered-device cookie. True when the device skipped the
    /// second factor (a session was issued), false when the login asked for it.
    /// </summary>
    private async Task<bool> DeviceSkipsSecondFactorAsync(TenantUser user, string deviceCookie)
    {
        using var client = CreateClient(user.Host);
        using var login = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login");
        login.Content = JsonContent.Create(new { email = user.Email, password = TestPassword });
        login.Headers.Add("Cookie", $"dependably_device={deviceCookie}");
        var resp = await client.SendAsync(login);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        bool mfaRequired = body.RootElement.TryGetProperty("mfaRequired", out var m) && m.GetBoolean();
        Assert.Equal(mfaRequired, ExtractCookieValue(resp, "dependably_session") is null);
        return !mfaRequired;
    }

    private async Task<long> CountTenantDevicesAsync(TenantUser user)
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId AND realm = 'tenant' AND tenant_id = @orgId",
            new { userId = user.UserId, orgId = user.OrgId });
    }

    // ── Lockout then restore ──────────────────────────────────────────────────

    /// <summary>
    /// A session and a remembered device issued before the lockout are both dead after the
    /// restore; a member who signs in again afterwards gets a working session; and a user in
    /// another tenant keeps both their session and their device.
    /// </summary>
    [Theory]
    [InlineData("suspended", "active")]
    [InlineData("suspended", "read_only")]
    [InlineData("soft-deleted", "active")]
    public async Task LockoutThenRestore_KillsPriorSessionsAndDevices_FreshLoginWorks_OtherTenantsUntouched(
        string lockout, string restoredTo)
    {
        var target = await SeedTenantUserAsync();
        var colleague = await SeedTenantUserAsync(target.Slug, target.OrgId);
        var bystander = await SeedTenantUserAsync();

        string targetKey = await EnrollMfaAsync(target);
        var (targetSession, targetDevice) = await SignInRememberingDeviceAsync(target, targetKey);
        using var colleagueSession = await BearerClientAsync(colleague);

        await EnrollMfaAsync(bystander);
        string bystanderDevice = await _factory.Services.GetRequiredService<TrustedDeviceService>()
            .CreateAsync(bystander.UserId, "tenant", bystander.OrgId, "test-agent");
        using var bystanderSession = await BearerClientAsync(bystander);

        // Everything works before the lockout (and the version cache is warm for each session).
        Assert.Equal(HttpStatusCode.OK, await CallWithSessionCookieAsync(target, targetSession));
        Assert.Equal(HttpStatusCode.OK, await CallMeAsync(colleagueSession));
        Assert.Equal(HttpStatusCode.OK, await CallMeAsync(bystanderSession));
        Assert.True(await DeviceSkipsSecondFactorAsync(target, targetDevice));
        Assert.True(await DeviceSkipsSecondFactorAsync(bystander, bystanderDevice));

        await LockOutAsync(target, lockout);
        await RestoreAsync(target, lockout, restoredTo);

        Assert.Equal(HttpStatusCode.Unauthorized, await CallWithSessionCookieAsync(target, targetSession));
        Assert.Equal(HttpStatusCode.Unauthorized, await CallMeAsync(colleagueSession));
        Assert.Equal(0, await CountTenantDevicesAsync(target));
        Assert.False(await DeviceSkipsSecondFactorAsync(target, targetDevice),
            "a device remembered before the lockout must not skip the second factor after the restore");

        using (var client = CreateClient(colleague.Host))
        {
            var login = await client.PostAsJsonAsync("/api/v1/auth/login", new { email = colleague.Email, password = TestPassword });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            string? fresh = ExtractCookieValue(login, "dependably_session");
            Assert.NotNull(fresh);
            Assert.Equal(HttpStatusCode.OK, await CallWithSessionCookieAsync(colleague, fresh!));
        }

        Assert.Equal(HttpStatusCode.OK, await CallMeAsync(bystanderSession));
        Assert.Equal(1, await CountTenantDevicesAsync(bystander));
        Assert.True(await DeviceSkipsSecondFactorAsync(bystander, bystanderDevice));
    }

    [Fact]
    public async Task SuspendedTenant_RefusesLoginWhileSuspended()
    {
        // Revoking on entry is sufficient only because nothing can be minted while the tenant is
        // locked out; this pins that half of the argument.
        var user = await SeedTenantUserAsync();
        await SetTenantStatusAsync(user, "suspended");

        using var client = CreateClient(user.Host);
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new { email = user.Email, password = TestPassword });

        Assert.Equal(HttpStatusCode.Locked, login.StatusCode);
        Assert.Null(ExtractCookieValue(login, "dependably_session"));
    }

    [Fact]
    public async Task ReadOnly_IsNotALockout_SessionsSurviveTheRoundTrip()
    {
        var user = await SeedTenantUserAsync();
        using var session = await BearerClientAsync(user);
        Assert.Equal(HttpStatusCode.OK, await CallMeAsync(session));

        await SetTenantStatusAsync(user, "read_only");
        Assert.Equal(HttpStatusCode.OK, await CallMeAsync(session));
        await SetTenantStatusAsync(user, "active");

        Assert.Equal(HttpStatusCode.OK, await CallMeAsync(session));
    }

    /// <summary>
    /// A lifecycle write revokes the target tenant's members whatever tenant scope its caller
    /// declared. Under row-level security a connection bound to another tenant sees none of the
    /// target's users, while the <c>orgs</c> write (no tenant column) still lands, so a write that
    /// relied on the caller's scope would flip the status and revoke nothing. Meaningful on the
    /// postgres-rls run; on SQLite there is no row-level security to get wrong.
    /// </summary>
    [Theory]
    [InlineData("suspend")]
    [InlineData("soft-delete")]
    public async Task LifecycleWrite_UnderAnotherTenantsScope_StillRevokesTheTargetsMembers(string action)
    {
        var target = await SeedTenantUserAsync();
        var bystander = await SeedTenantUserAsync();
        using var session = await BearerClientAsync(target);
        Assert.Equal(HttpStatusCode.OK, await CallMeAsync(session));
        long before = await ReadTokenVersionAsync(target);
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();

        using (Dependably.Infrastructure.RowLevelSecurity.DbScope.ForOrg(bystander.OrgId))
        {
            if (action == "suspend")
            {
                Assert.True((await orgs.UpdateOrgStatusAsync(target.OrgId, "suspended")).Applied);
            }
            else
            {
                await orgs.SoftDeleteOrgAsync(target.OrgId);
            }
        }

        Assert.Equal(before + 1, await ReadTokenVersionAsync(target));
    }

    private async Task<long> ReadTokenVersionAsync(TenantUser user)
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @userId AND tenant_id = @orgId",
            new { userId = user.UserId, orgId = user.OrgId });
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
