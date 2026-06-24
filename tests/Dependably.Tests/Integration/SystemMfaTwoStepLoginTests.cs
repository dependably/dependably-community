using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration tests for the system-admin MFA two-step login flow. Covers:
/// - Non-MFA system login path unchanged (no mfaRequired / no dependably_mfa)
/// - MFA challenge issued then TOTP step succeeds (scope=system session)
/// - MFA challenge issued then recovery-code step succeeds (audit + system scope)
/// - Shared lockout budget across first and second factor (mixed partial-failure scenario)
/// - Challenge token not accepted as a normal system session (scope=mfa_challenge rejected)
/// - Cross-realm: a tenant challenge cannot mint a system session
/// - Cross-realm: a system challenge cannot mint a tenant session
/// - Trusted-device for system: row realm='system', tenant_id NULL, skips step 2
/// - Disable revokes trusted devices + bumps token_version + invalidates old session
/// - Timing-oracle guard: unknown email at apex never produces dependably_mfa cookie
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemMfaTwoStepLoginTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
    private const string TestPassword = "SysTestMfa1!";

    public SystemMfaTwoStepLoginTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns a client with cookie management disabled and the apex Host header set.
    /// Cookie management is disabled so the MFA challenge cookie can be forwarded explicitly
    /// between step-1 and step-2, mirroring the pattern used by MfaTwoStepLoginTests.
    /// </summary>
    private HttpClient CreateApexClient()
    {
        var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
        });
        client.DefaultRequestHeaders.Host = DependablyMultiFactory.ApexHost;
        return client;
    }

    private async Task<(string AdminId, string Email)> SeedMfaAdminAsync()
    {
        string email = $"sys-mfa-{Guid.NewGuid():N}@test.local";

        // Create a system admin via DB insert (mirrors what FirstBootService does).
        string hash = BCrypt.Net.BCrypt.HashPassword(TestPassword, workFactor: 12);
        var sysAdminRepo = _factory.Services.GetRequiredService<SystemAdminRepository>();
        string adminId = await sysAdminRepo.CreateAsync(email, hash, mustChangePassword: false);

        // Clear must_change_password so PasswordRotationGuard doesn't block us.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE system_admins SET must_change_password = 0 WHERE id = @id", new { id = adminId });

        // Enroll MFA via the API using a valid system JWT.
        string jwt = await _factory.CreateSystemAdminJwtForUser(adminId);
        var client = CreateApexClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        var beginResp = await client.PostAsync("/api/v1/system/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        string manualKey = JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var vr = await client.PostAsJsonAsync("/api/v1/system/mfa/setup/verify", new { code });
            if (vr.IsSuccessStatusCode)
            {
                return (adminId, email);
            }
        }

        throw new InvalidOperationException("Could not enroll system admin MFA — TOTP window exhausted.");
    }

    private async Task<string> GetManualKeyForAdminAsync(string adminId)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        _ = await conn.ExecuteScalarAsync<string?>(
            "SELECT mfa_authenticator_key FROM system_admins WHERE id = @id", new { id = adminId })
            ?? throw new InvalidOperationException($"No MFA key found for admin {adminId}.");

        var mfaSvc = _factory.Services.GetRequiredService<ISystemMfaEnrollmentService>();
        string? key = await mfaSvc.GetKeyAsync(adminId);
        return key ?? throw new InvalidOperationException($"Failed to decrypt MFA key for admin {adminId}.");
    }

    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient client, string email, string password) =>
        await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });

    private static async Task<HttpResponseMessage> PostLoginTotpAsync(
        HttpClient client, string mfaCookieValue, string code, bool rememberDevice = false,
        string? deviceCookieValue = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login/totp");
        req.Content = JsonContent.Create(new { code, rememberDevice });
        string cookieHeader = $"dependably_mfa={mfaCookieValue}";
        if (deviceCookieValue is not null)
        {
            cookieHeader += $"; dependably_device={deviceCookieValue}";
        }

        req.Headers.Add("Cookie", cookieHeader);
        return await client.SendAsync(req);
    }

    private static string? ExtractCookieValue(HttpResponseMessage resp, string cookieName)
    {
        if (!resp.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
        {
            return null;
        }

        foreach (string header in setCookieHeaders)
        {
            string[] parts = header.Split(';');
            string nameValue = parts[0].Trim();
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

    // ── Non-MFA path unchanged ────────────────────────────────────────────────

    [Fact]
    public async Task SystemLogin_NonMfaAdmin_ReturnsSessionCookieAndOk()
    {
        string email = $"sys-nomfa-{Guid.NewGuid():N}@test.local";
        string hash = BCrypt.Net.BCrypt.HashPassword(TestPassword, workFactor: 12);
        var repo = _factory.Services.GetRequiredService<SystemAdminRepository>();
        string adminId = await repo.CreateAsync(email, hash, mustChangePassword: false);

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync("UPDATE system_admins SET must_change_password = 0 WHERE id = @id", new { id = adminId });

        using var c = CreateApexClient();
        var resp = await PostLoginAsync(c, email, TestPassword);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string setCookie = string.Join("; ", resp.Headers.GetValues("Set-Cookie"));
        Assert.Contains("dependably_session=", setCookie);
        Assert.DoesNotContain("dependably_mfa=", setCookie);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(body.TryGetProperty("message", out _));
        Assert.False(body.TryGetProperty("mfaRequired", out _));
    }

    // ── MFA → challenge → TOTP success ───────────────────────────────────────

    [Fact]
    public async Task SystemLogin_MfaAdmin_ReturnsChallengeCookie_ThenTotpSucceeds()
    {
        var (adminId, email) = await SeedMfaAdminAsync();
        string manualKey = await GetManualKeyForAdminAsync(adminId);

        using var c = CreateApexClient();

        var step1 = await PostLoginAsync(c, email, TestPassword);
        Assert.Equal(HttpStatusCode.OK, step1.StatusCode);

        var step1Body = JsonDocument.Parse(await step1.Content.ReadAsStringAsync()).RootElement;
        Assert.True(step1Body.TryGetProperty("mfaRequired", out var mfaReq) && mfaReq.GetBoolean(),
            "step 1 must return mfaRequired=true");

        string setCookie1 = string.Join("; ", step1.Headers.GetValues("Set-Cookie"));
        Assert.Contains("dependably_mfa=", setCookie1);
        Assert.DoesNotContain("dependably_session=", setCookie1);

        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var step2 = await PostLoginTotpAsync(c, mfaCookie, code);
            if (step2.StatusCode == HttpStatusCode.OK)
            {
                string setCookie2 = string.Join("; ", step2.Headers.GetValues("Set-Cookie"));
                Assert.Contains("dependably_session=", setCookie2);

                // Verify the issued session has scope=system (not tenant).
                string? sessionCookie = ExtractCookieValue(step2, "dependably_session");
                Assert.NotNull(sessionCookie);
                var jwtHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                Assert.True(jwtHandler.CanReadToken(sessionCookie));
                var jwt = jwtHandler.ReadJwtToken(sessionCookie);
                Assert.Equal("system", jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value);

                // Verify audit trail contains method=forms+totp.
                await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
                // xtenant: system audit is global, no org_id filter required
                string? detail = await conn.ExecuteScalarAsync<string?>(
                    """
                    SELECT detail FROM audit_log
                    WHERE actor_id = @adminId AND action = 'login.success' AND scope = 'system'
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    new { adminId });
                Assert.NotNull(detail);
                var detailDoc = JsonDocument.Parse(detail).RootElement;
                Assert.Equal("forms+totp", detailDoc.GetProperty("method").GetString());
                return;
            }
        }

        Assert.Fail("Could not verify TOTP code for system MFA step 2.");
    }

    // ── Recovery-code path ────────────────────────────────────────────────────

    [Fact]
    public async Task SystemLogin_MfaAdmin_RecoveryCode_Succeeds_AndAuditsSystemScope()
    {
        var (adminId, email) = await SeedMfaAdminAsync();
        string manualKey = await GetManualKeyForAdminAsync(adminId);

        // Regenerate recovery codes.
        string jwt = await _factory.CreateSystemAdminJwtForUser(adminId);
        using var authClient = CreateApexClient();
        authClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        string recoveryCode = "";
        foreach (string tc in TotpTestHelper.ComputeWindow(manualKey))
        {
            var r = await authClient.PostAsJsonAsync("/api/v1/system/mfa/recovery-codes/regenerate", new { code = tc });
            if (r.IsSuccessStatusCode)
            {
                var codes = JsonDocument.Parse(await r.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("recoveryCodes")
                    .EnumerateArray().Select(e => e.GetString()!).ToList();
                Assert.NotEmpty(codes);
                recoveryCode = codes[0];
                break;
            }
        }

        Assert.NotEmpty(recoveryCode);

        // Login with recovery code.
        using var c = CreateApexClient();
        var step1 = await PostLoginAsync(c, email, TestPassword);
        Assert.Equal(HttpStatusCode.OK, step1.StatusCode);

        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        var step2 = await PostLoginTotpAsync(c, mfaCookie, recoveryCode);
        Assert.Equal(HttpStatusCode.OK, step2.StatusCode);

        // Verify audit row for mfa.recovery_code_used with scope=system.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        // xtenant: system audit is global, no org_id filter required
        long used = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE actor_id = @adminId AND action = 'mfa.recovery_code_used' AND scope = 'system'",
            new { adminId });
        Assert.True(used >= 1, "expected mfa.recovery_code_used system-scoped audit row");

        // Verify session is system-scoped.
        string? sessionCookie = ExtractCookieValue(step2, "dependably_session");
        Assert.NotNull(sessionCookie);
        var jwtHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var issuedJwt = jwtHandler.ReadJwtToken(sessionCookie);
        Assert.Equal("system", issuedJwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value);
    }

    // ── Shared lockout budget (mixed partial-failure scenario) ────────────────

    [Fact]
    public async Task SharedLockout_SystemMfa_MixedFirstAndSecondFactorFailures_TriggersLockout()
    {
        var (_, email) = await SeedMfaAdminAsync();
        using var c = CreateApexClient();

        // Drive 5 wrong-password failures on step 1.
        for (int i = 0; i < 5; i++)
        {
            var r = await PostLoginAsync(c, email, "WrongPassword!");
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        }

        // Drive 5 wrong-code failures on step 2.
        for (int i = 0; i < 5; i++)
        {
            var step1 = await PostLoginAsync(c, email, TestPassword);
            Assert.Equal(HttpStatusCode.OK, step1.StatusCode);

            string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
            if (mfaCookie is null)
            {
                // Lockout already triggered at step 1 — test passes.
                break;
            }

            var step2 = await PostLoginTotpAsync(c, mfaCookie, "000000");
            if (step2.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return;
            }

            Assert.Equal(HttpStatusCode.Unauthorized, step2.StatusCode);
        }

        var final = await PostLoginAsync(c, email, "WrongPassword!");
        Assert.Equal(HttpStatusCode.TooManyRequests, final.StatusCode);
    }

    // ── Challenge token not accepted as a system session ──────────────────────

    [Fact]
    public async Task SystemChallengeToken_NotAcceptedOnSystemRoutes()
    {
        var (_, email) = await SeedMfaAdminAsync();
        using var c = CreateApexClient();

        var step1 = await PostLoginAsync(c, email, TestPassword);
        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        // Attempt to use the challenge token as a session token.
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/me");
        req.Headers.Add("Cookie", $"dependably_session={mfaCookie}");
        var meResp = await c.SendAsync(req);

        // RouteScopeFilter rejects scope=mfa_challenge.
        Assert.True(
            meResp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound or HttpStatusCode.Forbidden,
            $"Expected 401/403/404, got {meResp.StatusCode}");
    }

    // ── Cross-realm: tenant challenge cannot mint a system session ────────────

    [Fact]
    public async Task CrossRealm_TenantChallenge_CannotMintSystemSession()
    {
        // Seed a real tenant org + tenant user with MFA enrolled so the challenge token
        // and TOTP code are genuine. This pins the "branch on signed realm, not host" property:
        // a valid tenant TOTP code submitted to the apex host must never produce a system-scoped
        // session — even though a broken host-based branch would route this to the system path.
        string tenantSlug = $"xrealm-{Guid.NewGuid():N}";
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        string orgId = await Dependably.Tests.Infrastructure.Seeding.OrgSeeder.InsertAsync(db, tenantSlug);

        const string tenantUserPassword = "TenantMfa1!Cross"; // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        string tenantUserId = await Dependably.Tests.Infrastructure.Seeding.UserSeeder.InsertAsync(
            db, orgId, $"user-{Guid.NewGuid():N}@test.local", password: tenantUserPassword);

        // Enroll MFA for the tenant user via the tenant-domain endpoint.
        string tenantJwt = await _factory.CreateTenantJwt(tenantUserId, orgId, "member");
        var tenantClient = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
        });
        tenantClient.DefaultRequestHeaders.Host = $"{tenantSlug}.{DependablyMultiFactory.ApexHost}";
        tenantClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tenantJwt);

        var beginResp = await tenantClient.PostAsync("/api/v1/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        string tenantManualKey = System.Text.Json.JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        bool tenantMfaEnrolled = false;
        foreach (string enrollCode in TotpTestHelper.ComputeWindow(tenantManualKey))
        {
            var vr = await tenantClient.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code = enrollCode });
            if (vr.IsSuccessStatusCode) { tenantMfaEnrolled = true; break; }
        }
        Assert.True(tenantMfaEnrolled, "Tenant user MFA enrollment must succeed.");

        // Look up the email that UserSeeder generated, then run step 1 on the tenant subdomain
        // to obtain a real, HMAC-signed challenge cookie (realm=tenant, sub=tenantUserId, tid=orgId).
        await using var conn = await db.OpenAsync();
        string? tenantUserEmail = await conn.ExecuteScalarAsync<string?>(
            "SELECT email FROM users WHERE id = @id", new { id = tenantUserId });
        Assert.NotNull(tenantUserEmail);

        tenantClient.DefaultRequestHeaders.Remove("Authorization");
        var tenantStep1 = await tenantClient.PostAsJsonAsync(
            "/api/v1/auth/login", new { email = tenantUserEmail, password = tenantUserPassword });
        Assert.Equal(HttpStatusCode.OK, tenantStep1.StatusCode);

        string? tenantMfaCookie = ExtractCookieValue(tenantStep1, "dependably_mfa");
        Assert.NotNull(tenantMfaCookie);

        // Submit the REAL tenant challenge with a VALID TOTP code to the APEX host.
        // A correct implementation branches on the signed realm=tenant claim and routes to the
        // tenant second-factor path (which requires scope=system to be absent). A host-based
        // broken implementation would route this to the system second-factor path (because apex
        // host), fail to find tenantUserId in system_admins, and return 401.
        // Either way no scope=system session should be issued.
        using var apexClient = CreateApexClient();
        bool submittedValidCode = false;
        HttpResponseMessage? apexStep2 = null;
        foreach (string validCode in TotpTestHelper.ComputeWindow(tenantManualKey))
        {
            apexStep2 = await PostLoginTotpAsync(apexClient, tenantMfaCookie, validCode);
            // Stop on the first non-lockout response so we don't exhaust codes.
            if (apexStep2.StatusCode != HttpStatusCode.TooManyRequests)
            {
                submittedValidCode = true;
                break;
            }
        }

        Assert.True(submittedValidCode, "Should have submitted at least one valid-code attempt.");
        Assert.NotNull(apexStep2);

        // The request must be rejected (401/403) or, if a session cookie is somehow issued,
        // it must be scope=tenant (never system). This is the authoritative pin: the signed
        // realm=tenant claim, not the apex host, determines the routing.
        string? sessionCookie = ExtractCookieValue(apexStep2!, "dependably_session");
        if (sessionCookie is not null)
        {
            var jwtHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            if (jwtHandler.CanReadToken(sessionCookie))
            {
                var jwt = jwtHandler.ReadJwtToken(sessionCookie);
                string? scope = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;
                Assert.NotEqual("system", scope);

                // Even if a tenant session is issued, it must be rejected on system routes.
                using var systemCheckReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/me");
                systemCheckReq.Headers.Add("Cookie", $"dependably_session={sessionCookie}");
                var systemCheckResp = await apexClient.SendAsync(systemCheckReq);
                Assert.True(
                    systemCheckResp.StatusCode is HttpStatusCode.Unauthorized
                        or HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
                    $"A tenant-realm session must not grant access to /api/v1/system/me. Got {systemCheckResp.StatusCode}.");
            }
            else
            {
                Assert.Fail($"Set-Cookie: dependably_session was not a readable JWT: {sessionCookie[..Math.Min(20, sessionCookie.Length)]}...");
            }
        }
        else
        {
            // Rejected — correct behaviour. Verify the status is not 200.
            Assert.NotEqual(HttpStatusCode.OK, apexStep2!.StatusCode);
        }
    }

    // ── Cross-realm: system challenge cannot mint a tenant session ────────────

    [Fact]
    public async Task CrossRealm_SystemChallenge_CannotMintTenantSession()
    {
        // Forge a system challenge JWT (realm=system, no tid/role) and submit to a tenant endpoint.
        // The tenant branch in LoginTotp requires tid != null — a system challenge fails that gate.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        // xtenant: reads instance_settings which is global
        string secret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
            ?? throw new InvalidOperationException("jwt_secret missing");

        // Forge a system challenge — realm=system, no tid.
        string systemChallenge = LoginService.IssueSystemMfaChallengeJwt(
            "fake-admin", "admin@test.local", 1, secret, TimeProvider.System);

        // Submit to /auth/login/totp as if it were a tenant step-2.
        using var c = CreateApexClient();
        var step2 = await PostLoginTotpAsync(c, systemChallenge, "000000");

        // On the apex host this hits the system path. The code "000000" is wrong so we get 401/429.
        // What matters: no tenant-scoped session (scope=tenant) is ever issued.
        Assert.NotEqual(HttpStatusCode.OK, step2.StatusCode);

        string? sessionCookie = ExtractCookieValue(step2, "dependably_session");
        if (sessionCookie is not null)
        {
            var jwtHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            if (jwtHandler.CanReadToken(sessionCookie))
            {
                var jwt = jwtHandler.ReadJwtToken(sessionCookie);
                string? scope = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;
                Assert.NotEqual("tenant", scope);
            }
        }
    }

    // ── Trusted-device for system skips step 2 ────────────────────────────────

    [Fact]
    public async Task SystemLogin_RememberDevice_SkipsStepTwo()
    {
        var (adminId, email) = await SeedMfaAdminAsync();
        string manualKey = await GetManualKeyForAdminAsync(adminId);

        using var c = CreateApexClient();

        var step1 = await PostLoginAsync(c, email, TestPassword);
        Assert.Equal(HttpStatusCode.OK, step1.StatusCode);

        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        string? deviceCookie = null;
        bool loginSucceeded = false;
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var step2 = await PostLoginTotpAsync(c, mfaCookie, code, rememberDevice: true);
            if (step2.StatusCode == HttpStatusCode.OK)
            {
                loginSucceeded = true;
                deviceCookie = ExtractCookieValue(step2, "dependably_device");
                break;
            }
        }

        Assert.True(loginSucceeded, "First system MFA login must succeed.");
        Assert.NotNull(deviceCookie);

        // Verify the device row is realm='system' with tenant_id NULL.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        // xtenant: mfa_trusted_devices is user-scoped; user_id is already globally unique for system admins
        var (realm, tenantId) = await conn.QuerySingleOrDefaultAsync<(string, string?)>(
            "SELECT realm, tenant_id FROM mfa_trusted_devices WHERE user_id = @adminId ORDER BY created_at DESC LIMIT 1",
            new { adminId });
        Assert.Equal("system", realm);
        Assert.Null(tenantId);

        // Second login: forward device cookie — should skip TOTP.
        using var secondReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login");
        secondReq.Content = JsonContent.Create(new { email, password = TestPassword });
        secondReq.Headers.Add("Cookie", $"dependably_device={deviceCookie}");
        secondReq.Headers.Host = DependablyMultiFactory.ApexHost;
        var secondLogin = await c.SendAsync(secondReq);
        Assert.Equal(HttpStatusCode.OK, secondLogin.StatusCode);

        var secondBody = JsonDocument.Parse(await secondLogin.Content.ReadAsStringAsync()).RootElement;
        Assert.False(secondBody.TryGetProperty("mfaRequired", out _),
            "Second login with trusted device should not require MFA step.");

        string setCookie2 = string.Join("; ", secondLogin.Headers.GetValues("Set-Cookie"));
        Assert.Contains("dependably_session=", setCookie2);

        // Audit must show trusted_device_used with scope=system.
        // xtenant: system audit is global, no org_id filter required
        long trustedCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE actor_id = @adminId AND action = 'mfa.trusted_device_used' AND scope = 'system'",
            new { adminId });
        Assert.True(trustedCount >= 1, "expected mfa.trusted_device_used system-scoped audit row");
    }

    // ── Disable revokes trusted devices + bumps token_version ────────────────

    [Fact]
    public async Task SystemMfaDisable_RevokesDevices_BumpsTokenVersion_InvalidatesOldSession()
    {
        var (adminId, email) = await SeedMfaAdminAsync();
        string manualKey = await GetManualKeyForAdminAsync(adminId);

        // Login + remember device.
        using var c = CreateApexClient();
        var step1 = await PostLoginAsync(c, email, TestPassword);
        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        string? oldSession = null;
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var r = await PostLoginTotpAsync(c, mfaCookie, code, rememberDevice: true);
            if (r.IsSuccessStatusCode)
            {
                oldSession = ExtractCookieValue(r, "dependably_session");
                break;
            }
        }

        Assert.NotNull(oldSession);

        // Verify token_version before disable.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        // xtenant: system_admins is global, no org_id filter required
        long versionBefore = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id = adminId });

        // Disable MFA.
        string jwt = await _factory.CreateSystemAdminJwtForUser(adminId);
        using var authClient = CreateApexClient();
        authClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        bool disableSucceeded = false;
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var dr = await authClient.PostAsJsonAsync("/api/v1/system/mfa/disable",
                new { currentPassword = TestPassword, code });
            if (dr.IsSuccessStatusCode)
            {
                disableSucceeded = true;
                break;
            }
        }

        Assert.True(disableSucceeded, "MFA disable must succeed.");

        // token_version must have been bumped.
        long versionAfter = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id = adminId });
        Assert.True(versionAfter > versionBefore, "token_version must increase on MFA disable.");

        // Trusted devices must be gone.
        // xtenant: mfa_trusted_devices user_id is globally unique for system admins
        long deviceCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @adminId AND realm = 'system'",
            new { adminId });
        Assert.Equal(0, deviceCount);

        // The old session (tver=versionBefore) must be rejected.
        using var staleReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/me");
        staleReq.Headers.Add("Cookie", $"dependably_session={oldSession}");
        staleReq.Headers.Host = DependablyMultiFactory.ApexHost;
        var staleResp = await c.SendAsync(staleReq);
        Assert.True(
            staleResp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound,
            $"Stale session must be rejected. Got {staleResp.StatusCode}.");
    }

    // ── Password change invalidates active sessions + re-issues caller cookie ────

    [Fact]
    public async Task ChangePassword_BumpsTokenVersion_InvalidatesOldSession_AndReissuesCallerCookie()
    {
        // Seed an admin WITHOUT MFA so we can log in directly (no step 2).
        string email = $"sys-pwchange-{Guid.NewGuid():N}@test.local";
        const string oldPassword = "SysOldPassword1!"; // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        const string newPassword = "SysNewPassword2!"; // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        string hash = BCrypt.Net.BCrypt.HashPassword(oldPassword, workFactor: 12);
        var repo = _factory.Services.GetRequiredService<SystemAdminRepository>();
        string adminId = await repo.CreateAsync(email, hash, mustChangePassword: false);

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE system_admins SET must_change_password = 0 WHERE id = @id", new { id = adminId });

        // Log in to get a session cookie.
        using var c = CreateApexClient();
        var loginResp = await PostLoginAsync(c, email, oldPassword);
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
        string? oldSession = ExtractCookieValue(loginResp, "dependably_session");
        Assert.NotNull(oldSession);

        // Record token_version before the password change.
        // xtenant: system_admins is global, no org_id filter required
        long versionBefore = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id = adminId });

        // Change the password using a fresh authenticated client (with the old session).
        using var pwClient = CreateApexClient();
        using var pwReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/system/me/password");
        pwReq.Content = System.Net.Http.Json.JsonContent.Create(
            new { currentPassword = oldPassword, newPassword });
        pwReq.Headers.Add("Cookie", $"dependably_session={oldSession}");
        var pwResp = await pwClient.SendAsync(pwReq);
        Assert.Equal(HttpStatusCode.OK, pwResp.StatusCode);

        // token_version must have been bumped.
        long versionAfter = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id = adminId });
        Assert.True(versionAfter > versionBefore,
            $"token_version must increase after password change (was {versionBefore}, now {versionAfter}).");

        // The password-change response must re-issue a NEW session cookie at the new version.
        string? newSession = ExtractCookieValue(pwResp, "dependably_session");
        Assert.NotNull(newSession);
        Assert.NotEqual(oldSession, newSession);

        // The OLD session (tver=versionBefore) must now be rejected on /api/v1/system/me.
        using var staleReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/me");
        staleReq.Headers.Add("Cookie", $"dependably_session={oldSession}");
        staleReq.Headers.Host = DependablyMultiFactory.ApexHost;
        var staleResp = await c.SendAsync(staleReq);
        Assert.True(
            staleResp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound,
            $"Old session must be rejected after password change. Got {staleResp.StatusCode}.");

        // The NEW session (tver=versionAfter) must be accepted on /api/v1/system/me.
        using var freshReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/me");
        freshReq.Headers.Add("Cookie", $"dependably_session={newSession}");
        freshReq.Headers.Host = DependablyMultiFactory.ApexHost;
        var freshResp = await c.SendAsync(freshReq);
        Assert.Equal(HttpStatusCode.OK, freshResp.StatusCode);
    }

    // ── Timing-oracle guard: unknown email never produces a challenge ──────────

    [Fact]
    public async Task UnknownSystemEmail_NeverProducesMfaCookie()
    {
        using var c = CreateApexClient();
        var resp = await PostLoginAsync(c, $"ghost-sys-{Guid.NewGuid():N}@example.com", "AnyPassword!");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("mfaRequired", body, StringComparison.OrdinalIgnoreCase);
        if (resp.Headers.Contains("Set-Cookie"))
        {
            string cookies = string.Join("; ", resp.Headers.GetValues("Set-Cookie"));
            Assert.DoesNotContain("dependably_mfa=", cookies);
        }
    }
}
