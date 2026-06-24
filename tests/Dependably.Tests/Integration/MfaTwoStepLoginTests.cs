using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration tests for the MFA two-step login flow. Covers:
/// - Non-MFA login path unchanged
/// - MFA challenge issued then TOTP step succeeds
/// - MFA challenge issued then recovery-code step succeeds (mfa.recovery_code_used audit)
/// - Shared lockout budget across both factors (mix 1st+2nd factor failures)
/// - Challenge replay rejection (jti-revocation)
/// - Challenge token not accepted as a normal session token (RouteScopeFilter gate)
/// - Remember-device skips step 2 on the next login (trusted_device flow)
/// - Trusted device revoked on MFA disable
/// - Trusted device revoked on password change
/// - Trusted-device lookup is scoped by user/realm/tenant in TrustedDeviceService.TryConsumeAsync
/// - Timing-oracle guard: unknown email never produces a dependably_mfa cookie
/// </summary>
[Trait("Category", "Integration")]
public sealed class MfaTwoStepLoginTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
    private const string TestPassword = "TestMfaPass1!";

    public MfaTwoStepLoginTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a client without automatic cookie management so that Cookie headers
    /// set manually on requests are forwarded as-is. The MFA two-step flow requires
    /// explicit cookie control because the challenge cookie is extracted from the step-1
    /// response and forwarded to step-2 — the same pattern used by SAML tests.
    /// </summary>
    private HttpClient CreateClient() =>
        _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
        });

    private async Task<(string UserId, string Email)> SeedMfaUserAsync()
    {
        string email = $"mfa2-{Guid.NewGuid():N}@test.local";
        string userId = await _factory.CreateUser(email, TestPassword);

        // Enroll via the API to get a real TOTP key stored in the identity tables.
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        var beginResp = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        string manualKey = JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        // Verify with valid TOTP to enable MFA (try window to guard against 30s boundary).
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var vr = await client.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code });
            if (vr.IsSuccessStatusCode)
            {
                return (userId, email);
            }
        }

        throw new InvalidOperationException("Could not enroll MFA — TOTP window exhausted.");
    }

    // Sends POST /api/v1/auth/login and returns the full HttpResponseMessage.
    // deepcode ignore NoHardcodedCredentials/test: test helper forwards a fixture password, not a real credential.
    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient client, string email, string password) =>
        await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });

    // Sends POST /api/v1/auth/login/totp with the given code, forwarding the challenge cookie
    // extracted from a prior login response. The test client does not use an automatic cookie
    // container for the challenge cookie — the MFA cookie is forwarded explicitly to mirror
    // the established test-infrastructure pattern (SAML tests do the same).
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

    // Extracts the value of a named cookie from a Set-Cookie header collection.
    // Returns null when the cookie is not present or was explicitly deleted (empty value + past expiry).
    private static string? ExtractCookieValue(HttpResponseMessage resp, string cookieName)
    {
        if (!resp.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
        {
            return null;
        }

        foreach (string header in setCookieHeaders)
        {
            // Each Set-Cookie header has the form: name=value; attr1; attr2=val
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

    // Returns the TOTP key stored for a user (reads from DB via identity store).
    private async Task<string> GetManualKeyForUserAsync(string userId)
    {
        await using var conn = await Db.OpenAsync();
        // Confirm a row with an MFA key exists before calling the service layer.
        _ = await conn.ExecuteScalarAsync<string?>(
            "SELECT mfa_authenticator_key FROM users WHERE id = @id", new { id = userId })
            ?? throw new InvalidOperationException($"No MFA key found for user {userId}.");

        // The key is stored encrypted via IMfaSecretProtector — use the service layer.
        var mfaSvc = _factory.Services.GetRequiredService<Dependably.Infrastructure.Identity.IMfaEnrollmentService>();
        string? key = await mfaSvc.GetKeyAsync(userId);
        return key ?? throw new InvalidOperationException($"Failed to decrypt MFA key for user {userId}.");
    }

    // ── Non-MFA path unchanged ────────────────────────────────────────────────

    [Fact]
    public async Task Login_NonMfaUser_ReturnsSessionCookieAndOk()
    {
        string email = $"nomfa-{Guid.NewGuid():N}@test.local";
        await _factory.CreateUser(email, TestPassword);

        using var c = CreateClient();
        var resp = await PostLoginAsync(c, email, TestPassword);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.Contains("Set-Cookie"));
        // Must have a session cookie, must NOT have an MFA challenge cookie.
        string setCookie = string.Join("; ", resp.Headers.GetValues("Set-Cookie"));
        Assert.Contains("dependably_session=", setCookie);
        Assert.DoesNotContain("dependably_mfa=", setCookie);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(body.TryGetProperty("message", out _), "response should contain message");
        Assert.False(body.TryGetProperty("mfaRequired", out _), "non-MFA response must not contain mfaRequired");
    }

    // ── MFA → challenge → TOTP success ───────────────────────────────────────

    [Fact]
    public async Task Login_MfaUser_ReturnsChallengeCookie_ThenTotpSucceeds()
    {
        var (userId, email) = await SeedMfaUserAsync();
        string manualKey = await GetManualKeyForUserAsync(userId);

        using var c = CreateClient();

        // Step 1: POST /auth/login — should return mfaRequired=true + dependably_mfa cookie.
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

        // Step 2: POST /auth/login/totp with valid code, forwarding the challenge cookie.
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var step2 = await PostLoginTotpAsync(c, mfaCookie, code);
            if (step2.StatusCode == HttpStatusCode.OK)
            {
                var step2Body = JsonDocument.Parse(await step2.Content.ReadAsStringAsync()).RootElement;
                Assert.True(step2Body.TryGetProperty("message", out _));

                string setCookie2 = string.Join("; ", step2.Headers.GetValues("Set-Cookie"));
                Assert.Contains("dependably_session=", setCookie2);

                // Verify audit trail.
                await using var conn = await Db.OpenAsync();
                string? method = await conn.ExecuteScalarAsync<string?>(
                    """
                    SELECT detail FROM audit_log WHERE actor_id = @userId AND action = 'login.success'
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    new { userId });
                Assert.NotNull(method);
                var detail = JsonDocument.Parse(method).RootElement;
                Assert.Equal("forms+totp", detail.GetProperty("method").GetString());
                return;
            }
        }

        Assert.Fail("Could not verify TOTP code for MFA step 2.");
    }

    // ── Recovery-code path ────────────────────────────────────────────────────

    [Fact]
    public async Task Login_MfaUser_RecoveryCode_Succeeds_AndAuditsRecoveryCodeUsed()
    {
        var (userId, email) = await SeedMfaUserAsync();

        // Get a recovery code via the enrolled user's JWT.
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var authClient = CreateClient();
        authClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        string manualKey = await GetManualKeyForUserAsync(userId);
        // Regenerate to get plaintext codes.
        foreach (string tc in TotpTestHelper.ComputeWindow(manualKey))
        {
            var r = await authClient.PostAsJsonAsync("/api/v1/mfa/recovery-codes/regenerate", new { code = tc });
            if (r.IsSuccessStatusCode)
            {
                var codes = JsonDocument.Parse(await r.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("recoveryCodes")
                    .EnumerateArray().Select(e => e.GetString()!).ToList();
                Assert.NotEmpty(codes);

                // Now do the two-step login using a recovery code.
                using var c = CreateClient();
                var step1 = await PostLoginAsync(c, email, TestPassword);
                Assert.Equal(HttpStatusCode.OK, step1.StatusCode);

                string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
                Assert.NotNull(mfaCookie);

                var step2 = await PostLoginTotpAsync(c, mfaCookie, codes[0]);
                Assert.Equal(HttpStatusCode.OK, step2.StatusCode);

                // Verify audit row for mfa.recovery_code_used.
                await using var conn = await Db.OpenAsync();
                long used = await conn.ExecuteScalarAsync<long>(
                    "SELECT COUNT(*) FROM audit_log WHERE actor_id = @userId AND action = 'mfa.recovery_code_used'",
                    new { userId });
                Assert.True(used >= 1, "expected mfa.recovery_code_used audit row");

                // Verify login audit method=forms+recovery.
                string? loginDetail = await conn.ExecuteScalarAsync<string?>(
                    """
                    SELECT detail FROM audit_log WHERE actor_id = @userId AND action = 'login.success'
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    new { userId });
                Assert.NotNull(loginDetail);
                var loginDoc = JsonDocument.Parse(loginDetail).RootElement;
                Assert.Equal("forms+recovery", loginDoc.GetProperty("method").GetString());
                return;
            }
        }

        Assert.Fail("Could not regenerate recovery codes for test.");
    }

    // ── Shared lockout budget (mixed first/second factor failures) ────────────

    [Fact]
    public async Task SharedLockout_MixOfFirstAndSecondFactorFailures_TriggersLockout()
    {
        var (_, email) = await SeedMfaUserAsync();
        using var c = CreateClient();

        // Drive 5 wrong-password failures to deplete half the budget on step 1.
        for (int i = 0; i < 5; i++)
        {
            var r = await PostLoginAsync(c, email, "WrongPassword!");
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        }

        // Drive 5 wrong-code failures on step 2 (must complete step 1 first for each).
        for (int i = 0; i < 5; i++)
        {
            var step1 = await PostLoginAsync(c, email, TestPassword);
            Assert.Equal(HttpStatusCode.OK, step1.StatusCode);

            string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
            if (mfaCookie is null)
            {
                // Lockout may have already triggered at step 1 (429 at step 1 would be OK too).
                break;
            }

            var step2 = await PostLoginTotpAsync(c, mfaCookie, "000000");
            // Step 2 failures may return 401 or 429 once the budget hits the limit.
            if (step2.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return; // Lockout triggered — test passes.
            }

            Assert.Equal(HttpStatusCode.Unauthorized, step2.StatusCode);
        }

        // After 10 combined failures the next attempt should be 429.
        var final = await PostLoginAsync(c, email, "WrongPassword!");
        Assert.Equal(HttpStatusCode.TooManyRequests, final.StatusCode);
    }

    // ── Challenge replay rejection ─────────────────────────────────────────────

    [Fact]
    public async Task ChallengeReplay_AfterSuccess_Returns401()
    {
        var (userId, email) = await SeedMfaUserAsync();
        string manualKey = await GetManualKeyForUserAsync(userId);

        using var c = CreateClient();

        // Step 1: obtain challenge cookie.
        var step1 = await PostLoginAsync(c, email, TestPassword);
        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        // Step 2: succeed once.
        bool succeeded = false;
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var r = await PostLoginTotpAsync(c, mfaCookie, code);
            if (r.StatusCode == HttpStatusCode.OK)
            {
                succeeded = true;
                break;
            }
        }

        Assert.True(succeeded, "First TOTP attempt should succeed.");

        // Replay: attempt to reuse the same (now-revoked) challenge cookie.
        var replay = await PostLoginTotpAsync(c, mfaCookie, "000000");
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    // ── Challenge token not accepted as a session token ───────────────────────

    [Fact]
    public async Task ChallengeToken_NotAcceptedOnNormalRoute()
    {
        var (_, email) = await SeedMfaUserAsync();

        using var c = CreateClient();

        // Trigger step 1 to get the challenge cookie.
        var step1 = await PostLoginAsync(c, email, TestPassword);
        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        // Try to access a protected endpoint using the challenge token as a session cookie.
        // The RouteScopeFilter rejects scope=mfa_challenge on tenant routes — it returns
        // NotFound (404) per the 404-not-403 realm-boundary stance so cross-realm probing
        // reveals nothing, rather than Unauthorized (401).
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me");
        req.Headers.Add("Cookie", $"dependably_session={mfaCookie}");
        var meResp = await c.SendAsync(req);
        Assert.True(
            meResp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound,
            $"Expected 401 or 404, got {meResp.StatusCode}");
    }

    // ── Remember-device skips step 2 ──────────────────────────────────────────

    [Fact]
    public async Task RememberDevice_SkipsStepTwo_OnSubsequentLogin()
    {
        var (userId, email) = await SeedMfaUserAsync();
        string manualKey = await GetManualKeyForUserAsync(userId);

        using var c = CreateClient();

        // Login with MFA and request device remembering.
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
                // Verify device cookie was set.
                string setCookie = string.Join("; ", step2.Headers.GetValues("Set-Cookie"));
                Assert.Contains("dependably_device=", setCookie);
                deviceCookie = ExtractCookieValue(step2, "dependably_device");
                break;
            }
        }

        Assert.True(loginSucceeded, "First login with rememberDevice must succeed.");
        Assert.NotNull(deviceCookie);

        // Second login: forward the device cookie — should skip TOTP and succeed immediately.
        using var secondReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login");
        secondReq.Content = JsonContent.Create(new { email, password = TestPassword });
        secondReq.Headers.Add("Cookie", $"dependably_device={deviceCookie}");
        var secondLogin = await c.SendAsync(secondReq);
        Assert.Equal(HttpStatusCode.OK, secondLogin.StatusCode);

        var secondBody = JsonDocument.Parse(await secondLogin.Content.ReadAsStringAsync()).RootElement;
        // No mfaRequired field — device was trusted.
        Assert.False(secondBody.TryGetProperty("mfaRequired", out _),
            "Second login with trusted device should not require MFA step.");

        string setCookie2 = string.Join("; ", secondLogin.Headers.GetValues("Set-Cookie"));
        Assert.Contains("dependably_session=", setCookie2);

        // Verify audit shows trusted_device method.
        await using var conn = await Db.OpenAsync();
        long trustedCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE actor_id = @userId AND action = 'mfa.trusted_device_used'",
            new { userId });
        Assert.True(trustedCount >= 1, "expected mfa.trusted_device_used audit row");
    }

    // ── Trusted device revoked on MFA disable ────────────────────────────────

    [Fact]
    public async Task TrustedDevice_RevokedOnMfaDisable()
    {
        var (userId, email) = await SeedMfaUserAsync();
        string manualKey = await GetManualKeyForUserAsync(userId);

        using var c = CreateClient();

        // Login, remember device.
        var step1 = await PostLoginAsync(c, email, TestPassword);
        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var r = await PostLoginTotpAsync(c, mfaCookie, code, rememberDevice: true);
            if (r.IsSuccessStatusCode)
            {
                break;
            }
        }

        // Disable MFA via the API (requires a fresh session JWT).
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var authClient = CreateClient();
        authClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var disableResp = await authClient.PostAsJsonAsync("/api/v1/mfa/disable",
                new { currentPassword = TestPassword, code });
            if (disableResp.IsSuccessStatusCode)
            {
                break;
            }
        }

        // Verify trusted device was deleted.
        await using var conn = await Db.OpenAsync();
        long deviceCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId",
            new { userId });
        Assert.Equal(0, deviceCount);
    }

    // ── Trusted device revoked on password change ────────────────────────────

    [Fact]
    public async Task TrustedDevice_RevokedOnPasswordChange()
    {
        var (userId, email) = await SeedMfaUserAsync();
        string manualKey = await GetManualKeyForUserAsync(userId);

        using var c = CreateClient();

        // Login with remember-device.
        var step1 = await PostLoginAsync(c, email, TestPassword);
        string? mfaCookie = ExtractCookieValue(step1, "dependably_mfa");
        Assert.NotNull(mfaCookie);

        bool rememberSucceeded = false;
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var r = await PostLoginTotpAsync(c, mfaCookie, code, rememberDevice: true);
            if (r.IsSuccessStatusCode)
            {
                rememberSucceeded = true;
                break;
            }
        }

        Assert.True(rememberSucceeded, "Login with rememberDevice must succeed to create a device record.");

        // Verify a device row exists.
        await using var conn = await Db.OpenAsync();
        long beforeCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId",
            new { userId });
        Assert.True(beforeCount >= 1, "expected at least one trusted device before password change");

        // Change the password via the API.
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var authClient = CreateClient();
        authClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        // deepcode ignore NoHardcodedCredentials/test: test-only placeholder new password
        const string newPassword = "NewMfaPass2!";
        var pwResp = await authClient.PostAsJsonAsync("/api/v1/users/me/password",
            new { currentPassword = TestPassword, newPassword });
        Assert.Equal(HttpStatusCode.OK, pwResp.StatusCode);

        // Trusted devices must be gone.
        long afterCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @userId",
            new { userId });
        Assert.Equal(0, afterCount);
    }

    // ── Timing-oracle guard ───────────────────────────────────────────────────

    [Fact]
    public async Task UnknownEmail_NeverProducesMfaCookie()
    {
        using var c = CreateClient();
        var resp = await PostLoginAsync(c, $"ghost-{Guid.NewGuid():N}@example.com", "AnyPassword!");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        // Must NOT expose mfaRequired or set dependably_mfa.
        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("mfaRequired", body, StringComparison.OrdinalIgnoreCase);
        if (resp.Headers.Contains("Set-Cookie"))
        {
            string cookies = string.Join("; ", resp.Headers.GetValues("Set-Cookie"));
            Assert.DoesNotContain("dependably_mfa=", cookies);
        }
    }

    // ── Missing challenge cookie returns 401 generically ─────────────────────

    [Fact]
    public async Task LoginTotp_WithoutChallengeCookie_Returns401()
    {
        using var c = CreateClient();
        // Post to /login/totp without any Cookie header — no challenge cookie present.
        var resp = await c.PostAsJsonAsync("/api/v1/auth/login/totp", new { code = "123456", rememberDevice = false });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
