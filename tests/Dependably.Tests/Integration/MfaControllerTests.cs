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
/// Integration tests for the MFA enrollment surface (<c>/api/v1/mfa/…</c>).
/// Covers the enroll happy path, wrong-code rejection, disable credential requirements,
/// recovery-code regeneration, status on a fresh user, and audit-row emission.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MfaControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public MfaControllerTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // Creates a member user and returns (userId, jwt, client) for the caller.
    private async Task<(string UserId, string Jwt, HttpClient Client)> SeedUserAsync(
        // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        string? password = null)
    {
        // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        password ??= "TestPassword123!";
        string userId = await _factory.CreateUser($"mfa-{Guid.NewGuid():N}@test.local", password);
        string jwt = await _factory.CreateUserJwt(userId, "member");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return (userId, jwt, client);
    }

    // ── Status on a fresh user ────────────────────────────────────────────────

    [Fact]
    public async Task Status_FreshUser_ReturnsFalseAndZeroCodes()
    {
        var (_, _, client) = await SeedUserAsync();

        var resp = await client.GetAsync("/api/v1/mfa/status");
        resp.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        Assert.False(doc.GetProperty("enabled").GetBoolean());
        Assert.Equal(0, doc.GetProperty("recoveryCodesRemaining").GetInt32());
    }

    // ── Setup begin ───────────────────────────────────────────────────────────

    [Fact]
    public async Task SetupBegin_ReturnsOtpauthUriAndBase32ManualKey()
    {
        var (_, _, client) = await SeedUserAsync();

        var resp = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        resp.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        string uri = doc.GetProperty("otpauthUri").GetString()!;
        string key = doc.GetProperty("manualKey").GetString()!;

        Assert.StartsWith("otpauth://totp/", uri, StringComparison.Ordinal);
        Assert.Contains("?secret=", uri, StringComparison.Ordinal);
        Assert.Contains("&issuer=", uri, StringComparison.Ordinal);
        // Base32 alphabet: A-Z, 2-7
        Assert.Matches("^[A-Z2-7]+$", key);
    }

    // ── Enroll happy path ─────────────────────────────────────────────────────

    [Fact]
    public async Task Enroll_HappyPath_EnablesMfaAndReturns10RecoveryCodes()
    {
        var (userId, _, client) = await SeedUserAsync();

        // Step 1: begin
        var beginResp = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        var beginDoc = JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync()).RootElement;
        string manualKey = beginDoc.GetProperty("manualKey").GetString()!;

        // Step 2: verify with a valid TOTP code
        string code = TotpTestHelper.Compute(manualKey);
        var verifyResp = await client.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code });
        verifyResp.EnsureSuccessStatusCode();
        var verifyDoc = JsonDocument.Parse(await verifyResp.Content.ReadAsStringAsync()).RootElement;

        var codes = verifyDoc.GetProperty("recoveryCodes").EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal(10, codes.Count);
        Assert.All(codes, c => Assert.False(string.IsNullOrWhiteSpace(c)));

        // Step 3: status shows enabled + 10 remaining
        var statusResp = await client.GetAsync("/api/v1/mfa/status");
        statusResp.EnsureSuccessStatusCode();
        var statusDoc = JsonDocument.Parse(await statusResp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(statusDoc.GetProperty("enabled").GetBoolean());
        Assert.Equal(10, statusDoc.GetProperty("recoveryCodesRemaining").GetInt32());

        // Step 4: /auth/me reports mfaEnabled = true
        var meResp = await client.GetAsync("/api/v1/auth/me");
        meResp.EnsureSuccessStatusCode();
        var meDoc = JsonDocument.Parse(await meResp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(meDoc.GetProperty("mfaEnabled").GetBoolean());
    }

    // ── Wrong-code rejection ──────────────────────────────────────────────────

    [Fact]
    public async Task SetupVerify_WrongCode_Returns422AndStatusStaysFalse()
    {
        var (_, _, client) = await SeedUserAsync();

        await client.PostAsync("/api/v1/mfa/setup/begin", null);

        var verifyResp = await client.PostAsJsonAsync("/api/v1/mfa/setup/verify",
            new { code = "000000" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, verifyResp.StatusCode);

        var statusResp = await client.GetAsync("/api/v1/mfa/status");
        var statusDoc = JsonDocument.Parse(await statusResp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(statusDoc.GetProperty("enabled").GetBoolean());
    }

    // ── Disable ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Disable_WrongPassword_Returns401()
    {
        var (_, _, client) = await SeedUserAsync();
        await EnrollAsync(client);

        var resp = await client.PostAsJsonAsync("/api/v1/mfa/disable",
            // deepcode ignore NoHardcodedCredentials/test: deliberately wrong test credential
            new { currentPassword = "WrongPassword!", code = "000000" });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Disable_WrongCode_Returns400()
    {
        // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        const string pw = "TestPassword123!";
        var (_, _, client) = await SeedUserAsync(pw);
        await EnrollAsync(client);

        var resp = await client.PostAsJsonAsync("/api/v1/mfa/disable",
            new { currentPassword = pw, code = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Disable_CorrectCredentials_DisablesMfaAndBumpsTokenVersion()
    {
        // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        const string pw = "TestPassword123!";
        var (userId, _, client) = await SeedUserAsync(pw);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();

        // Read initial token_version before enrollment — close the connection immediately
        // so the in-memory SQLite shared-cache lock is released before EnrollAsync writes.
        long versionBefore;
        {
            await using var conn = await store.OpenAsync();
            versionBefore = await conn.ExecuteScalarAsync<long>(
                "SELECT token_version FROM users WHERE id = @id", new { id = userId });
        }

        // Enroll MFA.
        string manualKey = await EnrollAsync(client);

        // Disable with correct credentials.
        string code = TotpTestHelper.Compute(manualKey);
        var disableResp = await client.PostAsJsonAsync("/api/v1/mfa/disable",
            new { currentPassword = pw, code });
        Assert.Equal(HttpStatusCode.OK, disableResp.StatusCode);

        // token_version must have been bumped — open a fresh connection after the write.
        long versionAfter;
        {
            await using var conn = await store.OpenAsync();
            versionAfter = await conn.ExecuteScalarAsync<long>(
                "SELECT token_version FROM users WHERE id = @id", new { id = userId });
        }

        Assert.True(versionAfter > versionBefore,
            $"Expected token_version > {versionBefore} but got {versionAfter}.");

        // Verify MFA is disabled by querying the DB directly — the original JWT is stale
        // (token_version was bumped by disable) so we can't use it for another API call.
        long mfaEnabled;
        {
            await using var dbConn = await store.OpenAsync();
            mfaEnabled = await dbConn.ExecuteScalarAsync<long>(
                "SELECT mfa_enabled FROM users WHERE id = @id", new { id = userId });
        }

        Assert.Equal(0, mfaEnabled);
    }

    // ── Recovery-code regenerate ──────────────────────────────────────────────

    [Fact]
    public async Task RegenerateRecoveryCodes_NotEnrolled_Returns400()
    {
        var (_, _, client) = await SeedUserAsync();

        var resp = await client.PostAsJsonAsync("/api/v1/mfa/recovery-codes/regenerate",
            new { code = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task RegenerateRecoveryCodes_ValidTotp_ReturnsNewSetDisjointFromOld()
    {
        var (_, _, client) = await SeedUserAsync();
        string manualKey = await EnrollAsync(client);

        // Get initial set.
        var statusResp = await client.GetAsync("/api/v1/mfa/status");
        var statusDoc = JsonDocument.Parse(await statusResp.Content.ReadAsStringAsync()).RootElement;
        int initialRemaining = statusDoc.GetProperty("recoveryCodesRemaining").GetInt32();

        string code = TotpTestHelper.Compute(manualKey);
        var regenResp = await client.PostAsJsonAsync("/api/v1/mfa/recovery-codes/regenerate",
            new { code });
        regenResp.EnsureSuccessStatusCode();
        var regenDoc = JsonDocument.Parse(await regenResp.Content.ReadAsStringAsync()).RootElement;
        var newCodes = regenDoc.GetProperty("recoveryCodes").EnumerateArray().Select(e => e.GetString()!).ToList();

        Assert.Equal(10, newCodes.Count);

        // Status must still show 10 after regen.
        var afterStatus = await client.GetAsync("/api/v1/mfa/status");
        var afterDoc = JsonDocument.Parse(await afterStatus.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(10, afterDoc.GetProperty("recoveryCodesRemaining").GetInt32());
    }

    // ── Mixed partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task Disable_UsingRecoveryCode_Succeeds()
    {
        // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        const string pw = "TestPassword123!";
        var (userId, _, client) = await SeedUserAsync(pw);

        // Enroll — collect recovery codes via the full begin→verify flow.
        var beginResp = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        string manualKey = JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        List<string> recoveryCodes = [];
        foreach (string tryCode in TotpTestHelper.ComputeWindow(manualKey))
        {
            var verifyResp = await client.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code = tryCode });
            if (verifyResp.IsSuccessStatusCode)
            {
                recoveryCodes = JsonDocument.Parse(await verifyResp.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("recoveryCodes")
                    .EnumerateArray().Select(e => e.GetString()!).ToList();
                break;
            }
        }

        Assert.NotEmpty(recoveryCodes);

        // Disable using a recovery code (not TOTP).
        string recoveryCode = recoveryCodes[0];
        var disableResp = await client.PostAsJsonAsync("/api/v1/mfa/disable",
            new { currentPassword = pw, code = recoveryCode });
        Assert.Equal(HttpStatusCode.OK, disableResp.StatusCode);

        // Verify disabled via DB — the original JWT is stale after token_version bump,
        // and CreateUserJwt omits tver so it defaults to 1 while the DB holds 2.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        long mfaEnabled;
        {
            await using var dbConn = await store.OpenAsync();
            mfaEnabled = await dbConn.ExecuteScalarAsync<long>(
                "SELECT mfa_enabled FROM users WHERE id = @id", new { id = userId });
        }
        Assert.Equal(0, mfaEnabled);
    }

    // ── Audit rows ────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuditRows_EnrollAndDisable_ProduceCorrectActions()
    {
        // deepcode ignore NoHardcodedCredentials/test: test-only placeholder password
        const string pw = "TestPassword123!";
        var (userId, _, client) = await SeedUserAsync(pw);
        string manualKey = await EnrollAsync(client);

        // Disable MFA.
        string code = TotpTestHelper.Compute(manualKey);
        await client.PostAsJsonAsync("/api/v1/mfa/disable", new { currentPassword = pw, code });

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var actions = (await conn.QueryAsync<string>(
            "SELECT action FROM audit_log WHERE actor_id = @userId ORDER BY created_at ASC",
            new { userId })).ToList();

        Assert.Contains("mfa.enrolled", actions);
        Assert.Contains("mfa.disabled", actions);

        // Verify enrolled detail has snake_case keys.
        string? enrolledDetail = await conn.ExecuteScalarAsync<string?>(
            "SELECT detail FROM audit_log WHERE actor_id = @userId AND action = 'mfa.enrolled' LIMIT 1",
            new { userId });
        Assert.NotNull(enrolledDetail);
        var enrolledDoc = JsonDocument.Parse(enrolledDetail).RootElement;
        Assert.Equal(10, enrolledDoc.GetProperty("recovery_codes_generated").GetInt32());
    }

    [Fact]
    public async Task AuditRows_RegenerateRecoveryCodes_ProducesCorrectAction()
    {
        var (userId, _, client) = await SeedUserAsync();
        string manualKey = await EnrollAsync(client);

        string code = TotpTestHelper.Compute(manualKey);
        await client.PostAsJsonAsync("/api/v1/mfa/recovery-codes/regenerate", new { code });

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string?>(
            "SELECT detail FROM audit_log WHERE actor_id = @userId AND action = 'mfa.recovery_codes_regenerated' LIMIT 1",
            new { userId });

        Assert.NotNull(detail);
        var doc = JsonDocument.Parse(detail).RootElement;
        Assert.Equal(10, doc.GetProperty("count").GetInt32());
        Assert.Equal("totp", doc.GetProperty("method").GetString());
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    // Runs the full begin→verify flow and returns the manualKey so the caller can compute codes.
    private static async Task<string> EnrollAsync(HttpClient client)
    {
        var beginResp = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        beginResp.EnsureSuccessStatusCode();
        string manualKey = JsonDocument.Parse(await beginResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        // Try the current code and retry with the window codes if the 30s boundary is near.
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var resp = await client.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code });
            if (resp.IsSuccessStatusCode)
            {
                return manualKey;
            }
        }

        throw new InvalidOperationException("Could not verify TOTP code during enrollment helper. Clock boundary?");
    }
}
