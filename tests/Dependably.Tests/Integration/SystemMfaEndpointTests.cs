using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The system-admin MFA management endpoints (<c>/api/v1/system/mfa</c>): enrolment, the
/// already-enrolled refusals, recovery-code regeneration, status, and the password-and-code-gated
/// disable. Each refusal is paired with a check that the admin's MFA state did not change.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemMfaEndpointTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private const string AdminPassword = "SysTestMfa1!";
    private const string Base = "/api/v1/system/mfa";

    private readonly DependablyMultiFactory _factory;
    public SystemMfaEndpointTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(string AdminId, HttpClient Client)> NewAdminAsync()
    {
        var repo = _factory.Services.GetRequiredService<SystemAdminRepository>();
        string id = await repo.CreateAsync(
            $"sys-mfa-ep-{Guid.NewGuid():N}@test.local",
            BCrypt.Net.BCrypt.HashPassword(AdminPassword, workFactor: 4),
            mustChangePassword: false);
        string jwt = await _factory.CreateSystemAdminJwtForUser(id);
        var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return (id, client);
    }

    private static async Task<string> BeginAsync(HttpClient client)
    {
        var resp = await client.PostAsync($"{Base}/setup/begin", null);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await ProblemBody.ReadAsync(resp);
        Assert.StartsWith("otpauth://totp/dependably:", body.GetProperty("otpauthUri").GetString());
        return body.GetProperty("manualKey").GetString()!;
    }

    private static async Task<HttpResponseMessage> PostWithAnyValidCodeAsync(
        HttpClient client, string path, string manualKey, Func<string, object> body)
    {
        HttpResponseMessage? last = null;
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            last = await client.PostAsJsonAsync(path, body(code));
            if (last.IsSuccessStatusCode)
            {
                return last;
            }
        }

        return last!;
    }

    private async Task<(string AdminId, HttpClient Client, string Key, List<string> Recovery)> EnrolledAdminAsync()
    {
        var (id, client) = await NewAdminAsync();
        string key = await BeginAsync(client);
        var verify = await PostWithAnyValidCodeAsync(client, $"{Base}/setup/verify", key, code => new { code });
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
        var codes = (await ProblemBody.ReadAsync(verify)).GetProperty("recoveryCodes")
            .EnumerateArray().Select(e => e.GetString()!).ToList();
        return (id, client, key, codes);
    }

    private static async Task<(bool Enabled, int Remaining)> StatusAsync(HttpClient client)
    {
        var body = await ProblemBody.ReadAsync(await client.GetAsync($"{Base}/status"));
        return (body.GetProperty("enabled").GetBoolean(), body.GetProperty("recoveryCodesRemaining").GetInt32());
    }

    [Fact]
    public async Task Status_BeforeEnrolment_ReportsDisabledWithNoRecoveryCodes()
    {
        var (_, client) = await NewAdminAsync();

        Assert.Equal((false, 0), await StatusAsync(client));
    }

    [Fact]
    public async Task Enrolment_EnablesMfaAndIssuesTenRecoveryCodes()
    {
        var (_, client, _, recovery) = await EnrolledAdminAsync();

        Assert.Equal(10, recovery.Count);
        Assert.Equal(10, recovery.Distinct().Count());
        Assert.Equal((true, 10), await StatusAsync(client));
    }

    [Fact]
    public async Task SetupBegin_WhenNoAuthenticatorKeyCanBeGenerated_Returns500_AndMfaStaysOff()
    {
        var repo = _factory.Services.GetRequiredService<SystemAdminRepository>();
        string id = await repo.CreateAsync("", BCrypt.Net.BCrypt.HashPassword(AdminPassword, workFactor: 4), mustChangePassword: false);
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateSystemAdminJwtForUser(id));

        var beginResp = await client.PostAsync($"{Base}/setup/begin", null);

        Assert.Equal(HttpStatusCode.InternalServerError, beginResp.StatusCode);
        Assert.Equal("Failed to generate authenticator key.",
            (await ProblemBody.ReadAsync(beginResp)).GetProperty("detail").GetString());
        Assert.Equal((false, 0), await StatusAsync(client));
    }

    [Fact]
    public async Task SetupVerify_WithWrongCode_IsRefusedAndMfaStaysOff()
    {
        var (_, client) = await NewAdminAsync();
        await BeginAsync(client);

        var resp = await client.PostAsJsonAsync($"{Base}/setup/verify", new { code = "000000" });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        Assert.Equal((false, 0), await StatusAsync(client));
    }

    [Fact]
    public async Task SetupBeginAndVerify_WhenAlreadyEnrolled_AreConflicts_AndTheKeyIsNotRotated()
    {
        var (id, client, key, _) = await EnrolledAdminAsync();
        var mfa = _factory.Services.GetRequiredService<ISystemMfaEnrollmentService>();

        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsync($"{Base}/setup/begin", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict,
            (await client.PostAsJsonAsync($"{Base}/setup/verify", new { code = TotpTestHelper.Compute(key) })).StatusCode);

        Assert.Equal(key, await mfa.GetKeyAsync(id));
        Assert.Equal((true, 10), await StatusAsync(client));
    }

    [Fact]
    public async Task RecoveryCodeRegeneration_RequiresEnrolmentAndAValidCode()
    {
        var (_, notEnrolled) = await NewAdminAsync();
        Assert.Equal(HttpStatusCode.BadRequest,
            (await notEnrolled.PostAsJsonAsync($"{Base}/recovery-codes/regenerate", new { code = "123456" })).StatusCode);

        var (_, client, key, original) = await EnrolledAdminAsync();
        var bad = await client.PostAsJsonAsync($"{Base}/recovery-codes/regenerate", new { code = "not-a-code" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal((true, 10), await StatusAsync(client));

        var good = await PostWithAnyValidCodeAsync(client, $"{Base}/recovery-codes/regenerate", key, code => new { code });
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        var fresh = (await ProblemBody.ReadAsync(good)).GetProperty("recoveryCodes")
            .EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal(10, fresh.Count);
        Assert.Empty(fresh.Intersect(original));
    }

    [Fact]
    public async Task RecoveryCodeRegeneration_WithARecoveryCode_ConsumesItAndIssuesANewSet()
    {
        var (_, client, _, original) = await EnrolledAdminAsync();

        var resp = await client.PostAsJsonAsync($"{Base}/recovery-codes/regenerate", new { code = original[0] });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var fresh = (await ProblemBody.ReadAsync(resp)).GetProperty("recoveryCodes")
            .EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal(10, fresh.Count);

        // The old set is gone: the code that authorized the regeneration cannot be replayed.
        var replay = await client.PostAsJsonAsync($"{Base}/recovery-codes/regenerate", new { code = original[0] });
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    [Fact]
    public async Task Disable_WithWrongPassword_IsUnauthorizedAndMfaStaysOn()
    {
        var (_, client, key, _) = await EnrolledAdminAsync();

        var resp = await client.PostAsJsonAsync($"{Base}/disable",
            new { currentPassword = "WrongPassword9!", code = TotpTestHelper.Compute(key) });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Equal((true, 10), await StatusAsync(client));
    }

    [Fact]
    public async Task Disable_WithRightPasswordButWrongCode_IsBadRequestAndMfaStaysOn()
    {
        var (_, client, _, _) = await EnrolledAdminAsync();

        var resp = await client.PostAsJsonAsync($"{Base}/disable",
            new { currentPassword = AdminPassword, code = "definitely-wrong" });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Equal((true, 10), await StatusAsync(client));
    }

    [Fact]
    public async Task Disable_WithPasswordAndTotp_TurnsMfaOffAndClearsRecoveryCodes()
    {
        var (id, client, key, _) = await EnrolledAdminAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        long versionBefore = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id });

        var resp = await PostWithAnyValidCodeAsync(client, $"{Base}/disable", key,
            code => new { currentPassword = AdminPassword, code });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("MFA disabled.", (await ProblemBody.ReadAsync(resp)).GetProperty("message").GetString());
        Assert.True(await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @id", new { id }) > versionBefore);
        Assert.True(resp.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(c => c.StartsWith("dependably_session=", StringComparison.Ordinal)));

        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE action = 'mfa.disabled' AND actor_id = @id ORDER BY created_at DESC LIMIT 1",
            new { id });
        Assert.Contains("totp", detail);

        // The stale JWT carries the old token version, so a fresh session is needed to re-read state.
        var relogin = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        relogin.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateSystemAdminJwtForUser(id));
        Assert.Equal((false, 0), await StatusAsync(relogin));
    }

    [Fact]
    public async Task Disable_WithPasswordAndRecoveryCode_TurnsMfaOffAndAuditsTheMethod()
    {
        var (id, client, _, recovery) = await EnrolledAdminAsync();

        var resp = await client.PostAsJsonAsync($"{Base}/disable",
            new { currentPassword = AdminPassword, code = recovery[3] });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE action = 'mfa.disabled' AND actor_id = @id ORDER BY created_at DESC LIMIT 1",
            new { id });
        Assert.Contains("recovery_code", detail);
    }

    [Fact]
    public async Task Endpoints_RejectCallersWithoutASystemSession()
    {
        using var anonymous = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync($"{Base}/status")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync($"{Base}/setup/begin", null)).StatusCode);

        // A tenant-realm session on the apex host is not a system session.
        string tenantJwt = await _factory.CreateTenantJwt(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        using var tenantCaller = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        tenantCaller.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tenantJwt);
        Assert.NotEqual(HttpStatusCode.OK, (await tenantCaller.GetAsync($"{Base}/status")).StatusCode);
    }
}
