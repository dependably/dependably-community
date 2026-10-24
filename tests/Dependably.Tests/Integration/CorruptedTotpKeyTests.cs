using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Serilog.Events;

namespace Dependably.Tests.Integration;

/// <summary>
/// A stored TOTP key that does not decrypt, through the real login and MFA endpoints. Every code
/// is an invalid code (never a server error), the account can still sign in with a recovery
/// code, the log names the account and not the stored value, and another user's TOTP keeps
/// working. A key stored as plaintext Base32 never verifies either: the application only ever
/// writes ciphertext, so a plaintext key in the column was planted from outside, and the stored
/// secret check reports it rather than counting it as harmless legacy plaintext.
/// </summary>
[Trait("Category", "Integration")]
public sealed class CorruptedTotpKeyTests : IAsyncLifetime
{
    // test-only placeholder password
    private const string TestPassword = "TotpCorrupt1!";

    private readonly CapturingLogSink _sink = new();
    private DependablyFactory _factory = null!;

    public async Task InitializeAsync()
    {
        _factory = new DependablyFactory { LogSink = _sink };
        await _factory.InitializeAsync();
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private HttpClient CreateClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });

    private sealed record Enrolled(string UserId, string Email, string ManualKey, IReadOnlyList<string> RecoveryCodes);

    // Enrols a user through the API and collects a fresh set of recovery codes while the key is good.
    private async Task<Enrolled> EnrolAsync()
    {
        string email = $"totp-corrupt-{Guid.NewGuid():N}@test.local";
        string userId = await _factory.CreateUser(email, TestPassword);
        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateUserJwt(userId, "member"));

        var begin = await client.PostAsync("/api/v1/mfa/setup/begin", null);
        begin.EnsureSuccessStatusCode();
        string manualKey = JsonDocument.Parse(await begin.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manualKey").GetString()!;

        bool enabled = false;
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            if ((await client.PostAsJsonAsync("/api/v1/mfa/setup/verify", new { code })).IsSuccessStatusCode)
            {
                enabled = true;
                break;
            }
        }

        Assert.True(enabled, "MFA enrolment did not verify within the TOTP window.");

        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var r = await client.PostAsJsonAsync("/api/v1/mfa/recovery-codes/regenerate", new { code });
            if (r.IsSuccessStatusCode)
            {
                var codes = JsonDocument.Parse(await r.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("recoveryCodes").EnumerateArray().Select(e => e.GetString()!).ToList();
                return new Enrolled(userId, email, manualKey, codes);
            }
        }

        throw new InvalidOperationException("Could not regenerate recovery codes within the TOTP window.");
    }

    private async Task<string> StoredKeyAsync(string userId)
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT mfa_authenticator_key FROM users WHERE id = @userId", new { userId })
            ?? throw new InvalidOperationException("no stored key");
    }

    private async Task SetStoredKeyAsync(string userId, string value)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE users SET mfa_authenticator_key = @value WHERE id = @userId", new { value, userId });
    }

    private static async Task<string> ChallengeAsync(HttpClient client, string email)
    {
        var step1 = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestPassword });
        Assert.Equal(HttpStatusCode.OK, step1.StatusCode);
        foreach (string header in step1.Headers.GetValues("Set-Cookie"))
        {
            string nameValue = header.Split(';')[0].Trim();
            if (nameValue.StartsWith("dependably_mfa=", StringComparison.Ordinal) && nameValue.Length > "dependably_mfa=".Length)
            {
                return nameValue["dependably_mfa=".Length..];
            }
        }

        throw new InvalidOperationException("no MFA challenge cookie");
    }

    private static async Task<HttpResponseMessage> SecondFactorAsync(HttpClient client, string challenge, string code)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login/totp");
        req.Content = JsonContent.Create(new { code, rememberDevice = false });
        req.Headers.Add("Cookie", $"dependably_mfa={challenge}");
        return await client.SendAsync(req);
    }

    private static async Task<bool> AnyCodeInWindowSucceedsAsync(HttpClient client, string challenge, string manualKey)
    {
        foreach (string code in TotpTestHelper.ComputeWindow(manualKey))
        {
            var resp = await SecondFactorAsync(client, challenge, code);
            Assert.NotEqual(HttpStatusCode.InternalServerError, resp.StatusCode);
            if (resp.StatusCode == HttpStatusCode.OK)
            {
                return true;
            }

            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        return false;
    }

    [Fact]
    public async Task CorruptedKey_EveryCodeIsInvalidNotAServerError_RecoveryCodeStillSignsIn_AndTheLogNamesTheUser()
    {
        var broken = await EnrolAsync();
        var sibling = await EnrolAsync();
        string corrupted = CorruptCiphertext.FlipTagBit(await StoredKeyAsync(broken.UserId));
        await SetStoredKeyAsync(broken.UserId, corrupted);

        using var client = CreateClient();

        // The right code for the key the user enrolled with no longer verifies, and never 500s.
        string challenge = await ChallengeAsync(client, broken.Email);
        Assert.False(await AnyCodeInWindowSucceedsAsync(client, challenge, broken.ManualKey));

        // A recovery code still completes the sign-in.
        string recoveryChallenge = await ChallengeAsync(client, broken.Email);
        Assert.Equal(HttpStatusCode.OK,
            (await SecondFactorAsync(client, recoveryChallenge, broken.RecoveryCodes[0])).StatusCode);

        // An endpoint that checks a TOTP code for a signed-in user also answers "invalid", not 500.
        using var authed = CreateClient();
        authed.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateUserJwt(broken.UserId, "member"));
        foreach (string code in TotpTestHelper.ComputeWindow(broken.ManualKey))
        {
            var r = await authed.PostAsJsonAsync("/api/v1/mfa/recovery-codes/regenerate", new { code });
            Assert.NotEqual(HttpStatusCode.InternalServerError, r.StatusCode);
            Assert.False(r.IsSuccessStatusCode);
        }

        // Another user's TOTP is unaffected.
        string siblingChallenge = await ChallengeAsync(client, sibling.Email);
        Assert.True(await AnyCodeInWindowSucceedsAsync(client, siblingChallenge, sibling.ManualKey));

        Assert.True(_sink.Contains(
            $"\"{ProtectedSecretKinds.UserTotpKey}\" in \"users\" row \"{broken.UserId}\"", LogEventLevel.Warning));
        Assert.False(_sink.Contains(corrupted, LogEventLevel.Verbose));
    }

    [Fact]
    public async Task PlaintextShapedKey_NeverVerifies_AndTheStoredSecretCheckReportsIt()
    {
        var user = await EnrolAsync();

        // A known Base32 key written straight into the column, as a database write outside the
        // application would. Its codes are exactly what an attacker holding the key would send.
        await SetStoredKeyAsync(user.UserId, user.ManualKey);

        using var client = CreateClient();
        string challenge = await ChallengeAsync(client, user.Email);
        Assert.False(await AnyCodeInWindowSucceedsAsync(client, challenge, user.ManualKey));

        string recoveryChallenge = await ChallengeAsync(client, user.Email);
        Assert.Equal(HttpStatusCode.OK,
            (await SecondFactorAsync(client, recoveryChallenge, user.RecoveryCodes[0])).StatusCode);

        Assert.True(_sink.Contains(
            $"\"{ProtectedSecretKinds.UserTotpKey}\" in \"users\" row \"{user.UserId}\"", LogEventLevel.Warning));
        Assert.True(_sink.Contains(ProtectedSecretFailureReasons.UnexpectedPlaintext, LogEventLevel.Warning));
        Assert.False(_sink.Contains(user.ManualKey, LogEventLevel.Verbose));

        using var admin = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        var verify = await admin.PostAsync("/api/v1/instance/secrets/verify", null);
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
        string body = await verify.Content.ReadAsStringAsync();
        Assert.DoesNotContain(user.ManualKey, body);
        using var doc = JsonDocument.Parse(body);
        var failure = Assert.Single(
            doc.RootElement.GetProperty("failures").EnumerateArray(),
            f => f.GetProperty("rowId").GetString() == user.UserId);
        Assert.Equal(ProtectedSecretKinds.UserTotpKey, failure.GetProperty("kind").GetString());
        Assert.Equal(ProtectedSecretFailureReasons.UnexpectedPlaintext, failure.GetProperty("reason").GetString());
    }
}
