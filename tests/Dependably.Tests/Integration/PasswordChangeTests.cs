using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class PasswordChangeTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PasswordChangeTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ChangePassword_WrongCurrentPassword_Returns401()
    {
        const string email = "pwtest1@example.com";
        const string password = "originalPassword123";
        await CreateUserWithMembership(email, password);

        string jwt = await IssueJwtFor(email);
        using var client = _factory.CreateClientWithBearer(jwt);

        var body = JsonContent.Create(new { currentPassword = "wrong-password", newPassword = "brand-new-password-12345" });
        var resp = await client.PostAsync("/api/v1/users/me/password", body);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_NewPasswordTooShort_Returns400()
    {
        const string email = "pwtest2@example.com";
        const string password = "originalPassword123";
        await CreateUserWithMembership(email, password);

        string jwt = await IssueJwtFor(email);
        using var client = _factory.CreateClientWithBearer(jwt);

        var body = JsonContent.Create(new { currentPassword = password, newPassword = "tooshort" });
        var resp = await client.PostAsync("/api/v1/users/me/password", body);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_SameAsCurrent_Returns400()
    {
        const string email = "pwtest3@example.com";
        const string password = "originalPassword123";
        await CreateUserWithMembership(email, password);

        string jwt = await IssueJwtFor(email);
        using var client = _factory.CreateClientWithBearer(jwt);

        var body = JsonContent.Create(new { currentPassword = password, newPassword = password });
        var resp = await client.PostAsync("/api/v1/users/me/password", body);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_Success_UpdatesHashAndClearsForceFlag()
    {
        const string email = "pwtest4@example.com";
        const string password = "originalPassword123";
        const string newPassword = "freshNewPassword456";
        string userId = await CreateUserWithMembership(email, password);

        // Simulate forced rotation (e.g. invited or first-boot admin) by setting the flag.
        await using (var conn = await GetMetadataStore().OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 1 WHERE id = @id", new { id = userId });
        }

        string jwt = await IssueJwtFor(email);
        using var client = _factory.CreateClientWithBearer(jwt);

        var body = JsonContent.Create(new { currentPassword = password, newPassword });
        var resp = await client.PostAsync("/api/v1/users/me/password", body);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        await using var verifyConn = await GetMetadataStore().OpenAsync();
        var (hash, mustChange) = await verifyConn.QuerySingleAsync<(string Hash, int MustChange)>(
            "SELECT password_hash AS Hash, must_change_password AS MustChange FROM users WHERE id = @id",
            new { id = userId });

        Assert.True(BCrypt.Net.BCrypt.Verify(newPassword, hash));
        Assert.False(BCrypt.Net.BCrypt.Verify(password, hash));
        Assert.Equal(0, mustChange);
    }

    /// <summary>
    /// A password change must cut off every credential minted under the old password: other
    /// outstanding sessions (token_version bump rejected in OnTokenValidated) and pre-change
    /// API tokens (user_tokens revoked). The changing session itself continues on the
    /// re-issued cookie.
    /// </summary>
    [Fact]
    public async Task ChangePassword_InvalidatesOtherSessionsAndPreChangeApiTokens()
    {
        const string email = "pwtest-invalidate@example.com";
        const string password = "originalPassword123";
        const string newPassword = "rotatedPassword456!";
        string userId = await CreateUserWithMembership(email, password);

        // Two real sessions via the login endpoint. Each client manages its own cookie
        // container, so A and B hold independent pre-change session JWTs.
        using var sessionA = _factory.CreateClient();
        using var sessionB = _factory.CreateClient();
        (await sessionA.PostAsJsonAsync("/api/v1/auth/login", new { email, password })).EnsureSuccessStatusCode();
        (await sessionB.PostAsJsonAsync("/api/v1/auth/login", new { email, password })).EnsureSuccessStatusCode();

        // Pre-change API token for the same user.
        string orgId;
        await using (var conn = await GetMetadataStore().OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("default org missing");
        }
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var (rawApiToken, _) = await tokens.CreateUserTokenAsync(
            orgId, userId, """["read:artifact","read:metadata"]""", expiresAt: null);

        // Everything authenticates before the change.
        Assert.Equal(HttpStatusCode.OK, (await sessionB.GetAsync("/api/v1/auth/me")).StatusCode);
        using (var npm = _factory.CreateClientWithBearer(rawApiToken))
        {
            Assert.Equal(HttpStatusCode.OK, (await npm.GetAsync("/npm/-/whoami")).StatusCode);
        }

        // Change the password via session A.
        var change = await sessionA.PostAsJsonAsync("/api/v1/users/me/password",
            new { currentPassword = password, newPassword });
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        // Session B (pre-change JWT) is rejected…
        Assert.Equal(HttpStatusCode.Unauthorized, (await sessionB.GetAsync("/api/v1/auth/me")).StatusCode);

        // …the pre-change API token is revoked…
        using (var npm = _factory.CreateClientWithBearer(rawApiToken))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await npm.GetAsync("/npm/-/whoami")).StatusCode);
        }

        await using (var verify = await GetMetadataStore().OpenAsync())
        {
            long remaining = await verify.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM user_tokens WHERE user_id = @id", new { id = userId });
            Assert.Equal(0, remaining);
        }

        // …and session A continues on the cookie re-issued by the change response.
        Assert.Equal(HttpStatusCode.OK, (await sessionA.GetAsync("/api/v1/auth/me")).StatusCode);

        // The new password logs in; the old one no longer does.
        using var fresh = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK,
            (await fresh.PostAsJsonAsync("/api/v1/auth/login", new { email, password = newPassword })).StatusCode);
        using var stale = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await stale.PostAsJsonAsync("/api/v1/auth/login", new { email, password })).StatusCode);
    }

    [Fact]
    public async Task Me_ReflectsMustChangePasswordFlag()
    {
        const string email = "pwtest5@example.com";
        const string password = "originalPassword123";
        string userId = await CreateUserWithMembership(email, password);

        await using (var conn = await GetMetadataStore().OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 1 WHERE id = @id", new { id = userId });
        }

        string jwt = await IssueJwtFor(email);
        using var client = _factory.CreateClientWithBearer(jwt);

        var resp = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.True(doc.RootElement.GetProperty("mustChangePassword").GetBoolean());
    }

    [Fact]
    public async Task FirstBootAdmin_HasMustChangePasswordSet()
    {
        // The factory triggers first-boot on Initialize — verify the seeded tenant owner
        // has the must-rotate flag.
        await using var conn = await GetMetadataStore().OpenAsync();
        int flag = await conn.ExecuteScalarAsync<int>(
            "SELECT must_change_password FROM users WHERE role = 'owner' LIMIT 1");
        Assert.Equal(1, flag);
    }

    [Fact]
    public async Task FlaggedUser_NonAllowlistedEndpoint_Blocked_AllowlistReachable()
    {
        const string email = "pwtest6@example.com";
        const string password = "originalPassword123";
        string userId = await CreateUserWithMembership(email, password);

        string jwt = await IssueJwtFor(email);
        using var client = _factory.CreateClientWithBearer(jwt);

        // Before the flag: a normal authenticated endpoint is reachable (guard doesn't over-block).
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/tokens")).StatusCode);

        await using (var conn = await GetMetadataStore().OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 1 WHERE id = @id", new { id = userId });
        }

        // After the flag: the same endpoint is blocked with the machine-readable code...
        var blocked = await client.GetAsync("/api/v1/tokens");
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        var doc = await JsonDocument.ParseAsync(await blocked.Content.ReadAsStreamAsync());
        Assert.Equal("password_change_required", doc.RootElement.GetProperty("code").GetString());

        // ...while the routes needed to recover stay reachable.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private IMetadataStore GetMetadataStore() => _factory.Services.GetRequiredService<IMetadataStore>();

    private async Task<string> CreateUserWithMembership(string email, string password)
    {
        // CreateUser inserts into the default tenant with role=member; no separate membership
        // row needed under the 1:1 user:tenant model.
        return await _factory.CreateUser(email, password);
    }

    private async Task<string> IssueJwtFor(string email)
    {
        await using var conn = await GetMetadataStore().OpenAsync();
        string userId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE email = @email", new { email })
            ?? throw new InvalidOperationException($"User '{email}' not found.");
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("default org missing");
        string jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
            ?? throw new InvalidOperationException("jwt_secret missing");

        var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its (default: real) clock.
        var now = DateTime.UtcNow;
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            claims: new[]
            {
                new System.Security.Claims.Claim(
                    System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, userId),
                new System.Security.Claims.Claim(
                    System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new System.Security.Claims.Claim("org_id", orgId),
                new System.Security.Claims.Claim("tid", orgId),
                new System.Security.Claims.Claim("role", "member"),
                new System.Security.Claims.Claim("scope", "tenant"),
            },
            notBefore: now,
            expires: now.AddHours(1),
            signingCredentials: creds);
        return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
    }
}
