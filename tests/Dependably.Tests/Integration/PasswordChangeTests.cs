using System.Net;
using System.Net.Http.Headers;
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

        var jwt = await IssueJwtFor(email);
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

        var jwt = await IssueJwtFor(email);
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

        var jwt = await IssueJwtFor(email);
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
        var userId = await CreateUserWithMembership(email, password);

        // Simulate forced rotation (e.g. invited or first-boot admin) by setting the flag.
        await using (var conn = await GetMetadataStore().OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 1 WHERE id = @id", new { id = userId });
        }

        var jwt = await IssueJwtFor(email);
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

    [Fact]
    public async Task Me_ReflectsMustChangePasswordFlag()
    {
        const string email = "pwtest5@example.com";
        const string password = "originalPassword123";
        var userId = await CreateUserWithMembership(email, password);

        await using (var conn = await GetMetadataStore().OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 1 WHERE id = @id", new { id = userId });
        }

        var jwt = await IssueJwtFor(email);
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
        var flag = await conn.ExecuteScalarAsync<int>(
            "SELECT must_change_password FROM users WHERE role = 'owner' LIMIT 1");
        Assert.Equal(1, flag);
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
        var userId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE email = @email", new { email })
            ?? throw new InvalidOperationException($"User '{email}' not found.");
        var orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("default org missing");
        var jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
            ?? throw new InvalidOperationException("jwt_secret missing");

        var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
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
