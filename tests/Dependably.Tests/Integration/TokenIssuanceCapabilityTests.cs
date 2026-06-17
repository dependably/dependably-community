using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using Dapper;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class TokenIssuanceCapabilityTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public TokenIssuanceCapabilityTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Issues a JWT for an existing user (created via the factory's CreateUser helper) so we
    /// can post token-create requests as that user. Mirrors CreateAdminJwt but takes the user
    /// id and role explicitly — the factory's helper hard-codes the bootstrap owner.
    /// </summary>
    private async Task<string> JwtForUser(string userId, string role)
    {
        var db = _factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>();
        await using var conn = await db.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")!;
        string? jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")!;

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its (default: real) clock.
        var now = DateTime.UtcNow;
        var token = new JwtSecurityToken(
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim("org_id", orgId!),
                new Claim("tid", orgId!),
                new Claim("role", role),
                new Claim("scope", "tenant"),
            ],
            notBefore: now,
            expires: now.AddHours(8),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [Fact]
    public async Task Member_CannotMintPublishToken()
    {
        string memberId = await _factory.CreateUser("member-cap@example.com", "x", role: "member");
        string jwt = await JwtForUser(memberId, "member");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new
        {
            capabilities = new[] { "publish:npm", "read:metadata", "read:artifact" }
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("publish:npm", body);
    }

    [Fact]
    public async Task Member_CanMintReadOnlyToken()
    {
        string memberId = await _factory.CreateUser("member-pull@example.com", "x", role: "member");
        string jwt = await JwtForUser(memberId, "member");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new
        {
            capabilities = new[] { "read:metadata", "read:artifact" }
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Admin_CanMintPublishToken()
    {
        string adminId = await _factory.CreateUser("admin-cap@example.com", "x", role: "admin");
        string jwt = await JwtForUser(adminId, "admin");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new
        {
            capabilities = new[] { "publish:npm", "read:metadata", "read:artifact" }
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Member_CannotMintReadAuditToken()
    {
        // read:audit is owner / admin / auditor only.
        string memberId = await _factory.CreateUser("member-siem@example.com", "x", role: "member");
        string jwt = await JwtForUser(memberId, "member");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new
        {
            capabilities = new[] { "read:audit" }
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("read:audit", body);
    }

    [Fact]
    public async Task Admin_CanMintTokenWithNarrowedCapabilities()
    {
        string adminId = await _factory.CreateUser("admin-narrow@example.com", "x", role: "admin");
        string jwt = await JwtForUser(adminId, "admin");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new
        {
            capabilities = new[] { "publish:npm" }
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = await resp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        string? capabilitiesField = body.GetProperty("record").GetProperty("capabilities").GetString();
        Assert.NotNull(capabilitiesField);
        Assert.Contains("publish:npm", capabilitiesField);
    }

    [Fact]
    public async Task Admin_CannotMintCapabilitiesAboveOwnRole()
    {
        // admin caps don't include tenant:admin (owner-only) — the validator must reject.
        string adminId = await _factory.CreateUser("admin-overshoot@example.com", "x", role: "admin");
        string jwt = await JwtForUser(adminId, "admin");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new
        {
            capabilities = new[] { "publish:npm", "tenant:admin" }
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("tenant:admin", body);
    }

    [Fact]
    public async Task LegacyScopeField_Rejected()
    {
        // Callers updating from the old API must see a clear 400 if they still send `scope`.
        string adminId = await _factory.CreateUser("admin-legacy@example.com", "x", role: "admin");
        string jwt = await JwtForUser(adminId, "admin");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new
        {
            scope = "push",
            capabilities = new[] { "publish:npm" }
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("scope", body);
    }
}
