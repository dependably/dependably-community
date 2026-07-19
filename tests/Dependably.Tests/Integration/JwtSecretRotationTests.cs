using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Integration;

/// <summary>
/// Operator-triggered rotation of the instance JWT signing secret, end to end against a live host.
///
/// The point of these tests is the words "same process". Minting has always read jwt_secret live
/// per login, while validation used a key copied into JwtBearer once at startup — so rotating the
/// row on a running instance minted tokens the process could not verify, and a rotation was not
/// real until every replica restarted. A test that restarts the host proves nothing about that;
/// every assertion below runs against one host instance that is never restarted.
///
/// This class owns its own factory instance (IClassFixture) because rotating invalidates every
/// session on the host — sharing a fixture would sign other test classes out mid-run.
/// </summary>
[Trait("Category", "Integration")]
public sealed class JwtSecretRotationTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private const string RotateRoute = "/api/v1/system/jwt-secret/rotate";

    private readonly DependablyMultiFactory _factory;

    public JwtSecretRotationTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    // The factory configures no DEPENDABLY_MASTER_KEY, so the stored value is plaintext.
    private async Task<string> StoredSecretAsync()
    {
        await using var conn = await Db.OpenAsync();
        // xtenant: jwt_secret is an instance-wide secret, not scoped to any tenant.
        return await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
            ?? throw new InvalidOperationException("jwt_secret missing — did first boot run?");
    }

    // Mints a system-scoped JWT against an explicit secret, so a test can hold a token signed by
    // a secret the instance has since rotated away from.
    private static string SystemJwtSignedWith(string secret, string adminId, string? scope = "system")
    {
        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)), SecurityAlgorithms.HmacSha256);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, adminId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("role", "system_admin"),
        };
        if (scope is not null)
        {
            claims.Add(new Claim("scope", scope));
        }

        // now-ok: mints a JWT the host validates against its real clock.
        var now = DateTime.UtcNow;
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            claims: claims, notBefore: now, expires: now.AddHours(1), signingCredentials: creds));
    }

    private async Task<string> SystemAdminIdAsync()
    {
        await using var conn = await Db.OpenAsync();
        string id = await conn.ExecuteScalarAsync<string>("SELECT id FROM system_admins LIMIT 1")
            ?? throw new InvalidOperationException("system_admin not found. Was first-boot run?");
        // PasswordRotationGuard 403s a first-boot admin still holding a temporary password.
        await conn.ExecuteAsync(
            "UPDATE system_admins SET must_change_password = 0 WHERE id = @id", new { id });
        return id;
    }

    private HttpClient ClientWithToken(string jwt)
    {
        var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    [Fact]
    public async Task Rotate_ReplacesTheStoredSecretWithANewValue()
    {
        string before = await StoredSecretAsync();

        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PostAsync(RotateRoute, null);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string after = await StoredSecretAsync();
        Assert.NotEqual(before, after);
        Assert.False(string.IsNullOrWhiteSpace(after));
    }

    [Fact]
    public async Task Rotate_ResponseReportsInvalidationAndNeverEchoesTheSecret()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PostAsync(RotateRoute, null);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        var root = JsonDocument.Parse(body).RootElement;

        // camelCase: the Svelte operator UI reads these names.
        Assert.True(root.GetProperty("sessionsInvalidated").GetBoolean());
        Assert.True(root.GetProperty("callerSessionInvalidated").GetBoolean());
        Assert.True(root.TryGetProperty("rotatedAt", out _));

        // The secret must never leave the instance, not even truncated.
        string secret = await StoredSecretAsync();
        Assert.DoesNotContain(secret, body, StringComparison.Ordinal);
        Assert.DoesNotContain(secret[..8], body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenMintedBeforeRotation_IsRejected_WithoutARestart()
    {
        string adminId = await SystemAdminIdAsync();
        string oldSecret = await StoredSecretAsync();
        string oldToken = SystemJwtSignedWith(oldSecret, adminId);

        // Sanity: the token works before the rotation, so the assertion below is about the
        // rotation and not about a malformed token.
        using (var pre = ClientWithToken(oldToken))
        {
            Assert.Equal(HttpStatusCode.OK, (await pre.GetAsync("/api/v1/system/tenants")).StatusCode);
        }

        using (var rotator = await _factory.CreateSystemAdminClient())
        {
            Assert.Equal(HttpStatusCode.OK, (await rotator.PostAsync(RotateRoute, null)).StatusCode);
        }

        // No grace window: the superseded secret stops validating immediately on this replica,
        // which is the whole point when rotation is a response to a suspected key leak.
        using var post = ClientWithToken(oldToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await post.GetAsync("/api/v1/system/tenants")).StatusCode);
    }

    [Fact]
    public async Task TokenMintedAfterRotation_ValidatesInTheSameProcess_WithoutARestart()
    {
        string adminId = await SystemAdminIdAsync();

        using (var rotator = await _factory.CreateSystemAdminClient())
        {
            Assert.Equal(HttpStatusCode.OK, (await rotator.PostAsync(RotateRoute, null)).StatusCode);
        }

        // Mint against the freshly rotated secret exactly as the live login path would, and hit
        // the SAME never-restarted host. Before the signing-key resolver this returned 401: the
        // process was still validating against the key it captured at startup, so rotation broke
        // every new login until each replica restarted.
        string newToken = SystemJwtSignedWith(await StoredSecretAsync(), adminId);
        using var client = ClientWithToken(newToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/system/tenants")).StatusCode);
    }

    [Fact]
    public async Task Rotate_IsAudited_WithActorAndNoSecretMaterial()
    {
        string adminId = await SystemAdminIdAsync();

        using var client = await _factory.CreateSystemAdminClient();
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync(RotateRoute, null)).StatusCode);

        await using var conn = await Db.OpenAsync();
        // xtenant: scope='system' audit rows are operator-plane and carry no tenant.
        var (scope, actorId, detail) = await conn.QuerySingleOrDefaultAsync<(string Scope, string ActorId, string? Detail)>(
            """
            SELECT scope AS Scope, actor_id AS ActorId, detail AS Detail
            FROM audit_log
            WHERE action = 'system_admin.jwt_secret_rotated'
            ORDER BY created_at DESC LIMIT 1
            """);

        Assert.Equal("system", scope);
        Assert.Equal(adminId, actorId);

        // Never the secret, not even in the detail blob.
        string secret = await StoredSecretAsync();
        Assert.DoesNotContain(secret, detail ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rotate_WithTenantScopedSession_IsNotFound()
    {
        // A real tenant owner, not a synthetic id: an unknown sub fails the tver check and 401s
        // before RouteScopeFilter runs, which would pass this test for the wrong reason.
        var (userId, tenantId) = await CreateTenantWithOwnerAsync();
        string tenantJwt = await _factory.CreateTenantJwt(userId, tenantId);

        // RouteScopeFilter pins /api/v1/system/ to scope=system, answering 404 (not 403) so a
        // fully valid tenant session cannot even probe the control plane's shape.
        using var client = ClientWithToken(tenantJwt);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync(RotateRoute, null)).StatusCode);
    }

    // Creates a tenant through the operator surface and returns its owner's (userId, tenantId).
    private async Task<(string UserId, string TenantId)> CreateTenantWithOwnerAsync()
    {
        string slug = "rot-" + Guid.NewGuid().ToString("N")[..8];
        string ownerEmail = $"owner-{Guid.NewGuid():N}@example.com";

        using var admin = await _factory.CreateSystemAdminClient();
        var resp = await admin.PostAsJsonAsync("/api/v1/system/tenants", new { slug, ownerEmail });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        await using var conn = await Db.OpenAsync();
        // xtenant: resolves the just-created tenant's seeded owner by the unique email this test
        // generated; it is not a caller-supplied id.
        return await conn.QuerySingleAsync<(string UserId, string TenantId)>(
            "SELECT id AS UserId, tenant_id AS TenantId FROM users WHERE email = @ownerEmail",
            new { ownerEmail });
    }

    [Fact]
    public async Task Rotate_WithoutScopeClaim_IsUnauthorized()
    {
        string adminId = await SystemAdminIdAsync();
        string noScopeJwt = SystemJwtSignedWith(await StoredSecretAsync(), adminId, scope: null);

        using var client = ClientWithToken(noScopeJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync(RotateRoute, null)).StatusCode);
    }

    [Fact]
    public async Task Rotate_Unauthenticated_IsUnauthorized()
    {
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync(RotateRoute, null)).StatusCode);
    }
}
