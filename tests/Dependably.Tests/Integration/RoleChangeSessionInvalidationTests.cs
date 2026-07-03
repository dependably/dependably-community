using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// A role change (demotion) snapshots into the 8h session JWT via the <c>role</c> claim and is
/// authorized straight off that claim on the capability-only surfaces. These tests pin the
/// invariant that privilege reduction is immediate: demoting a member bumps <c>token_version</c>
/// so the target's outstanding session JWTs fail the <c>tver</c> check on their next request, a
/// self-demotion re-issues the caller's own cookie so they aren't logged out, and the SAML role
/// resync flow (which mints its session after the role change) still issues a session that
/// carries the post-bump version rather than self-invalidating.
/// </summary>
[Trait("Category", "Integration")]
public sealed class RoleChangeSessionInvalidationTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public RoleChangeSessionInvalidationTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Demotion_InvalidatesTargetsExistingSession_AndNewSessionReflectsLowerRole()
    {
        string ownerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "x", "owner");
        string adminEmail = $"admin-{Guid.NewGuid():N}@example.com";
        const string adminPassword = "adminPassword123";
        string adminId = await _factory.CreateUser(adminEmail, adminPassword, "admin");

        // The admin's live session JWT (role=admin, tver snapshotting the seeded token_version).
        using var adminClient = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(adminId, "admin"));
        Assert.Equal(HttpStatusCode.OK, (await adminClient.GetAsync("/api/v1/auth/me")).StatusCode);

        // The owner demotes the admin to member.
        using var ownerClient = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(ownerId, "owner"));
        var demote = await ownerClient.PatchAsJsonAsync($"/api/v1/users/{adminId}/role", new { role = "member" });
        Assert.Equal(HttpStatusCode.NoContent, demote.StatusCode);

        // The demoted admin's outstanding session JWT is now rejected — the tver bump plus cache
        // eviction takes effect on the very next request, not after the 8h token TTL.
        Assert.Equal(HttpStatusCode.Unauthorized, (await adminClient.GetAsync("/api/v1/auth/me")).StatusCode);

        // A freshly minted session reflects the lower role.
        using var fresh = _factory.CreateClient();
        (await fresh.PostAsJsonAsync("/api/v1/auth/login", new { email = adminEmail, password = adminPassword }))
            .EnsureSuccessStatusCode();
        using var me = await fresh.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        using var doc = JsonDocument.Parse(await me.Content.ReadAsStringAsync());
        Assert.Equal("member", doc.RootElement.GetProperty("role").GetString());
    }

    [Fact]
    public async Task SelfDemotion_ReissuesCallerCookieAtLowerRole()
    {
        string email = $"selfdemote-{Guid.NewGuid():N}@example.com";
        const string password = "selfDemotePwd123";
        await _factory.CreateUser(email, password, "admin");

        // A real cookie-backed session for the admin.
        using var client = _factory.CreateClient();
        (await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password })).EnsureSuccessStatusCode();

        string userId;
        using (var before = await client.GetAsync("/api/v1/auth/me"))
        {
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);
            using var beforeDoc = JsonDocument.Parse(await before.Content.ReadAsStringAsync());
            Assert.Equal("admin", beforeDoc.RootElement.GetProperty("role").GetString());
            userId = beforeDoc.RootElement.GetProperty("userId").GetString()!;
        }

        // The admin demotes THEMSELVES to member.
        var demote = await client.PatchAsJsonAsync($"/api/v1/users/{userId}/role", new { role = "member" });
        Assert.Equal(HttpStatusCode.NoContent, demote.StatusCode);

        // The token_version bump would normally stale the caller's own cookie; the controller
        // re-issues it, so the same client stays authenticated AND now reports the lower role.
        using var after = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
        using var afterDoc = JsonDocument.Parse(await after.Content.ReadAsStringAsync());
        Assert.Equal("member", afterDoc.RootElement.GetProperty("role").GetString());
    }

    [Fact]
    public async Task SameRolePatch_IsNoOp_DoesNotInvalidateSessionOrAuditRoleChange()
    {
        string ownerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "x", "owner");
        string adminId = await _factory.CreateUser($"admin-{Guid.NewGuid():N}@example.com", "adminPassword123", "admin");

        // The admin's live session JWT snapshots the seeded token_version.
        using var adminClient = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(adminId, "admin"));
        Assert.Equal(HttpStatusCode.OK, (await adminClient.GetAsync("/api/v1/auth/me")).StatusCode);

        long versionBefore = await ReadTokenVersionAsync(adminId);

        // The owner PATCHes the admin to the SAME role — an idempotent re-assert.
        using var ownerClient = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(ownerId, "owner"));
        var patch = await ownerClient.PatchAsJsonAsync($"/api/v1/users/{adminId}/role", new { role = "admin" });
        Assert.Equal(HttpStatusCode.NoContent, patch.StatusCode);

        // A same-role PATCH must not bump token_version: the admin's existing session stays valid...
        Assert.Equal(HttpStatusCode.OK, (await adminClient.GetAsync("/api/v1/auth/me")).StatusCode);
        Assert.Equal(versionBefore, await ReadTokenVersionAsync(adminId));

        // ...and it must not emit a spurious role-change audit event.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        long auditRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'member_role_changed' AND detail LIKE @pat",
            new { pat = $"%{adminId}%" });
        Assert.Equal(0, auditRows);
    }

    private async Task<long> ReadTokenVersionAsync(string userId)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });
    }

    /// <summary>
    /// Regression guard for the SAML mid-login resync: <c>LoginViaExternalIdentityAsync</c> reads
    /// <c>token_version</c> before <c>ResyncRoleAsync</c> runs, then issues its JWT. Because a role
    /// change now bumps <c>token_version</c>, the emitted session must carry the post-bump value —
    /// otherwise the just-issued token would fail the <c>tver</c> check on its first request.
    /// </summary>
    [Fact]
    public async Task SamlRoleResync_IssuesValidPostBumpSession()
    {
        var login = _factory.Services.GetRequiredService<LoginService>();
        string orgId = await GetDefaultOrgIdAsync();
        string nameId = $"resync-{Guid.NewGuid():N}";
        string email = $"{nameId}@example.com";

        // First login: JIT-provision as member (token_version starts at 1).
        var first = await login.LoginSamlAsync(orgId, "https://idp.example.com/entity", nameId, email);
        Assert.Equal("member", first.Role);

        // Second login: the IdP now maps this identity to admin. ResyncRoleAsync promotes
        // member->admin, which bumps token_version, then the session JWT is minted.
        var second = await login.LoginSamlAsync(orgId, "https://idp.example.com/entity", nameId, email,
            new SamlLoginOptions(MappedRole: "admin", IdpCanAssignAdmin: true));
        Assert.Equal("admin", second.Role);
        Assert.NotNull(second.Token);

        // The freshly issued session is accepted — it is NOT immediately invalidated by its own bump.
        using var client = _factory.CreateClientWithBearer(second.Token!);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/auth/me")).StatusCode);

        // Its tver claim matches the bumped DB token_version.
        long dbVersion;
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            dbVersion = await conn.ExecuteScalarAsync<long>(
                "SELECT token_version FROM users WHERE id = @id", new { id = second.UserId });
        }
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(second.Token);
        string tver = jwt.Claims.First(c => c.Type == "tver").Value;
        Assert.Equal(dbVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), tver);
        Assert.Equal(2, dbVersion);
    }

    private async Task<string> GetDefaultOrgIdAsync()
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("default org not found");
    }
}
