using System.Net;
using System.Net.Http.Headers;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression coverage for the JWT-branch cross-tenant leak in <c>SiemController</c>: before
/// the fix, any authenticated JWT (including a plain tenant <c>member</c>) reached the SIEM
/// endpoints and <c>ResolveOrgFilterAsync</c> fell through with <c>orgId=null</c>, which
/// <c>AuditRepository</c> treats as "all tenants". The handler must now require
/// <c>read:audit</c> and pin non-platform-admin callers to their own <c>tid</c>.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SiemControllerSecurityTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public SiemControllerSecurityTests(DependablyFactory factory) => _factory = factory;

    [Fact]
    public async Task GetAuthEvents_Anonymous_Returns401()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/siem/events/auth");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task GetAuthEvents_TenantMemberJwt_Returns403()
    {
        // Members carry no read:audit cap; previously the handler let them through with a
        // null org filter, returning rows from every tenant. Now they get a clean 403.
        var memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "pw", role: "member");
        var jwt = await _factory.CreateUserJwt(memberId, role: "member");

        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var resp = await c.GetAsync("/api/v1/siem/events/auth");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task GetAuthEvents_TenantOwnerJwt_PinnedToOwnTenant()
    {
        // Insert audit rows in two distinct orgs. An owner-role JWT (cap=read:audit, no
        // platform:*) calling /siem with no ?org= must see only its own tenant's row.
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES ('other-tenant', @slug) " +
                "ON CONFLICT(id) DO NOTHING",
                new { slug = $"other-{Guid.NewGuid():N}" });
            await conn.ExecuteAsync(
                "INSERT INTO audit_log (id, scope, org_id, action, actor_id, detail) " +
                "VALUES (@id, 'tenant', @orgId, 'login.success', 'foreign-user', '{}')",
                new { id = Guid.NewGuid().ToString("N"), orgId = "other-tenant" });
            var defaultOrgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'");
            await conn.ExecuteAsync(
                "INSERT INTO audit_log (id, scope, org_id, action, actor_id, detail) " +
                "VALUES (@id, 'tenant', @orgId, 'login.success', 'home-user', '{}')",
                new { id = Guid.NewGuid().ToString("N"), orgId = defaultOrgId });
        }

        var jwt = await _factory.CreateAdminJwt(); // role=owner, scope=tenant on default
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var resp = await c.GetAsync("/api/v1/siem/events/auth");
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync();

        Assert.Contains("home-user", body);
        Assert.DoesNotContain("foreign-user", body);
    }
}
