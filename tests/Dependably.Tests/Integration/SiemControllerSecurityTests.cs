using System.Net;
using System.Net.Http.Headers;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

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
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "pw", role: "member");
        string jwt = await _factory.CreateUserJwt(memberId, role: "member");

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
        // audit_log.created_at is explicit here (millisecond precision, matching
        // AuditRepository.LogAsync's real NowMs() writer) rather than left to the schema
        // DEFAULT, which is only second-precision — a mismatch that the SIEM window's
        // millisecond-precision `until` bound would otherwise be able to exclude this row on.
        string createdAt = _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow().ToUtcIsoMillis();
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES ('other-tenant', @slug) " +
                "ON CONFLICT(id) DO NOTHING",
                new { slug = $"other-{Guid.NewGuid():N}" });
            await conn.ExecuteAsync(
                "INSERT INTO audit_log (id, scope, org_id, action, actor_id, detail, created_at) " +
                "VALUES (@id, 'tenant', @orgId, 'login.success', 'foreign-user', '{}', @createdAt)",
                new { id = Guid.NewGuid().ToString("N"), orgId = "other-tenant", createdAt });
            string? defaultOrgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'");
            await conn.ExecuteAsync(
                "INSERT INTO audit_log (id, scope, org_id, action, actor_id, detail, created_at) " +
                "VALUES (@id, 'tenant', @orgId, 'login.success', 'home-user', '{}', @createdAt)",
                new { id = Guid.NewGuid().ToString("N"), orgId = defaultOrgId, createdAt });
        }

        string jwt = await _factory.CreateAdminJwt(); // role=owner, scope=tenant on default
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var resp = await c.GetAsync("/api/v1/siem/events/auth");
        resp.EnsureSuccessStatusCode();
        string body = await resp.Content.ReadAsStringAsync();

        Assert.Contains("home-user", body);
        Assert.DoesNotContain("foreign-user", body);
    }

    /// <summary>
    /// Regression for the <c>[AllowAnonymous]</c> guard-bypass: a JWT-session caller flagged
    /// <c>must_change_password</c> must not be able to pull SIEM data. Before the fix,
    /// <c>SiemController</c> carried <c>[AllowAnonymous]</c>, which made both
    /// <c>RouteScopeFilter</c> and <c>PasswordRotationGuard</c> skip the endpoint entirely
    /// (they early-return on <c>IAllowAnonymous</c> metadata), so a session mid-forced-rotation
    /// could still read audit/vuln data through this surface even though every other
    /// <c>/api/v1/</c> route was locked down to the password-change flow.
    /// </summary>
    [Fact]
    public async Task GetAuthEvents_JwtMustChangePassword_Returns403PasswordChangeRequired()
    {
        string email = $"siem-pwrotate-{Guid.NewGuid():N}@example.com";
        string userId = await _factory.CreateUser(email, "pw", role: "auditor"); // auditor: read:audit only

        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 1 WHERE id = @id", new { id = userId });
        }

        string jwt = await _factory.CreateUserJwt(userId, "auditor");
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var resp = await c.GetAsync("/api/v1/siem/events/auth");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("password_change_required", body);
    }

    /// <summary>
    /// Companion regression: with <c>require_mfa</c> on and the caller unenrolled,
    /// <c>MfaEnrollmentGuard</c> must also apply to the SIEM surface — the same
    /// <c>[AllowAnonymous]</c>-bypass class of bug as the password-rotation case above.
    /// </summary>
    [Fact]
    public async Task GetAuthEvents_JwtMfaRequiredUnenrolled_Returns403MfaEnrollmentRequired()
    {
        string email = $"siem-mfarequired-{Guid.NewGuid():N}@example.com";
        string userId = await _factory.CreateUser(email, "pw", role: "auditor");

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await db.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT tenant_id FROM users WHERE id = @id", new { id = userId })
                ?? throw new InvalidOperationException("User not found.");
            await conn.ExecuteAsync(
                "UPDATE org_settings SET require_mfa = 1 WHERE org_id = @orgId", new { orgId });
        }
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);

        try
        {
            string jwt = await _factory.CreateUserJwt(userId, "auditor");
            using var c = _factory.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            var resp = await c.GetAsync("/api/v1/siem/events/auth");

            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            Assert.Contains("mfa_enrollment_required", body);
        }
        finally
        {
            await using var conn = await db.OpenAsync();
            await conn.ExecuteAsync(
                "UPDATE org_settings SET require_mfa = 0 WHERE org_id = @orgId", new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }
}
