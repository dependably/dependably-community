using System.Net;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the org-scoping contract for tenant auth audit rows.
///
/// <para>
/// Every tenant-realm <c>audit_log</c> row must carry <c>org_id</c>: both tenant read surfaces
/// filter on it, so a NULL-org row is written and then reachable from nowhere — invisible on the
/// tenant audit page AND silently dropped from that tenant's SIEM feed.
/// </para>
///
/// <para>
/// <c>login.success</c> is the one deliberate asymmetry, and these tests pin all three sides of
/// it: the row carries <c>org_id</c> (so the SIEM export sees it), it is excluded from
/// <c>ListAuditAsync</c> (a routine login is not a configuration change), and the login is still
/// visible to the operator in the activity feed.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class AuthAuditOrgScopingTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public AuthAuditOrgScopingTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();
    private AuditRepository Audit => _factory.Services.GetRequiredService<AuditRepository>();

    private Task DrainActivityAsync() =>
        _factory.Services.GetRequiredService<ActivityWriterHostedService>().WaitForIdleAsync();

    private async Task<(string UserId, string OrgId, string Email)> SeedUserAsync(string password)
    {
        string email = $"auditorg-{Guid.NewGuid():N}@test.local";
        string userId = await _factory.CreateUser(email, password);
        await using var conn = await Db.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string?>(
            "SELECT tenant_id FROM users WHERE id = @userId", new { userId });
        Assert.NotNull(orgId);
        return (userId, orgId, email);
    }

    [Fact]
    public async Task LoginSuccess_AuditRow_CarriesOrgId_ButIsHiddenFromTheConfigAudit()
    {
        const string password = "OrgScopePass12345";
        var (userId, orgId, email) = await SeedUserAsync(password);

        using var c = _factory.CreateClient();
        var resp = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // 1. The audit_log row exists and is org-scoped — without this the SIEM export drops it.
        await using var conn = await Db.OpenAsync();
        string? rowOrgId = await conn.ExecuteScalarAsync<string?>(
            "SELECT org_id FROM audit_log WHERE actor_id = @userId AND action = 'login.success'",
            new { userId });
        Assert.Equal(orgId, rowOrgId);

        // 2. ...but it is NOT on the tenant Admin-actions list. A routine login is not a
        //    configuration change; surfacing it here is the regression this guards.
        var (items, total, _) = await Audit.ListAuditAsync(orgId, limit: 100, offset: 0);
        Assert.DoesNotContain(items, e => e.Action == "login.success");
        Assert.Equal(items.Count, total <= 100 ? total : items.Count);

        // 3. ...and the login IS still visible to the operator, in the activity feed.
        await DrainActivityAsync();
        long activityRows = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM activity
            WHERE org_id = @orgId AND ecosystem = 'auth' AND event_type = 'login.success'
              AND actor_id = @userId
            """,
            new { orgId, userId });
        Assert.True(activityRows >= 1, "expected login.success in the activity feed");
    }

    [Fact]
    public async Task LoginSuccess_IsVisibleToThePerTenantSiemFeed()
    {
        const string password = "OrgScopePass12345";
        var (userId, orgId, email) = await SeedUserAsync(password);

        using var c = _factory.CreateClient();
        var resp = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // The SIEM auth export is org-filtered (AND (@orgId IS NULL OR org_id = @orgId)), so a
        // NULL-org row would be silently dropped — a security feed blind to successful logins.
        var (events, _) = await Audit.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow().AddDays(1),
            orgId: orgId,
            actionFilter: null,
            limit: 100,
            afterCursor: null);

        Assert.Contains(events, e => e.Action == "login.success" && e.ActorId == userId);
    }

    [Fact]
    public async Task PasswordChange_AuditRow_CarriesOrgId_AndSurfacesOnTheConfigAudit()
    {
        const string password = "OrgScopePass12345";
        const string newPassword = "OrgScopePassRotated67890";
        var (userId, orgId, email) = await SeedUserAsync(password);

        string jwt = await _factory.CreateUserJwt(userId, "admin");
        using var client = _factory.CreateClientWithBearer(jwt);
        var resp = await client.PostAsync("/api/v1/users/me/password",
            JsonContent.Create(new { currentPassword = password, newPassword }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        await using var conn = await Db.OpenAsync();
        string? rowOrgId = await conn.ExecuteScalarAsync<string?>(
            "SELECT org_id FROM audit_log WHERE actor_id = @userId AND action = 'user.password_changed'",
            new { userId });
        Assert.Equal(orgId, rowOrgId);

        // A credential change IS a security event — unlike login.success it belongs on the
        // tenant's configuration/security audit list.
        var (items, _, _) = await Audit.ListAuditAsync(orgId, limit: 100, offset: 0);
        Assert.Contains(items, e => e.Action == "user.password_changed" && e.ActorId == userId);
    }

    [Fact]
    public async Task TenantLockout_AuditRow_CarriesOrgId_AndSurfacesOnTheConfigAudit()
    {
        const string password = "OrgScopePass12345";
        var (_, orgId, email) = await SeedUserAsync(password);

        // Burn through the lockout budget, then one more attempt to hit the locked branch that
        // writes lockout.triggered.
        using var c = _factory.CreateClient();
        for (int i = 0; i < 12; i++)
        {
            await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "wrong-password" });
        }

        await using var conn = await Db.OpenAsync();
        string? rowOrgId = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT org_id FROM audit_log
            WHERE action = 'lockout.triggered' AND detail LIKE '%tenant%'
            ORDER BY created_at DESC LIMIT 1
            """);
        Assert.Equal(orgId, rowOrgId);

        var (items, _, _) = await Audit.ListAuditAsync(orgId, limit: 100, offset: 0);
        Assert.Contains(items, e => e.Action == "lockout.triggered");
    }
}
