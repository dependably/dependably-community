using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Management API for the per-tenant alert center: capability gating (member 403, admin/owner
/// allowed), dismiss idempotency + audit trail, and BOLA (cross-tenant 404).
/// </summary>
[Trait("Category", "Integration")]
public sealed class AlertsControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public AlertsControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        return _factory.CreateClientWithBearer(jwt);
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"amem-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    private async Task<AlertRecord> SeedAlertAsync(string orgId, string? sourceRef = null)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        var repo = new AlertRepository(store, TimeProvider.System);
        var alert = await repo.TryInsertAsync(new NewAlert(
            orgId, AlertTypes.QuarantineNew, Severity: null,
            SourceRef: sourceRef ?? Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: "pkg:npm/ctrl-test@1.0.0",
            Title: "New quarantine item: pkg:npm/ctrl-test@1.0.0", Detail: null));
        return alert!;
    }

    // ── Capability gating ────────────────────────────────────────────────────

    [Fact]
    public async Task List_Member_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.GetAsync("/api/v1/alerts");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Summary_Member_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.GetAsync("/api/v1/alerts/summary");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Dismiss_Member_Forbidden()
    {
        string orgId = await DefaultOrgIdAsync();
        var alert = await SeedAlertAsync(orgId);
        using var c = await MemberClient();
        var resp = await c.PostAsync($"/api/v1/alerts/{alert.Id}/dismiss", content: null);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task List_Admin_Returns200_WithTotalAndItems()
    {
        string orgId = await DefaultOrgIdAsync();
        await SeedAlertAsync(orgId);
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/alerts");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.True(doc.RootElement.GetProperty("total").GetInt64() >= 1);
        Assert.Equal(JsonValueKind.Array, doc.RootElement.GetProperty("items").ValueKind);
    }

    [Fact]
    public async Task Summary_Admin_ReturnsActiveCount()
    {
        string orgId = await DefaultOrgIdAsync();
        await SeedAlertAsync(orgId);
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/alerts/summary");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.True(doc.RootElement.GetProperty("activeCount").GetInt64() >= 1);
    }

    // ── Dismiss: idempotency + audit trail ──────────────────────────────────

    [Fact]
    public async Task Dismiss_ActiveAlert_ChangesStateAndAuditsOnce()
    {
        string orgId = await DefaultOrgIdAsync();
        var alert = await SeedAlertAsync(orgId);
        using var c = await AdminClient();

        var first = await c.PostAsync($"/api/v1/alerts/{alert.Id}/dismiss", content: null);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var firstDoc = await JsonDocument.ParseAsync(await first.Content.ReadAsStreamAsync());
        Assert.Equal("dismissed", firstDoc.RootElement.GetProperty("state").GetString());

        // Repeat dismiss is idempotent — 200, state stays dismissed, no second audit row.
        var second = await c.PostAsync($"/api/v1/alerts/{alert.Id}/dismiss", content: null);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'alert_dismissed' AND detail LIKE @pattern",
            new { pattern = $"%{alert.Id}%" });
        Assert.Equal(1, auditCount);
    }

    [Fact]
    public async Task Dismiss_UnknownId_Returns404()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsync($"/api/v1/alerts/{Guid.NewGuid():N}/dismiss", content: null);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>BOLA guard: an alert seeded for a foreign org is invisible to the default admin — 404.</summary>
    [Fact]
    public async Task Dismiss_CrossTenantAlert_Returns404()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        string foreignOrg = await OrgSeeder.InsertAsync(store, $"alertctl-foreign-{Guid.NewGuid():N}");
        var alert = await SeedAlertAsync(foreignOrg);

        using var c = await AdminClient();
        var resp = await c.PostAsync($"/api/v1/alerts/{alert.Id}/dismiss", content: null);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);

        // The foreign org's alert is untouched.
        var repo = new AlertRepository(store, TimeProvider.System);
        var reread = await repo.GetByIdAsync(foreignOrg, alert.Id);
        Assert.Equal("active", reread!.State);
    }

    // ── Dismiss all: bulk clear, idempotency, tenant scope ──────────────────

    [Fact]
    public async Task DismissAll_Member_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PostAsync("/api/v1/alerts/dismiss-all", content: null);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task DismissAll_ClearsEveryActiveAlert_AuditsOnce_AndIsIdempotent()
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        var repo = new AlertRepository(store, TimeProvider.System);

        // More than one, and deliberately more than a single page would need to matter: the
        // point of the endpoint is that it clears what the caller cannot see.
        var seeded = new List<AlertRecord>();
        for (int i = 0; i < 3; i++)
        {
            seeded.Add(await SeedAlertAsync(orgId));
        }

        using var c = await AdminClient();
        var first = await c.PostAsync("/api/v1/alerts/dismiss-all", content: null);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var firstDoc = await JsonDocument.ParseAsync(await first.Content.ReadAsStreamAsync());
        Assert.True(firstDoc.RootElement.GetProperty("dismissed").GetInt32() >= seeded.Count);

        foreach (var alert in seeded)
        {
            var reread = await repo.GetByIdAsync(orgId, alert.Id);
            Assert.Equal("dismissed", reread!.State);
        }

        Assert.Equal(0, await repo.CountActiveAsync(orgId));

        // Repeat is a no-op: nothing left active, so nothing dismissed and no second audit row.
        var second = await c.PostAsync("/api/v1/alerts/dismiss-all", content: null);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var secondDoc = await JsonDocument.ParseAsync(await second.Content.ReadAsStreamAsync());
        Assert.Equal(0, secondDoc.RootElement.GetProperty("dismissed").GetInt32());

        await using var conn = await store.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'alert_dismissed_all' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(1, auditCount);
    }

    /// <summary>
    /// The adversarial twin of the bulk clear: a WHERE clause that dropped its org predicate
    /// would still satisfy every assertion above, because the caller's own alerts do get
    /// dismissed. This is the assertion that fails when the bulk UPDATE stops being tenant-scoped.
    /// </summary>
    [Fact]
    public async Task DismissAll_LeavesAnotherTenantsAlertsActive()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        string foreignOrg = await OrgSeeder.InsertAsync(store, $"alertctl-bulk-foreign-{Guid.NewGuid():N}");
        var foreignAlert = await SeedAlertAsync(foreignOrg);
        await SeedAlertAsync(await DefaultOrgIdAsync());

        using var c = await AdminClient();
        var resp = await c.PostAsync("/api/v1/alerts/dismiss-all", content: null);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var repo = new AlertRepository(store, TimeProvider.System);
        var reread = await repo.GetByIdAsync(foreignOrg, foreignAlert.Id);
        Assert.Equal("active", reread!.State);
        Assert.Equal(1, await repo.CountActiveAsync(foreignOrg));
    }

    [Fact]
    public async Task Anonymous_Rejected()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/alerts");
        Assert.True(resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
    }
}
