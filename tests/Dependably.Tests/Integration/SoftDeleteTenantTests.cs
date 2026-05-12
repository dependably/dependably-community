using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Dependably.Tests.Integration;

/// <summary>
/// Soft-delete + restore + hard-delete-after-grace coverage. Uses the multi-mode factory because
/// soft-delete only makes sense in a context where system_admin manages tenants.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SoftDeleteTenantTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;

    public SoftDeleteTenantTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task SoftDelete_MakesTenantSubdomainReturn404Immediately()
    {
        var slug = "del-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await _factory.CreateSystemAdminClient();
        await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug, ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });

        // Pre-delete: bootstrap on the tenant subdomain returns mode=multi (resolver finds tenant).
        using (var pre = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}"))
        {
            var preResp = await pre.GetAsync("/api/v1/bootstrap");
            Assert.Equal(HttpStatusCode.OK, preResp.StatusCode);
        }

        // Soft-delete via system surface.
        var delResp = await sys.DeleteAsync($"/api/v1/system/tenants/{slug}");
        Assert.Equal(HttpStatusCode.NoContent, delResp.StatusCode);

        // Post-delete: any login attempt at the subdomain hits TenantContext.Uninitialized → 404.
        using var postClient = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        var loginResp = await postClient.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = "anyone@example.com", password = "irrelevant",
        });
        Assert.Equal(HttpStatusCode.NotFound, loginResp.StatusCode);
    }

    [Fact]
    public async Task SoftDelete_TenantStillVisibleInSystemList_WithDeletedAt()
    {
        var slug = "vis-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await _factory.CreateSystemAdminClient();
        await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug, ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        await sys.DeleteAsync($"/api/v1/system/tenants/{slug}");

        var listResp = await sys.GetAsync("/api/v1/system/tenants?limit=200");
        var doc = JsonDocument.Parse(await listResp.Content.ReadAsStringAsync());
        var entry = doc.RootElement.GetProperty("items").EnumerateArray()
            .First(o => o.GetProperty("slug").GetString() == slug);
        Assert.NotEqual(JsonValueKind.Null, entry.GetProperty("deletedAt").ValueKind);
    }

    [Fact]
    public async Task Restore_ReactivatesSoftDeletedTenant()
    {
        var slug = "res-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await _factory.CreateSystemAdminClient();
        await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug, ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        await sys.DeleteAsync($"/api/v1/system/tenants/{slug}");

        var restoreResp = await sys.PatchAsync($"/api/v1/system/tenants/{slug}/restore", null);
        Assert.Equal(HttpStatusCode.NoContent, restoreResp.StatusCode);

        // After restore the subdomain resolves again.
        using var post = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        var bootResp = await post.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.OK, bootResp.StatusCode);
    }

    [Fact]
    public async Task Restore_ActiveTenant_Returns409()
    {
        var slug = "act-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await _factory.CreateSystemAdminClient();
        await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug, ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });

        var restoreResp = await sys.PatchAsync($"/api/v1/system/tenants/{slug}/restore", null);
        Assert.Equal(HttpStatusCode.Conflict, restoreResp.StatusCode);
    }

    [Fact]
    public async Task HardDeleteService_AfterGrace_CascadesAndAuditsScopeSystem()
    {
        var slug = "hard-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await _factory.CreateSystemAdminClient();
        var createResp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug, ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        var orgId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        // Force deleted_at to 31 days ago so the hard-delete service treats it as expired.
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            var thirtyOneDaysAgo = DateTimeOffset.UtcNow.AddDays(-31).ToString("yyyy-MM-ddTHH:mm:ssZ");
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @t WHERE id = @id",
                new { id = orgId, t = thirtyOneDaysAgo });
        }

        // Run the hard-delete pass directly (not waiting on cron).
        var svc = _factory.Services.GetServices<IHostedService>()
            .OfType<TenantHardDeleteService>().Single();
        await svc.RunPassAsync(default);

        // Verify cascade: orgs row is gone.
        await using (var conn = await db.OpenAsync())
        {
            var stillThere = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId });
            Assert.Equal(0, stillThere);

            // Audit row written with scope=system.
            var auditCount = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM audit_log WHERE org_id = @id AND action = 'tenant.hard_deleted' AND scope = 'system'",
                new { id = orgId });
            Assert.Equal(1, auditCount);
        }
    }

    [Fact]
    public async Task HardDeleteService_WithinGrace_DoesNotDelete()
    {
        var slug = "keep-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await _factory.CreateSystemAdminClient();
        var createResp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug, ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        var orgId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;
        await sys.DeleteAsync($"/api/v1/system/tenants/{slug}");

        // Soft-delete just happened — well within the 30-day grace.
        var svc = _factory.Services.GetServices<IHostedService>()
            .OfType<TenantHardDeleteService>().Single();
        await svc.RunPassAsync(default);

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        var stillThere = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId });
        Assert.Equal(1, stillThere);
    }
}
