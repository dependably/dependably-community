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
/// The projects plane hangs off <c>orgs</c> by FK cascade, so a tenant hard-delete must take the
/// whole tree with it — projects, their versions, and the collection that grouped them. A surviving
/// row here is a tenant's application inventory outliving the tenant, which is exactly the residue a
/// hard-delete exists to remove.
///
/// Runs against the real <see cref="TenantHardDeleteService"/> pass and the live schema rather than
/// asserting on the DDL, because a missing <c>ON DELETE CASCADE</c> is invisible to a declarative
/// check that only reads the schema file.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProjectsOrgCascadeTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;

    public ProjectsOrgCascadeTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task TenantHardDelete_CascadesThroughProjectsAndVersions()
    {
        string slug = "proj-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await _factory.CreateSystemAdminClient();
        var createResp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        string orgId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        var projects = new ProjectRepository(db, _factory.Services.GetRequiredService<TimeProvider>());

        // A collection with a child project and two versions — the full shape of the tree.
        await projects.CreateAsync(orgId, new NewProject("monorepo", ProjectKinds.Collection), null);
        var v1 = await projects.ResolveOrCreateAsync(
            orgId, new ProjectVersionRequest("web", "1.0.0", true, ParentName: "monorepo", IsLatest: true), null, CancellationToken.None);
        await projects.ResolveOrCreateAsync(
            orgId, new ProjectVersionRequest("web", "2.0.0", true, ParentName: "monorepo", IsLatest: true), null, CancellationToken.None);

        Assert.Equal(2, await ProjectCountAsync(db, orgId));
        Assert.Equal(2, await VersionCountAsync(db, orgId));

        // Force deleted_at past the grace window so the hard-delete pass claims the tenant.
        await using (var conn = await db.OpenAsync())
        {
            // now-ok: seeds relative to the host's real clock so the server-side 30-day grace
            // cutoff lands as intended; 90 days clears it with 3x margin rather than sitting one
            // day past it (leap-year/month-length safe).
            string ninetyDaysAgo = DateTimeOffset.UtcNow.AddDays(-90).ToUtcIso();
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @t WHERE id = @id", new { id = orgId, t = ninetyDaysAgo });
        }

        var svc = _factory.Services.GetServices<IHostedService>().OfType<TenantHardDeleteService>().Single();
        await svc.RunPassAsync(default);

        await using (var conn = await db.OpenAsync())
        {
            Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId }));
        }

        Assert.Equal(0, await ProjectCountAsync(db, orgId));
        Assert.Equal(0, await VersionCountAsync(db, orgId));

        // And the version rows are gone by id, not merely unreachable through their org filter.
        await using (var conn = await db.OpenAsync())
        {
            Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM project_versions WHERE id = @id",
                new { id = v1.ProjectVersionId }));
            Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM projects WHERE id = @id", new { id = v1.ProjectId }));
        }
    }

    private static async Task<int> ProjectCountAsync(IMetadataStore db, string orgId)
    {
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM projects WHERE org_id = @orgId", new { orgId });
    }

    private static async Task<int> VersionCountAsync(IMetadataStore db, string orgId)
    {
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM project_versions WHERE org_id = @orgId", new { orgId });
    }
}
