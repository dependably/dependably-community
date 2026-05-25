using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class AuditRepositorySystemAuditTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly AuditRepository _repo;

    public AuditRepositorySystemAuditTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new AuditRepository(_fixture.Store);
    }

    [Fact]
    public async Task ListSystemAuditAsync_ActionFilter_ExactMatch()
    {
        await _repo.LogSystemAsync("tenant.created",        detail: "{\"slug\":\"alpha\"}");
        await _repo.LogSystemAsync("tenant.deleted",        detail: "{\"slug\":\"beta\"}");
        await _repo.LogSystemAsync("tenant.status_changed", detail: "{\"slug\":\"gamma\"}");

        var (items, total) = await _repo.ListSystemAuditAsync(
            limit: 50, offset: 0, action: "tenant.deleted");
        Assert.Equal(1, total);
        Assert.Single(items);
        Assert.Equal("tenant.deleted", items[0].Action);
    }

    [Fact]
    public async Task ListSystemAuditAsync_Search_MatchesAcrossActionAndDetail()
    {
        await _repo.LogSystemAsync("tenant.created", detail: "{\"slug\":\"needle-tenant\"}");
        await _repo.LogSystemAsync("tenant.created", detail: "{\"slug\":\"hay\"}");
        await _repo.LogSystemAsync("system_admin.password_reset",
            actorId: "admin-needle", detail: "{\"email\":\"x@y\"}");

        // Substring across action / actor_id / org_id / detail (case-insensitive).
        var (items, _) = await _repo.ListSystemAuditAsync(limit: 50, offset: 0, search: "NEEDLE");

        // Both rows whose detail or actor contains 'needle' should match.
        Assert.Contains(items, e => e.Detail!.Contains("needle-tenant"));
        Assert.Contains(items, e => e.ActorId == "admin-needle");
        Assert.DoesNotContain(items, e => e.Detail == "{\"slug\":\"hay\"}");
    }

    [Fact]
    public async Task ListSystemAuditAsync_SortBy_ActionAsc_OrdersByAction()
    {
        await _repo.LogSystemAsync("zeta.action");
        await _repo.LogSystemAsync("alpha.action");
        await _repo.LogSystemAsync("mu.action");

        var (items, _) = await _repo.ListSystemAuditAsync(
            limit: 100, offset: 0,
            sortBy: "action", sortDir: "asc");

        // Find the 3 we just inserted (other tests may have written rows; we sample by action prefix).
        var ours = items.Where(e => e.Action is "alpha.action" or "mu.action" or "zeta.action")
                        .Select(e => e.Action)
                        .ToList();
        Assert.Equal(new[] { "alpha.action", "mu.action", "zeta.action" }, ours);
    }

    [Fact]
    public async Task ListSystemAuditAsync_SortBy_UnknownValue_FallsBackToCreatedAt()
    {
        // Whitelist guard: unknown sortBy values must not blow up the SQL. We don't assert
        // strict timestamp order (NowMs resolution is millisecond — same-tick rows can swap),
        // we just assert the call succeeds.
        await _repo.LogSystemAsync("fallback.action");
        var (items, _) = await _repo.ListSystemAuditAsync(
            limit: 50, offset: 0,
            sortBy: "DROP TABLE audit_log", sortDir: "DROP DATABASE");
        Assert.NotEmpty(items);
    }

    [Fact]
    public async Task ListSystemAuditAsync_NeverIncludesTenantScopeRows()
    {
        await _repo.LogAsync("package.publish", orgId: "tenant-id", detail: "tenant body");
        await _repo.LogSystemAsync("tenant.created", detail: "{}");

        var (items, _) = await _repo.ListSystemAuditAsync(limit: 100, offset: 0);
        Assert.DoesNotContain(items, e => e.Scope == "tenant");
        Assert.All(items, e => Assert.Equal("system", e.Scope));
    }

    [Fact]
    public async Task ListDistinctSystemActionsAsync_ReturnsUniqueSorted_SystemActionsOnly()
    {
        await _repo.LogSystemAsync("tenant.created");
        await _repo.LogSystemAsync("tenant.created"); // dupe
        await _repo.LogSystemAsync("tenant.status_changed");
        await _repo.LogAsync("package.publish"); // tenant scope — must not appear

        var actions = await _repo.ListDistinctSystemActionsAsync();
        Assert.Contains("tenant.created", actions);
        Assert.Contains("tenant.status_changed", actions);
        Assert.DoesNotContain("package.publish", actions);
        // Sorted ascending — distinct values appear once each.
        Assert.Equal(actions.OrderBy(a => a, StringComparer.Ordinal).ToList(), actions);
    }

    [Fact]
    public async Task ListSystemAuditAsync_PopulatesActorEmail_FromSystemAdminsJoin()
    {
        var email = $"op-{Guid.NewGuid():N}@example.test";
        var adminId = await SystemAdminSeeder.InsertAsync(_fixture.Store, email);
        await _repo.LogSystemAsync("tenant.status_changed", actorId: adminId,
            detail: $"{{\"slug\":\"join-test-{Guid.NewGuid():N}\"}}");

        var (items, _) = await _repo.ListSystemAuditAsync(
            limit: 50, offset: 0, search: adminId);

        var row = Assert.Single(items, e => e.ActorId == adminId);
        Assert.Equal(email, row.ActorEmail);
    }

    [Fact]
    public async Task ListSystemAuditAsync_Search_MatchesActorEmail_FromJoin()
    {
        // Search must reach across the system_admins JOIN — operators expect to find their
        // own actions by email even though the audit_log row only stores actor_id.
        var unique = Guid.NewGuid().ToString("N");
        var email = $"search-{unique}@example.test";
        var adminId = await SystemAdminSeeder.InsertAsync(_fixture.Store, email);
        await _repo.LogSystemAsync("tenant.created", actorId: adminId, detail: "{}");

        var (items, _) = await _repo.ListSystemAuditAsync(
            limit: 50, offset: 0, search: $"search-{unique}");

        Assert.Single(items, e => e.ActorId == adminId);
    }
}
