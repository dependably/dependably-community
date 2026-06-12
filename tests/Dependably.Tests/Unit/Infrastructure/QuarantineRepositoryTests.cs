using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers the quarantine state machine: UNIQUE(org_id, purl) + the state-guarded conflict
/// update mean repeat blocks refresh a pending row and never resurrect a decided one;
/// decisions apply exactly once; manual block/unblock resolution maps onto the same states.
/// </summary>
[Trait("Category", "Unit")]
public sealed class QuarantineRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly QuarantineRepository _repo;

    public QuarantineRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new QuarantineRepository(_fixture.Store);
    }

    [Fact]
    public async Task UpsertPending_RepeatBlocks_RefreshOneRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"q-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/upsert-{Guid.NewGuid():N}@1.0.0";
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "upsert-pkg");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/upsert-pkg@1.0.0");

        await _repo.UpsertPendingAsync(orgId, "npm", purl, "release_age", "{\"a\":1}", null);
        await _repo.UpsertPendingAsync(orgId, "npm", purl, "malicious", "{\"b\":2}", verId);

        var (items, total) = await _repo.ListAsync(orgId, null, null, 10, 0);
        Assert.Equal(1, total);
        // Latest gate + detail win; a later version id fills the initially-null column.
        Assert.Equal("malicious", items[0].Gate);
        Assert.Equal("{\"b\":2}", items[0].Detail);
        Assert.Equal(verId, items[0].PackageVersionId);
        Assert.Equal("pending", items[0].State);
    }

    [Fact]
    public async Task UpsertPending_AfterDecision_DoesNotResurrect()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"q-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/decided-{Guid.NewGuid():N}@1.0.0";

        await _repo.UpsertPendingAsync(orgId, "npm", purl, "kev", null, null);
        var (items, _) = await _repo.ListAsync(orgId, "pending", null, 10, 0);
        string id = items.Single(i => i.Purl == purl).Id;
        Assert.True(await _repo.DecideAsync(orgId, id, "denied", null, null));

        // The next block on the same purl must not flip the decided row back to pending.
        await _repo.UpsertPendingAsync(orgId, "npm", purl, "kev", null, null);
        var entry = await _repo.GetByIdAsync(orgId, id);
        Assert.Equal("denied", entry!.State);
    }

    [Fact]
    public async Task Decide_Twice_SecondReturnsFalse()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"q-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/double-{Guid.NewGuid():N}@1.0.0";
        await _repo.UpsertPendingAsync(orgId, "npm", purl, "epss", null, null);
        var (items, _) = await _repo.ListAsync(orgId, "pending", null, 10, 0);
        string id = items.Single(i => i.Purl == purl).Id;

        Assert.True(await _repo.DecideAsync(orgId, id, "approved", null, "fine"));
        Assert.False(await _repo.DecideAsync(orgId, id, "denied", null, null));

        var entry = await _repo.GetByIdAsync(orgId, id);
        Assert.Equal("approved", entry!.State);
        Assert.Equal("fine", entry.Note);
    }

    [Fact]
    public async Task GetById_CrossOrg_ReturnsNull()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"qa-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"qb-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/cross-{Guid.NewGuid():N}@1.0.0";
        await _repo.UpsertPendingAsync(orgA, "npm", purl, "deprecated", null, null);
        var (items, _) = await _repo.ListAsync(orgA, null, null, 10, 0);
        string id = items.Single(i => i.Purl == purl).Id;

        Assert.Null(await _repo.GetByIdAsync(orgB, id));
        Assert.False(await _repo.DecideAsync(orgB, id, "approved", null, null));
    }

    [Fact]
    public async Task ResolveForVersion_MapsManualStates()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"q-{Guid.NewGuid():N}");
        string purlA = $"pkg:npm/resolve-a-{Guid.NewGuid():N}@1.0.0";
        string purlB = $"pkg:npm/resolve-b-{Guid.NewGuid():N}@1.0.0";
        string pkgIdR = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "resolve-pkg");
        string verA = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgIdR, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/resolve-pkg@1.0.0");
        string verB = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgIdR, "2.0.0", $"pkg:npm/{Guid.NewGuid():N}/resolve-pkg@2.0.0");
        await _repo.UpsertPendingAsync(orgId, "npm", purlA, "vuln_score", null, verA);
        await _repo.UpsertPendingAsync(orgId, "npm", purlB, "vuln_score", null, verB);

        await _repo.ResolveForVersionAsync(orgId, verA, "allowed", null);
        await _repo.ResolveForVersionAsync(orgId, verB, "blocked", null);

        var (items, _) = await _repo.ListAsync(orgId, null, null, 10, 0);
        Assert.Equal("approved", items.Single(i => i.Purl == purlA).State);
        Assert.Equal("denied", items.Single(i => i.Purl == purlB).State);
    }

    [Fact]
    public async Task HasApprovedForPurl_TracksApprovalOnly()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"q-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/ffapprove-{Guid.NewGuid():N}@1.0.0";
        await _repo.UpsertPendingAsync(orgId, "npm", purl, "deprecated", null, null);
        Assert.False(await _repo.HasApprovedForPurlAsync(orgId, purl));

        var (items, _) = await _repo.ListAsync(orgId, "pending", null, 10, 0);
        string id = items.Single(i => i.Purl == purl).Id;
        await _repo.DecideAsync(orgId, id, "approved", null, null);

        Assert.True(await _repo.HasApprovedForPurlAsync(orgId, purl));
        // Org-scoped: another org sees nothing.
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"q2-{Guid.NewGuid():N}");
        Assert.False(await _repo.HasApprovedForPurlAsync(orgB, purl));
    }

    [Fact]
    public async Task List_FiltersByStateAndEcosystem()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"q-{Guid.NewGuid():N}");
        await _repo.UpsertPendingAsync(orgId, "npm", $"pkg:npm/f1-{Guid.NewGuid():N}@1", "kev", null, null);
        await _repo.UpsertPendingAsync(orgId, "pypi", $"pkg:pypi/f2-{Guid.NewGuid():N}@1", "kev", null, null);

        var (npmOnly, npmTotal) = await _repo.ListAsync(orgId, "pending", "npm", 10, 0);
        Assert.Equal(1, npmTotal);
        Assert.All(npmOnly, e => Assert.Equal("npm", e.Ecosystem));

        var (denied, deniedTotal) = await _repo.ListAsync(orgId, "denied", null, 10, 0);
        Assert.Equal(0, deniedTotal);
        Assert.Empty(denied);
    }
}
