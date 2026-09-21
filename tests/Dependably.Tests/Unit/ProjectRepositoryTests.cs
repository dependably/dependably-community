using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Repository-level coverage for the projects plane: the collection invariants, the
/// resolve-or-create seam the upload pipeline binds to, the promotion transaction whose whole job
/// is to survive concurrent promoters, and the rename/relocate write whose job is to refuse the
/// moves that would cut a subtree loose from the root.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProjectRepositoryTests : IAsyncLifetime
{
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    private readonly TestMetadataStore _db = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private ProjectRepository Repo => new(_db, _clock);

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)", new { id = OrgA, slug = "acme" });
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)", new { id = OrgB, slug = "globex" });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Ancestors and the folder listing ─────────────────────────────────────────────────────

    [Fact]
    public async Task ListAncestors_ReturnsTheChainRootFirst()
    {
        var repo = Repo;
        var platform = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var payments = await repo.CreateAsync(
            OrgA, new NewProject("payments", ProjectKinds.Collection, ParentId: platform.Id), "u1");
        var api = await repo.CreateAsync(
            OrgA, new NewProject("api", ProjectKinds.Project, ParentId: payments.Id), "u1");

        var chain = await repo.ListAncestorsAsync(OrgA, api.Id);

        Assert.Equal(["platform", "payments"], chain.Select(c => c.Name));
        Assert.Equal([platform.Id, payments.Id], chain.Select(c => c.Id));
    }

    [Fact]
    public async Task ListAncestors_ForRootProject_IsEmpty()
    {
        var repo = Repo;
        var root = await repo.CreateAsync(OrgA, new NewProject("standalone", ProjectKinds.Project), "u1");

        Assert.Empty(await repo.ListAncestorsAsync(OrgA, root.Id));
    }

    [Fact]
    public async Task ListAncestors_ForAnotherOrgsProject_IsEmpty()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgB, new NewProject("monorepo", ProjectKinds.Collection), "u2");
        var child = await repo.CreateAsync(
            OrgB, new NewProject("web", ProjectKinds.Project, ParentId: folder.Id), "u2");

        // Not "the chain minus what org A may see" — the whole read is scoped, so a caller in the
        // wrong org learns nothing about the tree, not even its depth.
        Assert.Empty(await repo.ListAncestorsAsync(OrgA, child.Id));
    }

    [Fact]
    public async Task ListCollections_ReturnsOnlyThisOrgsCollections()
    {
        var repo = Repo;
        var platform = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project, ParentId: platform.Id), "u1");
        await repo.CreateAsync(OrgB, new NewProject("other-folder", ProjectKinds.Collection), "u2");

        var rows = await repo.ListCollectionsAsync(OrgA, 100);

        Assert.Equal([platform.Id], rows.Select(r => r.Id));
    }

    // ── Rename and relocate ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Update_MovesProjectIntoCollection()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");

        var moved = await repo.UpdateAsync(
            OrgA, api.Id,
            new ProjectFields(
                Name: "api",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: folder.Id,
                IsActive: true));

        Assert.Equal(folder.Id, moved!.ParentId);
        Assert.Equal([folder.Id], (await repo.ListAncestorsAsync(OrgA, api.Id)).Select(c => c.Id));
    }

    [Fact]
    public async Task Update_WithNullParent_MovesProjectBackToRoot()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project, ParentId: folder.Id), "u1");

        var moved = await repo.UpdateAsync(OrgA, api.Id,
            new ProjectFields(
                Name: "api",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: null,
                IsActive: true));

        Assert.Null(moved!.ParentId);
        Assert.Empty(await repo.ListAncestorsAsync(OrgA, api.Id));
    }

    [Fact]
    public async Task Update_IntoOwnDescendant_IsRefusedAndLeavesTheTreeIntact()
    {
        var repo = Repo;
        var outer = await repo.CreateAsync(OrgA, new NewProject("outer", ProjectKinds.Collection), "u1");
        var middle = await repo.CreateAsync(
            OrgA, new NewProject("middle", ProjectKinds.Collection, ParentId: outer.Id), "u1");
        var inner = await repo.CreateAsync(
            OrgA, new NewProject("inner", ProjectKinds.Collection, ParentId: middle.Id), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.UpdateAsync(
            OrgA, outer.Id,
            new ProjectFields(
                Name: "outer",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: inner.Id,
                IsActive: true)));

        Assert.Equal(ProjectResolutionReason.ParentIsDescendant, ex.Reason);
        // The adversarial half: a refusal that still wrote would leave outer/middle/inner in a
        // cycle reachable from nothing, which no later read could distinguish from "deleted".
        Assert.Null((await repo.GetAsync(OrgA, outer.Id))!.ParentId);
        Assert.Equal(outer.Id, (await repo.GetAsync(OrgA, middle.Id))!.ParentId);
    }

    [Fact]
    public async Task Update_IntoItself_IsRefused()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.UpdateAsync(
            OrgA, folder.Id,
            new ProjectFields(
                Name: "platform",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: folder.Id,
                IsActive: true)));

        Assert.Equal(ProjectResolutionReason.ParentIsSelf, ex.Reason);
        Assert.Null((await repo.GetAsync(OrgA, folder.Id))!.ParentId);
    }

    [Fact]
    public async Task Update_IntoAProject_IsRefused()
    {
        var repo = Repo;
        var host = await repo.CreateAsync(OrgA, new NewProject("host", ProjectKinds.Project), "u1");
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.UpdateAsync(
            OrgA, api.Id,
            new ProjectFields(
                Name: "api",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: host.Id,
                IsActive: true)));

        Assert.Equal(ProjectResolutionReason.ParentNotACollection, ex.Reason);
    }

    [Fact]
    public async Task Update_IntoAnotherOrgsCollection_ReportsParentNotFound()
    {
        var repo = Repo;
        var foreign = await repo.CreateAsync(OrgB, new NewProject("monorepo", ProjectKinds.Collection), "u2");
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.UpdateAsync(
            OrgA, api.Id,
            new ProjectFields(
                Name: "api",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: foreign.Id,
                IsActive: true)));

        Assert.Equal(ProjectResolutionReason.ParentNotFound, ex.Reason);
        Assert.Null((await repo.GetAsync(OrgA, api.Id))!.ParentId);
    }

    [Fact]
    public async Task Update_ToANameAlreadyTakenInTheTargetScope_IsRefused()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("billing", ProjectKinds.Project), "u1");
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.UpdateAsync(
            OrgA, api.Id,
            new ProjectFields(
                Name: "billing",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: null,
                IsActive: true)));

        Assert.Equal(ProjectResolutionReason.NameTaken, ex.Reason);
        Assert.Equal("api", (await repo.GetAsync(OrgA, api.Id))!.Name);
    }

    [Fact]
    public async Task Update_ToANameTakenOnlyInAnotherScope_Succeeds()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project, ParentId: folder.Id), "u1");
        var rootApi = await repo.CreateAsync(OrgA, new NewProject("gateway", ProjectKinds.Project), "u1");

        // Each collection is its own name namespace, so "api" at the root is free even though the
        // folder already holds one.
        var renamed = await repo.UpdateAsync(
            OrgA, rootApi.Id,
            new ProjectFields(
                Name: "api",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: null,
                IsActive: true));

        Assert.Equal("api", renamed!.Name);
    }

    [Fact]
    public async Task Update_RenamingInPlace_DoesNotCollideWithItself()
    {
        var repo = Repo;
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project, Description: "notes"), "u1");

        var updated = await repo.UpdateAsync(
            OrgA, api.Id,
            new ProjectFields(
                Name: "api",
                Classifier: ProjectClassifiers.Default,
                Description: "notes",
                ParentId: null,
                IsActive: true));

        Assert.Equal("api", updated!.Name);
        Assert.Equal("notes", updated.Description);
    }

    [Fact]
    public async Task Update_ForAnotherOrgsProject_ReportsAbsent()
    {
        var repo = Repo;
        var foreign = await repo.CreateAsync(OrgB, new NewProject("api", ProjectKinds.Project), "u2");

        Assert.Null(await repo.UpdateAsync(
            OrgA, foreign.Id,
            new ProjectFields(
                Name: "hijacked",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: null,
                IsActive: true)));
        Assert.Equal("api", (await repo.GetAsync(OrgB, foreign.Id))!.Name);
    }

    [Fact]
    public async Task Update_MovingACollection_CarriesItsChildrenWithIt()
    {
        var repo = Repo;
        var outer = await repo.CreateAsync(OrgA, new NewProject("outer", ProjectKinds.Collection), "u1");
        var moving = await repo.CreateAsync(OrgA, new NewProject("moving", ProjectKinds.Collection), "u1");
        var leaf = await repo.CreateAsync(
            OrgA, new NewProject("leaf", ProjectKinds.Project, ParentId: moving.Id), "u1");

        await repo.UpdateAsync(OrgA, moving.Id,
            new ProjectFields(
                Name: "moving",
                Classifier: ProjectClassifiers.Default,
                Description: null,
                ParentId: outer.Id,
                IsActive: true));

        Assert.Equal(
            [outer.Id, moving.Id],
            (await repo.ListAncestorsAsync(OrgA, leaf.Id)).Select(c => c.Id));
    }

    // ── Collection rollups ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_CollectionRow_SumsItsWholeSubtreeNotJustItsChildren()
    {
        var repo = Repo;
        // outer / inner / api — the project is two levels down, so a rollup that only looked at
        // direct children would report zeros on the row an operator reads first.
        var outer = await repo.CreateAsync(OrgA, new NewProject("outer", ProjectKinds.Collection), "u1");
        var inner = await repo.CreateAsync(
            OrgA, new NewProject("inner", ProjectKinds.Collection, ParentId: outer.Id), "u1");
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project, ParentId: inner.Id), "u1");
        var web = await repo.CreateAsync(OrgA, new NewProject("web", ProjectKinds.Project, ParentId: outer.Id), "u1");

        await SeedVersionAsync(api.Id, "1.0.0", "pass", components: 3);
        await SeedVersionAsync(web.Id, "2.0.0", "pass", components: 5);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == outer.Id);

        Assert.Equal(8, row.ComponentCount);
        Assert.Equal("pass", row.PolicyStatus);
    }

    [Fact]
    public async Task List_CollectionRow_SumsSeverityCountsAcrossTheSubtree()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var one = await repo.CreateAsync(OrgA, new NewProject("one", ProjectKinds.Project, ParentId: folder.Id), "u1");
        var two = await repo.CreateAsync(OrgA, new NewProject("two", ProjectKinds.Project, ParentId: folder.Id), "u1");

        string v1 = await SeedVersionAsync(one.Id, "1.0.0", "violation", components: 1);
        string v2 = await SeedVersionAsync(two.Id, "1.0.0", "warn", components: 1);
        await SeedFindingAsync(v1, "CRITICAL");
        await SeedFindingAsync(v2, "HIGH");
        await SeedFindingAsync(v2, null);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == folder.Id);

        Assert.Equal(1, row.SeverityCounts.Critical);
        Assert.Equal(1, row.SeverityCounts.High);
        Assert.Equal(1, row.SeverityCounts.Unscored);
        // Worst-wins across the two children.
        Assert.Equal("violation", row.PolicyStatus);
    }

    [Fact]
    public async Task List_PlainProjectRow_SurfacesKevCount()
    {
        var repo = Repo;
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");
        string v1 = await SeedVersionAsync(api.Id, "1.0.0", "violation", components: 1);
        await SeedFindingAsync(v1, "CRITICAL", isKev: true);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == api.Id);

        Assert.Equal(1, row.SeverityCounts.Critical);
        Assert.Equal(1, row.SeverityCounts.KevCount);
    }

    [Fact]
    public async Task List_CollectionRow_FoldsKevCountAcrossTheSubtree()
    {
        var repo = Repo;
        // Mirrors List_CollectionRow_SumsSeverityCountsAcrossTheSubtree, but for the KEV signal
        // that Fold sums on a separate branch from the severity buckets: one child's advisory is
        // KEV-listed, the other's is not, and only the plain-severity leaf rows are asserted
        // correctly by that sibling test — this one is what would have caught Fold forgetting to
        // sum KevCount while the per-project row (and the SQL projection) were already correct.
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var one = await repo.CreateAsync(OrgA, new NewProject("one", ProjectKinds.Project, ParentId: folder.Id), "u1");
        var two = await repo.CreateAsync(OrgA, new NewProject("two", ProjectKinds.Project, ParentId: folder.Id), "u1");

        string v1 = await SeedVersionAsync(one.Id, "1.0.0", "violation", components: 1);
        string v2 = await SeedVersionAsync(two.Id, "1.0.0", "warn", components: 1);
        await SeedFindingAsync(v1, "CRITICAL", isKev: true);
        await SeedFindingAsync(v2, "HIGH", isKev: false);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == folder.Id);

        Assert.Equal(1, row.SeverityCounts.Critical);
        Assert.Equal(1, row.SeverityCounts.High);
        Assert.Equal(1, row.SeverityCounts.KevCount);
    }

    [Fact]
    public async Task List_CollectionRow_WithAnUnscannedProject_DoesNotClaimPass()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var scanned = await repo.CreateAsync(
            OrgA, new NewProject("scanned", ProjectKinds.Project, ParentId: folder.Id), "u1");
        // A project with no version at all reads as "Not scanned" on its own row, and must read
        // the same way through the folder rather than being summed away.
        await repo.CreateAsync(OrgA, new NewProject("never-uploaded", ProjectKinds.Project, ParentId: folder.Id), "u1");
        await SeedVersionAsync(scanned.Id, "1.0.0", "pass", components: 2);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == folder.Id);

        Assert.Null(row.PolicyStatus);
        Assert.Equal(2, row.ComponentCount);
    }

    [Fact]
    public async Task List_EmptyCollection_ReportsZeroesAndNoVerdict()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("empty", ProjectKinds.Collection), "u1");

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == folder.Id);

        Assert.Equal(0, row.ComponentCount);
        Assert.Null(row.PolicyStatus);
        Assert.Null(row.LastUploadAt);
        Assert.Null(row.LatestVersion);
    }

    [Fact]
    public async Task List_PlainProjectRow_StillReportsOnlyItsOwnLatestVersion()
    {
        var repo = Repo;
        // The adversarial twin of the rollup tests: adding subtree folding must not change what a
        // plain project row says, and a project is never a parent, so it can never sum anything.
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");
        await SeedVersionAsync(api.Id, "1.0.0", "pass", components: 4);
        await SeedVersionAsync(api.Id, "0.9.0", "violation", components: 99, isLatest: false);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == api.Id);

        Assert.Equal(4, row.ComponentCount);
        Assert.Equal("pass", row.PolicyStatus);
    }

    [Fact]
    public async Task List_CollectionRow_DoesNotSumAnotherOrgsProjects()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var mine = await repo.CreateAsync(
            OrgA, new NewProject("mine", ProjectKinds.Project, ParentId: folder.Id), "u1");
        await SeedVersionAsync(mine.Id, "1.0.0", "pass", components: 2);

        // A foreign row physically parented to this org's folder — the FK permits it, and only the
        // per-hop org_id filter keeps the walk from picking it up.
        var foreign = await repo.CreateAsync(OrgB, new NewProject("theirs", ProjectKinds.Project), "u2");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE projects SET parent_id = @parentId WHERE id = @id",
                new { parentId = folder.Id, id = foreign.Id });
        }

        await SeedVersionAsync(foreign.Id, "9.9.9", "violation", components: 50, orgId: OrgB);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == folder.Id);

        Assert.Equal(2, row.ComponentCount);
        Assert.Equal("pass", row.PolicyStatus);
    }

    [Fact]
    public async Task GetSubtreeRollup_ForACollection_CountsProjectsAtEveryDepth()
    {
        var repo = Repo;
        var outer = await repo.CreateAsync(OrgA, new NewProject("outer", ProjectKinds.Collection), "u1");
        var inner = await repo.CreateAsync(
            OrgA, new NewProject("inner", ProjectKinds.Collection, ParentId: outer.Id), "u1");
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project, ParentId: inner.Id), "u1");
        var web = await repo.CreateAsync(OrgA, new NewProject("web", ProjectKinds.Project, ParentId: outer.Id), "u1");
        await SeedVersionAsync(api.Id, "1.0.0", "warn", components: 1);
        await SeedVersionAsync(web.Id, "1.0.0", "pass", components: 2);

        var rollup = await repo.GetSubtreeRollupAsync(OrgA, outer.Id);

        Assert.NotNull(rollup);
        // Two projects, not three rows: the nested collection is structure, not inventory.
        Assert.Equal(2, rollup!.ProjectCount);
        Assert.Equal(3, rollup.ComponentCount);
        Assert.Equal("warn", rollup.PolicyStatus);
    }

    [Fact]
    public async Task GetSubtreeRollup_ForAPlainProject_IsNull()
    {
        var repo = Repo;
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");

        // Null means "no rollup applies here", which the API renders as an absent field — distinct
        // from an empty folder, which reports zeroes.
        Assert.Null(await repo.GetSubtreeRollupAsync(OrgA, api.Id));
    }

    [Fact]
    public async Task GetSubtreeRollup_ForAnotherOrgsCollection_IsNull()
    {
        var repo = Repo;
        var foreign = await repo.CreateAsync(OrgB, new NewProject("platform", ProjectKinds.Collection), "u2");

        Assert.Null(await repo.GetSubtreeRollupAsync(OrgA, foreign.Id));
    }

    [Fact]
    public async Task ListChildren_ChildCollection_CarriesItsOwnSubtreeRollup()
    {
        var repo = Repo;
        var outer = await repo.CreateAsync(OrgA, new NewProject("outer", ProjectKinds.Collection), "u1");
        var inner = await repo.CreateAsync(
            OrgA, new NewProject("inner", ProjectKinds.Collection, ParentId: outer.Id), "u1");
        var deep = await repo.CreateAsync(OrgA, new NewProject("deep", ProjectKinds.Project, ParentId: inner.Id), "u1");
        var direct = await repo.CreateAsync(
            OrgA, new NewProject("direct", ProjectKinds.Project, ParentId: outer.Id), "u1");
        await SeedVersionAsync(deep.Id, "1.0.0", "pass", components: 7);
        await SeedVersionAsync(direct.Id, "1.0.0", "pass", components: 1);

        var children = await repo.ListChildrenAsync(OrgA, outer.Id);

        Assert.Equal(7, children.Single(c => c.Id == inner.Id).ComponentCount);
        Assert.Equal(1, children.Single(c => c.Id == direct.Id).ComponentCount);
    }

    [Fact]
    public async Task Rollup_CountsHowManyDescendantsCarryNoVerdict()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var scanned = await repo.CreateAsync(
            OrgA, new NewProject("scanned", ProjectKinds.Project, ParentId: folder.Id), "u1");
        var stamped = await repo.CreateAsync(
            OrgA, new NewProject("stamped", ProjectKinds.Project, ParentId: folder.Id), "u1");
        await repo.CreateAsync(OrgA, new NewProject("never-uploaded", ProjectKinds.Project, ParentId: folder.Id), "u1");
        await SeedVersionAsync(scanned.Id, "1.0.0", "pass", components: 1);
        // A version that exists but was never evaluated counts the same as no version at all —
        // both are "nobody has answered for this yet", which is what the reader needs to act on.
        await SeedVersionAsync(stamped.Id, "1.0.0", null, components: 1);

        var rollup = await repo.GetSubtreeRollupAsync(OrgA, folder.Id);

        Assert.Equal(3, rollup!.ProjectCount);
        Assert.Equal(2, rollup.UnevaluatedProjectCount);
        Assert.Null(rollup.PolicyStatus);
    }

    [Fact]
    public async Task Rollup_WithEverythingEvaluated_CountsNoneUnevaluated()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var one = await repo.CreateAsync(OrgA, new NewProject("one", ProjectKinds.Project, ParentId: folder.Id), "u1");
        await SeedVersionAsync(one.Id, "1.0.0", "pass", components: 1);

        var rollup = await repo.GetSubtreeRollupAsync(OrgA, folder.Id);

        // The UI only renders the count between 0 and ProjectCount, so this is the case that must
        // report zero rather than something falsy-but-present.
        Assert.Equal(0, rollup!.UnevaluatedProjectCount);
        Assert.Equal("pass", rollup.PolicyStatus);
    }

    [Fact]
    public async Task List_ProjectRow_CarriesNoSubtreeCounts()
    {
        var repo = Repo;
        var api = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");
        await SeedVersionAsync(api.Id, "1.0.0", "pass", components: 1);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = items.Single(r => r.Id == api.Id);

        // Null, not zero: a project summarizes only itself, and "0 of 0 unevaluated" would be a
        // statement about a subtree it does not have.
        Assert.Null(row.SubtreeProjectCount);
        Assert.Null(row.SubtreeUnevaluatedProjectCount);
    }

    // ── Uploading into a folder ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ResolveOrCreate_WithParentId_CreatesTheProjectInsideThatFolder()
    {
        var repo = Repo;
        var outer = await repo.CreateAsync(OrgA, new NewProject("outer", ProjectKinds.Collection), "u1");
        var inner = await repo.CreateAsync(
            OrgA, new NewProject("inner", ProjectKinds.Collection, ParentId: outer.Id), "u1");

        var result = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("api", "1.0.0", true, ParentId: inner.Id, IsLatest: true), "u1", CancellationToken.None);

        // Nested two deep, which `parentName` cannot express at all — it is looked up in the root
        // scope, so the same upload without an id would have created a THIRD root-level row.
        Assert.True(result.ProjectCreated);
        Assert.Equal(inner.Id, (await repo.GetAsync(OrgA, result.ProjectId))!.ParentId);
    }

    [Fact]
    public async Task ResolveOrCreate_WithParentId_FindsTheExistingProjectInThatFolder()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var existing = await repo.CreateAsync(
            OrgA, new NewProject("api", ProjectKinds.Project, ParentId: folder.Id), "u1");

        var result = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("api", "2.0.0", true, ParentId: folder.Id, IsLatest: true), "u1", CancellationToken.None);

        Assert.False(result.ProjectCreated);
        Assert.Equal(existing.Id, result.ProjectId);
    }

    [Fact]
    public async Task ResolveOrCreate_WithParentId_DoesNotCollideWithASameNamedRootProject()
    {
        var repo = Repo;
        var folder = await repo.CreateAsync(OrgA, new NewProject("platform", ProjectKinds.Collection), "u1");
        var atRoot = await repo.CreateAsync(OrgA, new NewProject("api", ProjectKinds.Project), "u1");

        var result = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("api", "1.0.0", true, ParentId: folder.Id, IsLatest: true), "u1", CancellationToken.None);

        // Each scope is its own namespace, so this is a NEW project rather than a version added to
        // the root-level one — the failure mode that would silently attach a folder's SBOM to an
        // unrelated project of the same name.
        Assert.True(result.ProjectCreated);
        Assert.NotEqual(atRoot.Id, result.ProjectId);
    }

    [Fact]
    public async Task ResolveOrCreate_WithAnUnknownOrForeignParentId_IsRefusedRatherThanCreated()
    {
        var repo = Repo;
        var foreign = await repo.CreateAsync(OrgB, new NewProject("theirs", ProjectKinds.Collection), "u2");

        foreach (string parentId in new[] { Guid.NewGuid().ToString("N"), foreign.Id })
        {
            // An id the caller supplied and this org does not hold is a mistake to report, never a
            // folder to invent — unlike parentName, which auto-creates under autoCreate.
            var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.ResolveOrCreateAsync(
                OrgA, new ProjectVersionRequest("api", "1.0.0", true, ParentId: parentId, IsLatest: true), "u1", CancellationToken.None));
            Assert.Equal(ProjectResolutionReason.ParentNotFound, ex.Reason);
        }
    }

    [Fact]
    public async Task ResolveOrCreate_WithAProjectAsParentId_IsRefused()
    {
        var repo = Repo;
        var host = await repo.CreateAsync(OrgA, new NewProject("host", ProjectKinds.Project), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("api", "1.0.0", true, ParentId: host.Id, IsLatest: true), "u1", CancellationToken.None));

        Assert.Equal(ProjectResolutionReason.ParentNotACollection, ex.Reason);
    }

    // ── List sorting ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_SortsByNameAscendingByDefault()
    {
        var repo = Repo;
        foreach (string name in new[] { "charlie", "alpha", "bravo" })
        {
            await repo.CreateAsync(OrgA, new NewProject(name, ProjectKinds.Project), "u1");
        }

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);

        Assert.Equal(["alpha", "bravo", "charlie"], items.Select(i => i.Name));
    }

    [Fact]
    public async Task List_SortDescending_ReversesTheOrder()
    {
        var repo = Repo;
        foreach (string name in new[] { "charlie", "alpha", "bravo" })
        {
            await repo.CreateAsync(OrgA, new NewProject(name, ProjectKinds.Project), "u1");
        }

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0, "name", "desc");

        Assert.Equal(["charlie", "bravo", "alpha"], items.Select(i => i.Name));
    }

    [Fact]
    public async Task List_AnUnknownSortKey_FallsBackToTheDefaultRatherThanThrowing()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("bravo", ProjectKinds.Project), "u1");
        await repo.CreateAsync(OrgA, new NewProject("alpha", ProjectKinds.Project), "u1");

        // A stale bookmark naming a column that no longer exists still renders. This is also the
        // injection guard: anything outside the allowlist cannot reach the ORDER BY at all.
        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0, "name; DROP TABLE projects --", "desc");

        // The COLUMN falls back to the default; the direction is a separate, valid value and is
        // still honoured — so this is descending by name rather than the ascending default.
        Assert.Equal(["bravo", "alpha"], items.Select(i => i.Name));

        // And the table is still there: a query that had executed the injected fragment would
        // have taken it with it.
        var (after, total) = await repo.ListAsync(OrgA, null, 50, 0);
        Assert.Equal(2, total);
        Assert.Equal(2, after.Count);
    }

    [Fact]
    public async Task List_SortsByPolicy_WithTheSameSetTheApiAdvertises()
    {
        var repo = Repo;
        var warn = await repo.CreateAsync(OrgA, new NewProject("warned", ProjectKinds.Project), "u1");
        var pass = await repo.CreateAsync(OrgA, new NewProject("passed", ProjectKinds.Project), "u1");
        await SeedVersionAsync(warn.Id, "1.0.0", "warn", components: 0);
        await SeedVersionAsync(pass.Id, "1.0.0", "pass", components: 0);

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0, "policy", "asc");

        Assert.Equal(["passed", "warned"], items.Select(i => i.Name));
        // The allowlist and the UI's sortable headers have to name the same set; asserting the
        // key is accepted here is what makes a divergence visible rather than silent.
        Assert.Contains("policy", ProjectRepository.ListSortKeys);
    }

    [Fact]
    public async Task List_PagesDoNotOverlapWhenTheSortedValueIsShared()
    {
        var repo = Repo;
        // Every row shares a policy value, so only the id tiebreaker keeps the two pages disjoint.
        foreach (string name in new[] { "a", "b", "c", "d" })
        {
            var project = await repo.CreateAsync(OrgA, new NewProject(name, ProjectKinds.Project), "u1");
            await SeedVersionAsync(project.Id, "1.0.0", "pass", components: 0);
        }

        var (first, total) = await repo.ListAsync(OrgA, null, 2, 0, "policy", "asc");
        var (second, _) = await repo.ListAsync(OrgA, null, 2, 2, "policy", "asc");

        Assert.Equal(4, total);
        Assert.Empty(first.Select(i => i.Id).Intersect(second.Select(i => i.Id)));
    }

    // ── Seeding helpers ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Inserts a version and <paramref name="components"/> component rows against it, returning the
    /// version id. Written straight to the tables rather than through the SBOM ingest pipeline: the
    /// rollup reads these columns, so seeding them directly is what keeps the test about the fold.
    /// </summary>
    private async Task<string> SeedVersionAsync(
        string projectId, string version, string? policyStatus, int components,
        bool isLatest = true, string orgId = OrgA)
    {
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, policy_status, created_at)
            VALUES (@versionId, @orgId, @projectId, @version, @isLatest, @policyStatus, @createdAt)
            """,
            new
            {
                versionId,
                orgId,
                projectId,
                version,
                isLatest = isLatest ? 1 : 0,
                policyStatus,
                createdAt = _clock.GetUtcNow().ToUtcIso(),
            });

        for (int i = 0; i < components; i++)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                     dependency_scope, created_at)
                VALUES (@id, @orgId, @versionId, @purl, 'npm', @name, '1.0.0', @name,
                        'runtime', @createdAt)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    versionId,
                    purl = $"pkg:npm/{versionId[..8]}-{i}@1.0.0",
                    name = $"{versionId[..8]}-{i}",
                    createdAt = _clock.GetUtcNow().ToUtcIso(),
                });
        }

        return versionId;
    }

    /// <summary>Links the version's first component to a fresh advisory of the given severity.</summary>
    private async Task SeedFindingAsync(string versionId, string? severity, bool isKev = false)
    {
        await using var conn = await _db.OpenAsync();
        string componentId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM sbom_components WHERE project_version_id = @versionId LIMIT 1",
            new { versionId }) ?? throw new InvalidOperationException("Seed a component first.");

        string vulnId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, is_kev, fetched_at)
            VALUES (@vulnId, @osvId, 'npm', 'seed', @severity, @isKev, @fetchedAt)
            """,
            new
            {
                vulnId,
                osvId = $"GHSA-{vulnId[..12]}",
                severity,
                isKev = isKev ? 1 : 0,
                fetchedAt = _clock.GetUtcNow().ToUtcIso(),
            });

        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at)
            VALUES (@id, @componentId, @vulnId, @checkedAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                componentId,
                vulnId,
                checkedAt = _clock.GetUtcNow().ToUtcIso(),
            });
    }

    // ── Collection invariants ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Create_WithProjectAsParent_IsRefused()
    {
        var repo = Repo;
        var parent = await repo.CreateAsync(OrgA, new NewProject("payments-api", ProjectKinds.Project), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.CreateAsync(
            OrgA, new NewProject("child", ProjectKinds.Project, ParentId: parent.Id), "u1"));
        Assert.Equal(ProjectResolutionReason.ParentNotACollection, ex.Reason);
    }

    [Fact]
    public async Task Create_WithParentFromAnotherOrg_ReportsParentNotFound()
    {
        var repo = Repo;
        var foreign = await repo.CreateAsync(OrgB, new NewProject("monorepo", ProjectKinds.Collection), "u2");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.CreateAsync(
            OrgA, new NewProject("child", ProjectKinds.Project, ParentId: foreign.Id), "u1"));
        Assert.Equal(ProjectResolutionReason.ParentNotFound, ex.Reason);
    }

    [Fact]
    public async Task Create_UnderCollection_UsesItsOwnNameNamespace()
    {
        var repo = Repo;
        var collection = await repo.CreateAsync(OrgA, new NewProject("monorepo", ProjectKinds.Collection), "u1");

        // The same name at the root and inside the collection are two distinct projects — the two
        // partial unique indexes give each scope its own namespace.
        var root = await repo.CreateAsync(OrgA, new NewProject("web", ProjectKinds.Project), "u1");
        var nested = await repo.CreateAsync(
            OrgA, new NewProject("web", ProjectKinds.Project, ParentId: collection.Id), "u1");

        Assert.NotEqual(root.Id, nested.Id);
        Assert.Null((await repo.GetByNameAsync(OrgA, null, "web"))!.ParentId);
        Assert.Equal(collection.Id, (await repo.GetByNameAsync(OrgA, collection.Id, "web"))!.ParentId);
    }

    [Fact]
    public async Task Create_UnknownClassifier_FallsBackToApplication()
    {
        var created = await Repo.CreateAsync(
            OrgA, new NewProject("svc", ProjectKinds.Project, Classifier: "not-a-cyclonedx-type"), "u1");
        Assert.Equal(ProjectClassifiers.Default, created.Classifier);
    }

    // ── ResolveOrCreateAsync — the cross-agent seam ──────────────────────────────────────────

    [Fact]
    public async Task ResolveOrCreate_AutoCreate_CreatesProjectAndVersionAndMakesFirstLatest()
    {
        var result = await Repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: false, Classifier: "library"), "u1", CancellationToken.None);

        Assert.True(result.ProjectCreated);
        Assert.True(result.VersionCreated);
        Assert.Equal("checkout", result.ProjectName);
        Assert.Equal("1.0.0", result.VersionLabel);

        var project = await Repo.GetAsync(OrgA, result.ProjectId);
        Assert.Equal("library", project!.Classifier);

        // The first version is latest even though the caller did not ask, so `latest` resolves.
        Assert.Equal(result.ProjectVersionId, await Repo.ResolveVersionIdAsync(OrgA, result.ProjectId, "latest"));
    }

    [Fact]
    public async Task ResolveOrCreate_WithoutAutoCreate_ReportsNotFound()
    {
        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => Repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("absent", "1.0.0", false, IsLatest: false), "u1", CancellationToken.None));
        Assert.Equal(ProjectResolutionReason.NotFound, ex.Reason);
    }

    [Fact]
    public async Task ResolveOrCreate_ExistingProjectMissingVersionWithoutAutoCreate_ReportsNotFound()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("checkout", ProjectKinds.Project), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "9.9.9", false, IsLatest: false), "u1", CancellationToken.None));
        Assert.Equal(ProjectResolutionReason.NotFound, ex.Reason);
    }

    [Fact]
    public async Task ResolveOrCreate_TargetIsCollection_ReportsCollectionTarget()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("monorepo", ProjectKinds.Collection), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("monorepo", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None));
        Assert.Equal(ProjectResolutionReason.CollectionTarget, ex.Reason);
    }

    [Fact]
    public async Task ResolveOrCreate_NamedParent_AutoCreatesItAsACollection()
    {
        var repo = Repo;
        var result = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("web", "2.0.0", true, ParentName: "monorepo", ParentVersion: "ignored", IsLatest: true), "u1", CancellationToken.None);

        var project = await repo.GetAsync(OrgA, result.ProjectId);
        Assert.NotNull(project!.ParentId);

        var parent = await repo.GetAsync(OrgA, project.ParentId!);
        Assert.Equal(ProjectKinds.Collection, parent!.Kind);
        Assert.Equal("monorepo", parent.Name);
    }

    [Fact]
    public async Task ResolveOrCreate_NamedParentIsAProject_ReportsParentNotACollection()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("not-a-collection", ProjectKinds.Project), "u1");

        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("web", "1.0.0", true, ParentName: "not-a-collection", IsLatest: false), "u1", CancellationToken.None));
        Assert.Equal(ProjectResolutionReason.ParentNotACollection, ex.Reason);
    }

    [Fact]
    public async Task ResolveOrCreate_NamedParentAbsentWithoutAutoCreate_ReportsParentNotFound()
    {
        var ex = await Assert.ThrowsAsync<ProjectResolutionException>(() => Repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("web", "1.0.0", false, ParentName: "monorepo", IsLatest: false), "u1", CancellationToken.None));
        Assert.Equal(ProjectResolutionReason.ParentNotFound, ex.Reason);
    }

    [Fact]
    public async Task ResolveOrCreate_SecondCall_ResolvesRatherThanDuplicates()
    {
        var repo = Repo;
        var first = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);
        var second = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);

        Assert.Equal(first.ProjectId, second.ProjectId);
        Assert.Equal(first.ProjectVersionId, second.ProjectVersionId);
        Assert.False(second.ProjectCreated);
        Assert.False(second.VersionCreated);
    }

    [Fact]
    public async Task ResolveOrCreate_IsLatestOnANewerVersion_DemotesThePreviousOne()
    {
        var repo = Repo;
        var first = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);
        var second = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "2.0.0", true, IsLatest: true), "u1", CancellationToken.None);

        Assert.Equal(1, await LatestCountAsync(first.ProjectId));
        Assert.Equal(second.ProjectVersionId, await Repo.ResolveVersionIdAsync(OrgA, first.ProjectId, "latest"));
    }

    [Fact]
    public async Task ResolveOrCreate_WithoutIsLatest_LeavesTheStandingLatestAlone()
    {
        var repo = Repo;
        var first = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);
        await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.1.0-rc1", true, IsLatest: false), "u1", CancellationToken.None);

        Assert.Equal(first.ProjectVersionId, await repo.ResolveVersionIdAsync(OrgA, first.ProjectId, "latest"));
    }

    // ── Promotion ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PromoteLatest_MovesTheFlagAndLeavesExactlyOne()
    {
        var repo = Repo;
        var v1 = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);
        var v2 = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "2.0.0", true, IsLatest: false), "u1", CancellationToken.None);

        Assert.True(await repo.PromoteLatestAsync(OrgA, v1.ProjectId, v2.ProjectVersionId));

        Assert.Equal(1, await LatestCountAsync(v1.ProjectId));
        Assert.Equal(v2.ProjectVersionId, await repo.ResolveVersionIdAsync(OrgA, v1.ProjectId, "latest"));
    }

    [Fact]
    public async Task PromoteLatest_CrossOrgVersionId_ReportsAbsentRatherThanPromoting()
    {
        var repo = Repo;
        var mine = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);
        var theirs = await repo.ResolveOrCreateAsync(
            OrgB, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u2", CancellationToken.None);

        Assert.False(await repo.PromoteLatestAsync(OrgA, mine.ProjectId, theirs.ProjectVersionId));
        Assert.Equal(mine.ProjectVersionId, await repo.ResolveVersionIdAsync(OrgA, mine.ProjectId, "latest"));
    }

    /// <summary>
    /// The invariant the partial unique index exists for: several promoters racing over the same
    /// project must leave exactly one <c>is_latest</c> row, and every one of them must either win
    /// or resolve against the winner — none may fail outright.
    ///
    /// Deliberately unsequenced concurrency: without the clear-then-set transaction, a lost update
    /// leaves two rows flagged and the count assertion fails.
    /// </summary>
    [Fact]
    public async Task PromoteLatest_ConcurrentPromoters_LeaveExactlyOneLatestRow()
    {
        var repo = Repo;
        var seed = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);

        var versionIds = new List<string> { seed.ProjectVersionId };
        for (int i = 2; i <= 6; i++)
        {
            var created = await repo.ResolveOrCreateAsync(
                OrgA, new ProjectVersionRequest("checkout", $"{i}.0.0", true, IsLatest: false), "u1", CancellationToken.None);
            versionIds.Add(created.ProjectVersionId);
        }

        using var gate = new Barrier(versionIds.Count);
        var promotions = versionIds.Select(versionId => Task.Run(async () =>
        {
            gate.SignalAndWait();
            return await new ProjectRepository(_db, _clock)
                .PromoteLatestAsync(OrgA, seed.ProjectId, versionId);
        })).ToArray();

        bool[] outcomes = await Task.WhenAll(promotions);

        Assert.All(outcomes, Assert.True);
        Assert.Equal(1, await LatestCountAsync(seed.ProjectId));

        // And the surviving flag names a real version of this project, not a stale id.
        string? latestId = await repo.ResolveVersionIdAsync(OrgA, seed.ProjectId, "latest");
        Assert.Contains(latestId, versionIds);
    }

    // ── Latest resolution and deletes ────────────────────────────────────────────────────────

    [Fact]
    public async Task ResolveVersionId_UnknownIdAndLatestWithNoVersions_BothResolveToNull()
    {
        var repo = Repo;
        var empty = await repo.CreateAsync(OrgA, new NewProject("empty", ProjectKinds.Project), "u1");

        Assert.Null(await repo.ResolveVersionIdAsync(OrgA, empty.Id, "latest"));
        Assert.Null(await repo.ResolveVersionIdAsync(OrgA, empty.Id, "no-such-version"));
    }

    [Fact]
    public async Task DeleteVersion_RemovesOnlyThatVersion()
    {
        var repo = Repo;
        var v1 = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);
        var v2 = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "2.0.0", true, IsLatest: false), "u1", CancellationToken.None);

        Assert.True(await repo.DeleteVersionAsync(OrgA, v1.ProjectId, v2.ProjectVersionId));

        var remaining = await repo.ListVersionsAsync(OrgA, v1.ProjectId);
        Assert.Equal(v1.ProjectVersionId, Assert.Single(remaining).Id);
    }

    [Fact]
    public async Task Delete_CrossOrgProjectId_DoesNothing()
    {
        var repo = Repo;
        var theirs = await repo.CreateAsync(OrgB, new NewProject("theirs", ProjectKinds.Project), "u2");

        Assert.False(await repo.DeleteAsync(OrgA, theirs.Id));
        Assert.NotNull(await repo.GetAsync(OrgB, theirs.Id));
    }

    /// <summary>
    /// A collection's blob-key enumeration walks the whole subtree, and it is done BEFORE the
    /// delete because the metadata row is the blob's only reference. Mixed on purpose: one child
    /// carries documents, another carries none — the enumeration must return the first child's
    /// keys without being derailed by the second.
    /// </summary>
    [Fact]
    public async Task ListDocumentBlobKeysForProject_WalksTheSubtreeAcrossChildrenWithAndWithoutDocuments()
    {
        var repo = Repo;
        var collection = await repo.CreateAsync(OrgA, new NewProject("monorepo", ProjectKinds.Collection), "u1");

        var withDocs = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("web", "1.0.0", true, ParentName: "monorepo", IsLatest: true), "u1", CancellationToken.None);
        var withoutDocs = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("api", "1.0.0", true, ParentName: "monorepo", IsLatest: true), "u1", CancellationToken.None);

        await SeedDocumentAsync(withDocs.ProjectVersionId, "sbom", "key/sbom");
        await SeedDocumentAsync(withDocs.ProjectVersionId, "sarif", "key/sarif");

        var keys = await repo.ListDocumentBlobKeysForProjectAsync(OrgA, collection.Id);
        Assert.Equal(["key/sarif", "key/sbom"], keys.OrderBy(k => k, StringComparer.Ordinal));

        // The childless project contributes nothing but is still reachable in the tree.
        Assert.Empty(await repo.ListDocumentBlobKeysForVersionAsync(OrgA, withoutDocs.ProjectVersionId));

        // And deleting the collection cascades the whole subtree away.
        Assert.True(await repo.DeleteAsync(OrgA, collection.Id));
        Assert.Null(await repo.GetAsync(OrgA, withDocs.ProjectId));
        Assert.Null(await repo.GetAsync(OrgA, withoutDocs.ProjectId));
    }

    // ── List rollups ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_RollsUpTheLatestVersionAndNeverCrossesOrgs()
    {
        var repo = Repo;
        var mine = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);
        await repo.ResolveOrCreateAsync(
            OrgB, new ProjectVersionRequest("checkout", "9.9.9", true, IsLatest: true), "u2", CancellationToken.None);

        string critical = await SeedComponentWithAdvisoryAsync(mine.ProjectVersionId, "pkg:npm/qs@6.10.2", "CRITICAL");
        await SeedComponentWithAdvisoryAsync(mine.ProjectVersionId, "pkg:npm/minimist@1.2.5", null);
        Assert.NotEmpty(critical);

        var (items, total) = await repo.ListAsync(OrgA, null, 50, 0);

        var row = Assert.Single(items);
        Assert.Equal(1, total);
        Assert.Equal("checkout", row.Name);
        Assert.Equal("1.0.0", row.LatestVersion);
        Assert.Equal(2, row.ComponentCount);
        Assert.Equal(1, row.SeverityCounts.Critical);

        // An advisory with no CVSS classification surfaces as unscored rather than being folded
        // into a severity it was never assigned.
        Assert.Equal(1, row.SeverityCounts.Unscored);
        Assert.Equal(0, row.SeverityCounts.High);
    }

    [Fact]
    public async Task List_SeverityCounts_ExcludeVexSuppressedAdvisories()
    {
        var repo = Repo;
        var version = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u1", CancellationToken.None);

        await SeedSuppressedComponentAdvisoryAsync(version.ProjectVersionId, "pkg:npm/qs@6.10.2", "CRITICAL");

        var (items, _) = await repo.ListAsync(OrgA, null, 50, 0);
        var row = Assert.Single(items);

        // A VEX statement recording this advisory as not_affected suppresses it. The list's
        // severity chips must agree with the version-detail rollup, which excludes a suppressed
        // advisory from its counts by default — a fully triaged project reads clean on both
        // surfaces, not red on one and clean on the other.
        Assert.Equal(0, row.SeverityCounts.Critical);
        Assert.Equal(0, row.SeverityCounts.Unscored);
    }

    [Fact]
    public async Task List_SearchEscapesWildcardsInTheCallersText()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("cost-100%-service", ProjectKinds.Project), "u1");
        await repo.CreateAsync(OrgA, new NewProject("unrelated", ProjectKinds.Project), "u1");

        var (matched, matchedTotal) = await repo.ListAsync(OrgA, "100%", 50, 0);
        Assert.Equal(1, matchedTotal);
        Assert.Equal("cost-100%-service", Assert.Single(matched).Name);

        // A bare '%' is a literal too — it must not behave as "match everything".
        var (none, noneTotal) = await repo.ListAsync(OrgA, "%unrelated", 50, 0);
        Assert.Equal(0, noneTotal);
        Assert.Empty(none);
    }

    [Fact]
    public async Task List_CollectionRowCarriesNoVersionRollup()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("monorepo", ProjectKinds.Collection), "u1");

        var (items, _) = await repo.ListAsync(OrgA, "monorepo", 50, 0);
        var row = Assert.Single(items);

        Assert.Equal(ProjectKinds.Collection, row.Kind);
        Assert.Null(row.LatestVersion);
        Assert.Equal(0, row.ComponentCount);
        Assert.Null(row.LastUploadAt);
    }

    [Fact]
    public async Task List_Unfiltered_ReturnsRootLevelProjectsOnly()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("monorepo", ProjectKinds.Collection), "u1");
        var collection = (await repo.GetByNameAsync(OrgA, null, "monorepo"))!;
        await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("web", "1.0.0", true, ParentName: "monorepo", IsLatest: true), "u1", CancellationToken.None);

        var (items, total) = await repo.ListAsync(OrgA, null, 50, 0);

        // The nested project renders under its collection on the detail page, not interleaved
        // with root rows on the unfiltered list — the list holds root-level rows only, and the
        // count matches what it renders.
        var row = Assert.Single(items);
        Assert.Equal(1, total);
        Assert.Equal(collection.Id, row.Id);
        Assert.Null(row.ParentId);
    }

    [Fact]
    public async Task List_Search_MatchesANestedProjectAndCarriesItsParent()
    {
        var repo = Repo;
        await repo.CreateAsync(OrgA, new NewProject("monorepo", ProjectKinds.Collection), "u1");
        var web = await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("web-checkout", "1.0.0", true, ParentName: "monorepo", IsLatest: true), "u1", CancellationToken.None);

        var (items, total) = await repo.ListAsync(OrgA, "checkout", 50, 0);

        // A search matches at any depth — the root collection did not match "checkout" and is
        // correctly absent, but its child is found and carries the parent context the caller
        // needs to group it under.
        var row = Assert.Single(items);
        Assert.Equal(1, total);
        Assert.Equal(web.ProjectId, row.Id);
        Assert.Equal("monorepo", row.ParentName);
    }

    [Fact]
    public async Task ListChildren_ReturnsDirectChildrenWithTheirOwnLatest()
    {
        var repo = Repo;
        var collection = await repo.CreateAsync(OrgA, new NewProject("monorepo", ProjectKinds.Collection), "u1");
        await repo.ResolveOrCreateAsync(
            OrgA, new ProjectVersionRequest("web", "3.1.4", true, ParentName: "monorepo", IsLatest: true), "u1", CancellationToken.None);

        var child = Assert.Single(await repo.ListChildrenAsync(OrgA, collection.Id));
        Assert.Equal("web", child.Name);
        Assert.Equal("3.1.4", child.LatestVersion);
        Assert.Null(child.PolicyStatus);
    }

    // ── Seeding helpers ──────────────────────────────────────────────────────────────────────

    private async Task<long> LatestCountAsync(string projectId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_versions WHERE project_id = @projectId AND is_latest = 1",
            new { projectId });
    }

    private async Task SeedDocumentAsync(string projectVersionId, string docType, string blobKey)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents (id, org_id, project_version_id, doc_type, format, sha256,
                                           size_bytes, blob_key, uploaded_at)
            VALUES (@id, @orgId, @projectVersionId, @docType, @format, @sha256, 1, @blobKey, @uploadedAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = OrgA,
                projectVersionId,
                docType,
                format = docType == "sarif" ? "sarif-json" : "cyclonedx-json",
                sha256 = new string('a', 64),
                blobKey,
                uploadedAt = _clock.GetUtcNow().ToUtcIso(),
            });
    }

    // Inserts one component plus, when a severity is supplied or not, one advisory joined to it.
    // A null severity models an advisory carrying no CVSS classification.
    private async Task<string> SeedComponentWithAdvisoryAsync(
        string projectVersionId, string purl, string? severity)
    {
        string componentId = Guid.NewGuid().ToString("N");
        string vulnId = Guid.NewGuid().ToString("N");

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components (id, org_id, project_version_id, purl, ecosystem, purl_name,
                                         version, name, created_at)
            VALUES (@componentId, @orgId, @projectVersionId, @purl, 'npm', 'x', '1.0.0', 'x', @now)
            """,
            new { componentId, orgId = OrgA, projectVersionId, purl, now = _clock.GetUtcNow().ToUtcIso() });

        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity)
            VALUES (@vulnId, @osvId, 'npm', 'x', @severity)
            """,
            new { vulnId, osvId = "OSV-" + vulnId, severity });

        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at)
            VALUES (@id, @componentId, @vulnId, @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                componentId,
                vulnId,
                now = _clock.GetUtcNow().ToUtcIso(),
            });

        return componentId;
    }

    // Same shape as SeedComponentWithAdvisoryAsync, plus a VEX statement recording the advisory
    // as not_affected — the purl_key it is keyed under ("pkg:npm/x") matches what the read path
    // derives from the fixed ecosystem/purl_name the component below always carries.
    private async Task SeedSuppressedComponentAdvisoryAsync(
        string projectVersionId, string purl, string severity)
    {
        string componentId = Guid.NewGuid().ToString("N");
        string vulnId = Guid.NewGuid().ToString("N");
        string osvId = "OSV-" + vulnId;

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components (id, org_id, project_version_id, purl, ecosystem, purl_name,
                                         version, name, created_at)
            VALUES (@componentId, @orgId, @projectVersionId, @purl, 'npm', 'x', '1.0.0', 'x', @now)
            """,
            new { componentId, orgId = OrgA, projectVersionId, purl, now = _clock.GetUtcNow().ToUtcIso() });

        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity)
            VALUES (@vulnId, @osvId, 'npm', 'x', @severity)
            """,
            new { vulnId, osvId, severity });

        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at)
            VALUES (@id, @componentId, @vulnId, @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                componentId,
                vulnId,
                now = _clock.GetUtcNow().ToUtcIso(),
            });

        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis (id, org_id, project_version_id, purl_key, vuln_key,
                                               vex_state, vex_source, updated_at)
            VALUES (@id, @orgId, @projectVersionId, 'pkg:npm/x', @vulnKey, 'not_affected', 'upload', @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = OrgA,
                projectVersionId,
                vulnKey = osvId,
                now = _clock.GetUtcNow().ToUtcIso(),
            });
    }
}
