using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers the quarantine state machine: UNIQUE(org_id, purl) + the state-guarded conflict
/// update mean repeat blocks refresh a pending row and never resurrect a decided one; the
/// initial decision applies exactly once; a decided row can be re-decided or reset to pending
/// (the change-my-mind path); manual block/unblock resolution maps onto the same states.
/// Also covers PurgeAgedReleaseHoldsAsync: the lazy GC that deletes phantom pending
/// release_age rows whose version has since aged past the hold threshold.
/// </summary>
[Trait("Category", "Unit")]
public sealed class QuarantineRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly QuarantineRepository _repo;

    public QuarantineRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new QuarantineRepository(_fixture.Store, TimeProvider.System);
    }

    // Builds a repo backed by a frozen clock at TestTime.KnownNow.
    private QuarantineRepository RepoWithClock(FakeTimeProvider clock)
        => new(_fixture.Store, clock);

    // Seeds a package_version with a specific published_at timestamp for purge tests.
    private async Task<(string PkgId, string VerId)> SeedVersionWithPublishedAt(
        string orgId, string pkgSuffix, string publishedAt)
    {
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", $"purge-pkg-{pkgSuffix}");
        string verId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", $"pkg:npm/purge-pkg-{pkgSuffix}@1.0.0");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET published_at = @ts WHERE id = @id",
            new { ts = publishedAt, id = verId });
        return (pkgId, verId);
    }

    // ── PurgeAgedReleaseHoldsAsync ─────────────────────────────────────────────

    /// <summary>
    /// A version published 50 hours before frozen-now under a 24-hour hold is aged out.
    /// The pending release_age row is deleted and the count is 1.
    /// </summary>
    [Fact]
    public async Task Purge_AgedOut_DeletesRow_ReturnsOne()
    {
        var clock = TestTime.Frozen();
        var repo = RepoWithClock(clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"purge-a-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/purge-aged-{Guid.NewGuid():N}@1.0.0";
        // 50 hours before now — well past the 24-hour hold; seed offsets are far from boundary.
        string oldTs = TestTime.KnownNow.AddHours(-50).ToString("o");
        var (_, verId) = await SeedVersionWithPublishedAt(orgId, Guid.NewGuid().ToString("N"), oldTs);

        await repo.UpsertPendingAsync(orgId, "npm", purl, "release_age", null, verId);
        var (before, beforeTotal) = await repo.ListAsync(orgId, "pending", null, 10, 0);
        Assert.Equal(1, before.Count(e => e.Purl == purl));

        int deleted = await repo.PurgeAgedReleaseHoldsAsync(orgId, 24);

        Assert.Equal(1, deleted);
        var (after, _) = await repo.ListAsync(orgId, null, null, 10, 0);
        Assert.DoesNotContain(after, e => e.Purl == purl);
    }

    /// <summary>
    /// A version published only 1 hour before frozen-now under a 24-hour hold is still young.
    /// The pending row stays; the count is 0.
    /// </summary>
    [Fact]
    public async Task Purge_StillYoung_RetainsRow_ReturnsZero()
    {
        var clock = TestTime.Frozen();
        var repo = RepoWithClock(clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"purge-b-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/purge-young-{Guid.NewGuid():N}@1.0.0";
        // 1 hour before now — well within the 24-hour hold.
        string youngTs = TestTime.KnownNow.AddHours(-1).ToString("o");
        var (_, verId) = await SeedVersionWithPublishedAt(orgId, Guid.NewGuid().ToString("N"), youngTs);

        await repo.UpsertPendingAsync(orgId, "npm", purl, "release_age", null, verId);

        int deleted = await repo.PurgeAgedReleaseHoldsAsync(orgId, 24);

        Assert.Equal(0, deleted);
        var (remaining, _) = await repo.ListAsync(orgId, "pending", null, 10, 0);
        Assert.Contains(remaining, e => e.Purl == purl);
    }

    /// <summary>
    /// When the policy is off (minReleaseAgeHours = null), any pending release_age row is a
    /// phantom regardless of age. The row is deleted.
    /// </summary>
    [Fact]
    public async Task Purge_PolicyOff_DeletesRow()
    {
        var clock = TestTime.Frozen();
        var repo = RepoWithClock(clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"purge-c-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/purge-policyoff-{Guid.NewGuid():N}@1.0.0";
        // Age does not matter when policy is off — use an arbitrary published_at.
        string ts = TestTime.KnownNow.AddHours(-5).ToString("o");
        var (_, verId) = await SeedVersionWithPublishedAt(orgId, Guid.NewGuid().ToString("N"), ts);

        await repo.UpsertPendingAsync(orgId, "npm", purl, "release_age", null, verId);

        int deleted = await repo.PurgeAgedReleaseHoldsAsync(orgId, null);

        Assert.Equal(1, deleted);
        var (after, _) = await repo.ListAsync(orgId, null, null, 10, 0);
        Assert.DoesNotContain(after, e => e.Purl == purl);
    }

    /// <summary>
    /// A pending row for a different gate (e.g. deprecated) is not touched even when the
    /// version is aged out — only release_age+pending rows are purged.
    /// </summary>
    [Fact]
    public async Task Purge_OtherGate_IsUntouched()
    {
        var clock = TestTime.Frozen();
        var repo = RepoWithClock(clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"purge-d-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/purge-other-{Guid.NewGuid():N}@1.0.0";
        // Version is aged out, but the gate is 'deprecated', not 'release_age'.
        string oldTs = TestTime.KnownNow.AddHours(-50).ToString("o");
        var (_, verId) = await SeedVersionWithPublishedAt(orgId, Guid.NewGuid().ToString("N"), oldTs);

        await repo.UpsertPendingAsync(orgId, "npm", purl, "deprecated", null, verId);

        int deleted = await repo.PurgeAgedReleaseHoldsAsync(orgId, 24);

        Assert.Equal(0, deleted);
        var (remaining, _) = await repo.ListAsync(orgId, "pending", null, 10, 0);
        Assert.Contains(remaining, e => e.Purl == purl);
    }

    /// <summary>
    /// An already-decided (denied) release_age row is not purged even when aged out —
    /// only pending rows are touched.
    /// </summary>
    [Fact]
    public async Task Purge_DecidedRow_IsUntouched()
    {
        var clock = TestTime.Frozen();
        var repo = RepoWithClock(clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"purge-e-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/purge-decided-{Guid.NewGuid():N}@1.0.0";
        string oldTs = TestTime.KnownNow.AddHours(-50).ToString("o");
        var (_, verId) = await SeedVersionWithPublishedAt(orgId, Guid.NewGuid().ToString("N"), oldTs);

        await repo.UpsertPendingAsync(orgId, "npm", purl, "release_age", null, verId);
        var (pending, _) = await repo.ListAsync(orgId, "pending", null, 10, 0);
        string id = pending.Single(e => e.Purl == purl).Id;
        await repo.DecideAsync(orgId, id, "denied", null, null);

        int deleted = await repo.PurgeAgedReleaseHoldsAsync(orgId, 24);

        Assert.Equal(0, deleted);
        var entry = await repo.GetByIdAsync(orgId, id);
        Assert.NotNull(entry);
        Assert.Equal("denied", entry!.State);
    }

    /// <summary>
    /// Mixed partial-failure scenario: an aged-out row and a still-young row in the same org.
    /// Only the aged-out row is deleted.
    /// </summary>
    [Fact]
    public async Task Purge_Mixed_DeletesOnlyAgedRows()
    {
        var clock = TestTime.Frozen();
        var repo = RepoWithClock(clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"purge-f-{Guid.NewGuid():N}");
        string purlAged = $"pkg:npm/purge-mixed-aged-{Guid.NewGuid():N}@1.0.0";
        string purlYoung = $"pkg:npm/purge-mixed-young-{Guid.NewGuid():N}@1.0.0";

        string oldTs = TestTime.KnownNow.AddHours(-50).ToString("o");
        string youngTs = TestTime.KnownNow.AddHours(-1).ToString("o");

        var (_, verAged) = await SeedVersionWithPublishedAt(orgId, Guid.NewGuid().ToString("N"), oldTs);
        var (_, verYoung) = await SeedVersionWithPublishedAt(orgId, Guid.NewGuid().ToString("N"), youngTs);

        await repo.UpsertPendingAsync(orgId, "npm", purlAged, "release_age", null, verAged);
        await repo.UpsertPendingAsync(orgId, "npm", purlYoung, "release_age", null, verYoung);

        int deleted = await repo.PurgeAgedReleaseHoldsAsync(orgId, 24);

        Assert.Equal(1, deleted);
        var (remaining, total) = await repo.ListAsync(orgId, "pending", null, 10, 0);
        Assert.Equal(1, total);
        Assert.Contains(remaining, e => e.Purl == purlYoung);
        Assert.DoesNotContain(remaining, e => e.Purl == purlAged);
    }

    /// <summary>
    /// BOLA guard: an aged-out release_age row in org-B is not purged when purging for org-A.
    /// </summary>
    [Fact]
    public async Task Purge_CrossOrg_IsUntouched()
    {
        var clock = TestTime.Frozen();
        var repo = RepoWithClock(clock);
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"purge-ga-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"purge-gb-{Guid.NewGuid():N}");
        string purlB = $"pkg:npm/purge-xorg-{Guid.NewGuid():N}@1.0.0";
        string oldTs = TestTime.KnownNow.AddHours(-50).ToString("o");
        var (_, verB) = await SeedVersionWithPublishedAt(orgB, Guid.NewGuid().ToString("N"), oldTs);

        await repo.UpsertPendingAsync(orgB, "npm", purlB, "release_age", null, verB);

        // Purging for org-A must not touch org-B's row.
        int deleted = await repo.PurgeAgedReleaseHoldsAsync(orgA, 24);

        Assert.Equal(0, deleted);
        var (remaining, _) = await repo.ListAsync(orgB, "pending", null, 10, 0);
        Assert.Contains(remaining, e => e.Purl == purlB);
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
    public async Task ChangeState_RedecidesDecidedRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"q-{Guid.NewGuid():N}");
        // decided_by carries an FK to users(id) — seed real reviewers.
        string alice = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"alice-{Guid.NewGuid():N}@x");
        string bob = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"bob-{Guid.NewGuid():N}@x");
        string purl = $"pkg:npm/redecide-{Guid.NewGuid():N}@1.0.0";
        await _repo.UpsertPendingAsync(orgId, "npm", purl, "epss", null, null);
        var (items, _) = await _repo.ListAsync(orgId, "pending", null, 10, 0);
        string id = items.Single(i => i.Purl == purl).Id;
        Assert.True(await _repo.DecideAsync(orgId, id, "approved", alice, "vetted"));

        // The admin changes their mind — re-decide flips the state and decision metadata.
        Assert.True(await _repo.ChangeStateAsync(orgId, id, "denied", bob, "actually risky"));

        var entry = await _repo.GetByIdAsync(orgId, id);
        Assert.Equal("denied", entry!.State);
        Assert.Equal(bob, entry.DecidedBy);
        Assert.Equal("actually risky", entry.Note);
    }

    [Fact]
    public async Task ChangeState_ResetToPending_ClearsDecisionMetadata()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"q-{Guid.NewGuid():N}");
        string alice = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"alice-{Guid.NewGuid():N}@x");
        string purl = $"pkg:npm/reset-{Guid.NewGuid():N}@1.0.0";
        await _repo.UpsertPendingAsync(orgId, "npm", purl, "kev", null, null);
        var (items, _) = await _repo.ListAsync(orgId, "pending", null, 10, 0);
        string id = items.Single(i => i.Purl == purl).Id;
        Assert.True(await _repo.DecideAsync(orgId, id, "approved", alice, "vetted"));

        Assert.True(await _repo.ChangeStateAsync(orgId, id, "pending", null, null));

        var entry = await _repo.GetByIdAsync(orgId, id);
        Assert.Equal("pending", entry!.State);
        Assert.Null(entry.DecidedBy);
        Assert.Null(entry.DecidedAt);
        Assert.Null(entry.Note);
    }

    [Fact]
    public async Task ChangeState_CrossOrg_ReturnsFalse()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"qa-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"qb-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/xorg-{Guid.NewGuid():N}@1.0.0";
        await _repo.UpsertPendingAsync(orgA, "npm", purl, "deprecated", null, null);
        var (items, _) = await _repo.ListAsync(orgA, null, null, 10, 0);
        string id = items.Single(i => i.Purl == purl).Id;
        await _repo.DecideAsync(orgA, id, "approved", null, null);

        // A cross-tenant id matches no row — the BOLA guard holds for re-decide too.
        Assert.False(await _repo.ChangeStateAsync(orgB, id, "denied", null, null));
        Assert.Equal("approved", (await _repo.GetByIdAsync(orgA, id))!.State);
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
