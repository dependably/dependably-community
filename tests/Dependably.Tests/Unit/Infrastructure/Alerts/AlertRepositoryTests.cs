using Dependably.Infrastructure.Alerts;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure.Alerts;

/// <summary>
/// Covers <see cref="AlertRepository"/>: TryInsertAsync's ON-CONFLICT-DO-NOTHING dedup on
/// (org_id, type, source_ref), DismissAsync's idempotent state-guarded update, org isolation
/// (GetByIdAsync as the BOLA guard), and the raise-gating settings default.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AlertRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly AlertRepository _repo;

    public AlertRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new AlertRepository(_fixture.Store, TimeProvider.System);
    }

    private static NewAlert Quarantine(string orgId, string sourceRef, string purl = "pkg:npm/dedup-pkg@1.0.0") =>
        new(orgId, AlertTypes.QuarantineNew, Severity: null, SourceRef: sourceRef,
            Ecosystem: "npm", Purl: purl, Title: $"New quarantine item: {purl}", Detail: null);

    private static NewAlert Vuln(string orgId, string sourceRef) =>
        new(orgId, AlertTypes.VulnSeverity, Severity: "HIGH", SourceRef: sourceRef,
            Ecosystem: "npm", Purl: "pkg:npm/vuln-pkg@1.0.0", Title: "HIGH vulnerability GHSA-x in vuln-pkg", Detail: null);

    [Fact]
    public async Task TryInsert_FreshRow_ReturnsRecord()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-a-{Guid.NewGuid():N}");
        string qId = Guid.NewGuid().ToString("N");

        var alert = await _repo.TryInsertAsync(Quarantine(orgId, qId));

        Assert.NotNull(alert);
        Assert.Equal("active", alert!.State);
        Assert.Equal(AlertTypes.QuarantineNew, alert.Type);
    }

    /// <summary>
    /// The entire dedup mechanism: a second insert with the same (org_id, type, source_ref)
    /// is a no-op — TryInsertAsync returns null and the row count stays at 1.
    /// </summary>
    [Fact]
    public async Task TryInsert_RepeatSameSourceRef_Deduplicates()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-b-{Guid.NewGuid():N}");
        string qId = Guid.NewGuid().ToString("N");

        var first = await _repo.TryInsertAsync(Quarantine(orgId, qId));
        var second = await _repo.TryInsertAsync(Quarantine(orgId, qId));

        Assert.NotNull(first);
        Assert.Null(second);
        var (items, total) = await _repo.ListAsync(orgId, null, 10, 0);
        Assert.Equal(1, total);
        Assert.Single(items);
    }

    /// <summary>Different types with the same source_ref are independent rows — the key is (org, type, source_ref).</summary>
    [Fact]
    public async Task TryInsert_SameSourceRefDifferentType_BothInsert()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-c-{Guid.NewGuid():N}");
        string sharedRef = Guid.NewGuid().ToString("N");

        var q = await _repo.TryInsertAsync(Quarantine(orgId, sharedRef));
        var v = await _repo.TryInsertAsync(Vuln(orgId, sharedRef));

        Assert.NotNull(q);
        Assert.NotNull(v);
        var (_, total) = await _repo.ListAsync(orgId, null, 10, 0);
        Assert.Equal(2, total);
    }

    [Fact]
    public async Task Dismiss_ActiveAlert_ChangesState()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-d-{Guid.NewGuid():N}");
        string alice = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"alice-{Guid.NewGuid():N}@x");
        var alert = await _repo.TryInsertAsync(Quarantine(orgId, Guid.NewGuid().ToString("N")));

        bool changed = await _repo.DismissAsync(orgId, alert!.Id, alice);

        Assert.True(changed);
        var reread = await _repo.GetByIdAsync(orgId, alert.Id);
        Assert.Equal("dismissed", reread!.State);
        Assert.Equal(alice, reread.DismissedBy);
        Assert.NotNull(reread.DismissedAt);
    }

    /// <summary>Idempotent: dismissing an already-dismissed alert returns false and does not error.</summary>
    [Fact]
    public async Task Dismiss_Twice_SecondReturnsFalse()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-e-{Guid.NewGuid():N}");
        var alert = await _repo.TryInsertAsync(Quarantine(orgId, Guid.NewGuid().ToString("N")));

        Assert.True(await _repo.DismissAsync(orgId, alert!.Id, null));
        Assert.False(await _repo.DismissAsync(orgId, alert.Id, null));

        var reread = await _repo.GetByIdAsync(orgId, alert.Id);
        Assert.Equal("dismissed", reread!.State);
    }

    /// <summary>BOLA guard: an alert seeded for org-B is invisible to org-A's GetById/Dismiss.</summary>
    [Fact]
    public async Task GetById_And_Dismiss_CrossOrg_Fails()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-fa-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-fb-{Guid.NewGuid():N}");
        var alert = await _repo.TryInsertAsync(Quarantine(orgB, Guid.NewGuid().ToString("N")));

        Assert.Null(await _repo.GetByIdAsync(orgA, alert!.Id));
        Assert.False(await _repo.DismissAsync(orgA, alert.Id, null));

        // The row is untouched for the owning org.
        var stillActive = await _repo.GetByIdAsync(orgB, alert.Id);
        Assert.Equal("active", stillActive!.State);
    }

    [Fact]
    public async Task CountActive_OnlyCountsActiveForTheOrg()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-g-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-h-{Guid.NewGuid():N}");
        var a1 = await _repo.TryInsertAsync(Quarantine(orgA, Guid.NewGuid().ToString("N")));
        await _repo.TryInsertAsync(Quarantine(orgA, Guid.NewGuid().ToString("N")));
        await _repo.TryInsertAsync(Quarantine(orgB, Guid.NewGuid().ToString("N")));

        Assert.Equal(2, await _repo.CountActiveAsync(orgA));
        Assert.Equal(1, await _repo.CountActiveAsync(orgB));

        await _repo.DismissAsync(orgA, a1!.Id, null);
        Assert.Equal(1, await _repo.CountActiveAsync(orgA));
    }

    [Fact]
    public async Task List_FiltersByState()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-i-{Guid.NewGuid():N}");
        var a1 = await _repo.TryInsertAsync(Quarantine(orgId, Guid.NewGuid().ToString("N")));
        await _repo.TryInsertAsync(Quarantine(orgId, Guid.NewGuid().ToString("N")));
        await _repo.DismissAsync(orgId, a1!.Id, null);

        var (active, activeTotal) = await _repo.ListAsync(orgId, "active", 10, 0);
        var (dismissed, dismissedTotal) = await _repo.ListAsync(orgId, "dismissed", 10, 0);

        Assert.Equal(1, activeTotal);
        Assert.Equal(1, dismissedTotal);
        Assert.All(active, a => Assert.Equal("active", a.State));
        Assert.All(dismissed, a => Assert.Equal("dismissed", a.State));
    }

    [Fact]
    public async Task RecordSlackOutcome_PersistsStatusAndError()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-j-{Guid.NewGuid():N}");
        var alert = await _repo.TryInsertAsync(Quarantine(orgId, Guid.NewGuid().ToString("N")));

        await _repo.RecordSlackOutcomeAsync(orgId, alert!.Id, "failed", "timeout");

        var reread = await _repo.GetByIdAsync(orgId, alert.Id);
        Assert.Equal("failed", reread!.SlackStatus);
        Assert.Equal("timeout", reread.SlackError);
    }

    /// <summary>Absent alert_settings row projects the documented defaults — no backfill migration.</summary>
    [Fact]
    public async Task GetRaiseSettings_AbsentRow_ReturnsDefaults()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"alert-k-{Guid.NewGuid():N}");

        var settings = await _repo.GetRaiseSettingsAsync(orgId);

        Assert.True(settings.QuarantineAlertsEnabled);
        Assert.True(settings.VulnAlertsEnabled);
        Assert.Equal("HIGH", settings.VulnMinSeverity);
    }
}
