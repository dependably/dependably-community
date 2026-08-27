using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// The operator's assembled view: connection state, the scan path's health row, recent fetches,
/// and the registry-wide freshness counts, combined from three independently-tested sources.
///
/// <para>
/// One property is the whole reason this class exists rather than trusting the three pieces to
/// compose correctly on their own: <see cref="VulnTrackerHealthView.Configured"/> gates
/// everything else. A deployment that never configured a tracker and a freshly-configured one
/// that has done nothing yet are numerically identical everywhere except that one field, and
/// collapsing them renders an unbuilt integration as a dead one.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnTrackerHealthAggregatorTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static InstanceVulnTrackerConfig Connection(
        bool configured, bool enabled = true, int horizonHours = 24)
    {
        var rows = new Dictionary<string, string?>();
        if (configured)
        {
            rows["vuln_tracker_base_url"] = "https://tracker.example.com";
            rows["vuln_tracker_enabled"] = enabled ? "1" : "0";
            rows["vuln_tracker_max_staleness_hours"] = horizonHours.ToString();
        }
        return new InstanceVulnTrackerConfig(
            (key, _) => Task.FromResult(rows.TryGetValue(key, out string? v) ? v : null),
            TimeProvider.System);
    }

    private VulnTrackerHealthAggregator Aggregator(InstanceVulnTrackerConfig tracker) =>
        new(tracker, new VulnTrackerHealthRepository(_db, _clock), new VulnerabilityRepository(_db, _clock, tracker));

    // ── The gating field ─────────────────────────────────────────────────────

    [Fact]
    public async Task NotConfigured_ReportsConfiguredFalseAndNothingElse()
    {
        var view = await Aggregator(Connection(configured: false)).GetAsync();

        Assert.False(view.Configured);
        Assert.Null(view.Health);
        Assert.Empty(view.RecentFetches);
        Assert.Equal(0, view.EnrichedAdvisories);
        Assert.Equal(0, view.StaleAdvisories);
    }

    [Fact]
    public async Task NotConfigured_NeverQueriesTheAdvisoryCorpusOrTheHealthStore()
    {
        // Adversarial twin of the above: seed real health and fetch rows behind the aggregator's
        // back, then confirm the "not configured" answer still comes back empty rather than
        // leaking data from a connection that happens to share the same process's database.
        var health = new VulnTrackerHealthRepository(_db, _clock);
        await health.RecordScanFetchAsync(new VulnTrackerFetchOutcome(true, "none", 3, 5, 10, _clock.GetUtcNow()));

        var view = await Aggregator(Connection(configured: false)).GetAsync();

        Assert.False(view.Configured);
        Assert.Null(view.Health);
        Assert.Empty(view.RecentFetches);
    }

    [Fact]
    public async Task ConfiguredButNeverAttempted_IsConfiguredWithANullHealthRow()
    {
        // The pair that "not configured" must not be confused with: a real connection that has
        // simply not had a scan pass run against it yet.
        var view = await Aggregator(Connection(configured: true)).GetAsync();

        Assert.True(view.Configured);
        Assert.Null(view.Health);
        Assert.Empty(view.RecentFetches);
    }

    // ── Composition of the three sources ─────────────────────────────────────

    [Fact]
    public async Task ConfiguredWithHistory_CombinesHealthFetchesAndFreshnessCounts()
    {
        var tracker = Connection(configured: true, horizonHours: 24);
        var health = new VulnTrackerHealthRepository(_db, _clock);
        await health.RecordScanFetchAsync(new VulnTrackerFetchOutcome(true, "none", 4, 6, 12, _clock.GetUtcNow()));
        await health.RecordProbeFetchAsync(new VulnTrackerFetchOutcome(false, "timeout", 1, 0, 5, _clock.GetUtcNow()));

        var vulns = new VulnerabilityRepository(_db, _clock, tracker);
        string osvId = $"GHSA-{Guid.NewGuid():N}";
        await VulnerabilitySeeder.InsertVulnAsync(_db, osvId);
        await vulns.SetTrackerEnrichmentAsync(new TrackerEnrichmentWrite(
            OsvId: osvId, NvdSeverity: "HIGH", NvdScore: 8.1,
            SsvcExploitation: "active", SsvcAutomatable: "yes", SsvcTechnicalImpact: "total",
            CheckedAt: _clock.GetUtcNow(), NvdAssertedAt: _clock.GetUtcNow(), SsvcAssertedAt: _clock.GetUtcNow()));

        var view = await new VulnTrackerHealthAggregator(tracker, health, vulns).GetAsync();

        Assert.True(view.Configured);
        Assert.NotNull(view.Health);
        Assert.Equal("ok", view.Health!.LastStatus);
        Assert.Equal(2, view.RecentFetches.Count);
        Assert.Equal(1, view.EnrichedAdvisories);
        Assert.Equal(0, view.StaleAdvisories);
        Assert.Equal(24, view.MaxStalenessHours);
    }

    [Fact]
    public async Task PausedConnection_StillReportsConfiguredAndItsPastHistory()
    {
        // Pausing stops future lookups; it does not erase what already happened, and the panel
        // must keep showing the last real state rather than resetting to "nothing to report".
        var tracker = Connection(configured: true, enabled: false);
        var health = new VulnTrackerHealthRepository(_db, _clock);
        await health.RecordScanFetchAsync(new VulnTrackerFetchOutcome(false, "unauthorized", 2, 0, 8, _clock.GetUtcNow()));

        var view = await Aggregator(tracker).GetAsync();

        Assert.True(view.Configured);
        Assert.False(view.Enabled);
        Assert.NotNull(view.Health);
        Assert.Equal("failed", view.Health!.LastStatus);
    }

    // ── The wire projection ───────────────────────────────────────────────────

    [Fact]
    public void BuildView_ProjectsCamelCaseAndNullHealthAsNull()
    {
        var view = new VulnTrackerHealthView(
            Configured: true, Enabled: true, MaxStalenessHours: 24,
            Health: null, RecentFetches: [], EnrichedAdvisories: 0, StaleAdvisories: 0);

        dynamic projected = VulnTrackerHealthAggregator.BuildView(view);

        Assert.True((bool)projected.configured);
        Assert.Null(projected.health);
    }
}
