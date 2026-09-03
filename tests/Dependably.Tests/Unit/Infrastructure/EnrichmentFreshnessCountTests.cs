using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="VulnerabilityRepository.CountEnrichmentFreshnessAsync"/> — the registry-wide
/// inventory question the health panel renders, as distinct from the four per-artefact gate
/// aggregates <see cref="EnrichmentStalenessHorizonTests"/> covers.
///
/// <para>
/// The two counts answer different things and must not be confused: <c>Enriched</c> is "has
/// tracker enrichment ever been recorded for this advisory", <c>Stale</c> is "of those, how many
/// are past the horizon right now". An advisory that was never enriched contributes to neither.
/// </para>
///
/// <para>
/// A fresh <see cref="TestMetadataStore"/> per test, not the shared <c>InMemoryDbFixture</c>: the
/// query under test is deliberately registry-wide with no per-test scoping key, so a shared store
/// would let one test's rows count toward another's assertions.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class EnrichmentFreshnessCountTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static InstanceVulnTrackerConfig TrackerConfig(TimeProvider time, int horizonHours) =>
        new((key, _) => Task.FromResult<string?>(key switch
        {
            "vuln_tracker_base_url" => "https://tracker.example.invalid",
            "vuln_tracker_enabled" => "true",
            "vuln_tracker_max_staleness_hours" => horizonHours.ToString(),
            _ => null,
        }), time);

    // InsertVulnAsync returns the row's internal id, not the osv_id passed in — SetTrackerEnrichmentAsync
    // updates by osv_id, so the caller needs the string it generated, not the seeder's return value.
    private async Task<string> SeedAdvisoryAsync()
    {
        string osvId = $"GHSA-{Guid.NewGuid():N}";
        await VulnerabilitySeeder.InsertVulnAsync(_db, osvId);
        return osvId;
    }

    private static TrackerEnrichmentWrite Enrichment(
        string osvId, DateTimeOffset checkedAt, DateTimeOffset assertedAt) =>
        new(OsvId: osvId, NvdSeverity: "CRITICAL", NvdScore: 9.8,
            SsvcExploitation: "active", SsvcAutomatable: "yes", SsvcTechnicalImpact: "total",
            CheckedAt: checkedAt, NvdAssertedAt: assertedAt, SsvcAssertedAt: assertedAt);

    [Fact]
    public async Task NoAdvisoryEverEnriched_CountsZeroAndZero()
    {
        var clock = TestTime.Frozen();
        await SeedAdvisoryAsync(); // exists, but never enriched
        var repo = new VulnerabilityRepository(_db, clock, TrackerConfig(clock, 48));

        var (enriched, stale) = await repo.CountEnrichmentFreshnessAsync();

        Assert.Equal(0, enriched);
        Assert.Equal(0, stale);
    }

    [Fact]
    public async Task FreshEnrichment_CountsAsEnrichedAndNotStale()
    {
        var clock = TestTime.Frozen();
        string osvId = await SeedAdvisoryAsync();
        var repo = new VulnerabilityRepository(_db, clock, TrackerConfig(clock, 48));
        var now = clock.GetUtcNow();

        await repo.SetTrackerEnrichmentAsync(Enrichment(osvId, now, now));

        var (enriched, stale) = await repo.CountEnrichmentFreshnessAsync();

        Assert.Equal(1, enriched);
        Assert.Equal(0, stale);
    }

    [Fact]
    public async Task EnrichmentPastTheHorizon_StaysCountedAsEnrichedButAlsoStale()
    {
        // The pair that makes the two counts non-redundant: a stale advisory is still an
        // enriched one. Collapsing them would make an operator unable to tell "we've never
        // reached this deployment's advisories" from "we reached them, once, a long time ago".
        var clock = TestTime.Frozen();
        string osvId = await SeedAdvisoryAsync();
        var repo = new VulnerabilityRepository(_db, clock, TrackerConfig(clock, 48));
        var reached = clock.GetUtcNow();

        await repo.SetTrackerEnrichmentAsync(Enrichment(osvId, reached, reached));
        clock.Advance(TimeSpan.FromHours(120));

        var (enriched, stale) = await repo.CountEnrichmentFreshnessAsync();

        Assert.Equal(1, enriched);
        Assert.Equal(1, stale);
    }

    [Fact]
    public async Task ReachableTrackerAssertingStaleData_CountsStaleFromTheOlderStamp()
    {
        // Mirrors the gate-signal test of the same shape: a tracker that answers promptly with
        // data it asserts is a month old must count as stale here too, or the panel would call a
        // month-old assessment current just because dependably itself reached the tracker recently.
        var clock = TestTime.Frozen();
        string osvId = await SeedAdvisoryAsync();
        var repo = new VulnerabilityRepository(_db, clock, TrackerConfig(clock, 48));
        var staleAssertion = clock.GetUtcNow().AddDays(-30);

        await repo.SetTrackerEnrichmentAsync(Enrichment(osvId, clock.GetUtcNow(), staleAssertion));

        var (enriched, stale) = await repo.CountEnrichmentFreshnessAsync();

        Assert.Equal(1, enriched);
        Assert.Equal(1, stale);
    }

    [Fact]
    public async Task MixOfFreshAndStale_CountsEachCorrectly()
    {
        var clock = TestTime.Frozen();
        string freshId = await SeedAdvisoryAsync();
        string staleId = await SeedAdvisoryAsync();
        string neverId = await SeedAdvisoryAsync();
        var repo = new VulnerabilityRepository(_db, clock, TrackerConfig(clock, 48));
        var now = clock.GetUtcNow();

        await repo.SetTrackerEnrichmentAsync(Enrichment(freshId, now, now));
        await repo.SetTrackerEnrichmentAsync(Enrichment(staleId, now.AddHours(-120), now.AddHours(-120)));
        _ = neverId;

        var (enriched, stale) = await repo.CountEnrichmentFreshnessAsync();

        Assert.Equal(2, enriched);
        Assert.Equal(1, stale);
    }

    [Fact]
    public async Task NoTrackerConfigured_TreatsEverythingAsFresh()
    {
        // FreshnessCutoffAsync returns DateTimeOffset.MinValue with no connection, so nothing can
        // be past it — matching the gate signals' posture that an unconfigured deployment has no
        // horizon to age anything out against.
        var clock = TestTime.Frozen();
        string osvId = await SeedAdvisoryAsync();
        var repo = new VulnerabilityRepository(_db, clock, trackerConfig: null);

        await repo.SetTrackerEnrichmentAsync(Enrichment(osvId, clock.GetUtcNow(), clock.GetUtcNow()));
        clock.Advance(TimeSpan.FromDays(365));

        var (enriched, stale) = await repo.CountEnrichmentFreshnessAsync();

        Assert.Equal(1, enriched);
        Assert.Equal(0, stale);
    }
}
