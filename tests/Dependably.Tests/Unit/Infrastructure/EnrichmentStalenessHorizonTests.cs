using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The staleness horizon, exercised through the repository rather than asserted on the SQL.
///
/// <para>
/// The horizon lives in the aggregate query, so an enrichment value past it is simply not there
/// by the time policy runs. That makes it invisible to a gate test: a version whose SSVC
/// assessment aged out looks identical to one that never had an assessment, and the arm passes
/// either way. Only a repository-level test can tell the two apart, which is why this one seeds
/// real rows and reads back the aggregate.
/// </para>
///
/// <para>
/// Freshness is the <b>older</b> of the two stamps — our own reach time and the tracker's
/// asserted source as-of — so both directions are pinned here: a stale reach time with a recent
/// as-of, and a recent reach time with a stale as-of, must each read as stale. A tracker that
/// answers promptly with data it ingested a month ago is the case the second stamp exists for.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class EnrichmentStalenessHorizonTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public EnrichmentStalenessHorizonTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // A resolver over a stub setting reader, standing in for the operator's configured
    // connection. 48 hours is far from any boundary the seeds sit near.
    private InstanceVulnTrackerConfig TrackerConfig(TimeProvider time, int horizonHours) =>
        new((key, _) => Task.FromResult<string?>(key switch
        {
            "vuln_tracker_base_url" => "https://tracker.example.invalid",
            "vuln_tracker_enabled" => "true",
            "vuln_tracker_max_staleness_hours" => horizonHours.ToString(),
            _ => null,
        }), time);

    private async Task<(VulnerabilityRepository Repo, string VersionId, string VulnId)> SeedAsync(
        TimeProvider clock, int horizonHours)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        string osvId = $"GHSA-{Guid.NewGuid():N}";
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(_fixture.Store, osvId);

        var repo = new VulnerabilityRepository(
            _fixture.Store, clock, TrackerConfig(clock, horizonHours));
        await repo.LinkVersionVulnAsync(verId, vulnId);
        return (repo, verId, osvId);
    }

    private async Task<string> SeedCacheArtifactAsync()
    {
        string id = Guid.NewGuid().ToString("N");
        string name = $"acme-{Guid.NewGuid():N}";
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES (@id, 'npm', @name, '1.0.0', @filename, @blobKey, @hash, 0, @purl)
            """,
            new
            {
                id,
                name,
                filename = $"{name}-1.0.0.tgz",
                blobKey = $"proxy/npm/{name}/1.0.0/{name}-1.0.0.tgz",
                hash = $"sha256:{Guid.NewGuid():N}",
                purl = $"pkg:npm/{name}@1.0.0",
            });
        return id;
    }

    private static TrackerEnrichmentWrite Enrichment(
        string osvId, DateTimeOffset checkedAt, DateTimeOffset assertedAt) =>
        new(OsvId: osvId,
            NvdSeverity: "CRITICAL",
            NvdScore: 9.8,
            SsvcExploitation: "active",
            SsvcAutomatable: "yes",
            SsvcTechnicalImpact: "total",
            CheckedAt: checkedAt,
            NvdAssertedAt: assertedAt,
            SsvcAssertedAt: assertedAt);

    [Fact]
    public async Task FreshEnrichment_IsReadByTheGateSignals()
    {
        var clock = TestTime.Frozen();
        var (repo, verId, osvId) = await SeedAsync(clock, horizonHours: 48);
        var now = clock.GetUtcNow();

        await repo.SetTrackerEnrichmentAsync(Enrichment(osvId, now, now));

        var signals = await repo.GetGateSignalsAsync("package_version", verId);

        Assert.True(signals.HasSsvcActiveExploitation);
        Assert.Equal(9.8, signals.MaxNvdScore);
        Assert.False(signals.HasStaleEnrichment);
    }

    /// <summary>Our own reach time aged past the horizon.</summary>
    [Fact]
    public async Task EnrichmentPastTheHorizon_IsDroppedAndReportedStale()
    {
        var clock = TestTime.Frozen();
        var (repo, verId, osvId) = await SeedAsync(clock, horizonHours: 48);
        var reached = clock.GetUtcNow();

        await repo.SetTrackerEnrichmentAsync(Enrichment(osvId, reached, reached));
        clock.Advance(TimeSpan.FromHours(120));

        var signals = await repo.GetGateSignalsAsync("package_version", verId);

        Assert.False(signals.HasSsvcActiveExploitation);
        Assert.Null(signals.MaxNvdScore);
        Assert.True(signals.HasStaleEnrichment);
    }

    /// <summary>
    /// The case the second stamp exists for: the tracker answered a minute ago, with data it
    /// asserts is a month old. Reading only our own reach time would call this current.
    /// </summary>
    [Fact]
    public async Task ReachableTrackerAssertingStaleData_ReadsAsStale()
    {
        var clock = TestTime.Frozen();
        var (repo, verId, osvId) = await SeedAsync(clock, horizonHours: 48);
        var now = clock.GetUtcNow();

        await repo.SetTrackerEnrichmentAsync(
            Enrichment(osvId, checkedAt: now, assertedAt: now.AddDays(-30)));

        var signals = await repo.GetGateSignalsAsync("package_version", verId);

        Assert.False(signals.HasSsvcActiveExploitation);
        Assert.Null(signals.MaxNvdScore);
        Assert.True(signals.HasStaleEnrichment);
    }

    /// <summary>
    /// The same advisory read through all four gate-signal paths must produce the same
    /// enrichment verdict.
    ///
    /// <para>
    /// There are four: scalar and batch, each on the uploaded (<c>package_version</c>) and proxy
    /// (<c>cache_artifact</c>) planes, and they are four separate copies of the aggregate SQL.
    /// "They are the same query" is the assumption, not the guarantee — the freshness parameter
    /// shipped bound on one of them and unbound on another, where SQLite silently read it as NULL
    /// and dropped every enrichment value while the other path worked fine. Only a cross-path
    /// comparison catches that, because each path is individually self-consistent.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(0, true)]    // fresh: active assessment visible, not stale
    [InlineData(120, false)] // aged past the horizon: dropped, and reported stale
    public async Task AllFourGateSignalPaths_AgreeOnTheSameAdvisory(int advanceHours, bool expectFresh)
    {
        var clock = TestTime.Frozen();
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        string osvId = $"GHSA-{Guid.NewGuid():N}";
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(_fixture.Store, osvId);
        string cacheArtifactId = await SeedCacheArtifactAsync();

        await VulnerabilitySeeder.LinkAsync(_fixture.Store, verId, vulnId);
        await VulnerabilitySeeder.LinkToCacheArtifactAsync(_fixture.Store, cacheArtifactId, vulnId);

        var repo = new VulnerabilityRepository(
            _fixture.Store, clock, TrackerConfig(clock, horizonHours: 48));
        var reached = clock.GetUtcNow();
        await repo.SetTrackerEnrichmentAsync(Enrichment(osvId, reached, reached));
        clock.Advance(TimeSpan.FromHours(advanceHours));

        var paths = new (string Name, VulnGateSignals Signals)[]
        {
            ("scalar/package_version",
                await repo.GetGateSignalsAsync("package_version", verId)),
            ("scalar/cache_artifact",
                await repo.GetGateSignalsAsync("cache_artifact", cacheArtifactId)),
            ("batch/package_version",
                (await repo.GetGateSignalsBatchAsync([verId]))[verId]),
            ("batch/cache_artifact",
                (await repo.GetGateSignalsBatchForCacheArtifactsAsync([cacheArtifactId]))[cacheArtifactId]),
        };

        foreach (var (name, signals) in paths)
        {
            Assert.Equal(expectFresh, signals.HasSsvcActiveExploitation);
            Assert.Equal(expectFresh ? 9.8 : null, signals.MaxNvdScore);
            Assert.Equal(!expectFresh, signals.HasStaleEnrichment);
            Assert.NotNull(name);
        }
    }

    /// <summary>
    /// The optionality guarantee at the layer that produces the fact: an advisory that was never
    /// enriched is not stale. A deployment with no tracker only ever produces this state, which
    /// is why the SSVC arm is inert there however a tenant sets it.
    /// </summary>
    [Fact]
    public async Task NeverEnrichedAdvisory_IsNotStale()
    {
        var clock = TestTime.Frozen();
        var (repo, verId, _) = await SeedAsync(clock, horizonHours: 48);
        clock.Advance(TimeSpan.FromDays(400));

        var signals = await repo.GetGateSignalsAsync("package_version", verId);

        Assert.False(signals.HasSsvcActiveExploitation);
        Assert.Null(signals.MaxNvdScore);
        Assert.False(signals.HasStaleEnrichment);
    }
}
