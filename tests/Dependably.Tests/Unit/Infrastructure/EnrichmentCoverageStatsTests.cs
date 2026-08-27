using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The dashboard/Risk tenant-facing enrichment-coverage tile: "N of M advisories affecting your
/// packages carry an NVD band or SSVC decision". Exercised through
/// <see cref="PackageAnalyticsRepository.GetOrgStatsAsync"/>, which is what both read surfaces
/// actually call.
///
/// <para>
/// <b>Absence is never a measured zero.</b> An org with no tracker connection and an org whose
/// packages genuinely carry zero enriched advisories must render differently — the first is "not
/// configured", the second is a real, measured 0/0 or 0/N. <see cref="OrgStats.TrackerConfigured"/>
/// is the only field that distinguishes them, so every test below asserts it explicitly rather
/// than inferring the state from the counts alone.
/// </para>
///
/// <para>
/// <b>The H1 cache-plane read-path miss this repo has hit before</b> (proxy rows silently
/// returning empty because a query joined only <c>package_versions</c>) is the reason this class
/// pins both storage planes independently, not just the union.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class EnrichmentCoverageStatsTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'other')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private InstanceVulnTrackerConfig ActiveTracker() =>
        new((key, _) => Task.FromResult<string?>(key switch
        {
            "vuln_tracker_base_url" => "https://tracker.example.invalid",
            "vuln_tracker_enabled" => "true",
            _ => null,
        }), _clock);

    private InstanceVulnTrackerConfig NoTracker() =>
        new((_, _) => Task.FromResult<string?>(null), _clock);

    private async Task<string> SeedAdvisoryAsync(bool enriched)
    {
        string osvId = $"GHSA-{Guid.NewGuid():N}";
        await VulnerabilitySeeder.InsertVulnAsync(_db, osvId);
        if (enriched)
        {
            var repo = new VulnerabilityRepository(_db, _clock);
            await repo.SetTrackerEnrichmentAsync(new TrackerEnrichmentWrite(
                OsvId: osvId, NvdSeverity: "HIGH", NvdScore: 7.5,
                SsvcExploitation: null, SsvcAutomatable: null, SsvcTechnicalImpact: null,
                CheckedAt: _clock.GetUtcNow(), NvdAssertedAt: _clock.GetUtcNow(), SsvcAssertedAt: null));
        }
        return osvId;
    }

    private async Task<string> AdvisoryIdAsync(string osvId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM vulnerabilities WHERE osv_id = @osvId", new { osvId })
            ?? throw new InvalidOperationException("seeded advisory missing");
    }

    private async Task LinkUploadedAsync(string orgId, string osvId)
    {
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", $"pkg-{Guid.NewGuid():N}");
        string verId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}@1.0.0");
        await new VulnerabilityRepository(_db, _clock).LinkVersionVulnAsync(verId, await AdvisoryIdAsync(osvId));
    }

    private async Task<string> LinkProxyAsync(string orgId, string osvId)
    {
        string caId = Guid.NewGuid().ToString("N");
        string name = $"acme-{Guid.NewGuid():N}";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES (@id, 'npm', @name, '1.0.0', @filename, @blobKey, @hash, 0, @purl)
            """,
            new
            {
                id = caId,
                name,
                filename = $"{name}-1.0.0.tgz",
                blobKey = $"proxy/npm/{name}/1.0.0/{name}-1.0.0.tgz",
                hash = $"sha256:{Guid.NewGuid():N}",
                purl = $"pkg:npm/{name}@1.0.0",
            });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
        await new VulnerabilityRepository(_db, _clock).LinkCacheArtifactVulnAsync(caId, await AdvisoryIdAsync(osvId));
        return caId;
    }

    // ── The gating field ─────────────────────────────────────────────────────

    [Fact]
    public async Task NoTrackerConfigured_ReportsNotConfiguredWithoutTouchingCounts()
    {
        string osvId = await SeedAdvisoryAsync(enriched: true);
        await LinkUploadedAsync("o1", osvId);

        var stats = await new PackageAnalyticsRepository(_db, time: _clock, trackerConfig: NoTracker())
            .GetOrgStatsAsync("o1");

        Assert.False(stats.TrackerConfigured);
        Assert.Equal(0, stats.EnrichedAdvisoryCount);
        Assert.Equal(0, stats.TotalAdvisoryCount);
    }

    [Fact]
    public async Task NoTrackerConfigResolverSupplied_AlsoReportsNotConfigured()
    {
        // The DI-optional constructor path: production always supplies the resolver, but a test
        // (or a partially-wired container) that omits it must default to the same honest "not
        // configured" answer, not a crash and not a silent 0/0 that looks like measured coverage.
        string osvId = await SeedAdvisoryAsync(enriched: true);
        await LinkUploadedAsync("o1", osvId);

        var stats = await new PackageAnalyticsRepository(_db, time: _clock).GetOrgStatsAsync("o1");

        Assert.False(stats.TrackerConfigured);
    }

    [Fact]
    public async Task Configured_WithNoAdvisoriesAtAll_IsAMeasuredZeroNotAnAbsence()
    {
        var stats = await new PackageAnalyticsRepository(_db, time: _clock, trackerConfig: ActiveTracker())
            .GetOrgStatsAsync("o1");

        Assert.True(stats.TrackerConfigured);
        Assert.Equal(0, stats.TotalAdvisoryCount);
        Assert.Equal(0, stats.EnrichedAdvisoryCount);
    }

    // ── Counting ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task EnrichedAndUnenrichedAdvisories_AreCountedCorrectly()
    {
        string enrichedId = await SeedAdvisoryAsync(enriched: true);
        string plainId = await SeedAdvisoryAsync(enriched: false);
        await LinkUploadedAsync("o1", enrichedId);
        await LinkUploadedAsync("o1", plainId);

        var stats = await new PackageAnalyticsRepository(_db, time: _clock, trackerConfig: ActiveTracker())
            .GetOrgStatsAsync("o1");

        Assert.True(stats.TrackerConfigured);
        Assert.Equal(2, stats.TotalAdvisoryCount);
        Assert.Equal(1, stats.EnrichedAdvisoryCount);
    }

    [Fact]
    public async Task SameAdvisoryAcrossSeveralVersions_CountsOnceNotOncePerLink()
    {
        // The same CVE commonly affects several of an org's versions. Counting rows would inflate
        // both numerator and denominator by however many versions happen to share it.
        string osvId = await SeedAdvisoryAsync(enriched: true);
        await LinkUploadedAsync("o1", osvId);
        await LinkUploadedAsync("o1", osvId);
        await LinkUploadedAsync("o1", osvId);

        var stats = await new PackageAnalyticsRepository(_db, time: _clock, trackerConfig: ActiveTracker())
            .GetOrgStatsAsync("o1");

        Assert.Equal(1, stats.TotalAdvisoryCount);
        Assert.Equal(1, stats.EnrichedAdvisoryCount);
    }

    // ── Both storage planes ───────────────────────────────────────────────────

    [Fact]
    public async Task ProxyOnlyAdvisories_AreCounted()
    {
        // The H1-class miss this repo has hit before: a query that only joins package_versions
        // silently returns empty for a proxy-only org. This asserts the proxy arm alone, not just
        // the union with an uploaded row that could mask a broken proxy join.
        string osvId = await SeedAdvisoryAsync(enriched: true);
        await LinkProxyAsync("o1", osvId);

        var stats = await new PackageAnalyticsRepository(_db, time: _clock, trackerConfig: ActiveTracker())
            .GetOrgStatsAsync("o1");

        Assert.Equal(1, stats.TotalAdvisoryCount);
        Assert.Equal(1, stats.EnrichedAdvisoryCount);
    }

    [Fact]
    public async Task BothPlanesTogether_UnionWithoutDoubleCounting()
    {
        string sharedId = await SeedAdvisoryAsync(enriched: true);
        string uploadedOnlyId = await SeedAdvisoryAsync(enriched: false);
        string proxyOnlyId = await SeedAdvisoryAsync(enriched: true);

        // The shared advisory is linked on BOTH planes for the same org.
        await LinkUploadedAsync("o1", sharedId);
        await LinkProxyAsync("o1", sharedId);
        await LinkUploadedAsync("o1", uploadedOnlyId);
        await LinkProxyAsync("o1", proxyOnlyId);

        var stats = await new PackageAnalyticsRepository(_db, time: _clock, trackerConfig: ActiveTracker())
            .GetOrgStatsAsync("o1");

        Assert.Equal(3, stats.TotalAdvisoryCount);
        Assert.Equal(2, stats.EnrichedAdvisoryCount);
    }

    // ── Tenant isolation ──────────────────────────────────────────────────────

    [Fact]
    public async Task AnotherOrgsAdvisories_DoNotLeakIntoThisOrgsCount()
    {
        string o1Id = await SeedAdvisoryAsync(enriched: true);
        string o2Id = await SeedAdvisoryAsync(enriched: true);
        await LinkUploadedAsync("o1", o1Id);
        await LinkUploadedAsync("o2", o2Id);
        await LinkProxyAsync("o2", o2Id);

        var stats = await new PackageAnalyticsRepository(_db, time: _clock, trackerConfig: ActiveTracker())
            .GetOrgStatsAsync("o1");

        Assert.Equal(1, stats.TotalAdvisoryCount);
    }
}
