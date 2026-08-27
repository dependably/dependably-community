using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// Tracker health as recorded by the scan pass itself, rather than by calling the repository
/// directly. The distinction matters: the repository tests pin what a recorded outcome means, and
/// these pin that the scan actually records one — on every arm, including the two that produce no
/// enrichment at all. A connection that silently stopped being exercised would leave every
/// repository test green and the panel permanently stale.
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnTrackerScanHealthTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Doubles ───────────────────────────────────────────────────────────────

    private sealed class StubEnrichmentSource : IVulnerabilityEnrichmentSource
    {
        private readonly Func<IReadOnlyList<EnrichmentLookupTarget>, VulnerabilityEnrichmentBatchResult> _answer;
        public StubEnrichmentSource(
            Func<IReadOnlyList<EnrichmentLookupTarget>, VulnerabilityEnrichmentBatchResult> answer)
            => _answer = answer;

        public Task<VulnerabilityEnrichmentBatchResult> TryLookupBatchAsync(
            IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct = default)
            => Task.FromResult(_answer(targets));
    }

    /// <summary>
    /// A source that throws rather than returning an unreached result — the one thing the client
    /// contracts never to do, which is exactly why the scan has to survive it.
    /// </summary>
    private sealed class ThrowingSource : IVulnerabilityEnrichmentSource
    {
        public Task<VulnerabilityEnrichmentBatchResult> TryLookupBatchAsync(
            IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct = default)
            => throw new InvalidOperationException("upstream client fault");
    }

    private static VulnerabilityEnrichmentBatchResult Reached(
        IReadOnlyList<EnrichmentLookupTarget> targets, params AdvisoryEnrichment[] advisories)
        => new(
            results: targets.Select(_ => (IReadOnlyList<AdvisoryEnrichment>)advisories).ToList(),
            reached: true,
            checkedAt: TestTime.KnownNow,
            freshness:
            [
                new EnrichmentSourceFreshness("nvd", TestTime.KnownNow.AddDays(-1)),
                new EnrichmentSourceFreshness("vulnrichment", TestTime.KnownNow.AddDays(-2)),
            ],
            reason: EnrichmentUnreachedReason.None);

    private static VulnerabilityEnrichmentBatchResult Unreached(
        IReadOnlyList<EnrichmentLookupTarget> targets, EnrichmentUnreachedReason reason)
        => VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, reason);

    private static IOsvSource OsvWith(params string[] cveAliases) =>
        TestOsvSource.Create(_ =>
        [
            new("GHSA-test-0001", cveAliases, "test advisory", "HIGH",
                CvssScore: 8.1, AffectedPackages: [], Published: null, Modified: null,
                IsHydrated: true),
        ]);

    // ── Harness ───────────────────────────────────────────────────────────────

    private VulnerabilityScanService BuildService(
        IOsvSource osv,
        IVulnerabilityEnrichmentSource enrichment,
        InstanceVulnTrackerConfig tracker)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VULN_SCAN_BATCH_DELAY_MS"] = "0",
                ["VULN_RESCAN_AGE_HOURS"] = "24",
            })
            .Build();

        return new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, new VulnerabilityRepository(_db, _clock), new AuditRepository(_db),
            config, new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(),
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, _clock),
            new SbomComponentVulnRepository(_db, _clock),
            new SbomComponentScanner(osv, new VulnerabilityRepository(_db, _clock),
                new SbomComponentVulnRepository(_db, _clock), NullLogger<SbomComponentScanner>.Instance),
            TestSbomPolicy.Service(_db, _clock),
            enrichment,
            tracker));
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private async Task SeedArtifactAsync(string name, string version = "1.0.0")
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES (@id, 'npm', @name, @version, @filename, @blobKey, @hash, 0, @purl)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                name,
                version,
                filename = $"{name}-{version}.tgz",
                blobKey = $"proxy/npm/{name}/{version}/{name}-{version}.tgz",
                hash = $"sha256:{Guid.NewGuid():N}",
                purl = $"pkg:npm/{name}@{version}",
            });
    }

    private VulnTrackerHealthRepository Health() => new(_db, _clock);

    // ── The unconfigured deployment records nothing at all ────────────────────

    [Fact]
    public async Task NoConnectionConfigured_RecordsNoHealthAndNoFetch()
    {
        // The state most deployments are permanently in. An empty health row is what lets the
        // read surfaces say "not configured" rather than rendering a dead-looking connection —
        // so a pass that recorded a NotConfigured failure here would be actively harmful.
        await SeedArtifactAsync("lodash");

        await BuildService(OsvWith("CVE-2024-0001"), TestEnrichment.Unused(), TestEnrichment.NoConnection())
            .RunScanPassAsync(CancellationToken.None);

        Assert.Null(await Health().GetHealthAsync());
        Assert.Empty(await Health().ListRecentFetchesAsync(10));
    }

    // ── The three arms that do record ─────────────────────────────────────────

    [Fact]
    public async Task ReachedLookup_RecordsSuccessWithTheProducersAssertedAsOf()
    {
        await SeedArtifactAsync("lodash");
        var source = new StubEnrichmentSource(t => Reached(
            t, new AdvisoryEnrichment("GHSA-test-0001", "CVE-2024-0001",
                EnrichmentAdvisoryStatus.Active, new NvdBand("HIGH", 8.1), null)));

        await BuildService(OsvWith("CVE-2024-0001"), source, TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        var health = await Health().GetHealthAsync();
        Assert.NotNull(health);
        Assert.Equal("ok", health!.LastStatus);
        Assert.Equal("none", health.LastReason);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.LastSuccessAt);
        Assert.Equal(0, health.ConsecutiveFailures);
        Assert.Equal(1, health.LastPurlCount);
        Assert.Equal(1, health.LastAdvisoryCount);
        // Both freshness facts land, keyed off the producer's own source names.
        Assert.Equal(TestTime.KnownNow.AddDays(-1).ToUtcIso(), health.NvdAssertedAt);
        Assert.Equal(TestTime.KnownNow.AddDays(-2).ToUtcIso(), health.SsvcAssertedAt);

        var log = Assert.Single(await Health().ListRecentFetchesAsync(10));
        Assert.Equal("scan", log.Kind);
        Assert.Equal("ok", log.Outcome);
    }

    [Theory]
    [InlineData(EnrichmentUnreachedReason.RateLimited, "rateLimited")]
    [InlineData(EnrichmentUnreachedReason.Unauthorized, "unauthorized")]
    [InlineData(EnrichmentUnreachedReason.ServerError, "serverError")]
    [InlineData(EnrichmentUnreachedReason.MalformedResponse, "malformedResponse")]
    public async Task UnreachedLookup_RecordsTheRefusalItActuallyGot(
        EnrichmentUnreachedReason reason, string expected)
    {
        // Every refusal is distinguishable in the panel. Collapsing them into one "failed" is what
        // makes an operator unable to tell a wrong credential from a quota wall from an outage —
        // three problems with three different fixes.
        await SeedArtifactAsync("lodash");
        var source = new StubEnrichmentSource(t => Unreached(t, reason));

        await BuildService(OsvWith("CVE-2024-0001"), source, TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        var health = await Health().GetHealthAsync();
        Assert.Equal("failed", health!.LastStatus);
        Assert.Equal(expected, health.LastReason);
        Assert.Null(health.LastSuccessAt);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.FailingSince);

        var log = Assert.Single(await Health().ListRecentFetchesAsync(10));
        Assert.Equal("failed", log.Outcome);
        Assert.Equal(expected, log.Reason);
    }

    [Fact]
    public async Task LookupThatThrows_IsRecordedAsAFailureAndDoesNotAbandonTheScan()
    {
        // The client contracts never to throw for a remote failure. If it ever does, the pass must
        // still complete — the artefacts are already scanned and an unenriched advisory is a fully
        // scanned one — and the failure must still be visible rather than vanishing into a log line.
        await SeedArtifactAsync("lodash");

        await BuildService(OsvWith("CVE-2024-0001"), new ThrowingSource(), TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        var health = await Health().GetHealthAsync();
        Assert.Equal("failed", health!.LastStatus);
        Assert.Equal("exception", health.LastReason);

        // The scan itself still landed its advisory — the throw was contained to enrichment.
        await using var conn = await _db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = 'GHSA-test-0001'"));
    }

    [Fact]
    public async Task AdvisoryWithNoCveAlias_IsNotALookupAndRecordsNothing()
    {
        // NVD and Vulnrichment are CVE-keyed, so an advisory without a CVE alias has no signal to
        // fetch and no request is made. Recording a fetch here would make the panel report
        // traffic that never left the process.
        await SeedArtifactAsync("lodash");

        await BuildService(OsvWith("GHSA-only-alias"), TestEnrichment.Unused(), TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        Assert.Null(await Health().GetHealthAsync());
        Assert.Empty(await Health().ListRecentFetchesAsync(10));
    }
}
