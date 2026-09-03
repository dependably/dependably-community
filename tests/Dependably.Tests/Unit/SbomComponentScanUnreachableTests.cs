using System.Diagnostics.Metrics;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins the same unreachable-source discipline <c>VulnerabilityScanUnreachableTests</c> pins for
/// package versions and cache artifacts, but for SBOM components: an unreached OSV batch answers
/// with a full-length list of empty advisory lists, byte-identical to a genuinely clean batch.
/// <see cref="SbomComponentScanner"/> must defer the whole batch — <c>vuln_checked_at</c> stays
/// NULL and the row stays in the scan work queue (<c>idx_sbom_components_scan</c>) — rather than
/// stamp a screening that never happened. Every test here is paired with the adversarial twin
/// proving a genuinely reached-and-clean batch still stamps, so the fix does not degrade into
/// "never mark anything scanned".
///
/// The negative-control test below (<c>ScanBatchAsync_MustUseTryQueryBatchAsync_NotTheFailOpenForm</c>)
/// is the one that actually pins the CONTRACT-mandated call shape: it fails if
/// <see cref="SbomComponentScanner"/> is changed to call the fail-open
/// <see cref="IOsvSource.QueryBatchAsync"/> instead of <see cref="IOsvSource.TryQueryBatchAsync"/>.
/// </summary>
// Two tests below attach a MeterListener filtered by DependablyMeter.MeterName +
// dependably.sbom.scan_components, so the class runs alone against the process-wide static
// meter — see MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class SbomComponentScanUnreachableTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── SbomComponentScanner.ScanBatchAsync — the shared primitive ──────────────────────────

    [Fact]
    public async Task ScanBatchAsync_SourceUnreachable_LeavesComponentUnscanned()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"unreachable-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");

        var result = await BuildScanner(TestOsvSource.Create(reached: false))
            .ScanBatchAsync([component], CancellationToken.None);

        Assert.True(result.Deferred);
        Assert.Empty(result.ScannedComponentIds);
        Assert.Null(await VulnCheckedAtAsync(component.Id));
    }

    [Fact]
    public async Task ScanBatchAsync_SourceReachedWithNoAdvisories_MarksComponentScanned()
    {
        // Adversarial twin: a genuinely clean sweep must still stamp.
        string orgId = await OrgSeeder.InsertAsync(_db, $"clean-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");

        var result = await BuildScanner(TestOsvSource.Create(reached: true))
            .ScanBatchAsync([component], CancellationToken.None);

        Assert.False(result.Deferred);
        Assert.Contains(component.Id, result.ScannedComponentIds);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(component.Id));
    }

    [Fact]
    public async Task ScanBatchAsync_SourceUnreachable_WritesNoVulnLink()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"unreachable-nolink-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "evil-pkg", "1.0.0");
        string purl = component.Purl;

        // Even if the (unreachable) source were to somehow answer with a hit, the caller only
        // sees the empty answer TryQueryBatchAsync(Reached:false) actually returns — this test
        // documents that a deferred batch links nothing at all.
        var unreachable = TestOsvSource.Create(reached: false);

        await BuildScanner(unreachable).ScanBatchAsync([component], CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        long linkCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sbom_component_vulns WHERE component_id = @id",
            new { id = component.Id });
        Assert.Equal(0, linkCount);
        _ = purl;
    }

    [Fact]
    public async Task ScanBatchAsync_UnreachableThenRecovered_MaliciousAdvisoryIsStillCaught()
    {
        // The whole point of the deferral: a component scanned during an outage must remain in
        // the unscanned bucket so the very next scan finds a since-disclosed advisory.
        string orgId = await OrgSeeder.InsertAsync(_db, $"outage-recover-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "evil-pkg", "1.0.0");

        var pass1 = await BuildScanner(TestOsvSource.Create(reached: false))
            .ScanBatchAsync([component], CancellationToken.None);
        Assert.True(pass1.Deferred);
        Assert.Null(await VulnCheckedAtAsync(component.Id));

        var malicious = TestOsvSource.Create(
            p => p == component.Purl ? [MalAdvisory()] : [],
            reached: true);
        var pass2 = await BuildScanner(malicious).ScanBatchAsync([component], CancellationToken.None);

        Assert.False(pass2.Deferred);
        Assert.Contains(component.Id, pass2.ScannedComponentIds);
        Assert.Equal(1, pass2.AdvisoryCountByComponentId[component.Id]);
        Assert.NotNull(await VulnCheckedAtAsync(component.Id));

        await using var conn = await _db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM sbom_component_vulns scv
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            WHERE scv.component_id = @id AND v.osv_id = 'MAL-2026-0001'
            """,
            new { id = component.Id }));
    }

    // ── dependably.sbom.scan_components — the fail-closed deferral metric ───────────────────

    [Fact]
    public async Task ScanBatchAsync_SourceUnreachable_RecordsDeferredOutcome()
    {
        // The fail-closed deferral branch was previously log-only. Pinning the metric here is
        // what would have caught a regression where the branch keeps deferring correctly but
        // silently stops reporting it — an OSV outage would again surface only as a wall of warn
        // versions rather than a directly observable deferral rate.
        string orgId = await OrgSeeder.InsertAsync(_db, $"unreachable-metric-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");

        var byOutcome = new Dictionary<string, long>(StringComparer.Ordinal);
        using var listener = ScanComponentsOutcomeListener((outcome, count) =>
            byOutcome[outcome] = byOutcome.GetValueOrDefault(outcome) + count);

        await BuildScanner(TestOsvSource.Create(reached: false))
            .ScanBatchAsync([component], CancellationToken.None);

        Assert.Equal(1, byOutcome.GetValueOrDefault("deferred"));
        Assert.False(byOutcome.ContainsKey("scanned"));
    }

    [Fact]
    public async Task ScanBatchAsync_SourceReachedWithNoAdvisories_RecordsScannedOutcome()
    {
        // Adversarial twin of the deferred-outcome test above: a genuinely reached-and-clean
        // batch must record "scanned", not "deferred" — a scanner that always emitted
        // "deferred" regardless of Reached would pass the first test and fail this one.
        string orgId = await OrgSeeder.InsertAsync(_db, $"clean-metric-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");

        var byOutcome = new Dictionary<string, long>(StringComparer.Ordinal);
        using var listener = ScanComponentsOutcomeListener((outcome, count) =>
            byOutcome[outcome] = byOutcome.GetValueOrDefault(outcome) + count);

        await BuildScanner(TestOsvSource.Create(reached: true))
            .ScanBatchAsync([component], CancellationToken.None);

        Assert.Equal(1, byOutcome.GetValueOrDefault("scanned"));
        Assert.False(byOutcome.ContainsKey("deferred"));
    }

    // Captures the outcome tag recorded on dependably.sbom.scan_components.
    private static MeterListener ScanComponentsOutcomeListener(Action<string, long> onOutcome)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName
                    && instrument.Name == "dependably.sbom.scan_components")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };

        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "outcome" && tag.Value is string outcome)
                {
                    onOutcome(outcome, measurement);
                }
            }
        });

        listener.Start();
        return listener;
    }

    // ── The negative control: pins the TryQueryBatchAsync call shape itself ─────────────────

    /// <summary>
    /// This is the test that must fail on the fail-open form. <see cref="IOsvSource.QueryBatchAsync"/>
    /// swallows every failure/unreachable mode and answers a clean-looking, full-length empty
    /// list — indistinguishable from a genuine clean scan to any caller that only reads the list.
    /// A double wired with <c>reached: false</c> answers <c>TryQueryBatchAsync</c> with
    /// <c>Reached: false</c> but <c>QueryBatchAsync</c> with the SAME empty advisory lists
    /// regardless — so a scanner that called the fail-open form would stamp every component here
    /// as scanned. This test was verified against a temporary swap to
    /// <c>_osv.QueryBatchAsync(...)</c> in <c>SbomComponentScanner.ScanBatchAsync</c>: with that
    /// swap in place this assertion fails (the component gets stamped); reverted, it passes.
    /// </summary>
    [Fact]
    public async Task ScanBatchAsync_MustUseTryQueryBatchAsync_NotTheFailOpenForm()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"failopen-pin-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");

        var unreachable = TestOsvSource.Create(reached: false);

        var result = await BuildScanner(unreachable).ScanBatchAsync([component], CancellationToken.None);

        Assert.True(result.Deferred);
        Assert.Null(await VulnCheckedAtAsync(component.Id));
    }

    // ── The nightly third pass wraps the same primitive ─────────────────────────────────────

    [Fact]
    public async Task NightlySbomScanPass_SourceUnreachable_LeavesComponentUnscanned()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-unreachable-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");

        await BuildService(TestOsvSource.Create(reached: false)).RunSbomScanPassAsync(CancellationToken.None);

        Assert.Null(await VulnCheckedAtAsync(component.Id));
    }

    [Fact]
    public async Task NightlySbomScanPass_SourceReachedWithNoAdvisories_MarksComponentScanned()
    {
        // Adversarial twin.
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-clean-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");

        await BuildService(TestOsvSource.Create(reached: true)).RunSbomScanPassAsync(CancellationToken.None);

        Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(component.Id));
    }

    [Fact]
    public async Task NightlySbomScanPass_Disabled_ScansNothing()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-disabled-{Guid.NewGuid():N}");
        var component = await SeedComponentAsync(orgId, "npm", "left-pad", "1.3.0");

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DISABLE_BACKGROUND_JOBS"] = "sbom-scan" })
            .Build();
        var airGap = new AirGapMode(config);

        await BuildService(TestOsvSource.Create(reached: true), airGap, config)
            .RunSbomScanPassAsync(CancellationToken.None);

        Assert.Null(await VulnCheckedAtAsync(component.Id));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static OsvAdvisory MalAdvisory() => new(
        Id: "MAL-2026-0001",
        Aliases: [],
        Summary: "Malicious package",
        Severity: "CRITICAL",
        CvssScore: null,
        AffectedPackages: [new OsvAffectedPackage(null, "npm", "evil-pkg", ["1.0.0"])],
        Published: "2026-01-01T00:00:00Z",
        Modified: "2026-01-01T00:00:00Z",
        IsHydrated: true,
        RawJson: "{\"id\":\"MAL-2026-0001\"}");

    private async Task<string?> VulnCheckedAtAsync(string componentId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT vuln_checked_at FROM sbom_components WHERE id = @id", new { id = componentId });
    }

    private async Task<ScannableSbomComponent> SeedComponentAsync(
        string orgId, string ecosystem, string name, string version)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string projectVersionId = Guid.NewGuid().ToString("N");
        string componentId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:{ecosystem}/{name}@{version}";

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @orgId, @name)",
            new { id = projectId, orgId, name = $"proj-{Guid.NewGuid():N}" });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@id, @orgId, @projectId, '1.0.0')",
            new { id = projectVersionId, orgId, projectId });
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name)
            VALUES
                (@id, @orgId, @projectVersionId, @purl, @ecosystem, @name, @version, @name)
            """,
            new { id = componentId, orgId, projectVersionId, purl, ecosystem, name, version });

        return new ScannableSbomComponent(componentId, purl, ecosystem, name);
    }

    private SbomComponentScanner BuildScanner(IOsvSource osv) =>
        new(osv, new VulnerabilityRepository(_db, _clock), new SbomComponentVulnRepository(_db, _clock),
            NullLogger<SbomComponentScanner>.Instance);

    private VulnerabilityScanService BuildService(
        IOsvSource osv, IAirGapMode? airGap = null, IConfiguration? config = null)
    {
        config ??= new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VULN_SCAN_BATCH_DELAY_MS"] = "0",
                ["VULN_RESCAN_AGE_HOURS"] = "24",
            })
            .Build();
        airGap ??= new NoAirGapMode();

        var vulns = new VulnerabilityRepository(_db, _clock);
        var sbomVulns = new SbomComponentVulnRepository(_db, _clock);
        return new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, new AuditRepository(_db),
            config, airGap,
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, _clock),
            new SbomComponentScanner(osv, vulns, sbomVulns, NullLogger<SbomComponentScanner>.Instance),
            Dependably.Tests.Infrastructure.TestSbomPolicy.Service(_db, _clock),
            Dependably.Tests.Infrastructure.TestEnrichment.Unused(),
            Dependably.Tests.Infrastructure.TestEnrichment.NoConnection()));
    }

    private sealed class NoAirGapMode : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
