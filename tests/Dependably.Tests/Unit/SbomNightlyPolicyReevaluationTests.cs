using Dapper;
using Dependably.Infrastructure;
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
/// Pins the nightly SBOM pass's second half: it re-evaluates policy, not just advisory links.
///
/// <para>The drift this covers is invisible to the component rows. An advisory already linked to
/// an already-scanned component is added to KEV, or its EPSS/CVSS score is revised, or the tenant
/// moves its own threshold — none of that touches <c>sbom_components</c>, so the version is not in
/// the scan work queue and nothing re-stamps it. Without a re-evaluation the version keeps
/// whatever verdict its last upload produced, and <c>sbom_policy_findings</c> stays empty while a
/// blocking fact sits in the database, until somebody happens to re-upload or hit rescan. That is
/// unbounded drift on a security surface whose whole promise is that it is bounded by a day.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomNightlyPolicyReevaluationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Pass_AdvisoryBecomesKev_RestampsAnAlreadyScannedVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-kev-{Guid.NewGuid():N}");
        await SetBlockKevAsync(orgId);
        var seeded = await SeedScannedComponentAsync(orgId, "CVE-2100-1000", isKev: true);

        // The component was scanned at the frozen "now", so it is not stale and this pass will not
        // re-scan it — the re-evaluation is the only thing that can produce a verdict here.
        Assert.Null(await PolicyStatusAsync(seeded.ProjectVersionId));

        await BuildService(TestOsvSource.Create(reached: true)).RunSbomScanPassAsync(CancellationToken.None);

        Assert.Equal("violation", await PolicyStatusAsync(seeded.ProjectVersionId));
        Assert.Equal(1, await FindingCountAsync(seeded.ProjectVersionId));
    }

    [Fact]
    public async Task Pass_AdvisoryNotKev_LeavesTheVersionPassing()
    {
        // Adversarial twin: the re-evaluation must derive a verdict from the facts, not stamp
        // "violation" on everything it visits.
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-clean-{Guid.NewGuid():N}");
        await SetBlockKevAsync(orgId);
        var seeded = await SeedScannedComponentAsync(orgId, "CVE-2100-1001", isKev: false);

        await BuildService(TestOsvSource.Create(reached: true)).RunSbomScanPassAsync(CancellationToken.None);

        Assert.Equal("pass", await PolicyStatusAsync(seeded.ProjectVersionId));
        Assert.Equal(0, await FindingCountAsync(seeded.ProjectVersionId));
    }

    /// <summary>
    /// The pass has two halves and only the scanning half reaches the network. Disabling
    /// <c>sbom-scan</c> — via <c>AIR_GAPPED</c> or <c>DISABLE_BACKGROUND_JOBS</c> — must stop the
    /// outbound OSV queries and nothing else: policy re-evaluation reads only stored components,
    /// stored advisory rows and the tenant's own settings. Skipping it too leaves an air-gapped
    /// tenant with a <c>policy_status</c> that no longer tracks its own advisory data, permanently
    /// and with no next-pass floor to recover it.
    /// </summary>
    [Fact]
    public async Task Pass_JobDisabled_SkipsScanningButStillEvaluates()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-off-{Guid.NewGuid():N}");
        await SetBlockKevAsync(orgId);
        // Scanned, but ten days stale against the 24-hour rescan window, so the scanning half has
        // real work queued for it. It stays scanned because the KEV arm only fires on a component
        // carrying a vuln_checked_at stamp — an unscanned row is an open question, not a verdict.
        var seeded = await SeedScannedComponentAsync(
            orgId, "CVE-2100-1002", isKev: true, scannedAge: TimeSpan.FromDays(10));
        string? stampBefore = await VulnCheckedAtAsync(seeded.ComponentId);

        var osv = TestOsvSource.Create(reached: true);
        await BuildService(osv, new SbomScanDisabled()).RunSbomScanPassAsync(CancellationToken.None);

        // The evaluation half ran: the stored KEV fact produced a verdict and a finding.
        Assert.Equal("violation", await PolicyStatusAsync(seeded.ProjectVersionId));
        Assert.Equal(1, await FindingCountAsync(seeded.ProjectVersionId));

        // The scanning half did not: no outbound query, and the stale stamp is left alone rather
        // than refreshed against an advisory source nothing dialed.
        await osv.DidNotReceive().TryQueryBatchAsync(
            Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>());
        Assert.Equal(stampBefore, await VulnCheckedAtAsync(seeded.ComponentId));
    }

    /// <summary>
    /// The nightly sweep is bounded to the in-service set — <c>ProjectLifecycle.InServiceFilter</c>.
    /// A superseded AND retired version's documents are frozen and no surface reads its verdict, so
    /// re-reading its whole component set every night buys nothing and scales with the entire
    /// release history; a CI pattern of one SBOM per build makes that arbitrarily expensive. The
    /// adversarial half is what makes this test worth anything: the latest version must still be
    /// evaluated in the same pass, so a sweep that simply stopped working fails here rather than
    /// reading as a win.
    /// </summary>
    [Fact]
    public async Task Pass_RetiredSupersededVersion_IsNotReevaluated()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-super-{Guid.NewGuid():N}");
        await SetBlockKevAsync(orgId);

        string projectId = await InsertProjectAsync(orgId);
        var superseded = await SeedScannedComponentAsync(
            orgId, "CVE-2100-1003", isKev: true, projectId: projectId, versionLabel: "1.0.0",
            isLatest: false, isActive: false);
        var latest = await SeedScannedComponentAsync(
            orgId, "CVE-2100-1004", isKev: true, projectId: projectId, versionLabel: "2.0.0", isLatest: true);

        await BuildService(TestOsvSource.Create(reached: true)).RunSbomScanPassAsync(CancellationToken.None);

        Assert.Equal("violation", await PolicyStatusAsync(latest.ProjectVersionId));
        Assert.Null(await PolicyStatusAsync(superseded.ProjectVersionId));
        Assert.Equal(0, await FindingCountAsync(superseded.ProjectVersionId));
    }

    /// <summary>
    /// The discriminating twin: an active superseded version IS re-evaluated. This is the half the
    /// blast radius depends on — it counts an active superseded release, so if this sweep skipped
    /// one, that count would be built on advisory links frozen at whenever the version last was
    /// latest, presented beside freshly-evaluated rows under a single number with nothing saying
    /// which is which.
    /// </summary>
    [Fact]
    public async Task Pass_ActiveSupersededVersion_IsReevaluated()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-active-{Guid.NewGuid():N}");
        await SetBlockKevAsync(orgId);

        string projectId = await InsertProjectAsync(orgId);
        var stillDeployed = await SeedScannedComponentAsync(
            orgId, "CVE-2100-1005", isKev: true, projectId: projectId, versionLabel: "1.0.0",
            isLatest: false, isActive: true);

        await BuildService(TestOsvSource.Create(reached: true)).RunSbomScanPassAsync(CancellationToken.None);

        Assert.Equal("violation", await PolicyStatusAsync(stillDeployed.ProjectVersionId));
        Assert.Equal(1, await FindingCountAsync(stillDeployed.ProjectVersionId));
    }

    /// <summary>
    /// A retired project's versions are skipped whatever their own flags say — the project half of
    /// the predicate, which the two version-level cases above cannot distinguish.
    /// </summary>
    [Fact]
    public async Task Pass_RetiredProjectsLatestVersion_IsNotReevaluated()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"nightly-retired-{Guid.NewGuid():N}");
        await SetBlockKevAsync(orgId);

        string projectId = await InsertProjectAsync(orgId);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE projects SET is_active = 0 WHERE id = @projectId", new { projectId });
        }

        var latest = await SeedScannedComponentAsync(
            orgId, "CVE-2100-1006", isKev: true, projectId: projectId, versionLabel: "1.0.0", isLatest: true);

        await BuildService(TestOsvSource.Create(reached: true)).RunSbomScanPassAsync(CancellationToken.None);

        Assert.Null(await PolicyStatusAsync(latest.ProjectVersionId));
        Assert.Equal(0, await FindingCountAsync(latest.ProjectVersionId));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private sealed record SeededVersion(string ProjectVersionId, string ComponentId);

    private async Task SetBlockKevAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET block_kev = 'block' WHERE org_id = @orgId", new { orgId });
    }

    private async Task<string> InsertProjectAsync(string orgId)
    {
        string projectId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @name)",
            new { projectId, orgId, name = $"proj-{projectId[..8]}" });
        return projectId;
    }

    /// <summary>
    /// Seeds one project version holding one component already linked to <paramref name="osvId"/>.
    /// <paramref name="isLatest"/> defaults to true because the nightly sweep is bounded to latest
    /// versions — a seed that left the flag at the column default would be invisible to the pass.
    /// <paramref name="scannedAge"/> backdates the <c>vuln_checked_at</c> stamp; a value past the
    /// 24-hour rescan window is what puts real work in front of the scanning half.
    /// </summary>
    private async Task<SeededVersion> SeedScannedComponentAsync(
        string orgId, string osvId, bool isKev, string? projectId = null,
        string versionLabel = "1.0.0", bool isLatest = true, TimeSpan scannedAge = default,
        bool isActive = true)
    {
        projectId ??= await InsertProjectAsync(orgId);
        string projectVersionId = Guid.NewGuid().ToString("N");
        string componentId = Guid.NewGuid().ToString("N");
        string checkedAt = (TestTime.KnownNow - scannedAge).ToUtcIso();

        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, osvId, ecosystem: "npm", packageName: "left-pad", cvssScore: null, severity: null, isKev: isKev);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, is_active)
            VALUES (@projectVersionId, @orgId, @projectId, @versionLabel, @isLatest, @isActive)
            """,
            new
            {
                projectVersionId,
                orgId,
                projectId,
                versionLabel,
                isLatest = isLatest ? 1 : 0,
                isActive = isActive ? 1 : 0,
            });
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name, vuln_checked_at)
            VALUES
                (@componentId, @orgId, @projectVersionId, 'pkg:npm/left-pad@1.3.0', 'npm', 'left-pad',
                 '1.3.0', 'left-pad', @checkedAt)
            """,
            new { componentId, orgId, projectVersionId, checkedAt });
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });

        return new SeededVersion(projectVersionId, componentId);
    }

    private async Task<string?> VulnCheckedAtAsync(string componentId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT vuln_checked_at FROM sbom_components WHERE id = @id", new { id = componentId });
    }

    private async Task<string?> PolicyStatusAsync(string projectVersionId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT policy_status FROM project_versions WHERE id = @id", new { id = projectVersionId });
    }

    private async Task<long> FindingCountAsync(string projectVersionId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sbom_policy_findings WHERE project_version_id = @id",
            new { id = projectVersionId });
    }

    private VulnerabilityScanService BuildService(IOsvSource osv, IAirGapMode? airGap = null)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VULN_SCAN_BATCH_DELAY_MS"] = "0",
                ["VULN_RESCAN_AGE_HOURS"] = "24",
            })
            .Build();

        var vulns = new VulnerabilityRepository(_db, _clock);
        var sbomVulns = new SbomComponentVulnRepository(_db, _clock);
        return new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, new AuditRepository(_db),
            config, airGap ?? new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, _clock),
            new SbomComponentScanner(osv, vulns, sbomVulns, NullLogger<SbomComponentScanner>.Instance),
            TestSbomPolicy.Service(_db, _clock),
            Dependably.Tests.Infrastructure.TestEnrichment.Unused(),
            Dependably.Tests.Infrastructure.TestEnrichment.NoConnection()));
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class SbomScanDisabled : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string> { "sbom-scan" };
        public bool IsJobDisabled(string jobName) => jobName == "sbom-scan";
    }
}
