using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// A suspended/archived/deleting org's queued SBOM scan request is never sent to OSV (see
/// TenantLifecycle) — the scan is an outbound advisory query on the org's behalf, and
/// <see cref="SbomScanWorker"/>'s nightly safety net (<see cref="VulnerabilityScanService"/>)
/// already excludes the same org, so nothing loses coverage by skipping it here too.
///
/// Regression coverage for a gap an adversarial review found: <see cref="SbomScanWorker"/>'s
/// <c>TenantLifecycle.IsActive(...)</c> check had no test that would fail if the check were removed
/// or made to fail open. Every assertion pairs the negative probe with the adversarial twin (an
/// active org's request in the SAME drain is still scanned).
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomScanWorkerSuspensionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task<string> SeedOrgWithComponentAsync(string orgId, string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@orgId, @orgId, @status)",
            new { orgId, status });

        string projectId = orgId + "-proj";
        string versionId = orgId + "-ver";
        string componentId = orgId + "-comp";
        string name = "sbom-pkg-" + orgId;
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @orgId, @name)",
            new { id = projectId, orgId, name = "proj-" + orgId });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@id, @orgId, @projectId, '1.0.0')",
            new { id = versionId, orgId, projectId });
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name)
            VALUES
                (@id, @orgId, @versionId, @purl, 'npm', @name, '1.0.0', @name)
            """,
            new { id = componentId, orgId, versionId, purl = $"pkg:npm/{name}@1.0.0", name });

        return versionId;
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task Drain_NeverQueriesOsvFor_ANonActiveOrgsRequest_ButStillScansAnActiveOrgInTheSamePass(
        string nonActiveStatus)
    {
        string lockedVersion = await SeedOrgWithComponentAsync("locked", nonActiveStatus);
        string liveVersion = await SeedOrgWithComponentAsync("live", "active");

        var osv = new RecordingOsvSource();
        var worker = BuildWorker(osv);

        Assert.True(worker.TryEnqueue("locked", lockedVersion));
        Assert.True(worker.TryEnqueue("live", liveVersion));
        await worker.DrainPendingAsync();

        // Negative probe: never sent to OSV.
        Assert.DoesNotContain(osv.Queried, p => p.Contains("locked", StringComparison.Ordinal));
        // Adversarial twin, same drain: the active org's component IS queried.
        Assert.Contains(osv.Queried, p => p.Contains("live", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Drain_ResumesScanning_OnceTheOrgIsReinstated()
    {
        string versionId = await SeedOrgWithComponentAsync("reinstated", "suspended");
        var osv = new RecordingOsvSource();
        var worker = BuildWorker(osv);

        Assert.True(worker.TryEnqueue("reinstated", versionId));
        await worker.DrainPendingAsync();
        Assert.Empty(osv.Queried);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE orgs SET status = 'active' WHERE id = 'reinstated'");
        }

        Assert.True(worker.TryEnqueue("reinstated", versionId));
        await worker.DrainPendingAsync();
        Assert.Contains(osv.Queried, p => p.Contains("reinstated", StringComparison.Ordinal));
    }

    /// <summary>
    /// A soft-deleted org (<c>orgs.deleted_at</c> set) is not active even though its <c>status</c>
    /// column is untouched at <c>'active'</c> — see <see cref="TenantLifecycle.IsActive(Org?)"/>.
    /// </summary>
    [Fact]
    public async Task Drain_NeverQueriesOsvFor_ASoftDeletedOrg_EvenThoughStatusIsStillActive()
    {
        string versionId = await SeedOrgWithComponentAsync("softdeleted", "active");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @now WHERE id = 'softdeleted'",
                new { now = _clock.GetUtcNow().ToUtcIso() });
        }

        var osv = new RecordingOsvSource();
        var worker = BuildWorker(osv);

        Assert.True(worker.TryEnqueue("softdeleted", versionId));
        await worker.DrainPendingAsync();
        Assert.Empty(osv.Queried);
    }

    private SbomScanWorker BuildWorker(RecordingOsvSource osv)
    {
        var vulns = new VulnerabilityRepository(_db, _clock);
        var sbomVulns = new SbomComponentVulnRepository(_db, _clock);
        var scanner = new SbomComponentScanner(osv, vulns, sbomVulns, NullLogger<SbomComponentScanner>.Instance);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["VULN_SCAN_BATCH_DELAY_MS"] = "0" })
            .Build();
        var policy = new Dependably.Protocol.SbomPolicyEvaluationService(
            new SbomPolicyRepository(_db, _clock),
            new OrgRepository(_db),
            new LicenseRepository(_db, _clock, TestNormalizers.License(_db)),
            new AlertService(new AlertRepository(_db, _clock), new NoOpAlertNotifier(),
                NullLogger<AlertService>.Instance),
            new AuditRepository(_db),
            NullLogger<Dependably.Protocol.SbomPolicyEvaluationService>.Instance);

        return new SbomScanWorker(
                   new SbomScanWorkerServices(
                   sbomVulns, scanner, policy, new AuditRepository(_db), new OrgRepository(_db), new NoAirGap(), config, _clock, NullLogger<SbomScanWorker>.Instance));
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    // Records every purl the scanner asks about, so a test can assert an artifact was never sent
    // upstream at all — not merely that it came back with no advisories.
    private sealed class RecordingOsvSource : IOsvSource
    {
        public List<string> Queried { get; } = [];

        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
        {
            Queried.Add(purl);
            return Task.FromResult(new List<OsvAdvisory>());
        }

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(
            IReadOnlyList<string> purls, CancellationToken ct = default)
        {
            Queried.AddRange(purls);
            return Task.FromResult(purls.Select(_ => new List<OsvAdvisory>()).ToList());
        }
    }
}
