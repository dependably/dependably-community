using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Pins the one predicate that decides which <c>sbom_components</c> rows the OSV scan queue
/// covers, across all three of its readers.
///
/// <para>Two writers stamp <c>vuln_checked_at</c>: the upload/rescan-triggered
/// <see cref="SbomScanWorker"/> and the nightly safety net in
/// <see cref="VulnerabilityScanService"/>. If they select different sets, a component's terminal
/// state becomes a function of which path happened to run — stamped after an upload, NULL forever
/// when a queue overflow or a restart left the nightly pass to cover it. Every test here asserts
/// the two paths agree, and each is paired with the adversarial twin proving a genuinely
/// scannable component is still stamped by both.</para>
///
/// <para>Also covers the two behaviours that predicate implies: a version with an empty scannable
/// set still reaches policy evaluation (the scan is skipped, the verdict is not), and a reached
/// OSV response carrying fewer result slots than purls queried leaves its unanswered tail
/// unstamped instead of recording a screening the response never contained.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomScannablePredicateTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── The predicate itself ─────────────────────────────────────────────────

    [Theory]
    [InlineData("npm", "pkg:npm/left-pad@1.3.0", true)]
    [InlineData("rpm", "pkg:rpm/rocky/openssl@3.0.7", true)]
    [InlineData("oci", "pkg:oci/base@sha256%3Aabc", false)]
    [InlineData("terraform", "pkg:terraform/hashicorp/aws@5.0.0", false)]
    [InlineData(null, null, false)]
    [InlineData("npm", null, false)]
    [InlineData(null, "pkg:generic/blob@1.0.0", false)]
    public void IsScannable_MatchesTheSqlPredicatesThreeConditions(
        string? ecosystem, string? purl, bool expected) =>
        Assert.Equal(expected, SbomScannableComponents.IsScannable(ecosystem, purl));

    // ── Worker / nightly parity on the no-feed exclusion ─────────────────────

    /// <summary>
    /// The parity assertion. One project version holding a no-feed <c>pkg:oci</c> component and a
    /// scannable <c>pkg:npm</c> one, scanned by the worker; a second, identically seeded version
    /// scanned by the nightly pass. Both must reach the same terminal state per component.
    /// </summary>
    [Fact]
    public async Task OciComponent_ReachesTheSameTerminalState_ViaTheWorkerAndTheNightlyPass()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"predicate-parity-{Guid.NewGuid():N}");

        string workerVersionId = await SeedProjectVersionAsync(orgId);
        string workerOci = await SeedComponentAsync(orgId, workerVersionId, "oci", "base-image", "1.0.0");
        string workerNpm = await SeedComponentAsync(orgId, workerVersionId, "npm", "left-pad", "1.3.0");

        string nightlyVersionId = await SeedProjectVersionAsync(orgId);
        string nightlyOci = await SeedComponentAsync(orgId, nightlyVersionId, "oci", "base-image", "1.0.0");
        string nightlyNpm = await SeedComponentAsync(orgId, nightlyVersionId, "npm", "left-pad", "1.3.0");

        var worker = BuildWorker(TestOsvSource.Create(reached: true));
        Assert.True(worker.TryEnqueue(orgId, workerVersionId));
        await worker.DrainPendingAsync();

        await BuildNightlyService(TestOsvSource.Create(reached: true))
            .RunSbomScanPassAsync(CancellationToken.None);

        // The no-feed component: unstamped on both paths, so its NULL never depends on luck.
        Assert.Null(await VulnCheckedAtAsync(workerOci));
        Assert.Null(await VulnCheckedAtAsync(nightlyOci));

        // Adversarial twin: the exclusion must not have degraded into "stamp nothing".
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(workerNpm));
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(nightlyNpm));
    }

    [Fact]
    public async Task Worker_NoFeedComponentOnly_QueriesOsvForNothing()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"predicate-nofeed-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        await SeedComponentAsync(orgId, versionId, "terraform", "hashicorp/aws", "5.0.0");

        var osv = TestOsvSource.Create(reached: true);
        var worker = BuildWorker(osv);
        Assert.True(worker.TryEnqueue(orgId, versionId));
        await worker.DrainPendingAsync();

        await osv.DidNotReceive().TryQueryBatchAsync(
            Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>());
    }

    // ── An empty scannable set skips the scan, not the evaluation ────────────

    /// <summary>
    /// A version whose components carry no parseable purl yields an empty scannable set. The OSV
    /// loop has nothing to do, but the tenant's licence gate still applies to every component's
    /// declared licence — so the evaluation must run and persist a verdict.
    /// </summary>
    [Fact]
    public async Task Drain_VersionWithNoScannableComponents_StillRunsPolicyEvaluation()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"predicate-nolicence-{Guid.NewGuid():N}");
        await SetLicenseEnforcementAsync(orgId, "block");
        string versionId = await SeedProjectVersionAsync(orgId);
        await SeedPurllessComponentAsync(orgId, versionId, "vendored-blob.so", "GPL-3.0-only");

        var worker = BuildWorker(TestOsvSource.Create(reached: true));
        Assert.True(worker.TryEnqueue(orgId, versionId));
        await worker.DrainPendingAsync();

        Assert.Equal("violation", await PolicyStatusAsync(versionId));

        await using var conn = await _db.OpenAsync();
        long licenseFindings = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sbom_policy_findings WHERE project_version_id = @versionId AND arm = 'license'",
            new { versionId });
        Assert.Equal(1, licenseFindings);
    }

    [Fact]
    public async Task Drain_VersionWithNoScannableComponents_AndNoLicenceProblem_RollsUpToPass()
    {
        // Adversarial twin: running the evaluation must not manufacture a verdict of its own —
        // an inventory with nothing to answer for and nothing blocked reads as pass.
        string orgId = await OrgSeeder.InsertAsync(_db, $"predicate-nolicence-ok-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        await SeedPurllessComponentAsync(orgId, versionId, "vendored-blob.so", licenseSpdx: null);

        var worker = BuildWorker(TestOsvSource.Create(reached: true));
        Assert.True(worker.TryEnqueue(orgId, versionId));
        await worker.DrainPendingAsync();

        Assert.Equal("pass", await PolicyStatusAsync(versionId));
    }

    // ── A short OSV result array defers its tail ─────────────────────────────

    /// <summary>
    /// A reached-but-malformed OSV response answering fewer result slots than purls queried. The
    /// answered prefix persists; the tail stays in the scan work queue rather than being recorded
    /// as screened-clean off the back of a response that said nothing about it.
    /// </summary>
    [Fact]
    public async Task ScanBatchAsync_ShortResultArray_LeavesTheUnansweredTailUnstamped()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"short-tail-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        var batch = new List<ScannableSbomComponent>
        {
            await ScannableAsync(orgId, versionId, "npm", "answered", "1.0.0"),
            await ScannableAsync(orgId, versionId, "npm", "tail-a", "1.0.0"),
            await ScannableAsync(orgId, versionId, "npm", "tail-b", "1.0.0"),
        };

        var result = await BuildScanner(ShortAnsweringOsv(answeredSlots: 1))
            .ScanBatchAsync(batch, CancellationToken.None);

        Assert.False(result.Deferred);
        Assert.Equal([batch[0].Id], result.ScannedComponentIds.ToList());
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(batch[0].Id));
        Assert.Null(await VulnCheckedAtAsync(batch[1].Id));
        Assert.Null(await VulnCheckedAtAsync(batch[2].Id));
    }

    [Fact]
    public async Task ScanBatchAsync_FullLengthResultArray_StampsEveryComponent()
    {
        // Adversarial twin: a well-formed clean answer must still stamp the whole batch.
        string orgId = await OrgSeeder.InsertAsync(_db, $"full-tail-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        var batch = new List<ScannableSbomComponent>
        {
            await ScannableAsync(orgId, versionId, "npm", "answered", "1.0.0"),
            await ScannableAsync(orgId, versionId, "npm", "tail-a", "1.0.0"),
            await ScannableAsync(orgId, versionId, "npm", "tail-b", "1.0.0"),
        };

        var result = await BuildScanner(TestOsvSource.Create(reached: true))
            .ScanBatchAsync(batch, CancellationToken.None);

        Assert.False(result.Deferred);
        Assert.Equal(3, result.ScannedComponentIds.Count);
        foreach (var component in batch)
        {
            Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(component.Id));
        }
    }

    /// <summary>
    /// The tail is deferred, not dropped: the very next pass re-selects it and a since-disclosed
    /// advisory is still caught.
    /// </summary>
    [Fact]
    public async Task ShortResultArray_ThenAWellFormedPass_StampsTheTail()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"short-recover-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        var batch = new List<ScannableSbomComponent>
        {
            await ScannableAsync(orgId, versionId, "npm", "answered", "1.0.0"),
            await ScannableAsync(orgId, versionId, "npm", "tail-a", "1.0.0"),
        };

        await BuildScanner(ShortAnsweringOsv(answeredSlots: 1)).ScanBatchAsync(batch, CancellationToken.None);
        Assert.Null(await VulnCheckedAtAsync(batch[1].Id));

        await BuildScanner(TestOsvSource.Create(reached: true)).ScanBatchAsync(batch, CancellationToken.None);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(batch[1].Id));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static IOsvSource ShortAnsweringOsv(int answeredSlots)
    {
        var osv = Substitute.For<IOsvSource>();
        osv.TryQueryBatchAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(new OsvBatchQueryResult(
                call.ArgAt<IReadOnlyList<string>>(0)
                    .Take(answeredSlots)
                    .Select(_ => new List<OsvAdvisory>())
                    .ToList(),
                Reached: true)));
        return osv;
    }

    private async Task<string?> VulnCheckedAtAsync(string componentId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT vuln_checked_at FROM sbom_components WHERE id = @id", new { id = componentId });
    }

    private async Task<string?> PolicyStatusAsync(string versionId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT policy_status FROM project_versions WHERE id = @id", new { id = versionId });
    }

    private async Task SetLicenseEnforcementAsync(string orgId, string mode)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET license_enforcement_mode = @mode WHERE org_id = @orgId",
            new { orgId, mode });
    }

    private async Task<string> SeedProjectVersionAsync(string orgId)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @orgId, @name)",
            new { id = projectId, orgId, name = $"proj-{Guid.NewGuid():N}" });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@id, @orgId, @projectId, '1.0.0')",
            new { id = versionId, orgId, projectId });
        return versionId;
    }

    private async Task<string> SeedComponentAsync(
        string orgId, string projectVersionId, string ecosystem, string name, string version)
        => (await ScannableAsync(orgId, projectVersionId, ecosystem, name, version)).Id;

    private async Task<ScannableSbomComponent> ScannableAsync(
        string orgId, string projectVersionId, string ecosystem, string name, string version)
    {
        string id = Guid.NewGuid().ToString("N");
        string purl = $"pkg:{ecosystem}/{name}@{version}";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name)
            VALUES
                (@id, @orgId, @projectVersionId, @purl, @ecosystem, @name, @version, @name)
            """,
            new { id, orgId, projectVersionId, purl, ecosystem, name, version });
        return new ScannableSbomComponent(id, purl, ecosystem, name);
    }

    private async Task SeedPurllessComponentAsync(
        string orgId, string projectVersionId, string name, string? licenseSpdx)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components (id, org_id, project_version_id, name, license_spdx)
            VALUES (@id, @orgId, @projectVersionId, @name, @licenseSpdx)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, projectVersionId, name, licenseSpdx });
    }

    private SbomComponentScanner BuildScanner(IOsvSource osv) =>
        new(osv, new VulnerabilityRepository(_db, _clock), new SbomComponentVulnRepository(_db, _clock),
            NullLogger<SbomComponentScanner>.Instance);

    private SbomScanWorker BuildWorker(IOsvSource osv)
    {
        var sbomVulns = new SbomComponentVulnRepository(_db, _clock);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VULN_SCAN_BATCH_DELAY_MS"] = "0",
            })
            .Build();

        return new SbomScanWorker(
                   new SbomScanWorkerServices(
                   sbomVulns, BuildScanner(osv), TestSbomPolicy.Service(_db, _clock), new AuditRepository(_db), new OrgRepository(_db), new AirGapMode(new ConfigurationBuilder().Build()), config, _clock, NullLogger<SbomScanWorker>.Instance),
                   channelCapacity: null);
    }

    private VulnerabilityScanService BuildNightlyService(IOsvSource osv)
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
            config, new AirGapMode(new ConfigurationBuilder().Build()),
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, _clock),
            sbomVulns,
            new SbomComponentScanner(osv, vulns, sbomVulns, NullLogger<SbomComponentScanner>.Instance),
            TestSbomPolicy.Service(_db, _clock),
            Dependably.Tests.Infrastructure.TestEnrichment.Unused(),
            Dependably.Tests.Infrastructure.TestEnrichment.NoConnection()));
    }
}
