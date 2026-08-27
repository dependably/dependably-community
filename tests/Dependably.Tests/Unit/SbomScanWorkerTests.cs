using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="SbomScanWorker"/> — the upload/rescan-triggered channel drainer. Covers the enqueue
/// -> drain -> stamp/link happy path, a genuine mixed partial-failure scan (one project version
/// whose components span two OSV batches, the first reached and the second not, in the SAME
/// drain call), and the activity row the drain writes on completion.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomScanWorkerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task TryEnqueue_ThenDrain_ScansEveryComponentOfTheVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"worker-happy-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        string c1 = await SeedComponentAsync(orgId, versionId, "npm", "left-pad", "1.3.0");
        string c2 = await SeedComponentAsync(orgId, versionId, "pypi", "requests", "2.28.1");

        var worker = BuildWorker(TestOsvSource.Create(reached: true));

        Assert.True(worker.TryEnqueue(orgId, versionId));
        await worker.DrainPendingAsync();

        Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(c1));
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(c2));

        await using var conn = await _db.OpenAsync();
        long activityCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND event_type = 'sbom_scan_complete'",
            new { orgId });
        Assert.Equal(1, activityCount);
    }

    [Fact]
    public async Task Drain_SourceUnreachable_LeavesEveryComponentUnscanned()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"worker-unreachable-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        string c1 = await SeedComponentAsync(orgId, versionId, "npm", "left-pad", "1.3.0");

        var worker = BuildWorker(TestOsvSource.Create(reached: false));
        worker.TryEnqueue(orgId, versionId);
        await worker.DrainPendingAsync();

        Assert.Null(await VulnCheckedAtAsync(c1));
    }

    /// <summary>
    /// A genuine mixed partial-failure scan: one project version with 150 scannable components —
    /// two 100-purl OSV batches. The first batch's query reaches OSV and scans clean; the second's
    /// hits an outage mid-scan and defers. The same worker drain call must leave the first 100
    /// components stamped and the last 50 still NULL, not an all-or-nothing outcome.
    /// </summary>
    [Fact]
    public async Task Drain_FirstBatchReachedSecondBatchUnreachable_StampsOnlyTheReachedHalf()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"worker-partial-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);

        for (int i = 0; i < 100; i++)
        {
            await SeedComponentAsync(orgId, versionId, "npm", $"pkg-a-{i}", "1.0.0");
        }

        for (int i = 0; i < 50; i++)
        {
            await SeedComponentAsync(orgId, versionId, "npm", $"pkg-b-{i}", "1.0.0");
        }

        // The worker batches in the same order GetScannableComponentsForVersionAsync selects
        // (ORDER BY id) — a lexical id order that has no relation to insertion order, since ids
        // are random GUIDs. Read that true order back rather than assuming it matches the
        // pkg-a/pkg-b naming above.
        List<string> firstBatchIds;
        List<string> secondBatchIds;
        await using (var orderConn = await _db.OpenAsync())
        {
            var orderedIds = (await orderConn.QueryAsync<string>(
                "SELECT id FROM sbom_components WHERE project_version_id = @versionId ORDER BY id",
                new { versionId })).ToList();
            firstBatchIds = orderedIds.Take(100).ToList();
            secondBatchIds = orderedIds.Skip(100).ToList();
        }

        var osv = Substitute.For<IOsvSource>();
        var emptyPerPurl = new Func<IReadOnlyList<string>, List<List<OsvAdvisory>>>(
            purls => purls.Select(_ => new List<OsvAdvisory>()).ToList());
        osv.TryQueryBatchAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns(
                call => Task.FromResult(new OsvBatchQueryResult(
                    emptyPerPurl(call.ArgAt<IReadOnlyList<string>>(0)), Reached: true)),
                call => Task.FromResult(new OsvBatchQueryResult(
                    emptyPerPurl(call.ArgAt<IReadOnlyList<string>>(0)), Reached: false)));

        var worker = BuildWorker(osv, batchDelayMs: 0);
        worker.TryEnqueue(orgId, versionId);
        await worker.DrainPendingAsync();

        foreach (string id in firstBatchIds)
        {
            Assert.Equal(TestTime.KnownNow.ToUtcIso(), await VulnCheckedAtAsync(id));
        }

        foreach (string id in secondBatchIds)
        {
            Assert.Null(await VulnCheckedAtAsync(id));
        }
    }

    [Fact]
    public async Task TryEnqueue_QueueFull_ReturnsFalseAndDoesNotThrow()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"worker-full-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);

        var worker = BuildWorker(TestOsvSource.Create(), channelCapacity: 1);
        Assert.True(worker.TryEnqueue(orgId, versionId));
        // Second enqueue overflows the capacity-1 channel before anything drains it.
        Assert.False(worker.TryEnqueue(orgId, versionId));
    }

    [Fact]
    public async Task JobDisabled_TryEnqueue_ReportsNotQueuedAndScansNothing()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"worker-disabled-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        string componentId = await SeedComponentAsync(orgId, versionId, "npm", "left-pad", "1.3.0");

        var worker = BuildWorker(
            TestOsvSource.Create(reached: true),
            airGap: DisabledSbomScan());

        // False, not a silent no-op: the upload response reports this value as scanQueued, so a
        // request that was never queued must not read as queued.
        Assert.False(worker.TryEnqueue(orgId, versionId));
        await worker.DrainPendingAsync();

        Assert.Null(await VulnCheckedAtAsync(componentId));
        await using var conn = await _db.OpenAsync();
        long activityCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND event_type = 'sbom_scan_complete'",
            new { orgId });
        Assert.Equal(0, activityCount);
    }

    [Fact]
    public async Task JobDisabledAfterEnqueue_Drain_ScansNothing()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"worker-disabled-mid-{Guid.NewGuid():N}");
        string versionId = await SeedProjectVersionAsync(orgId);
        string componentId = await SeedComponentAsync(orgId, versionId, "npm", "left-pad", "1.3.0");

        var enabled = BuildWorker(TestOsvSource.Create(reached: true));
        Assert.True(enabled.TryEnqueue(orgId, versionId));

        var disabled = BuildWorker(TestOsvSource.Create(reached: true), airGap: DisabledSbomScan());
        Assert.False(disabled.TryEnqueue(orgId, versionId));
        await disabled.DrainPendingAsync();

        Assert.Null(await VulnCheckedAtAsync(componentId));
    }

    private static IAirGapMode DisabledSbomScan() =>
        new AirGapMode(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DISABLE_BACKGROUND_JOBS"] = "sbom-scan",
            })
            .Build());

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<string?> VulnCheckedAtAsync(string componentId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT vuln_checked_at FROM sbom_components WHERE id = @id", new { id = componentId });
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
        return id;
    }

    private SbomScanWorker BuildWorker(
        IOsvSource osv, int batchDelayMs = 0, int? channelCapacity = null, IAirGapMode? airGap = null)
    {
        var vulns = new VulnerabilityRepository(_db, _clock);
        var sbomVulns = new SbomComponentVulnRepository(_db, _clock);
        var scanner = new SbomComponentScanner(osv, vulns, sbomVulns, NullLogger<SbomComponentScanner>.Instance);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VULN_SCAN_BATCH_DELAY_MS"] = batchDelayMs.ToString(),
            })
            .Build();

        return new SbomScanWorker(
                   new SbomScanWorkerServices(
                   sbomVulns, scanner, BuildPolicyService(), new AuditRepository(_db), new OrgRepository(_db), airGap ?? new AirGapMode(new ConfigurationBuilder().Build()), config, _clock, NullLogger<SbomScanWorker>.Instance),
                   channelCapacity);
    }

    private Dependably.Protocol.SbomPolicyEvaluationService BuildPolicyService()
        => new(
            new SbomPolicyRepository(_db, _clock),
            new OrgRepository(_db),
            new LicenseRepository(_db, _clock, TestNormalizers.License(_db)),
            new AlertService(new AlertRepository(_db, _clock), new NoOpAlertNotifier(),
                NullLogger<AlertService>.Instance),
            new AuditRepository(_db),
            NullLogger<Dependably.Protocol.SbomPolicyEvaluationService>.Instance);
}
