using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Per-tenant health derivation tests and the GET /api/v1/system/health endpoint authz tests.
/// Health is derived inline from <c>OrgListItem</c> data in <c>ListTenants</c> and from
/// <see cref="Dependably.Infrastructure.Health.HealthService"/> in <c>GetHealth</c>.
///
/// Per-tenant health covers:
/// <list type="bullet">
///   <item>suspended → warn</item>
///   <item>storage ≥ 90% quota → warn; ≥ 100% → critical</item>
///   <item>stale stats snapshot → warn</item>
///   <item>missing stats snapshot → warn</item>
///   <item>critical vulns in stats_json → critical</item>
///   <item>quarantine pending in stats_json → warn</item>
///   <item>multiple reasons at once (mixed tenant hitting several signals)</item>
/// </list>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SystemHealthTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    // Deserialises the health object from a serialised ListTenants row.
    private static (string Status, string[] Reasons) ReadHealth(System.Text.Json.JsonElement tenantEl)
    {
        var health = tenantEl.GetProperty("health");
        string status = health.GetProperty("status").GetString()!;
        string[] reasons = health.GetProperty("reasons")
            .EnumerateArray()
            .Select(r => r.GetString()!)
            .ToArray();
        return (status, reasons);
    }

    private static System.Text.Json.JsonElement FindTenant(
        System.Text.Json.JsonElement items, string slug)
        => items.EnumerateArray().First(i => i.GetProperty("slug").GetString() == slug);

    private static string SerializeTenants(OkObjectResult ok)
    {
        // Use Web options so property names are camelCase.
        return JsonSerializer.Serialize(ok.Value, WebJson);
    }

    // ── health = ok (baseline) ────────────────────────────────────────────────

    [Fact]
    public async Task ListTenants_ActiveTenantNoSnapshot_HealthMissing()
    {
        // An active tenant with no snapshot at all surfaces stats_missing as a warn.
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"healthy-{Guid.NewGuid():N}"[..18];
        await OrgSeeder.InsertAsync(s.Store, slug);
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        // No snapshot → stats_missing → warn.
        Assert.Equal("warn", status);
        Assert.Contains("stats_missing", reasons);
    }

    // ── suspended → warn ────────────────────────────────────────────────────────

    [Fact]
    public async Task ListTenants_SuspendedTenant_HealthIsWarn()
    {
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"suspended-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);
        await using (var conn = await s.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET status = 'suspended' WHERE id = @id", new { id = orgId });
        }

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        Assert.Equal("warn", status);
        Assert.Contains("suspended", reasons);
    }

    // ── storage quota: near → warn, exceeded → critical ─────────────────────────

    [Fact]
    public async Task ListTenants_StorageAt92Percent_HealthIsWarn()
    {
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"quota-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        // Set quota of 1000 bytes; inject 920 bytes of stored data via a package version.
        var orgs = new OrgRepository(s.Store);
        await orgs.SetStorageQuotaBytesAsync(orgId, 1000);

        // Seed a package and version so storageBytes is non-zero.
        await using (var conn = await s.Store.OpenAsync())
        {
            string pkgId = Guid.NewGuid().ToString("N");
            string verId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES (@id, @orgId, 'npm', 'testpkg', 'testpkg')",
                new { id = pkgId, orgId });
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES (@id, @pkg, '1.0.0', 'pkg:npm/testpkg@1.0.0', 'blob/key', 920, 'uploaded')",
                new { id = verId, pkg = pkgId });
        }

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        Assert.Equal("warn", status);
        Assert.Contains("storage_quota_near", reasons);
    }

    [Fact]
    public async Task ListTenants_StorageAt100Percent_HealthIsCritical()
    {
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"over-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        var orgs = new OrgRepository(s.Store);
        await orgs.SetStorageQuotaBytesAsync(orgId, 500);

        await using (var conn = await s.Store.OpenAsync())
        {
            string pkgId = Guid.NewGuid().ToString("N");
            string verId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES (@id, @orgId, 'npm', 'overpkg', 'overpkg')",
                new { id = pkgId, orgId });
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES (@id, @pkg, '1.0.0', 'pkg:npm/overpkg@1.0.0', 'blob/over', 500, 'uploaded')",
                new { id = verId, pkg = pkgId });
        }

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        Assert.Equal("critical", status);
        Assert.Contains("storage_quota_exceeded", reasons);
    }

    // ── stale snapshot → warn ────────────────────────────────────────────────────

    [Fact]
    public async Task ListTenants_StaleSnapshot_HealthIsWarn()
    {
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"stale-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        // Insert a snapshot that is 3 hours old (exceeds the 2h threshold).
        // Offset is far from the boundary — 3h vs 2h gives 1 full hour of margin.
        var staleTime = s.Clock.GetUtcNow().AddHours(-3);
        var statsSnaps = new StatsSnapshotRepository(s.Store);
        await statsSnaps.UpsertSnapshotAsync(
            orgId,
            """{"packagesByEcosystem":[],"downloadsByHour":[],"vulnsByEcosystemAndSeverity":[],"diskByEcosystem":[],"totalDiskBytes":0,"newVulns":{"day":0,"week":0,"month":0},"activeUsers7d":0,"blockedPulls30d":0,"totalDownloads30d":0}""",
            staleTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            100);

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        Assert.Equal("warn", status);
        Assert.Contains("stats_stale", reasons);
    }

    // ── unparseable computed_at → treated as stale, not ignored ──────────────────

    [Fact]
    public async Task ListTenants_MalformedComputedAt_HealthIsWarnStale()
    {
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"badts-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        // Valid stats_json (so the JSON-parse path stays clean) but a garbage
        // computed_at timestamp — must still surface as stale rather than fall through.
        var statsSnaps = new StatsSnapshotRepository(s.Store);
        await statsSnaps.UpsertSnapshotAsync(
            orgId,
            """{"packagesByEcosystem":[],"downloadsByHour":[],"vulnsByEcosystemAndSeverity":[],"diskByEcosystem":[],"totalDiskBytes":0,"newVulns":{"day":0,"week":0,"month":0},"activeUsers7d":0,"blockedPulls30d":0,"totalDownloads30d":0,"quarantinePending":0}""",
            "not-a-timestamp",
            100);

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        Assert.Equal("warn", status);
        Assert.Contains("stats_stale", reasons);
    }

    // ── critical vulns in stats_json do not drive the health dot ──────────────────

    [Fact]
    public async Task ListTenants_CriticalVulnsInStats_DoesNotAffectHealthDot()
    {
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"vuln-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        // Snapshot is fresh (1 minute old) but contains critical vulns.
        var freshTime = s.Clock.GetUtcNow().AddMinutes(-1);
        var statsSnaps = new StatsSnapshotRepository(s.Store);
        string statsJson = JsonSerializer.Serialize(new
        {
            packagesByEcosystem = Array.Empty<object>(),
            downloadsByHour = Array.Empty<object>(),
            vulnsByEcosystemAndSeverity = new[]
            {
                new { ecosystem = "npm", severity = "critical", count = 3 },
            },
            diskByEcosystem = Array.Empty<object>(),
            totalDiskBytes = 0,
            newVulns = new { day = 0, week = 0, month = 0 },
            activeUsers7d = 0,
            blockedPulls30d = 0,
            totalDownloads30d = 0,
            quarantinePending = 0,
        }, WebJson);
        await statsSnaps.UpsertSnapshotAsync(
            orgId, statsJson, freshTime.ToString("yyyy-MM-ddTHH:mm:ssZ"), 50);

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        Assert.Equal("ok", status);
        Assert.DoesNotContain("critical_vulns", reasons);
    }

    // ── quarantine pending → warn ────────────────────────────────────────────────

    [Fact]
    public async Task ListTenants_QuarantinePendingInStats_HealthIsWarn()
    {
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"qpend-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        var freshTime = s.Clock.GetUtcNow().AddMinutes(-1);
        var statsSnaps = new StatsSnapshotRepository(s.Store);
        string statsJson = JsonSerializer.Serialize(new
        {
            packagesByEcosystem = Array.Empty<object>(),
            downloadsByHour = Array.Empty<object>(),
            vulnsByEcosystemAndSeverity = Array.Empty<object>(),
            diskByEcosystem = Array.Empty<object>(),
            totalDiskBytes = 0,
            newVulns = new { day = 0, week = 0, month = 0 },
            activeUsers7d = 0,
            blockedPulls30d = 0,
            totalDownloads30d = 0,
            quarantinePending = 5,
        }, WebJson);
        await statsSnaps.UpsertSnapshotAsync(
            orgId, statsJson, freshTime.ToString("yyyy-MM-ddTHH:mm:ssZ"), 50);

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        Assert.Equal("warn", status);
        Assert.Contains("quarantine_pending", reasons);
    }

    // ── multiple reasons at once (mixed tenant) ──────────────────────────────────

    [Fact]
    public async Task ListTenants_TenantHitsManySignals_AllReasonsPresent_CriticalDominates()
    {
        // Mixed scenario: suspended + storage at 100% + critical vulns + quarantine pending.
        // Storage-exceeded (>=100% quota) is the operational signal that drives the dot to
        // "critical"; critical vulns are detail-panel only and do not affect the health dot.
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"chaos-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        var orgs = new OrgRepository(s.Store);
        await orgs.SetStorageQuotaBytesAsync(orgId, 100);

        await using (var conn = await s.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET status = 'suspended' WHERE id = @id", new { id = orgId });

            string pkgId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES (@id, @orgId, 'npm', 'chaospkg', 'chaospkg')",
                new { id = pkgId, orgId });
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES (@id, @pkg, '1.0.0', 'pkg:npm/chaospkg@1.0.0', 'blob/chaos', 100, 'uploaded')",
                new { id = Guid.NewGuid().ToString("N"), pkg = pkgId });
        }

        // Fresh snapshot with critical vulns and quarantine pending.
        var freshTime = s.Clock.GetUtcNow().AddMinutes(-1);
        var statsSnaps = new StatsSnapshotRepository(s.Store);
        string statsJson = JsonSerializer.Serialize(new
        {
            packagesByEcosystem = Array.Empty<object>(),
            downloadsByHour = Array.Empty<object>(),
            vulnsByEcosystemAndSeverity = new[]
            {
                new { ecosystem = "npm", severity = "critical", count = 2 },
            },
            diskByEcosystem = Array.Empty<object>(),
            totalDiskBytes = 100,
            newVulns = new { day = 0, week = 0, month = 0 },
            activeUsers7d = 0,
            blockedPulls30d = 0,
            totalDownloads30d = 0,
            quarantinePending = 3,
        }, WebJson);
        await statsSnaps.UpsertSnapshotAsync(
            orgId, statsJson, freshTime.ToString("yyyy-MM-ddTHH:mm:ssZ"), 50);

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);
        var (status, reasons) = ReadHealth(el);

        // Critical should dominate.
        Assert.Equal("critical", status);

        // All relevant signals must be present.
        Assert.Contains("suspended", reasons);
        Assert.Contains("storage_quota_exceeded", reasons);
        Assert.DoesNotContain("critical_vulns", reasons);
        Assert.Contains("quarantine_pending", reasons);
    }

    // ── GetHealth endpoint: verifies shape and reports dependencies ─────────────

    [Fact]
    public async Task GetHealth_ReturnsOverallAndDependenciesAndJobs()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Build a real HealthService injecting the test store.
        var blobs = new Dependably.Storage.InMemoryBlobStore();
        var sp = new ServiceCollection().BuildServiceProvider();
        var readiness = new Dependably.Infrastructure.Health.ReadinessAggregator(b.Db, blobs, sp);
        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsJobDisabled(Arg.Any<string>()).Returns(false);
        var jobRuns = new BackgroundJobRunRepository(b.Db);
        var statsSnaps = new StatsSnapshotRepository(b.Db);
        var snapshots = new Dependably.Infrastructure.Observability.MetricsSnapshotProvider(s.Clock);
        var orgs = new OrgRepository(b.Db);
        var healthSvc = new Dependably.Infrastructure.Health.HealthService(
            readiness, jobRuns, snapshots, airGap, statsSnaps, orgs, s.Clock);

        var result = await b.SystemController.GetHealth(healthSvc, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        string json = JsonSerializer.Serialize(ok.Value, WebJson);
        using var doc = JsonDocument.Parse(json);

        // Must contain the key fields.
        Assert.True(doc.RootElement.TryGetProperty("overall", out _));
        Assert.True(doc.RootElement.TryGetProperty("dependencies", out _));
        Assert.True(doc.RootElement.TryGetProperty("jobs", out _));
        Assert.True(doc.RootElement.TryGetProperty("storage", out _));
        Assert.True(doc.RootElement.TryGetProperty("tenants", out _));
        Assert.True(doc.RootElement.TryGetProperty("capturedAt", out _));

        // DB dependency must show ok (in-memory store responds to SELECT 1).
        var deps = doc.RootElement.GetProperty("dependencies");
        var dbDep = deps.EnumerateArray().FirstOrDefault(d => d.GetProperty("name").GetString() == "db");
        Assert.Equal(System.Text.Json.JsonValueKind.Object, dbDep.ValueKind);
        Assert.Equal("ok", dbDep.GetProperty("status").GetString());
    }

    [Fact]
    public async Task ListTenants_HealthFieldPresent_ForEachRow()
    {
        // Every row in the ListTenants response must carry a `health` object with
        // `status` and `reasons` — confirms the camelCase contract the frontend reads.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync("acme");
        await s.WithUserAsync(role: "owner");
        await OrgSeeder.InsertAsync(s.Store, $"second-{Guid.NewGuid():N}"[..16]);
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var items = doc.RootElement.GetProperty("items");

        foreach (var item in items.EnumerateArray())
        {
            Assert.True(item.TryGetProperty("health", out var health),
                $"Tenant '{item.GetProperty("slug").GetString()}' is missing the health field.");
            Assert.True(health.TryGetProperty("status", out _),
                "health.status missing");
            Assert.True(health.TryGetProperty("reasons", out _),
                "health.reasons missing");
        }
    }

    // ── GetHealth: jobs carry new fields ─────────────────────────────────────────

    [Fact]
    public async Task GetHealth_JobsCarryLastRunAtAndLastOutcome()
    {
        // The /health endpoint must expose lastRunAt and lastOutcome on each job entry
        // so the frontend can display "last ran <relative time>" for non-ok jobs.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var blobs = new Dependably.Storage.InMemoryBlobStore();
        var sp = new ServiceCollection().BuildServiceProvider();
        var readiness = new Dependably.Infrastructure.Health.ReadinessAggregator(b.Db, blobs, sp);
        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsJobDisabled(Arg.Any<string>()).Returns(false);
        var jobRuns = new BackgroundJobRunRepository(b.Db);
        var statsSnaps = new StatsSnapshotRepository(b.Db);
        var snapshots = new Dependably.Infrastructure.Observability.MetricsSnapshotProvider(s.Clock);
        var orgs = new OrgRepository(b.Db);
        var healthSvc = new Dependably.Infrastructure.Health.HealthService(
            readiness, jobRuns, snapshots, airGap, statsSnaps, orgs, s.Clock);

        // Seed a run row for one job so we can verify field population.
        var seedTime = s.Clock.GetUtcNow().AddMinutes(-30);
        var runRecord = new BackgroundJobRunRecord(
            Id: Guid.NewGuid().ToString("N"),
            JobName: "vuln-scan",
            Operation: "test.op",
            RunId: Guid.NewGuid().ToString("N"),
            StartedAt: seedTime,
            FinishedAt: seedTime.AddSeconds(5),
            DurationMs: 5000,
            Outcome: "success",
            ErrorMessage: null);
        await jobRuns.RecordAsync(runRecord);

        var result = await b.SystemController.GetHealth(healthSvc, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        string json = JsonSerializer.Serialize(ok.Value, WebJson);
        using var doc = JsonDocument.Parse(json);

        var jobs = doc.RootElement.GetProperty("jobs");
        var vulnJob = jobs.EnumerateArray().FirstOrDefault(j => j.GetProperty("name").GetString() == "vuln-scan");
        Assert.Equal(System.Text.Json.JsonValueKind.Object, vulnJob.ValueKind);
        Assert.Equal("ok", vulnJob.GetProperty("status").GetString());

        // lastRunAt and lastOutcome must be present and non-null for a seeded job.
        Assert.True(vulnJob.TryGetProperty("lastRunAt", out var lastRunAt));
        Assert.Equal(System.Text.Json.JsonValueKind.String, lastRunAt.ValueKind);
        Assert.True(vulnJob.TryGetProperty("lastOutcome", out var lastOutcome));
        Assert.Equal("success", lastOutcome.GetString());
    }

    // ── ListTenants: stats field populated from snapshot ─────────────────────────

    [Fact]
    public async Task ListTenants_TenantWithSnapshot_StatsFieldPresent()
    {
        // When a tenant has a stats snapshot, the list row must carry a stats object
        // with packagesByEcosystem, vulnsByEcosystemAndSeverity, etc.
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"stats-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        var freshTime = s.Clock.GetUtcNow().AddMinutes(-1);
        var statsSnaps = new StatsSnapshotRepository(s.Store);
        string statsJson = JsonSerializer.Serialize(new
        {
            packagesByEcosystem = new[] { new { ecosystem = "npm", count = 5 } },
            downloadsByHour = Array.Empty<object>(),
            vulnsByEcosystemAndSeverity = new[]
            {
                new { ecosystem = "npm", severity = "high", count = 2 },
            },
            diskByEcosystem = Array.Empty<object>(),
            totalDiskBytes = 0,
            newVulns = new { day = 0, week = 0, month = 0 },
            activeUsers7d = 0,
            blockedPulls30d = 0,
            totalDownloads30d = 42,
            quarantinePending = 0,
        }, WebJson);
        await statsSnaps.UpsertSnapshotAsync(
            orgId, statsJson, freshTime.ToString("yyyy-MM-ddTHH:mm:ssZ"), 100);

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);

        // stats field must be present.
        Assert.True(el.TryGetProperty("stats", out var statsEl),
            "Expected 'stats' field on tenant list item.");
        Assert.True(statsEl.TryGetProperty("packagesByEcosystem", out _),
            "stats.packagesByEcosystem missing");
        Assert.True(statsEl.TryGetProperty("totalDownloads30d", out var dl30d),
            "stats.totalDownloads30d missing");
        Assert.Equal(42, dl30d.GetInt32());
        Assert.True(statsEl.TryGetProperty("vulnsByEcosystemAndSeverity", out _),
            "stats.vulnsByEcosystemAndSeverity missing");
    }

    [Fact]
    public async Task ListTenants_TenantWithMalformedSnapshot_NoThrow_StatsNull()
    {
        // A malformed stats_json must not throw; the tenant row should still be returned
        // with a null stats field.
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"badj-{Guid.NewGuid():N}"[..18];
        string orgId = await OrgSeeder.InsertAsync(s.Store, slug);

        // Insert a row with garbage stats_json via the underlying table directly.
        await using var conn = await s.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO org_stats_snapshot (org_id, stats_json, computed_at, duration_ms)
            VALUES (@orgId, 'NOT_JSON', @computedAt, 0)
            """,
            new { orgId, computedAt = s.Clock.GetUtcNow().AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ") });

        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Must not throw.
        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);

        // stats should be null (no parsed data).
        Assert.True(el.TryGetProperty("stats", out var statsEl));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, statsEl.ValueKind);

        // Health should still surface stats_stale due to malformed JSON.
        var (status, reasons) = ReadHealth(el);
        Assert.Contains("stats_stale", reasons);
    }

    [Fact]
    public async Task ListTenants_TenantWithNoSnapshot_StatsNull()
    {
        // A tenant with no stats snapshot at all should have a null stats field.
        await using var s = await ControllerScenario.CreateAsync();
        string slug = $"nosnap-{Guid.NewGuid():N}"[..18];
        await OrgSeeder.InsertAsync(s.Store, slug);
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var ok = Assert.IsType<OkObjectResult>(await b.SystemController.ListTenants());
        string json = SerializeTenants(ok);
        using var doc = JsonDocument.Parse(json);
        var el = FindTenant(doc.RootElement.GetProperty("items"), slug);

        Assert.True(el.TryGetProperty("stats", out var statsEl));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, statsEl.ValueKind);
    }
}
