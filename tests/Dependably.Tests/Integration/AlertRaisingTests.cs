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
using NSubstitute;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end alert raising against a real schema-initialized SQLite database, wiring the real
/// <see cref="BlockGateService"/> / <see cref="QuarantineRepository"/> / <see cref="VulnerabilityScanService"/>
/// production classes together with <see cref="AlertService"/> and <see cref="AlertRepository"/> —
/// the same graph the running host uses, minus the HTTP layer. A private
/// <see cref="TestMetadataStore"/> per test method (xUnit creates a fresh test-class instance per
/// fact) avoids the cross-test races a shared database would introduce, since
/// <see cref="VulnerabilityScanService.RunScanPassAsync"/> scans unscoped across every org.
///
/// Covers the quarantine trigger (via the real block gate) and the vulnerability-severity
/// trigger (via a stubbed <see cref="IOsvSource"/> — no real OSV network call). Both must raise
/// exactly once across two firings on the same natural key, respect the org's severity floor, and
/// skip the cache_artifact (global-plane) arm entirely.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AlertRaisingTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Quarantine trigger ───────────────────────────────────────────────────

    /// <summary>
    /// A repeat block on the same purl (still pending) refreshes the quarantine row without a
    /// fresh insert — BlockGateService must raise exactly one quarantine_new alert, not two.
    /// </summary>
    [Fact]
    public async Task QuarantineTrigger_BlockedTwice_RaisesExactlyOneAlert()
    {
        var blockGate = TestBlockGate.Create(_db, TimeProvider.System);
        var alerts = new AlertRepository(_db, TimeProvider.System);
        string orgId = await OrgSeeder.InsertAsync(_db, $"raise-q-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "raise-quarantine-pkg");
        string purl = $"pkg:npm/raise-quarantine-pkg@{Guid.NewGuid():N}";
        string verId = await PackageSeeder.InsertVersionAsync(_db, pkgId, "1.0.0", purl);

        // now-ok: real-clock request field, matching TestBlockGate's real TimeProvider.System.
        var recentPublish = TimeProvider.System.GetUtcNow().AddHours(-1);
        var request = new BlockGateRequest(
            OrgId: orgId, Ecosystem: "npm", Purl: purl, VersionId: verId,
            ManualState: null, VulnCheckedAt: null, UserId: null, MaxOsvScoreTolerance: 10.0,
            MinReleaseAgeHours: 24, PublishedAt: recentPublish, Origin: "proxy");

        var first = await blockGate.EvaluateAsync(request);
        var second = await blockGate.EvaluateAsync(request);

        Assert.Equal(BlockDecision.Blocked, first);
        Assert.Equal(BlockDecision.Blocked, second);
        Assert.Equal(1, await alerts.CountActiveAsync(orgId));

        var (items, _) = await alerts.ListAsync(orgId, "active", 10, 0);
        Assert.Contains(items, a => a.Type == AlertTypes.QuarantineNew && a.Purl == purl);
    }

    /// <summary>Purge-then-reblock produces a fresh quarantine row → a second, independent alert.</summary>
    [Fact]
    public async Task QuarantineTrigger_PurgeThenReblock_RaisesSecondAlert()
    {
        var blockGate = TestBlockGate.Create(_db, TimeProvider.System);
        var quarantine = new QuarantineRepository(_db, TimeProvider.System);
        var alerts = new AlertRepository(_db, TimeProvider.System);
        string orgId = await OrgSeeder.InsertAsync(_db, $"raise-qp-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "raise-purge-pkg");
        string purl = $"pkg:npm/raise-purge-pkg@{Guid.NewGuid():N}";
        string verId = await PackageSeeder.InsertVersionAsync(_db, pkgId, "1.0.0", purl);

        var recentPublish = TimeProvider.System.GetUtcNow().AddHours(-1); // now-ok: see above
        var request = new BlockGateRequest(
            OrgId: orgId, Ecosystem: "npm", Purl: purl, VersionId: verId,
            ManualState: null, VulnCheckedAt: null, UserId: null, MaxOsvScoreTolerance: 10.0,
            MinReleaseAgeHours: 24, PublishedAt: recentPublish, Origin: "proxy");

        await blockGate.EvaluateAsync(request);
        Assert.Equal(1, await alerts.CountActiveAsync(orgId));

        // Policy off (null hours) makes the pending release_age row a phantom — purge deletes it,
        // freeing the UNIQUE(org_id, purl) slot for a genuinely fresh insert next block.
        await quarantine.PurgeAgedReleaseHoldsAsync(orgId, null);
        await blockGate.EvaluateAsync(request);

        Assert.Equal(2, await alerts.CountActiveAsync(orgId));
    }

    // ── Vulnerability-severity trigger ──────────────────────────────────────

    private VulnerabilityScanService BuildScanService(IOsvSource osv) =>
        new(new VulnerabilityScanService.Dependencies(
            _db, osv,
            new VulnerabilityRepository(_db, TimeProvider.System),
            new AuditRepository(_db),
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VULN_SCAN_BATCH_DELAY_MS"] = "0",
                    ["VULN_RESCAN_AGE_HOURS"] = "24",
                })
                .Build(),
            new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(),
            new InProcessDistributedLock(TimeProvider.System),
            new AlertService(new AlertRepository(_db, TimeProvider.System), new NoOpAlertNotifier(), NullLogger<AlertService>.Instance)));

    private static OsvAdvisory BuildAdvisory(string id, string severity) => new(
        Id: id, Aliases: [], Summary: $"Test advisory {id}", Severity: severity,
        CvssScore: severity == "CRITICAL" ? 9.8 : 7.5,
        AffectedPackages: [], Published: "2026-01-01T00:00:00Z", Modified: "2026-01-01T00:00:00Z",
        IsHydrated: true, RawJson: $"{{\"id\":\"{id}\"}}");

    private sealed class StubOsvSource : IOsvSource
    {
        private readonly Func<string, List<OsvAdvisory>> _selector;
        public StubOsvSource(Func<string, List<OsvAdvisory>> selector) => _selector = selector;

        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
            => Task.FromResult(_selector(purl));

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default)
            => Task.FromResult(purls.Select(_selector).ToList());
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    /// <summary>
    /// Two unscanned versions of the same package linked to the same advisory, scanned across two
    /// separate passes, dedup to one alert — the natural key is vulnId:ecosystem:packageName, not
    /// per-version, matching "one alert per advisory-per-package, not per version".
    /// </summary>
    [Fact]
    public async Task VulnTrigger_SameAdvisoryAcrossTwoVersions_RaisesExactlyOneAlert()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"raise-v-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "raise-vuln-pkg");
        string purlV1 = $"pkg:npm/raise-vuln-pkg@1.0.0-{Guid.NewGuid():N}";
        string purlV2 = $"pkg:npm/raise-vuln-pkg@2.0.0-{Guid.NewGuid():N}";
        await PackageSeeder.InsertVersionAsync(_db, pkgId, "1.0.0", purlV1);
        string verV2 = await PackageSeeder.InsertVersionAsync(_db, pkgId, "2.0.0", purlV2);

        const string osvId = "GHSA-raise-twice";
        var osv = new StubOsvSource(_ => [BuildAdvisory(osvId, "CRITICAL")]);
        var alerts = new AlertRepository(_db, TimeProvider.System);

        // First pass scans v1 only (v2 stays unscanned) — one alert raised.
        await StampCheckedAsync(verV2); // keep v2 out of the first pass
        var svc1 = BuildScanService(osv);
        await svc1.RunScanPassAsync(CancellationToken.None);
        Assert.Equal(1, await alerts.CountActiveAsync(orgId));

        // Reset v2 to unscanned and run a second pass — the same advisory-per-package key must dedupe.
        await ClearCheckedAsync(verV2);
        var svc2 = BuildScanService(osv);
        await svc2.RunScanPassAsync(CancellationToken.None);

        Assert.Equal(1, await alerts.CountActiveAsync(orgId));
        var (items, _) = await alerts.ListAsync(orgId, "active", 10, 0);
        Assert.Contains(items, a => a.Type == AlertTypes.VulnSeverity && a.Ecosystem == "npm");
    }

    /// <summary>An advisory below the org's severity floor never raises.</summary>
    [Fact]
    public async Task VulnTrigger_BelowSeverityFloor_DoesNotRaise()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"raise-vt-{Guid.NewGuid():N}");
        await SeedAlertSettingsAsync(orgId, minSeverity: "CRITICAL");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "raise-threshold-pkg");
        string purl = $"pkg:npm/raise-threshold-pkg@{Guid.NewGuid():N}";
        await PackageSeeder.InsertVersionAsync(_db, pkgId, "1.0.0", purl);

        var osv = new StubOsvSource(_ => [BuildAdvisory("GHSA-below-floor", "HIGH")]);
        var svc = BuildScanService(osv);
        await svc.RunScanPassAsync(CancellationToken.None);

        var alerts = new AlertRepository(_db, TimeProvider.System);
        Assert.Equal(0, await alerts.CountActiveAsync(orgId));
    }

    /// <summary>An advisory at/above the org's severity floor raises.</summary>
    [Fact]
    public async Task VulnTrigger_AtSeverityFloor_Raises()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"raise-vf-{Guid.NewGuid():N}");
        await SeedAlertSettingsAsync(orgId, minSeverity: "HIGH");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "raise-atfloor-pkg");
        string purl = $"pkg:npm/raise-atfloor-pkg@{Guid.NewGuid():N}";
        await PackageSeeder.InsertVersionAsync(_db, pkgId, "1.0.0", purl);

        var osv = new StubOsvSource(_ => [BuildAdvisory("GHSA-at-floor", "HIGH")]);
        var svc = BuildScanService(osv);
        await svc.RunScanPassAsync(CancellationToken.None);

        var alerts = new AlertRepository(_db, TimeProvider.System);
        Assert.Equal(1, await alerts.CountActiveAsync(orgId));
    }

    /// <summary>
    /// The global cache_artifact scan arm (proxy metadata scanned before any tenant version
    /// exists) never raises — there is no tenant owner for a global row. Vuln data still
    /// persists (vuln_checked_at stamped, link written) on the cache_artifact side.
    /// </summary>
    [Fact]
    public async Task VulnTrigger_CacheArtifactArm_NeverRaises()
    {
        string caId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:npm/raise-cache-pkg@{Guid.NewGuid():N}";
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl, vuln_checked_at)
                VALUES
                    (@id, 'npm', 'raise-cache-pkg', '1.0.0', 'raise-cache-pkg-1.0.0.tgz',
                     @blobKey, @contentHash, 0, @purl, NULL)
                """,
                new
                {
                    id = caId,
                    blobKey = "proxy/npm/raise-cache-pkg/1.0.0/raise-cache-pkg-1.0.0.tgz",
                    contentHash = $"sha256:{Guid.NewGuid():N}",
                    purl
                });
        }

        var osv = new StubOsvSource(_ => [BuildAdvisory("GHSA-cache-arm", "CRITICAL")]);
        var svc = BuildScanService(osv);
        await svc.RunScanPassAsync(CancellationToken.None);

        // Vuln data was persisted on the cache_artifact side...
        await using var checkConn = await _db.OpenAsync();
        string? checkedAt = await checkConn.ExecuteScalarAsync<string?>(
            "SELECT vuln_checked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.NotNull(checkedAt);
        long links = await checkConn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_vulns WHERE cache_artifact_id = @id", new { id = caId });
        Assert.Equal(1, links);

        // ...but no alert was raised anywhere — the cache_artifact arm has no tenant owner to alert.
        long alertCount = await checkConn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM alert WHERE type = 'vuln_severity'");
        Assert.Equal(0, alertCount);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task SeedAlertSettingsAsync(string orgId, string minSeverity)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings (org_id, vuln_min_severity, created_at, updated_at)
            VALUES (@orgId, @minSeverity, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { orgId, minSeverity });
    }

    private async Task StampCheckedAsync(string versionId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET vuln_checked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @id",
            new { id = versionId });
    }

    private async Task ClearCheckedAsync(string versionId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET vuln_checked_at = NULL WHERE id = @id",
            new { id = versionId });
    }
}
