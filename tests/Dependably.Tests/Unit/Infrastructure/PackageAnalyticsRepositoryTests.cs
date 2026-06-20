using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The dashboard 24-hour chart (<see cref="OrgStats.DownloadsByHour"/>) counts every served
/// download exactly once. Cache hits and hosted/published serves log <c>download</c>; PyPI/npm/
/// NuGet/Maven proxy cache-misses log <c>first_fetch</c> instead (RPM/OCI log <c>download</c> for
/// both hit and miss and never emit <c>first_fetch</c>), so the filter spans both event types with
/// no double-counting. Blocked attempts and publishes are not downloads and are excluded.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageAnalyticsRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'other')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Download_and_blocked_dashboard_stats_count_correct_event_types_per_org()
    {
        var audit = new AuditRepository(_db);

        // Served downloads: cache hits / hosted serves ('download') + proxy cache-miss ('first_fetch').
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/left-pad@1.0.0", "download");
        await audit.LogActivityAsync("o1", "pypi", "pkg:pypi/requests@2.0.0", "download");
        await audit.LogActivityAsync("o1", "nuget", "pkg:nuget/Newtonsoft.Json@13.0.0", "first_fetch");

        // Not downloads: blocked attempts and a publish must never inflate the chart.
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/evil@1.0.0", "blocked");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/evil@1.0.0", "blocked_vuln_score");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/mine@1.0.0", "push");

        // Another tenant's download must not leak into o1's chart (org_id scoping).
        await audit.LogActivityAsync("o2", "npm", "pkg:npm/left-pad@1.0.0", "download");

        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync("o1");

        Assert.Equal(3, stats.DownloadsByHour.Sum(h => h.Count)); // 2 download + 1 first_fetch, last 24h
        Assert.Equal(3, stats.TotalDownloads30d);                 // same definition, 30-day window
        Assert.Equal(2, stats.BlockedPulls30d);                   // blocked + blocked_vuln_score, excluded from downloads
    }

    [Fact]
    public async Task Blocked_pulls_count_every_gate_and_break_down_per_gate()
    {
        var audit = new AuditRepository(_db);

        // One row per gate the BlockGateService can emit, plus a legacy bare 'blocked'. The total
        // must include every gate — the previous enumerated filter dropped malicious/kev/epss/
        // deprecated/release_age, so this is the regression guard for that undercount.
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/a@1", "blocked_malicious");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/b@1", "blocked_malicious");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/c@1", "blocked_kev");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/d@1", "blocked_epss");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/e@1", "blocked_deprecated");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/f@1", "blocked_release_age");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/g@1", "blocked_vuln_score");
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/h@1", "blocked");        // legacy → 'manual'

        // Another tenant's blocks must not leak into o1's counts.
        await audit.LogActivityAsync("o2", "npm", "pkg:npm/x@1", "blocked_malicious");

        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync("o1");

        Assert.Equal(8, stats.BlockedPulls30d);                   // every blocked* row, o1 only
        var byGate = stats.BlockedByGate30d!.ToDictionary(g => g.Gate, g => g.Count);
        Assert.Equal(2, byGate["malicious"]);
        Assert.Equal(1, byGate["kev"]);
        Assert.Equal(1, byGate["epss"]);
        Assert.Equal(1, byGate["deprecated"]);
        Assert.Equal(1, byGate["release_age"]);
        Assert.Equal(1, byGate["vuln_score"]);
        Assert.Equal(1, byGate["manual"]);                        // legacy bare 'blocked' folds here
        Assert.Equal(8, byGate.Values.Sum());
    }

    [Fact]
    public async Task Supply_chain_metrics_count_quarantine_proxy_split_and_quota_per_org()
    {
        await using var conn = await _db.OpenAsync();

        // Hosted (is_proxy=0) vs proxied (is_proxy=1) packages, plus another tenant's row.
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES
              ('p1', 'o1', 'npm',  'mine',     'mine',     0),
              ('p2', 'o1', 'npm',  'alsomine', 'alsomine', 0),
              ('p3', 'o1', 'pypi', 'requests', 'requests', 1),
              ('p4', 'o2', 'npm',  'theirs',   'theirs',   0)
            """);

        // Pending quarantine entries count; decided ones do not; another tenant's does not.
        await conn.ExecuteAsync(
            """
            INSERT INTO quarantine (id, org_id, ecosystem, purl, gate, state) VALUES
              ('q1', 'o1', 'npm',  'pkg:npm/evil@1',  'malicious',  'pending'),
              ('q2', 'o1', 'pypi', 'pkg:pypi/bad@2',  'kev',        'pending'),
              ('q3', 'o1', 'npm',  'pkg:npm/old@1',   'deprecated', 'approved'),
              ('q4', 'o2', 'npm',  'pkg:npm/other@1', 'malicious',  'pending')
            """);

        await conn.ExecuteAsync("UPDATE orgs SET storage_quota_bytes = 5000000 WHERE id = 'o1'");

        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync("o1");

        Assert.Equal(2, stats.HostedPackages);        // p1, p2
        Assert.Equal(1, stats.ProxiedPackages);       // p3
        Assert.Equal(2, stats.QuarantinePending);     // q1, q2 (q3 decided, q4 other tenant)
        Assert.Equal(5000000, stats.StorageQuotaBytes);
    }

    [Fact]
    public async Task Quarantine_pending_excludes_aged_out_release_age_holds_so_card_matches_the_queue()
    {
        // The review queue purges aged-out release_age holds on load; the dashboard card must not
        // count phantoms the queue can no longer show. Frozen clock so the age boundary is exact.
        var clock = TestTime.Frozen();                       // now = 2026-06-15T12:00:00Z
        await using var conn = await _db.OpenAsync();

        // 72-hour release-age hold window for o1.
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, min_release_age_hours) VALUES ('o1', 72)");

        // Two proxy versions: one published 1h ago (still held), one published 10 days ago (aged out).
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES ('p1','o1','npm','dep','dep',1)");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, published_at) VALUES
              ('vfresh','p1','1.1.0','pkg:npm/dep@1.1.0','registry/dep-1.1.0','uploaded','2026-06-15T11:00:00Z'),
              ('vaged', 'p1','1.0.0','pkg:npm/dep@1.0.0','registry/dep-1.0.0','uploaded','2026-06-05T12:00:00Z')
            """);

        await conn.ExecuteAsync(
            """
            INSERT INTO quarantine (id, org_id, package_version_id, ecosystem, purl, gate, state) VALUES
              ('qm',     'o1', NULL,      'npm', 'pkg:npm/evil@1',  'malicious',   'pending'),
              ('qfresh', 'o1', 'vfresh',  'npm', 'pkg:npm/dep@1.1.0','release_age', 'pending'),
              ('qaged',  'o1', 'vaged',   'npm', 'pkg:npm/dep@1.0.0','release_age', 'pending'),
              ('qnover', 'o1', NULL,      'npm', 'pkg:npm/gone@1',  'release_age',  'pending')
            """);

        var stats = await new PackageAnalyticsRepository(_db, time: clock).GetOrgStatsAsync("o1");

        // qm (malicious) + qfresh (still held) count; qaged (aged past 72h) and qnover (no publish
        // date → re-evaluated as serveable) are phantoms the queue purges, so they are excluded.
        Assert.Equal(2, stats.QuarantinePending);
    }

    [Fact]
    public async Task Quarantine_pending_counts_release_age_holds_when_the_policy_is_off()
    {
        // With no release-age policy, the gate cannot still be holding anything; a release_age
        // pending row is therefore stale and the queue purges it — so it must not be counted.
        var clock = TestTime.Frozen();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES ('p1','o1','npm','dep','dep',1)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, published_at) " +
            "VALUES ('vfresh','p1','1.1.0','pkg:npm/dep@1.1.0','registry/dep-1.1.0','uploaded','2026-06-15T11:00:00Z')");
        await conn.ExecuteAsync(
            """
            INSERT INTO quarantine (id, org_id, package_version_id, ecosystem, purl, gate, state) VALUES
              ('qm',     'o1', NULL,     'npm', 'pkg:npm/evil@1',   'malicious',   'pending'),
              ('qfresh', 'o1', 'vfresh', 'npm', 'pkg:npm/dep@1.1.0','release_age', 'pending')
            """);

        var stats = await new PackageAnalyticsRepository(_db, time: clock).GetOrgStatsAsync("o1");

        // Only the malicious hold counts; the release_age hold is stale with the policy off.
        Assert.Equal(1, stats.QuarantinePending);
    }

    [Fact]
    public async Task Storage_quota_is_null_when_unset_and_breakdowns_empty()
    {
        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync("o1");
        Assert.Null(stats.StorageQuotaBytes);
        Assert.Empty(stats.BlockedByGate30d!);
        Assert.Equal(0, stats.QuarantinePending);
    }

    [Fact]
    public async Task Vuln_severity_periods_and_disk_span_uploaded_and_proxy_cache_planes_per_org()
    {
        await using var conn = await _db.OpenAsync();

        // Two CVEs used across both planes.
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity) VALUES
              ('vu-high', 'OSV-HIGH', 'npm', 'shared', 'HIGH'),
              ('vu-crit', 'OSV-CRIT', 'npm', 'left-pad', 'CRITICAL')
            """);

        // Uploaded npm artifact (owner_kind='package_version', org-scoped via packages.org_id),
        // 100 bytes, carrying the HIGH CVE.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES ('p1','o1','npm','mine','mine',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) " +
            "VALUES ('v1','p1','1.0.0','pkg:npm/mine@1.0.0','registry/mine',100,'uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind, checked_at) " +
            "VALUES ('pvv1','v1','vu-high','package_version', strftime('%Y-%m-%dT%H:%M:%SZ','now'))");

        // Proxy npm artifact on the global cache plane, accessed by o1 (owner_kind='cache_artifact',
        // org-scoped via tenant_artifact_access), 250 bytes, carrying the CRITICAL CVE plus the same
        // HIGH CVE the uploaded artifact has — the HIGH must dedupe to one across the two planes.
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) " +
            "VALUES ('ca1','npm','left-pad','1.0.0','left-pad-1.0.0.tgz','proxy/abc','abc',250)");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','ca1')");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind, checked_at) VALUES
              ('pvv2','ca1','vu-crit','cache_artifact', strftime('%Y-%m-%dT%H:%M:%SZ','now')),
              ('pvv3','ca1','vu-high','cache_artifact', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """);

        // Another tenant pulled a different proxy artifact with the CRITICAL CVE — must not leak into o1.
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) " +
            "VALUES ('ca2','npm','other','2.0.0','other-2.0.0.tgz','proxy/def','def',9999)");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o2','ca2')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind, checked_at) " +
            "VALUES ('pvv4','ca2','vu-crit','cache_artifact', strftime('%Y-%m-%dT%H:%M:%SZ','now'))");

        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync("o1");

        var sev = stats.VulnsByEcosystemAndSeverity
            .Where(s => s.Ecosystem == "npm").ToDictionary(s => s.Severity, s => s.Count);
        Assert.Equal(1, sev["CRITICAL"]);          // proxy CVE; o2's copy does not leak in
        Assert.Equal(1, sev["HIGH"]);              // present on both planes for o1 → deduped to one

        Assert.Equal(2, stats.NewVulns.Day);       // distinct vu-high + vu-crit for o1, within 1 day

        long npmDisk = stats.DiskByEcosystem.First(d => d.Ecosystem == "npm").TotalBytes;
        Assert.Equal(350, npmDisk);                // 100 uploaded + 250 proxy (o2's 9999 excluded)
    }
}
