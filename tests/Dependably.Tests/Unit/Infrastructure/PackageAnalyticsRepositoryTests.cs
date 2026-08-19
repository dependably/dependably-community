using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using NSubstitute;

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
    public async Task Dashboard_windows_include_millisecond_precision_activity_rows_exactly_at_the_boundary_second()
    {
        // activity.created_at is millisecond-precision text (AuditRepository.LogActivityAsync's
        // only writer stamps NowMs()). Every window cutoff below is a lexicographic string compare
        // against that column, so a probe seeded through the real writer at the cutoff's exact whole
        // second (plus a sub-second offset) pins the regression: '.' (0x2E) collates before 'Z'
        // (0x5A), so a second-precision cutoff wrongly excludes a millisecond row in that second.
        var now = TestTime.KnownNow;

        var hourCutoff = now.AddHours(-24);
        var sevenDaysCutoff = now.AddDays(-7);
        var thirtyDaysCutoff = now.AddDays(-30);

        // FakeTimeProvider refuses to go backward, so seed in ascending chronological order,
        // starting from before the earliest (30-day) boundary.
        var writerClock = TestTime.Frozen(thirtyDaysCutoff.AddMilliseconds(-1));
        var audit = new AuditRepository(_db, time: writerClock);

        // 30-day total (thirtyDaysCutoff): one row just outside the window, one just inside — the
        // adversarial twin proving the fix doesn't just return everything.
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/out-of-30d@1.0.0", "download");
        writerClock.SetUtcNow(thirtyDaysCutoff.AddMilliseconds(500));
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/in-30d@1.0.0", "download");

        // 7-day active users (sevenDaysCutoff): one actor just outside, one just inside.
        writerClock.SetUtcNow(sevenDaysCutoff.AddMilliseconds(-1));
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/actor-out@1.0.0", "pull", actorId: "user-out");
        writerClock.SetUtcNow(sevenDaysCutoff.AddMilliseconds(500));
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/actor-in@1.0.0", "pull", actorId: "user-in");

        // Hourly download chart (hourCutoff): one row just outside the 24h window, one just inside.
        writerClock.SetUtcNow(hourCutoff.AddMilliseconds(-1));
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/out-of-hour@1.0.0", "download");
        writerClock.SetUtcNow(hourCutoff.AddMilliseconds(500));
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/in-hour@1.0.0", "download");

        var stats = await new PackageAnalyticsRepository(_db, time: TestTime.Frozen(now)).GetOrgStatsAsync("o1");

        // Hourly chart: only the in-window download falls inside the 24h bucket.
        Assert.Equal(1, stats.DownloadsByHour.Sum(h => h.Count));

        // 30-day total spans the two hour-boundary downloads (both far inside 30 days) plus the
        // dedicated 30-day boundary probe; the row just outside the 30-day window is excluded.
        Assert.Equal(3, stats.TotalDownloads30d);

        // 7-day active users: only the in-window actor counts.
        Assert.Equal(1, stats.ActiveUsers7d);
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
    public async Task GetOrgStatsAsync_SamlConfigReadFails_OmitsCertStats_AndLogsWarning()
    {
        // Drop the table so SamlConfigRepository.GetAsync throws instead of returning null for
        // "no config" — a persistent DB failure must stay observable, not look identical to the
        // ordinary no-SAML-configured case.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DROP TABLE IF EXISTS tenant_saml_config");
        }

        var logger = Substitute.For<ILogger<PackageAnalyticsRepository>>();
        var repo = new PackageAnalyticsRepository(_db, new SamlConfigRepository(_db, TimeProvider.System), logger: logger);

        var stats = await repo.GetOrgStatsAsync("o1");

        Assert.Null(stats.SamlCertExpiry);
        logger.Received(1).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception>(),
            Arg.Any<Func<object, Exception?, string>>());
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

    [Fact]
    public async Task Operational_risk_tile_counts_distinct_packages_across_both_planes_and_respects_threshold()
    {
        await using var conn = await _db.OpenAsync();

        // Uploaded plane: one package with a version at the threshold, one just under it.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('p1','o1','npm','at-threshold','at-threshold',0), " +
            "('p2','o1','npm','under-threshold','under-threshold',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, versions_behind) VALUES " +
            "('v1','p1','1.0.0','pkg:npm/at-threshold@1.0.0','registry/v1','uploaded'," + PackageAnalyticsRepository.VersionsBehindDashboardThreshold + "), " +
            "('v2','p2','1.0.0','pkg:npm/under-threshold@1.0.0','registry/v2','uploaded'," + (PackageAnalyticsRepository.VersionsBehindDashboardThreshold - 1) + ")");

        // Proxy plane: one package over the threshold (must count), one with an unknown (NULL)
        // count that must never count as "high risk".
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, versions_behind) VALUES " +
            "('ca1','npm','proxy-over','1.0.0','proxy-over-1.0.0.tgz','proxy/aaa','aaa'," + (PackageAnalyticsRepository.VersionsBehindDashboardThreshold + 5) + "), " +
            "('ca2','npm','proxy-unknown','1.0.0','proxy-unknown-1.0.0.tgz','proxy/bbb','bbb',NULL)");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','ca1'), ('o1','ca2')");

        // Another tenant's high-risk package must not leak into o1's count.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES ('p3','o2','npm','theirs','theirs',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, versions_behind) VALUES " +
            "('v3','p3','1.0.0','pkg:npm/theirs@1.0.0','registry/v3','uploaded',99)");

        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync("o1");

        Assert.Equal(2, stats.OperationalRiskPackageCount); // at-threshold (v1) + proxy-over (ca1)
        Assert.Equal(PackageAnalyticsRepository.VersionsBehindDashboardThreshold, stats.VersionsBehindThreshold);
    }

    [Fact]
    public async Task License_risk_tile_counts_blocklisted_and_unknown_licenses_across_both_planes()
    {
        await using var conn = await _db.OpenAsync();

        await conn.ExecuteAsync(
            "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES ('bl1', 'o1', 'GPL-3.0-only')");

        // Uploaded plane: one blocklisted license, one clean license, one with no license row at all.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('p1','o1','npm','gpl-pkg','gpl-pkg',0), " +
            "('p2','o1','npm','mit-pkg','mit-pkg',0), " +
            "('p3','o1','npm','no-license-pkg','no-license-pkg',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) VALUES " +
            "('v1','p1','1.0.0','pkg:npm/gpl-pkg@1.0.0','registry/v1','uploaded'), " +
            "('v2','p2','1.0.0','pkg:npm/mit-pkg@1.0.0','registry/v2','uploaded'), " +
            "('v3','p3','1.0.0','pkg:npm/no-license-pkg@1.0.0','registry/v3','uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, package_version_id, license_spdx, owner_kind) VALUES " +
            "('l1','v1','GPL-3.0-only','package_version'), " +
            "('l2','v2','MIT','package_version')");

        // Proxy plane: one blocklisted license via the global cache_artifact-owned row.
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) VALUES " +
            "('ca1','npm','proxy-gpl','1.0.0','proxy-gpl-1.0.0.tgz','proxy/aaa','aaa')");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','ca1')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, cache_artifact_id, license_spdx, owner_kind) VALUES " +
            "('l3','ca1','GPL-3.0-only','cache_artifact')");

        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync("o1");

        // v1 (blocklisted) + v3 (no license row) + ca1 (blocklisted, proxy plane) = 3. v2 (MIT,
        // not blocklisted) is clean and must not count.
        Assert.Equal(3, stats.LicenseRiskVersionCount);
    }

    [Fact]
    public async Task Operational_risk_list_lists_both_planes_and_its_package_count_equals_the_tile()
    {
        await SeedOperationalRiskAsync();
        var repo = new PackageAnalyticsRepository(_db);

        var stats = await repo.GetOrgStatsAsync("o1");
        var (items, total, packageCount) = await repo.ListOperationalRiskAsync("o1", null, limit: 50, offset: 0);

        // The drill-down must show exactly the population the tile counts: the at-threshold uploaded
        // version and the over-threshold proxy artifact. The under-threshold and unknown-count rows
        // are absent, and so is the other tenant's high-risk package.
        Assert.Equal(2, total);
        Assert.Equal(["proxy-over", "at-threshold"], items.Select(r => r.Name)); // ordered most-behind first
        Assert.DoesNotContain(items, r => r.Name == "theirs");

        // The number on the tile is the number the page's summary renders.
        Assert.Equal(stats.OperationalRiskPackageCount, packageCount);
        Assert.Equal(2, packageCount);

        var proxy = items.Single(r => r.Name == "proxy-over");
        Assert.Equal("proxy", proxy.Origin);
        Assert.Equal(PackageAnalyticsRepository.VersionsBehindDashboardThreshold + 5, proxy.VersionsBehind);
    }

    [Fact]
    public async Task Operational_risk_counts_the_same_name_in_two_ecosystems_as_two_packages()
    {
        await using var conn = await _db.OpenAsync();

        // One name, two ecosystems — two distinct packages, and the drill-down lists two rows. A
        // count keyed on the bare name alone would collapse them and disagree with its own list.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('p1','o1','npm','requests','requests',0), " +
            "('p2','o1','pypi','requests','requests',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, versions_behind) VALUES " +
            "('v1','p1','1.0.0','pkg:npm/requests@1.0.0','registry/v1','uploaded',9), " +
            "('v2','p2','2.0.0','pkg:pypi/requests@2.0.0','registry/v2','uploaded',9)");

        var repo = new PackageAnalyticsRepository(_db);
        var stats = await repo.GetOrgStatsAsync("o1");
        var (items, total, packageCount) = await repo.ListOperationalRiskAsync("o1", null, limit: 50, offset: 0);

        Assert.Equal(2, stats.OperationalRiskPackageCount);
        Assert.Equal(2, packageCount);
        Assert.Equal(2, total);
        Assert.Equal(["npm", "pypi"], items.Select(r => r.Ecosystem).Order());
    }

    [Fact]
    public async Task Operational_risk_list_keeps_a_proxy_row_that_has_no_packages_row()
    {
        await using var conn = await _db.OpenAsync();

        // An org reaches a cache_artifact through tenant_artifact_access alone — it need not also
        // have a packages row for it. The tile counts this artifact, so the list must show it:
        // joining packages any way but a LEFT JOIN would silently drop it.
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, versions_behind) " +
            "VALUES ('ca1','npm','orphan','1.0.0','orphan-1.0.0.tgz','proxy/aaa','aaa',7)");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','ca1')");

        var repo = new PackageAnalyticsRepository(_db);
        var stats = await repo.GetOrgStatsAsync("o1");
        var (items, total, packageCount) = await repo.ListOperationalRiskAsync("o1", null, limit: 50, offset: 0);

        Assert.Equal(1, stats.OperationalRiskPackageCount);
        Assert.Equal(1, total);
        Assert.Equal(1, packageCount);
        var row = Assert.Single(items);
        Assert.Equal("orphan", row.Name);
        Assert.Equal("orphan", row.DisplayName);   // falls back to the purl name with no packages row
    }

    [Fact]
    public async Task Operational_risk_list_ecosystem_filter_scopes_both_planes()
    {
        await SeedOperationalRiskAsync();
        await using var conn = await _db.OpenAsync();

        // A pypi package over the threshold, on the uploaded plane.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES ('p9','o1','pypi','pyrisk','pyrisk',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, versions_behind) " +
            "VALUES ('v9','p9','1.0.0','pkg:pypi/pyrisk@1.0.0','registry/v9','uploaded',8)");

        var repo = new PackageAnalyticsRepository(_db);
        var (npmItems, npmTotal, npmPackages) = await repo.ListOperationalRiskAsync("o1", "npm", limit: 50, offset: 0);
        var (pypiItems, pypiTotal, _) = await repo.ListOperationalRiskAsync("o1", "pypi", limit: 50, offset: 0);

        Assert.Equal(2, npmTotal);                 // the uploaded + proxy npm rows only
        Assert.Equal(2, npmPackages);
        Assert.All(npmItems, r => Assert.Equal("npm", r.Ecosystem));

        Assert.Equal(1, pypiTotal);
        Assert.Equal("pyrisk", Assert.Single(pypiItems).Name);
    }

    [Fact]
    public async Task License_risk_list_total_equals_the_tile_and_labels_each_reason()
    {
        await SeedLicenseRiskAsync();
        var repo = new PackageAnalyticsRepository(_db);

        var stats = await repo.GetOrgStatsAsync("o1");
        var (items, total) = await repo.ListLicenseRiskAsync("o1", null, null, limit: 50, offset: 0);

        // With no conditional licence configured, the tile and the unfiltered drill-down agree.
        // They deliberately diverge once one exists — see the tile/drill-down test below.
        Assert.Equal(stats.LicenseRiskVersionCount, total);
        Assert.Equal(3, total);

        // Every listed row says why it is at risk, and the clean MIT version is not listed at all.
        Assert.Equal("blocklisted", items.Single(r => r.Name == "gpl-pkg").Reason);
        Assert.Equal("unknown", items.Single(r => r.Name == "no-license-pkg").Reason);
        Assert.Equal("blocklisted", items.Single(r => r.Name == "proxy-gpl").Reason);
        Assert.DoesNotContain(items, r => r.Name == "mit-pkg");

        // The proxy row is reachable only through tenant_artifact_access, and carries its plane.
        Assert.Equal("cache_artifact", items.Single(r => r.Name == "proxy-gpl").OwnerKind);
        Assert.Equal("proxy", items.Single(r => r.Name == "proxy-gpl").Origin);
    }

    [Fact]
    public async Task License_risk_tile_counts_a_maven_coordinate_with_two_filenames_as_two_rows()
    {
        await using var conn = await _db.OpenAsync();

        // One Maven (name, version) legitimately carries several proxied files — the .jar and the
        // -sources.jar each cast their own cache_artifact row. Routing the query onto
        // artifact_inventory must not collapse them into one: it is already one row per artifact
        // (one row per cache_artifact id), so the per-filename count survives without this query
        // deduping anything itself.
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) VALUES " +
            "('mca1','maven','com.acme:widget','1.0.0','widget-1.0.0.jar','proxy/mca1','mca1'), " +
            "('mca2','maven','com.acme:widget','1.0.0','widget-1.0.0-sources.jar','proxy/mca2','mca2')");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','mca1'), ('o1','mca2')");
        // Neither file has a license row at all — both are 'unknown'.

        var repo = new PackageAnalyticsRepository(_db);
        var stats = await repo.GetOrgStatsAsync("o1");
        var (items, total) = await repo.ListLicenseRiskAsync("o1", "maven", null, limit: 50, offset: 0);

        Assert.Equal(2, total);
        Assert.Equal(2, stats.LicenseRiskVersionCount);
        Assert.Equal(
            ["widget-1.0.0-sources.jar", "widget-1.0.0.jar"],
            items.Select(r => r.Filename).Order());
        Assert.All(items, r => Assert.Equal("unknown", r.Reason));
    }

    [Fact]
    public async Task License_risk_list_reason_filter_splits_blocklisted_from_unknown()
    {
        await SeedLicenseRiskAsync();
        var repo = new PackageAnalyticsRepository(_db);

        var (blocked, blockedTotal) = await repo.ListLicenseRiskAsync("o1", null, "blocklisted", limit: 50, offset: 0);
        var (unknown, unknownTotal) = await repo.ListLicenseRiskAsync("o1", null, "unknown", limit: 50, offset: 0);

        Assert.Equal(2, blockedTotal);   // gpl-pkg (uploaded) + proxy-gpl (proxy plane)
        Assert.All(blocked, r => Assert.Equal("blocklisted", r.Reason));

        Assert.Equal(1, unknownTotal);
        Assert.Equal("no-license-pkg", Assert.Single(unknown).Name);
    }

    [Fact]
    public async Task License_risk_list_pages_without_dropping_or_repeating_a_row()
    {
        await SeedLicenseRiskAsync();
        var repo = new PackageAnalyticsRepository(_db);

        var (first, firstTotal) = await repo.ListLicenseRiskAsync("o1", null, null, limit: 2, offset: 0);
        var (second, secondTotal) = await repo.ListLicenseRiskAsync("o1", null, null, limit: 2, offset: 2);

        // The total is the whole population on both pages — a COUNT that forgot the filters would
        // drift from the rows and mis-size the pager.
        Assert.Equal(3, firstTotal);
        Assert.Equal(3, secondTotal);
        Assert.Equal(2, first.Count);
        Assert.Single(second);
        Assert.Empty(first.Select(r => r.OwnerId).Intersect(second.Select(r => r.OwnerId)));
    }

    [Fact]
    public async Task Risk_lists_never_show_another_tenants_rows()
    {
        await SeedOperationalRiskAsync();
        await SeedLicenseRiskAsync();
        var repo = new PackageAnalyticsRepository(_db);

        // o2 has one high-risk package of its own and holds no artifact access, so each list shows
        // o2 exactly its own row and none of o1's — on either plane.
        var (opItems, opTotal, opPackages) = await repo.ListOperationalRiskAsync("o2", null, limit: 50, offset: 0);
        var (licItems, licTotal) = await repo.ListLicenseRiskAsync("o2", null, null, limit: 50, offset: 0);

        Assert.Equal(1, opTotal);                                   // only o2's own package
        Assert.Equal(1, opPackages);
        Assert.Equal("theirs", Assert.Single(opItems).Name);
        Assert.DoesNotContain(opItems, r => r.Name is "at-threshold" or "proxy-over");

        // o2's own version carries no license row of its own, so it is license-risk "unknown" —
        // but o1's blocklisted rows, on both planes, stay invisible to it.
        Assert.Equal(1, licTotal);
        Assert.Equal("theirs", Assert.Single(licItems).Name);
        Assert.Equal("unknown", licItems[0].Reason);
        Assert.DoesNotContain(licItems, r => r.Name is "gpl-pkg" or "proxy-gpl");
    }

    [Fact]
    public async Task License_risk_sees_an_oci_images_license_on_both_planes()
    {
        await using var conn = await _db.OpenAsync();

        // An image is catalogued on whichever plane ingested it — package_versions for a tag push,
        // cache_artifact for a proxy pull — and its license is projected onto that row like any
        // other package's. Neither image is at license risk; the third, with no license at all, is.
        const string pushed = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        const string pulled = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        const string bare = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('po1','o1','oci','library/nginx','library/nginx',0), " +
            "('po2','o1','oci','library/alpine','library/alpine',1), " +
            "('po3','o1','oci','library/mystery','library/mystery',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) VALUES " +
            "('vo1','po1',@pushed,'pkg:oci/nginx@' || @pushed,'oci/sha256/1111','uploaded'), " +
            "('vo3','po3',@bare,'pkg:oci/mystery@' || @bare,'oci/sha256/3333','uploaded')",
            new { pushed, bare });
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('cao1','oci','library/alpine',@pulled,'manifest','oci/sha256/2222','2222')",
            new { pulled });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','cao1')");

        // Both images' licenses live in the shared table, exactly as every other ecosystem's do.
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, package_version_id, owner_kind, license_spdx, source) " +
            "VALUES ('l1','vo1','package_version','MIT','oci-label')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, cache_artifact_id, owner_kind, license_spdx, source) " +
            "VALUES ('l2','cao1','cache_artifact','Apache-2.0','oci-label')");

        var repo = new PackageAnalyticsRepository(_db);
        var stats = await repo.GetOrgStatsAsync("o1");
        var (items, total) = await repo.ListLicenseRiskAsync("o1", null, null, limit: 50, offset: 0);

        Assert.Equal(1, total);
        Assert.Equal(1, stats.LicenseRiskVersionCount);
        var row = Assert.Single(items);
        Assert.Equal("library/mystery", row.Name);
        Assert.Equal("unknown", row.Reason);
        Assert.DoesNotContain(items, r => r.Name is "library/nginx" or "library/alpine");
    }

    [Fact]
    public async Task License_risk_flags_a_proxied_oci_image_whose_license_is_blocklisted()
    {
        await using var conn = await _db.OpenAsync();

        // The proxied shadow is the common one (docker pull) and was the last to be reported as
        // having no license at all.
        const string digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
        await conn.ExecuteAsync(
            "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES ('bl1','o1','GPL-3.0-only')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('po1','o1','oci','library/copyleft','library/copyleft',1)");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('cao1','oci','library/copyleft',@digest,'manifest','oci/sha256/4444','4444')",
            new { digest });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','cao1')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, cache_artifact_id, owner_kind, license_spdx, source) " +
            "VALUES ('l1','cao1','cache_artifact','GPL-3.0-only','oci-label')");

        var repo = new PackageAnalyticsRepository(_db);
        var (items, total) = await repo.ListLicenseRiskAsync("o1", null, null, limit: 50, offset: 0);

        Assert.Equal(1, total);
        var row = Assert.Single(items);
        Assert.Equal("blocklisted", row.Reason);
        Assert.Equal("cache_artifact", row.OwnerKind);
    }

    // Two packages over/at the threshold for o1 (one per plane), two that must never count (under
    // threshold, unknown count), and one high-risk package belonging to o2.
    private async Task SeedOperationalRiskAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('p1','o1','npm','at-threshold','at-threshold',0), " +
            "('p2','o1','npm','under-threshold','under-threshold',0), " +
            "('p3','o2','npm','theirs','theirs',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, versions_behind) VALUES " +
            "('v1','p1','1.0.0','pkg:npm/at-threshold@1.0.0','registry/v1','uploaded'," + PackageAnalyticsRepository.VersionsBehindDashboardThreshold + "), " +
            "('v2','p2','1.0.0','pkg:npm/under-threshold@1.0.0','registry/v2','uploaded'," + (PackageAnalyticsRepository.VersionsBehindDashboardThreshold - 1) + "), " +
            "('v3','p3','1.0.0','pkg:npm/theirs@1.0.0','registry/v3','uploaded',99)");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, versions_behind) VALUES " +
            "('ca1','npm','proxy-over','1.0.0','proxy-over-1.0.0.tgz','proxy/aaa','aaa'," + (PackageAnalyticsRepository.VersionsBehindDashboardThreshold + 5) + "), " +
            "('ca2','npm','proxy-unknown','1.0.0','proxy-unknown-1.0.0.tgz','proxy/bbb','bbb',NULL)");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','ca1'), ('o1','ca2')");
    }

    // For o1: a blocklisted uploaded version, a clean MIT one, one with no license row at all, and a
    // blocklisted artifact on the proxy plane.
    // Adds a conditional-licence artifact on each plane: an uploaded npm package and a proxied
    // one. Both must reach the drill-down, or the read model has the cache-plane blind spot that
    // has bitten every other per-org licence surface.
    [Fact]
    public async Task License_risk_list_surfaces_conditional_artifacts_on_both_planes()
    {
        await SeedLicenseRiskAsync();
        await SeedConditionalLicenseAsync();
        var repo = new PackageAnalyticsRepository(_db);

        var (items, total) = await repo.ListLicenseRiskAsync("o1", null, "conditional", limit: 50, offset: 0);

        Assert.Equal(2, total);
        Assert.All(items, r => Assert.Equal("conditional", r.Reason));
        // The uploaded arm and the proxy arm both report. A read model that joined only
        // package_versions would return the first and silently drop the second.
        Assert.Equal(["lgpl-pkg", "proxy-lgpl"], items.Select(r => r.Name).Order());
        Assert.Equal("cache_artifact", items.Single(r => r.Name == "proxy-lgpl").OwnerKind);
    }

    // The Dashboard tile has always meant "these are problems". Conditional artifacts serve
    // normally — the org already decided they are acceptable — so they must stay out of the tile
    // even though they share the drill-down. Without this the tile silently grows the moment an
    // org marks its first licence conditional.
    [Fact]
    public async Task License_risk_tile_excludes_conditional_but_the_drilldown_includes_it()
    {
        await SeedLicenseRiskAsync();
        await SeedConditionalLicenseAsync();
        var repo = new PackageAnalyticsRepository(_db);

        var stats = await repo.GetOrgStatsAsync("o1");
        var (_, total) = await repo.ListLicenseRiskAsync("o1", null, null, limit: 50, offset: 0);

        Assert.Equal(3, stats.LicenseRiskVersionCount);   // gpl-pkg, no-license-pkg, proxy-gpl
        Assert.Equal(5, total);                           // ...plus the two conditional rows
    }

    // A blocklisted licence outranks a conditional one in the reason ranking, so an artifact
    // somehow carrying both is reported as blocklisted — the more severe fact wins rather than
    // the artifact being filed under a reason that reads as acceptable.
    [Fact]
    public async Task License_risk_reason_prefers_blocklisted_over_conditional()
    {
        await SeedLicenseRiskAsync();
        await SeedConditionalLicenseAsync();
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO package_version_licenses (id, package_version_id, license_spdx, owner_kind) " +
                "VALUES ('ll6','lv4','GPL-3.0-only','package_version')");
        }

        var repo = new PackageAnalyticsRepository(_db);
        var (items, _) = await repo.ListLicenseRiskAsync("o1", null, null, limit: 50, offset: 0);

        Assert.Equal("blocklisted", items.Single(r => r.Name == "lgpl-pkg").Reason);
    }

    private async Task SeedConditionalLicenseAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_allowlist (id, org_id, license_spdx, disposition, note) " +
            "VALUES ('al1', 'o1', 'LGPL-3.0-only', 'conditional', 'OK when dynamically linked')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('lp4','o1','npm','lgpl-pkg','lgpl-pkg',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) VALUES " +
            "('lv4','lp4','1.0.0','pkg:npm/lgpl-pkg@1.0.0','registry/lv4','uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, package_version_id, license_spdx, owner_kind) VALUES " +
            "('ll4','lv4','LGPL-3.0-only','package_version')");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) VALUES " +
            "('lca2','npm','proxy-lgpl','1.0.0','proxy-lgpl-1.0.0.tgz','proxy/lic2','lic2')");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','lca2')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, cache_artifact_id, license_spdx, owner_kind) VALUES " +
            "('ll5','lca2','LGPL-3.0-only','cache_artifact')");
    }

    private async Task SeedLicenseRiskAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES ('bl1', 'o1', 'GPL-3.0-only')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('lp1','o1','npm','gpl-pkg','gpl-pkg',0), " +
            "('lp2','o1','npm','mit-pkg','mit-pkg',0), " +
            "('lp3','o1','npm','no-license-pkg','no-license-pkg',0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) VALUES " +
            "('lv1','lp1','1.0.0','pkg:npm/gpl-pkg@1.0.0','registry/lv1','uploaded'), " +
            "('lv2','lp2','1.0.0','pkg:npm/mit-pkg@1.0.0','registry/lv2','uploaded'), " +
            "('lv3','lp3','1.0.0','pkg:npm/no-license-pkg@1.0.0','registry/lv3','uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, package_version_id, license_spdx, owner_kind) VALUES " +
            "('ll1','lv1','GPL-3.0-only','package_version'), " +
            "('ll2','lv2','MIT','package_version')");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) VALUES " +
            "('lca1','npm','proxy-gpl','1.0.0','proxy-gpl-1.0.0.tgz','proxy/lic','lic')");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1','lca1')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, cache_artifact_id, license_spdx, owner_kind) VALUES " +
            "('ll3','lca1','GPL-3.0-only','cache_artifact')");
    }
}
