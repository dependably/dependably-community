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
    public async Task Storage_quota_is_null_when_unset_and_breakdowns_empty()
    {
        var stats = await new PackageAnalyticsRepository(_db).GetOrgStatsAsync("o1");
        Assert.Null(stats.StorageQuotaBytes);
        Assert.Empty(stats.BlockedByGate30d!);
        Assert.Equal(0, stats.QuarantinePending);
    }
}
