using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Xunit;

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
}
