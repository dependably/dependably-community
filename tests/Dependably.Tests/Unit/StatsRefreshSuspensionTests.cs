using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// A suspended/archived/deleting org is excluded from <see cref="StatsRefreshService"/>'s org
/// enumeration (see TenantLifecycle) — this pass runs
/// <see cref="PackageAnalyticsRepository.GetOrgStatsAsync"/>'s eight aggregate queries per org on
/// every tick (default every 60s), forever, for a locked-out org that cannot reach
/// <c>/api/v1/stats</c> to read the result.
///
/// Regression coverage for a gap an adversarial review found: <c>StatsSnapshotRepository.ListActiveOrgIdsAsync</c>'s
/// <c>o.status = 'active'</c> predicate had no test that would fail if it were removed. Every
/// assertion pairs the negative probe with the adversarial twin (an active org's snapshot in the
/// SAME pass is still refreshed).
/// </summary>
[Trait("Category", "Unit")]
public sealed class StatsRefreshSuspensionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task SeedOrgAsync(string orgId, string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@orgId, @orgId, @status)",
            new { orgId, status });
    }

    private async Task<bool> HasSnapshotAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM org_stats_snapshot WHERE org_id = @orgId", new { orgId });
        return count > 0;
    }

    private StatsRefreshService BuildService()
    {
        var snapshots = new StatsSnapshotRepository(_db);
        var history = new OrgStatsHistoryRepository(_db);
        var analytics = new PackageAnalyticsRepository(_db, time: _clock);
        var cfg = new ConfigurationBuilder().Build();
        return new StatsRefreshService(
            snapshots, history, analytics, cfg, new NoAirGap(), new InProcessDistributedLock(_clock),
            NullLogger<StatsRefreshService>.Instance, _clock);
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task RunRefreshPass_SkipsSnapshotFor_ANonActiveOrg_ButStillRefreshesAnActiveOrgInTheSamePass(
        string nonActiveStatus)
    {
        await SeedOrgAsync("locked", nonActiveStatus);
        await SeedOrgAsync("live", "active");

        await BuildService().RunRefreshPassAsync(CancellationToken.None);

        // Negative probe: no snapshot row for the non-active org.
        Assert.False(await HasSnapshotAsync("locked"));
        // Adversarial twin, same pass: the active org's snapshot IS written.
        Assert.True(await HasSnapshotAsync("live"));
    }

    [Fact]
    public async Task RunRefreshPass_ResumesSnapshotting_OnceTheOrgIsReinstated()
    {
        await SeedOrgAsync("reinstated", "suspended");
        var svc = BuildService();

        await svc.RunRefreshPassAsync(CancellationToken.None);
        Assert.False(await HasSnapshotAsync("reinstated"));

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE orgs SET status = 'active' WHERE id = 'reinstated'");
        }

        await svc.RunRefreshPassAsync(CancellationToken.None);
        Assert.True(await HasSnapshotAsync("reinstated"));
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
