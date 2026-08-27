using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins the trend wiring a refresh pass performs alongside its existing snapshot write: it
/// upserts today's <c>org_stats_history</c> row (last write of the day wins across passes on the
/// same day) and embeds the recent window as <see cref="OrgStats.Trend"/> on the cached snapshot,
/// so <c>/api/v1/stats</c> serves the trend series without an extra query.
/// </summary>
[Trait("Category", "Unit")]
public sealed class StatsRefreshTrendTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug, status) VALUES ('o1', 'acme', 'active')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private StatsRefreshService BuildService()
    {
        var snapshots = new StatsSnapshotRepository(_db);
        var history = new OrgStatsHistoryRepository(_db);
        var analytics = new PackageAnalyticsRepository(_db, time: _clock);
        var cfg = new ConfigurationBuilder().Build();
        return new StatsRefreshService(
            snapshots, history, analytics, cfg, new AirGapMode(cfg),
            new InProcessDistributedLock(_clock), NullLogger<StatsRefreshService>.Instance, _clock);
    }

    private async Task<OrgStats> GetSnapshotStatsAsync()
    {
        var snapshots = new StatsSnapshotRepository(_db);
        var row = await snapshots.GetSnapshotAsync("o1");
        Assert.NotNull(row);
        var stats = JsonSerializer.Deserialize<OrgStats>(row!.StatsJson, JsonContracts.Web);
        Assert.NotNull(stats);
        return stats!;
    }

    [Fact]
    public async Task RunRefreshPass_FirstEverPass_HistoryHasOneRow_TrendHasOnePoint()
    {
        await BuildService().RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        long historyRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM org_stats_history WHERE org_id = 'o1'");
        Assert.Equal(1, historyRows);

        var stats = await GetSnapshotStatsAsync();
        var point = Assert.Single(stats.Trend ?? []);
        Assert.Equal("2026-06-15", point.Day);
    }

    [Fact]
    public async Task RunRefreshPass_TwoPassesSameDay_HistoryStillOneRow_LastWriteWins()
    {
        var service = BuildService();

        await service.RunRefreshPassAsync(CancellationToken.None);

        // Seed a download so the second pass's TotalDownloads30d genuinely differs from the
        // first — proving the second row overwrote the first rather than the first surviving.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO activity (id, org_id, ecosystem, event_type, actor_id, source_ip, created_at)
                VALUES ('a1', 'o1', 'npm', 'download', 'u1', '203.0.113.7', '2026-06-15T10:00:00Z')
                """);
        }

        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn2 = await _db.OpenAsync();
        long historyRows = await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM org_stats_history WHERE org_id = 'o1'");
        Assert.Equal(1, historyRows);

        var stats = await GetSnapshotStatsAsync();
        var point = Assert.Single(stats.Trend ?? []);
        Assert.Equal(1, point.TotalDownloads30d);
    }

    [Fact]
    public async Task RunRefreshPass_AcrossThreeDays_TrendCarriesAllThreePoints_OldestFirst()
    {
        var service = BuildService();

        await service.RunRefreshPassAsync(CancellationToken.None);

        _clock.SetUtcNow(TestTime.KnownNow.AddDays(1));
        await service.RunRefreshPassAsync(CancellationToken.None);

        _clock.SetUtcNow(TestTime.KnownNow.AddDays(2));
        await service.RunRefreshPassAsync(CancellationToken.None);

        var stats = await GetSnapshotStatsAsync();
        var trend = stats.Trend;
        Assert.NotNull(trend);
        Assert.Equal(3, trend!.Count);
        Assert.Equal("2026-06-15", trend[0].Day);
        Assert.Equal("2026-06-16", trend[1].Day);
        Assert.Equal("2026-06-17", trend[2].Day);
    }
}
