using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins <see cref="OrgStatsHistoryRepository"/>'s upsert-on-(org_id, day) contract: a second
/// write for the same org+day overwrites the first row rather than inserting a sibling, and
/// <see cref="OrgStatsHistoryRepository.GetRecentAsync"/> returns rows oldest-first, the shape a
/// trend series/sparkline renders in.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgStatsHistoryRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private OrgStatsHistoryRepository Build() => new(_db);

    private async Task<long> CountRowsAsync(string orgId, string day)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM org_stats_history WHERE org_id = @orgId AND day = @day",
            new { orgId, day });
    }

    [Fact]
    public async Task UpsertAsync_TwoWritesSameDay_OneRow_SecondWins()
    {
        var repo = Build();

        await repo.UpsertAsync("o1", "2026-06-15", """{"totalVulnerabilities":1,"blockedPulls30d":2,"totalDownloads30d":3}""", "2026-06-15T08:00:00Z");
        await repo.UpsertAsync("o1", "2026-06-15", """{"totalVulnerabilities":9,"blockedPulls30d":8,"totalDownloads30d":7}""", "2026-06-15T20:00:00Z");

        Assert.Equal(1, await CountRowsAsync("o1", "2026-06-15"));

        var recent = await repo.GetRecentAsync("o1", 30);
        var row = Assert.Single(recent);
        Assert.Equal("2026-06-15", row.Day);
        Assert.Contains("\"totalVulnerabilities\":9", row.TrendJson);
    }

    [Fact]
    public async Task GetRecentAsync_ReturnsRowsOldestFirst_LimitedToRequestedDays()
    {
        var repo = Build();
        await repo.UpsertAsync("o1", "2026-06-13", """{"totalVulnerabilities":1,"blockedPulls30d":0,"totalDownloads30d":0}""", "2026-06-13T00:00:00Z");
        await repo.UpsertAsync("o1", "2026-06-14", """{"totalVulnerabilities":2,"blockedPulls30d":0,"totalDownloads30d":0}""", "2026-06-14T00:00:00Z");
        await repo.UpsertAsync("o1", "2026-06-15", """{"totalVulnerabilities":3,"blockedPulls30d":0,"totalDownloads30d":0}""", "2026-06-15T00:00:00Z");

        var recent = await repo.GetRecentAsync("o1", 2);

        Assert.Equal(2, recent.Count);
        Assert.Equal("2026-06-14", recent[0].Day);
        Assert.Equal("2026-06-15", recent[1].Day);
    }

    [Fact]
    public async Task GetRecentAsync_AnotherOrgsHistory_NeverReturned()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'globex')");
        }

        var repo = Build();
        await repo.UpsertAsync("o1", "2026-06-15", """{"totalVulnerabilities":1,"blockedPulls30d":0,"totalDownloads30d":0}""", "2026-06-15T00:00:00Z");
        await repo.UpsertAsync("o2", "2026-06-15", """{"totalVulnerabilities":99,"blockedPulls30d":0,"totalDownloads30d":0}""", "2026-06-15T00:00:00Z");

        var recent = await repo.GetRecentAsync("o1", 30);

        var row = Assert.Single(recent);
        Assert.DoesNotContain("99", row.TrendJson);
    }
}
