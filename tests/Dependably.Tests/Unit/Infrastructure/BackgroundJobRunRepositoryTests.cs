using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class BackgroundJobRunRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly BackgroundJobRunRepository _repo;

    public BackgroundJobRunRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new BackgroundJobRunRepository(_fixture.Store);
    }

    private async Task<string> SeedAsync(
        string jobName = "cache-eviction",
        string operation = "tick",
        string outcome = "success",
        string? errorMessage = null,
        DateTimeOffset? startedAt = null,
        long durationMs = 42)
    {
        string id = Guid.NewGuid().ToString("N");
        var start = startedAt ?? TestTime.KnownNow;
        await _repo.RecordAsync(new BackgroundJobRunRecord(
            Id: id, JobName: jobName, Operation: operation, RunId: Guid.NewGuid().ToString("N"),
            StartedAt: start, FinishedAt: start.AddMilliseconds(durationMs),
            DurationMs: durationMs, Outcome: outcome, ErrorMessage: errorMessage));
        return id;
    }

    [Fact]
    public async Task RecordAsync_PersistsAllColumns()
    {
        var started = TestTime.KnownNow.AddSeconds(-5);
        string id = await SeedAsync(
            jobName: "vuln-scan", operation: "scheduled",
            outcome: "server_error", errorMessage: "OSV 500",
            startedAt: started, durationMs: 1234);

        var (items, _) = await _repo.ListAsync(new BackgroundJobRunQuery(
            JobName: "vuln-scan", Limit: 50, Offset: 0));

        var row = Assert.Single(items, r => r.Id == id);
        Assert.Equal("vuln-scan", row.JobName);
        Assert.Equal("scheduled", row.Operation);
        Assert.Equal("server_error", row.Outcome);
        Assert.Equal("OSV 500", row.ErrorMessage);
        Assert.Equal(1234, row.DurationMs);
    }

    [Fact]
    public async Task ListAsync_FiltersByJobNameAndOutcome()
    {
        await SeedAsync(jobName: "cache-eviction", outcome: "success");
        await SeedAsync(jobName: "cache-eviction", outcome: "server_error");
        await SeedAsync(jobName: "retention", outcome: "success");

        var (cacheErrors, _) = await _repo.ListAsync(new BackgroundJobRunQuery(
            JobName: "cache-eviction", Outcome: "server_error", Limit: 50, Offset: 0));

        Assert.Single(cacheErrors);
        Assert.Equal("cache-eviction", cacheErrors[0].JobName);
        Assert.Equal("server_error", cacheErrors[0].Outcome);
    }

    [Fact]
    public async Task ListAsync_SearchMatchesErrorMessage_CaseInsensitive()
    {
        await SeedAsync(jobName: "retention", outcome: "server_error", errorMessage: "Timeout reaching upstream");
        await SeedAsync(jobName: "retention", outcome: "success", errorMessage: null);

        var (items, _) = await _repo.ListAsync(new BackgroundJobRunQuery(
            Search: "TIMEOUT", Limit: 50, Offset: 0));

        Assert.Single(items);
        Assert.Contains("Timeout", items[0].ErrorMessage);
    }

    [Fact]
    public async Task ListAsync_SortByDurationDesc_PutsLongestFirst()
    {
        var t = TestTime.KnownNow.AddMinutes(-1);
        await SeedAsync(jobName: "sort-a", startedAt: t, durationMs: 100);
        await SeedAsync(jobName: "sort-a", startedAt: t.AddSeconds(1), durationMs: 9000);
        await SeedAsync(jobName: "sort-a", startedAt: t.AddSeconds(2), durationMs: 2500);

        var (items, _) = await _repo.ListAsync(new BackgroundJobRunQuery(
            JobName: "sort-a", SortBy: "durationMs", SortDir: "desc", Limit: 50, Offset: 0));

        Assert.Equal(new long[] { 9000, 2500, 100 }, items.Select(r => r.DurationMs).ToArray());
    }

    [Fact]
    public async Task ListAsync_UnknownSortBy_FallsBackToStartedAt()
    {
        // Whitelist guard: bad input must not blow up the SQL.
        await SeedAsync(jobName: "fallback-sort");
        var (items, _) = await _repo.ListAsync(new BackgroundJobRunQuery(
            JobName: "fallback-sort",
            SortBy: "; DROP TABLE background_job_runs --", SortDir: "asc",
            Limit: 50, Offset: 0));
        Assert.NotEmpty(items);
    }

    [Fact]
    public async Task ListDistinctJobNamesAsync_ReturnsUniqueAlphabetical()
    {
        await SeedAsync(jobName: "zulu-job");
        await SeedAsync(jobName: "alpha-job");
        await SeedAsync(jobName: "alpha-job"); // dupe

        var names = await _repo.ListDistinctJobNamesAsync();
        Assert.Contains("alpha-job", names);
        Assert.Contains("zulu-job", names);
        // Sorted ascending; each name appears once.
        var ours = names.Where(n => n is "alpha-job" or "zulu-job").ToList();
        Assert.Equal(new[] { "alpha-job", "zulu-job" }, ours);
    }
}
