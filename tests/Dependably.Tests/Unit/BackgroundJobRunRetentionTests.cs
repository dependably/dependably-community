using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins <see cref="RetentionService.PruneBackgroundJobRunsAsync"/>. Nothing else deletes from
/// <c>background_job_runs</c>, and its loudest writer is a 60-second timer, so the sweep is the
/// only bound on the table.
///
/// The load-bearing part is what it must NOT delete. <c>HealthService</c> reads two rows per job:
/// the latest run, and — when that run is <c>cancelled</c> — the latest success. Both survive any
/// age, or retention on an idle job would flip it to unknown. Each keep rule below is paired with
/// the delete that proves the rule is doing work rather than being masked by a window.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BackgroundJobRunRetentionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build(IConfiguration cfg)
    {
        var jwt = new JwtRevocationRepository(_db, time: _clock);
        var invites = new InviteRepository(_db, _clock);
        var samlConfig = new SamlConfigRepository(_db, _clock);
        var trusted = new TrustedDeviceService(_db, _clock, cfg);
        var blobs = new Dependably.Storage.InMemoryBlobStore();
        return new RetentionService(new RetentionService.Dependencies(
            _db, blobs, jwt, invites, samlConfig, trusted, cfg, new AirGapMode(cfg),
            NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(blobs, blobs),
                new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg),
            new OrgStatsHistoryRepository(_db),
            new BackgroundJobRunRepository(_db)));
    }

    private static IConfiguration Config(params (string Key, string Value)[] settings) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            settings.Select(s => new KeyValuePair<string, string?>(s.Key, s.Value))).Build();

    /// <summary>Seeds one run row aged <paramref name="daysAgo"/> before the frozen clock.</summary>
    private async Task SeedAsync(string id, string jobName, string outcome, int daysAgo)
    {
        string at = _clock.GetUtcNow().AddDays(-daysAgo).UtcDateTime.ToUtcIso();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO background_job_runs
                (id, job_name, operation, run_id, started_at, finished_at, duration_ms, outcome, error_message)
            VALUES (@id, @jobName, 'op', @id, @at, @at, 1, @outcome, NULL)
            """,
            new { id, jobName, at, outcome });
    }

    private async Task<List<string>> SurvivingIdsAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<string>(
            "SELECT id FROM background_job_runs ORDER BY id")).ToList();
    }

    /// <summary>
    /// The volume case: aged successes go. Seeded 30 days back against the 14-day default, with a
    /// newer success per job so the keep-latest rule is not what is being measured here.
    /// </summary>
    [Fact]
    public async Task Prune_DeletesSuccessesPastTheDefaultWindow()
    {
        await SeedAsync("old-1", "stats-refresh", "success", 30);
        await SeedAsync("old-2", "stats-refresh", "success", 20);
        await SeedAsync("recent", "stats-refresh", "success", 1);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["recent"], await SurvivingIdsAsync());
    }

    /// <summary>
    /// The twin of the above: a success INSIDE the window is untouched, so the delete above is the
    /// window doing work rather than the sweep emptying the table.
    /// </summary>
    [Fact]
    public async Task Prune_KeepsSuccessesInsideTheWindow()
    {
        await SeedAsync("day-13", "stats-refresh", "success", 13);
        await SeedAsync("newest", "stats-refresh", "success", 0);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["day-13", "newest"], await SurvivingIdsAsync());
    }

    /// <summary>
    /// Non-successes get the longer window: a failure 30 days old outlives a success of the same
    /// age, in one pass, which is the asymmetry the whole two-window design exists for.
    /// </summary>
    [Fact]
    public async Task Prune_KeepsFailuresThatOutliveSuccessesOfTheSameAge()
    {
        await SeedAsync("failure-30d", "cache-eviction", "failure", 30);
        await SeedAsync("success-30d", "cache-eviction", "success", 30);
        await SeedAsync("newest", "cache-eviction", "success", 0);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["failure-30d", "newest"], await SurvivingIdsAsync());
    }

    /// <summary>And past its own longer window, a failure goes too — the window is real, not infinite.</summary>
    [Fact]
    public async Task Prune_DeletesFailuresPastTheFailureWindow()
    {
        await SeedAsync("failure-120d", "cache-eviction", "failure", 120);
        await SeedAsync("newest", "cache-eviction", "success", 0);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["newest"], await SurvivingIdsAsync());
    }

    /// <summary>
    /// The keep-latest rule, isolated: a job whose ONLY row is far past every window keeps that
    /// row, because HealthService reads it to report the job's last outcome. This is the case the
    /// issue calls out as the one a naive age-only sweep gets wrong.
    /// </summary>
    [Fact]
    public async Task Prune_KeepsTheLatestRowPerJobEvenWhenPastEveryWindow()
    {
        await SeedAsync("only-row", "oci-blob-sweep", "success", 400);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["only-row"], await SurvivingIdsAsync());
    }

    /// <summary>
    /// The keep rule is per job, not global: an ancient job that has not run in a year keeps its
    /// one row even while a noisy job's rows of the same age are deleted around it.
    /// </summary>
    [Fact]
    public async Task Prune_KeepsTheLatestRowPerJobIndependently()
    {
        await SeedAsync("idle-job-row", "oci-blob-sweep", "success", 400);
        await SeedAsync("noisy-old", "stats-refresh", "success", 400);
        await SeedAsync("noisy-newest", "stats-refresh", "success", 0);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["idle-job-row", "noisy-newest"], await SurvivingIdsAsync());
    }

    /// <summary>
    /// The second protected row, and the adversarial twin the issue asks for. When the latest run
    /// is <c>cancelled</c> (graceful-shutdown disposal mid-tick) HealthService falls back to the
    /// latest success — so an aged success must survive when it is that fallback. Dropping the
    /// success half of the keep set makes this test red while every other test here stays green.
    /// </summary>
    [Fact]
    public async Task Prune_KeepsTheLatestSuccessBehindACancelledLatestRun()
    {
        await SeedAsync("stale-success", "cache-eviction", "success", 200);
        await SeedAsync("cancelled-latest", "cache-eviction", "cancelled", 1);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["cancelled-latest", "stale-success"], await SurvivingIdsAsync());
    }

    /// <summary>
    /// ...and that protection is exactly one row deep: an older success behind the kept one is
    /// still deleted, so the fallback rule cannot be read as "keep every success".
    /// </summary>
    [Fact]
    public async Task Prune_KeepsOnlyTheNewestSuccessBehindACancelledLatestRun()
    {
        await SeedAsync("older-success", "cache-eviction", "success", 300);
        await SeedAsync("newer-success", "cache-eviction", "success", 200);
        await SeedAsync("cancelled-latest", "cache-eviction", "cancelled", 1);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["cancelled-latest", "newer-success"], await SurvivingIdsAsync());
    }

    /// <summary>Both windows are operator-tunable; a shorter override deletes what the default keeps.</summary>
    [Fact]
    public async Task Prune_HonoursConfiguredWindows()
    {
        await SeedAsync("day-5-success", "stats-refresh", "success", 5);
        await SeedAsync("day-5-failure", "stats-refresh", "failure", 5);
        await SeedAsync("newest", "stats-refresh", "success", 0);

        await Build(Config(
            ("JOB_RUN_RETENTION_DAYS", "2"),
            ("JOB_RUN_FAILURE_RETENTION_DAYS", "3")))
            .PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["newest"], await SurvivingIdsAsync());
    }

    /// <summary>
    /// The batching loop terminates and drains a backlog larger than one chunk. Sized off the
    /// production constant rather than a copy of it, so the test follows if the constant moves.
    /// </summary>
    [Fact]
    public async Task Prune_DrainsABacklogLargerThanOneBatch()
    {
        int total = RetentionService.JobRunPruneBatchSize + 25;
        string at = _clock.GetUtcNow().AddDays(-60).UtcDateTime.ToUtcIso();
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO background_job_runs
                    (id, job_name, operation, run_id, started_at, finished_at, duration_ms, outcome, error_message)
                VALUES (@id, 'stats-refresh', 'op', @id, @at, @at, 1, 'success', NULL)
                """,
                Enumerable.Range(0, total).Select(i => new { id = $"row-{i:D6}", at }).ToArray());
        }
        await SeedAsync("newest", "stats-refresh", "success", 0);

        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Equal(["newest"], await SurvivingIdsAsync());
    }

    /// <summary>An empty table is a no-op, not a loop that never terminates.</summary>
    [Fact]
    public async Task Prune_OnAnEmptyTableIsANoOp()
    {
        await Build(Config()).PruneBackgroundJobRunsAsync(CancellationToken.None);

        Assert.Empty(await SurvivingIdsAsync());
    }
}
