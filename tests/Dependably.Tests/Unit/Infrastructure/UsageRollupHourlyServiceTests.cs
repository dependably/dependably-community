using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="UsageRollupHourlyService"/>'s catch-up window: the pass recomputes from the last
/// successful run's watermark (minus a safety margin), bounded to the lookback floor, through now.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageRollupHourlyServiceTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen(Now);
    private UsageRollupRepository _rollups = null!;
    private BackgroundJobRunRepository _jobRuns = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        _rollups = new UsageRollupRepository(_db);
        _jobRuns = new BackgroundJobRunRepository(_db);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private UsageRollupHourlyService Build(string? disableJobs = null)
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DISABLE_BACKGROUND_JOBS"] = disableJobs,
            })
            .Build();
        return new UsageRollupHourlyService(
            _rollups, new UsagePostureRepository(_db, _clock), _jobRuns, cfg, new AirGapMode(cfg),
            NullLogger<UsageRollupHourlyService>.Instance, _clock,
            new InProcessDistributedLock(_clock));
    }

    private async Task InsertEventAsync(DateTimeOffset at, long quantity)
    {
        var events = new UsageEventRepository(_db);
        await events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, quantity, "npm", null, at),
        ]);
    }

    private async Task<List<string>> HourlyBucketsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<string>("SELECT bucket FROM usage_hourly ORDER BY bucket");
        return rows.ToList();
    }

    [Fact]
    public async Task First_ever_run_rolls_up_the_full_lookback_floor()
    {
        // An event from 3 days ago is well inside the 7-day lookback floor used when no prior
        // successful run exists.
        await InsertEventAsync(Now.AddDays(-3), 100);

        await Build().RunPassAsync(CancellationToken.None);

        var buckets = await HourlyBucketsAsync();
        Assert.Contains(buckets, b => b == Now.AddDays(-3).ToString("yyyy-MM-ddTHH:00:00Z"));
    }

    [Fact]
    public async Task Catches_up_from_the_last_successful_runs_watermark_minus_the_safety_margin()
    {
        // A prior successful run finished 5 hours ago. The pass should start its window at
        // (watermark - 2h safety margin) = 7 hours ago, not from the full 7-day floor.
        var watermark = Now.AddHours(-5);
        await _jobRuns.RecordAsync(new BackgroundJobRunRecord(
            Id: Guid.NewGuid().ToString("N"), JobName: UsageRollupHourlyService.JobName,
            Operation: "usage.rollup.hourly", RunId: Guid.NewGuid().ToString("N"),
            StartedAt: watermark, FinishedAt: watermark, DurationMs: 10,
            Outcome: "success", ErrorMessage: null));

        // Inside the expected window ([now-7h, now)).
        await InsertEventAsync(Now.AddHours(-6), 50);
        // Well outside the expected window and outside the 7-day floor's reach is not needed here —
        // an event 3 days back, before the resolved watermark, must NOT appear in the new rollup.
        await InsertEventAsync(Now.AddDays(-3), 999);

        await Build().RunPassAsync(CancellationToken.None);

        var buckets = await HourlyBucketsAsync();
        Assert.Contains(buckets, b => b == Now.AddHours(-6).ToString("yyyy-MM-ddTHH:00:00Z"));
        Assert.DoesNotContain(buckets, b => b == Now.AddDays(-3).ToString("yyyy-MM-ddTHH:00:00Z"));
    }

    [Fact]
    public async Task Recomputing_after_a_long_gap_is_bounded_to_the_lookback_floor()
    {
        // A prior success finished 30 days ago — far past MaxLookbackDays (7). The window must not
        // reach back 30 days; it is capped at the 7-day floor.
        var watermark = Now.AddDays(-30);
        await _jobRuns.RecordAsync(new BackgroundJobRunRecord(
            Id: Guid.NewGuid().ToString("N"), JobName: UsageRollupHourlyService.JobName,
            Operation: "usage.rollup.hourly", RunId: Guid.NewGuid().ToString("N"),
            StartedAt: watermark, FinishedAt: watermark, DurationMs: 10,
            Outcome: "success", ErrorMessage: null));

        await InsertEventAsync(Now.AddDays(-10), 999); // outside the 7-day floor
        await InsertEventAsync(Now.AddDays(-2), 42);    // inside the 7-day floor

        await Build().RunPassAsync(CancellationToken.None);

        var buckets = await HourlyBucketsAsync();
        Assert.DoesNotContain(buckets, b => b == Now.AddDays(-10).ToString("yyyy-MM-ddTHH:00:00Z"));
        Assert.Contains(buckets, b => b == Now.AddDays(-2).ToString("yyyy-MM-ddTHH:00:00Z"));
    }

    [Fact]
    public async Task The_pass_ends_by_recomputing_usage_posture_from_the_buckets_it_wrote()
    {
        var postures = new UsagePostureRepository(_db, _clock);
        await postures.SetCapsAsync("o1", new Dictionary<string, long?> { [UsageCapMeters.EgressBytes] = 100 });
        await InsertEventAsync(Now.AddMinutes(-20), 60);
        await InsertEventAsync(Now.AddMinutes(-10), 45);

        await Build().RunPassAsync(CancellationToken.None);

        // 105 of a 100-byte cap: over 100 %, under 110 %.
        Assert.Equal(UsagePostures.UploadsRefused, await postures.GetPostureAsync("o1"));
    }

    [Fact]
    public async Task A_disabled_pass_leaves_usage_posture_alone()
    {
        var postures = new UsagePostureRepository(_db, _clock);
        await postures.SetCapsAsync("o1", new Dictionary<string, long?> { [UsageCapMeters.EgressBytes] = 100 });
        await InsertEventAsync(Now.AddMinutes(-10), 500);

        await Build(disableJobs: UsageRollupHourlyService.JobName).RunPassAsync(CancellationToken.None);

        Assert.Equal(UsagePostures.Normal, await postures.GetPostureAsync("o1"));
    }

    [Fact]
    public async Task Disabled_via_DISABLE_BACKGROUND_JOBS_writes_nothing()
    {
        await InsertEventAsync(Now.AddMinutes(-5), 100);

        await Build(disableJobs: UsageRollupHourlyService.JobName).RunPassAsync(CancellationToken.None);

        Assert.Empty(await HourlyBucketsAsync());
    }

    [Fact]
    public async Task Edge_mode_force_disables_the_job()
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPLOYMENT_MODE"] = "edge" })
            .Build();
        var svc = new UsageRollupHourlyService(
            _rollups, new UsagePostureRepository(_db, _clock), _jobRuns, cfg, new AirGapMode(cfg),
            NullLogger<UsageRollupHourlyService>.Instance, _clock,
            new InProcessDistributedLock(_clock));

        await InsertEventAsync(Now.AddMinutes(-5), 100);
        await svc.RunPassAsync(CancellationToken.None);

        Assert.Empty(await HourlyBucketsAsync());
    }
}
