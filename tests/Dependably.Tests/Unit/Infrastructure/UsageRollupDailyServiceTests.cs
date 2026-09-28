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
/// <see cref="UsageRollupDailyService"/> re-derives usage_hourly for its own two-day span before
/// deriving usage_daily, so a correct daily bucket never depends on the hourly job having run.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageRollupDailyServiceTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 0, 40, 0, TimeSpan.Zero);
    private static readonly DateOnly Today = new(2026, 9, 24);
    private static readonly DateOnly Yesterday = new(2026, 9, 23);

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen(Now);
    private UsageRollupRepository _rollups = null!;
    private UsageEventRepository _events = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        _rollups = new UsageRollupRepository(_db);
        _events = new UsageEventRepository(_db);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private UsageRollupDailyService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        return new UsageRollupDailyService(
            _rollups, cfg, new AirGapMode(cfg),
            NullLogger<UsageRollupDailyService>.Instance, _clock,
            new InProcessDistributedLock(_clock));
    }

    [Fact]
    public async Task Produces_correct_usage_daily_even_when_the_hourly_job_never_ran()
    {
        // No usage_hourly rows exist at all — only raw events for yesterday and today.
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 100, "npm", null,
                new DateTimeOffset(2026, 9, 23, 10, 0, 0, TimeSpan.Zero)),
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 25, "npm", null,
                new DateTimeOffset(2026, 9, 24, 0, 10, 0, TimeSpan.Zero)),
        ]);

        await using (var conn = await _db.OpenAsync())
        {
            Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM usage_hourly"));
        }

        await Build().RunPassAsync(CancellationToken.None);

        var daily = await _rollups.GetDailyAsync("o1", Yesterday, Today.AddDays(1));
        Assert.Equal(2, daily.Count);
        Assert.Contains(daily, r => r.Bucket == "2026-09-23" && r.Quantity == 100);
        Assert.Contains(daily, r => r.Bucket == "2026-09-24" && r.Quantity == 25);
    }

    [Fact]
    public async Task Recomputes_both_yesterday_and_today()
    {
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 10, "npm", null,
                new DateTimeOffset(2026, 9, 22, 10, 0, 0, TimeSpan.Zero)), // day before yesterday — out of window
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 20, "npm", null,
                new DateTimeOffset(2026, 9, 23, 10, 0, 0, TimeSpan.Zero)),
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 5, "npm", null,
                new DateTimeOffset(2026, 9, 24, 0, 5, 0, TimeSpan.Zero)),
        ]);

        await Build().RunPassAsync(CancellationToken.None);

        var daily = await _rollups.GetDailyAsync("o1", new DateOnly(2026, 9, 1), Today.AddDays(1));
        Assert.DoesNotContain(daily, r => r.Bucket == "2026-09-22");
        Assert.Contains(daily, r => r.Bucket == "2026-09-23" && r.Quantity == 20);
        Assert.Contains(daily, r => r.Bucket == "2026-09-24" && r.Quantity == 5);
    }

    [Fact]
    public async Task Recomputing_twice_is_idempotent()
    {
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 50, "npm", null,
                new DateTimeOffset(2026, 9, 23, 10, 0, 0, TimeSpan.Zero)),
        ]);

        await Build().RunPassAsync(CancellationToken.None);
        var first = await _rollups.GetDailyAsync("o1", Yesterday, Today.AddDays(1));
        await Build().RunPassAsync(CancellationToken.None);
        var second = await _rollups.GetDailyAsync("o1", Yesterday, Today.AddDays(1));

        Assert.Equal(first.Select(r => (r.Bucket, r.Quantity)), second.Select(r => (r.Bucket, r.Quantity)));
    }

    [Fact]
    public async Task Disabled_via_DISABLE_BACKGROUND_JOBS_writes_nothing()
    {
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 50, "npm", null,
                new DateTimeOffset(2026, 9, 23, 10, 0, 0, TimeSpan.Zero)),
        ]);

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DISABLE_BACKGROUND_JOBS"] = UsageRollupDailyService.JobName,
            })
            .Build();
        var svc = new UsageRollupDailyService(
            _rollups, cfg, new AirGapMode(cfg),
            NullLogger<UsageRollupDailyService>.Instance, _clock,
            new InProcessDistributedLock(_clock));

        await svc.RunPassAsync(CancellationToken.None);

        Assert.Empty(await _rollups.GetDailyAsync("o1", Yesterday, Today.AddDays(1)));
    }
}
