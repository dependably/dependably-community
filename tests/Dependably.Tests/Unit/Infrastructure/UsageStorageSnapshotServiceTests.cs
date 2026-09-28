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
/// <see cref="UsageStorageSnapshotService"/> captures today's storage every tick, backfills
/// yesterday only when it was never captured, and never lowers a day's already-recorded
/// usage_daily storage_bytes mark.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageStorageSnapshotServiceTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 0, 5, 0, TimeSpan.Zero);
    private static readonly DateOnly Today = new(2026, 9, 24);
    private static readonly DateOnly Yesterday = new(2026, 9, 23);

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen(Now);
    private StorageSnapshotRepository _snapshots = null!;
    private UsageRollupRepository _rollups = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('p1', 'o1', 'npm', 'pkg', 'pkg', 0)
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin)
            VALUES ('v1', 'p1', '1.0.0', 'pkg:npm/pkg@1.0.0', 'registry/v1', 1000, 'uploaded')
            """);
        _snapshots = new StorageSnapshotRepository(_db);
        _rollups = new UsageRollupRepository(_db);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private UsageStorageSnapshotService Build(string? disableJobs = null)
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DISABLE_BACKGROUND_JOBS"] = disableJobs })
            .Build();
        return new UsageStorageSnapshotService(
            _snapshots, cfg, new AirGapMode(cfg),
            NullLogger<UsageStorageSnapshotService>.Instance, _clock,
            new InProcessDistributedLock(_clock));
    }

    [Fact]
    public async Task Captures_todays_snapshot_and_raises_the_storage_mark()
    {
        await Build().RunPassAsync(CancellationToken.None);

        var snapshot = await _snapshots.GetAsync("o1", Today);
        Assert.NotNull(snapshot);
        Assert.Equal(1000L, snapshot.BillableBytes);

        var mark = Assert.Single(await _rollups.GetDailyAsync("o1", Today, Today.AddDays(1)));
        Assert.Equal(UsageMeters.StorageBytes, mark.Meter);
        Assert.Equal(1000L, mark.Quantity);
    }

    [Fact]
    public async Task Backfills_yesterday_when_it_has_no_snapshot_yet()
    {
        await Build().RunPassAsync(CancellationToken.None);

        var yesterdaySnapshot = await _snapshots.GetAsync("o1", Yesterday);
        Assert.NotNull(yesterdaySnapshot);

        var mark = Assert.Single(await _rollups.GetDailyAsync("o1", Yesterday, Yesterday.AddDays(1)));
        Assert.Equal(1000L, mark.Quantity);
    }

    [Fact]
    public async Task Does_not_recapture_yesterday_once_it_already_has_a_snapshot()
    {
        // Seed yesterday's snapshot directly, composed differently from today's current state —
        // if the job recaptured it, this value would be overwritten.
        await _snapshots.CaptureAsync(Yesterday, Now.AddDays(-1));
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE storage_snapshot SET billable_bytes = 42 WHERE org_id = 'o1' AND day_utc = @day",
                new { day = "2026-09-23" });
        }

        await Build().RunPassAsync(CancellationToken.None);

        var yesterdaySnapshot = await _snapshots.GetAsync("o1", Yesterday);
        Assert.NotNull(yesterdaySnapshot);
        Assert.Equal(42L, yesterdaySnapshot.BillableBytes);
    }

    [Fact]
    public async Task The_storage_mark_only_rises_across_repeated_captures()
    {
        await Build().RunPassAsync(CancellationToken.None);
        var firstMark = Assert.Single(await _rollups.GetDailyAsync("o1", Today, Today.AddDays(1)));
        Assert.Equal(1000L, firstMark.Quantity);

        // Storage shrinks between captures on the same day.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = 'v1'");
        }

        _clock.Advance(TimeSpan.FromHours(1));
        await Build().RunPassAsync(CancellationToken.None);

        var secondMark = Assert.Single(await _rollups.GetDailyAsync("o1", Today, Today.AddDays(1)));
        Assert.Equal(1000L, secondMark.Quantity);

        var snapshot = await _snapshots.GetAsync("o1", Today);
        Assert.NotNull(snapshot);
        Assert.Equal(0L, snapshot.BillableBytes);
    }

    [Fact]
    public async Task Disabled_via_DISABLE_BACKGROUND_JOBS_captures_nothing()
    {
        await Build(disableJobs: UsageStorageSnapshotService.JobName).RunPassAsync(CancellationToken.None);

        Assert.Null(await _snapshots.GetAsync("o1", Today));
        Assert.Null(await _snapshots.GetAsync("o1", Yesterday));
    }
}
