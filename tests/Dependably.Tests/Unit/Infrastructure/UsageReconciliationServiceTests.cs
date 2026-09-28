using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Usage;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="UsageReconciliationService"/>'s weekly integrity check: usage_daily egress and
/// request counts must match a fresh recompute from usage_events within 2%, and every (org, meter, day) row on either
/// side must exist on the other.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageReconciliationServiceTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 29, 2, 0, 0, TimeSpan.Zero); // a Monday
    private static readonly DateOnly ADayInWindow = new(2026, 9, 24);

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

    private UsageReconciliationService Build(string? disableJobs = null)
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DISABLE_BACKGROUND_JOBS"] = disableJobs })
            .Build();
        var blobs = new InMemoryBlobStore(_clock);
        var storedBytes = new StoredByteReconciler(
            new TieredBlobStorage(blobs, blobs), new StoredBytesRepository(_db));
        return new UsageReconciliationService(
            _rollups, storedBytes, cfg, new AirGapMode(cfg),
            NullLogger<UsageReconciliationService>.Instance, _clock,
            new InProcessDistributedLock(_clock));
    }

    private async Task SeedConsistentDayAsync(long quantity)
    {
        var at = UsageRollupRepository.UtcMidnight(ADayInWindow);
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, quantity, "npm", null, at),
        ]);
        await _rollups.RecomputeHourlyAsync(at, at.AddHours(1), Now);
        await _rollups.RecomputeDailyEgressAsync(ADayInWindow, ADayInWindow.AddDays(1), Now);
    }

    [Fact]
    public async Task Passes_on_consistent_data()
    {
        await SeedConsistentDayAsync(1000);

        Assert.Null(await Record.ExceptionAsync(() => Build().RunReconciliationPassAsync(CancellationToken.None)));
    }

    [Fact]
    public async Task Throws_when_a_usage_daily_row_is_tampered_beyond_tolerance()
    {
        await SeedConsistentDayAsync(1000);

        // Tamper usage_daily so it disagrees with the events sum by more than 2%.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE usage_daily SET quantity = 500 WHERE org_id = 'o1' AND bucket = @bucket",
                new { bucket = "2026-09-24" });
        }

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build().RunReconciliationPassAsync(CancellationToken.None));
        Assert.Contains("mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Tolerates_a_mismatch_within_two_percent()
    {
        await SeedConsistentDayAsync(1000);

        // 1% off — within tolerance.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE usage_daily SET quantity = 1010 WHERE org_id = 'o1' AND bucket = @bucket",
                new { bucket = "2026-09-24" });
        }

        Assert.Null(await Record.ExceptionAsync(() => Build().RunReconciliationPassAsync(CancellationToken.None)));
    }

    [Fact]
    public async Task Throws_when_the_stored_request_count_drifts_beyond_tolerance()
    {
        await SeedConsistentDayAsync(1000);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE usage_daily SET request_count = 3 WHERE org_id = 'o1' AND bucket = @bucket",
                new { bucket = "2026-09-24" });
        }

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build().RunReconciliationPassAsync(CancellationToken.None));
        Assert.Contains("request_count mismatch", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A bucket rolled up before the rollups counted requests holds the column default, 0. Every
    /// bucket a rollup writes now holds at least one event, so 0 marks the row as older than the
    /// count, and the first week after an upgrade must not fail on history nobody can backfill.
    /// </summary>
    [Fact]
    public async Task A_row_rolled_up_before_request_counts_existed_is_not_compared_on_count()
    {
        await SeedConsistentDayAsync(1000);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE usage_daily SET request_count = 0 WHERE org_id = 'o1' AND bucket = @bucket",
                new { bucket = "2026-09-24" });
        }

        Assert.Null(await Record.ExceptionAsync(() => Build().RunReconciliationPassAsync(CancellationToken.None)));
    }

    [Fact]
    public async Task A_row_older_than_the_count_is_still_compared_on_quantity()
    {
        await SeedConsistentDayAsync(1000);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE usage_daily SET request_count = 0, quantity = 500 WHERE org_id = 'o1' AND bucket = @bucket",
                new { bucket = "2026-09-24" });
        }

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build().RunReconciliationPassAsync(CancellationToken.None));
        Assert.Contains("quantity mismatch", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("request_count", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_mixed_window_reports_only_the_rows_whose_count_drifted()
    {
        static UsageDailyRow Row(string org, long quantity, long count) => new()
        {
            OrgId = org,
            Meter = UsageMeters.EgressBytes,
            Bucket = "2026-09-24",
            Quantity = quantity,
            RequestCount = count,
        };

        var stored = new[] { Row("clean", 100, 10), Row("legacy", 100, 0), Row("drifted", 100, 20) };
        var recomputed = new[] { Row("clean", 100, 10), Row("legacy", 100, 10), Row("drifted", 100, 10) };

        var violations = UsageReconciliationService.FindMismatches(stored, recomputed);

        string violation = Assert.Single(violations);
        Assert.StartsWith("drifted/", violation, StringComparison.Ordinal);
        Assert.Contains("request_count mismatch", violation, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Throws_when_usage_daily_is_missing_a_row_events_have()
    {
        await SeedConsistentDayAsync(1000);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM usage_daily WHERE org_id = 'o1' AND bucket = @bucket",
                new { bucket = "2026-09-24" });
        }

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build().RunReconciliationPassAsync(CancellationToken.None));
        Assert.Contains("missing", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Throws_when_events_are_missing_a_row_usage_daily_has()
    {
        await SeedConsistentDayAsync(1000);

        // usage_daily still has the row, but the underlying events were pruned out from under it.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM usage_events WHERE org_id = 'o1'");
        }

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build().RunReconciliationPassAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Todays_still_accumulating_bucket_is_excluded_from_the_window()
    {
        // An event for "today" (the day the job runs) with no usage_daily row at all must not be
        // treated as a missing-row violation — today is still accumulating.
        await _events.InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 999, "npm", null, Now),
        ]);

        Assert.Null(await Record.ExceptionAsync(() => Build().RunReconciliationPassAsync(CancellationToken.None)));
    }

    [Fact]
    public async Task Disabled_via_DISABLE_BACKGROUND_JOBS_skips_the_check_entirely()
    {
        await SeedConsistentDayAsync(1000);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE usage_daily SET quantity = 1 WHERE org_id = 'o1' AND bucket = @bucket",
                new { bucket = "2026-09-24" });
        }

        // Would throw if the check ran; disabled, it must not.
        Assert.Null(await Record.ExceptionAsync(
            () => Build(disableJobs: UsageReconciliationService.JobName).RunReconciliationPassAsync(CancellationToken.None)));
    }
}
