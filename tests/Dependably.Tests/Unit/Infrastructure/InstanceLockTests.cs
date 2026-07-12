using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Tests the shared-SQLite single-writer guard (<see cref="InstanceLock"/>). Uses a real
/// file-backed SQLite database — the guard deliberately self-skips in-memory stores, so an
/// on-disk file is required for the acquisition/heartbeat/release paths to run at all.
///
/// Every clock read is driven by a <see cref="FakeTimeProvider"/> so freshness/staleness and
/// heartbeat advancement are asserted at exact instants without real waits.
/// </summary>
[Trait("Category", "Unit")]
public sealed class InstanceLockTests : IAsyncLifetime
{
    private string _dbPath = "";
    private FileSqliteStore _db = null!;

    public async Task InitializeAsync()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"dependably_lock_{Guid.NewGuid():N}.db");
        _db = new FileSqliteStore(_dbPath);
        // Build the schema (creates instance_lock among everything else).
        var schema = new SchemaInitializer(_db, NullLogger<SchemaInitializer>.Instance);
        await schema.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        TryDeleteDbFiles(_dbPath);
    }

    private InstanceLock NewLock(FakeTimeProvider clock, int staleSeconds = 90)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["INSTANCE_LOCK_STALE_SECONDS"] = staleSeconds.ToString(),
            })
            .Build();
        return new InstanceLock(_db, config, clock, NullLogger<InstanceLock>.Instance);
    }

    private async Task<(string InstanceId, string HeartbeatAt)?> ReadRowAsync()
    {
        await using var conn = await _db.OpenAsync();
        var row = await conn.QuerySingleOrDefaultAsync<(string InstanceId, string HeartbeatAt)>(
            "SELECT instance_id AS InstanceId, heartbeat_at AS HeartbeatAt FROM instance_lock WHERE id = 'primary'");
        return row.InstanceId is null ? null : row;
    }

    // Simulates a foreign holder by inserting its lock row directly with a chosen heartbeat instant.
    private async Task SeedForeignHolderAsync(string instanceId, DateTimeOffset heartbeat)
    {
        await using var conn = await _db.OpenAsync();
        string iso = heartbeat.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(
            """
            INSERT INTO instance_lock (id, instance_id, hostname, heartbeat_at, acquired_at)
            VALUES ('primary', @instanceId, 'other-host', @hb, @hb)
            """,
            new { instanceId, hb = iso });
    }

    // Advances the foreign holder's heartbeat to a chosen instant — a live peer's refresh tick.
    private async Task BeatForeignHolderAsync(DateTimeOffset heartbeat)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE instance_lock SET heartbeat_at = @hb WHERE id = 'primary'",
            new { hb = heartbeat.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ") });
    }

    // Drives a pending acquisition that is waiting out a fresh foreign holder: steps the fake clock
    // forward (which fires the wait loop's poll timer) and optionally beats the foreign heartbeat in
    // between, since a beating holder is exactly what tells a live peer from an orphaned row. Gives
    // each step a moment of real time for the loop's continuation to read the row, and stops as soon
    // as the acquisition settles.
    private static async Task DriveAsync(
        Task acquisition,
        FakeTimeProvider clock,
        Func<Task>? beat = null,
        int maxSteps = 40)
    {
        for (int step = 0; step < maxSteps && !acquisition.IsCompleted; step++)
        {
            clock.Advance(TimeSpan.FromSeconds(5));
            if (beat is not null)
            {
                await beat();
            }

            for (int spin = 0; spin < 10 && !acquisition.IsCompleted; spin++)
            {
                await Task.Delay(2);
            }
        }
    }

    [Fact]
    public async Task Acquire_OnEmptyTable_ClaimsTheLock()
    {
        var clock = TestTime.Frozen();
        var guard = NewLock(clock);

        await guard.TryAcquireAsync();

        var row = await ReadRowAsync();
        Assert.NotNull(row);
        Assert.Equal(guard.InstanceId, row!.Value.InstanceId);
    }

    [Fact]
    public async Task Acquire_WhenForeignHeartbeatFreshAndBeating_ThrowsNamingTheLivePeer()
    {
        var clock = TestTime.Frozen();
        // Foreign heartbeat 30s ago, well inside the 90s window.
        await SeedForeignHolderAsync("foreign-instance-abc", clock.GetUtcNow().AddSeconds(-30));

        var guard = NewLock(clock, staleSeconds: 90);
        var acquisition = guard.TryAcquireAsync();

        // The holder keeps beating as the clock advances: it is live, and this node must refuse.
        await DriveAsync(acquisition, clock, beat: () => BeatForeignHolderAsync(clock.GetUtcNow()));

        Assert.True(acquisition.IsCompleted, "acquisition never settled while the peer was beating");
        var ex = await Assert.ThrowsAsync<InstanceLockHeldException>(() => acquisition);
        Assert.Contains("foreign-instance-abc", ex.Message, StringComparison.Ordinal);
        Assert.Contains("other-host", ex.Message, StringComparison.Ordinal);

        // The foreign row is untouched — the live peer keeps the lock.
        var row = await ReadRowAsync();
        Assert.Equal("foreign-instance-abc", row!.Value.InstanceId);
    }

    [Fact]
    public async Task Acquire_WhenForeignHeartbeatFreshButFrozen_WaitsOutTheWindowAndTakesOver()
    {
        var clock = TestTime.Frozen();
        // The redeploy case: the predecessor was SIGKILLed 10s ago, so its heartbeat is still well
        // inside the 90s window but nothing is beating it. Failing fast here is what crash-loops a
        // replacement container for the whole window.
        await SeedForeignHolderAsync("killed-predecessor", clock.GetUtcNow().AddSeconds(-10));

        var guard = NewLock(clock, staleSeconds: 90);
        var acquisition = guard.TryAcquireAsync();

        await DriveAsync(acquisition, clock);

        Assert.True(acquisition.IsCompleted, "acquisition never settled against a frozen heartbeat");
        await acquisition; // must not throw
        var row = await ReadRowAsync();
        Assert.Equal(guard.InstanceId, row!.Value.InstanceId);
    }

    [Fact]
    public async Task Acquire_WhenForeignHeartbeatStale_TakesOverTheLock()
    {
        var clock = TestTime.Frozen();
        // Foreign heartbeat 200s ago, past the 90s window → crashed predecessor.
        await SeedForeignHolderAsync("crashed-predecessor", clock.GetUtcNow().AddSeconds(-200));

        var guard = NewLock(clock, staleSeconds: 90);
        await guard.TryAcquireAsync();

        var row = await ReadRowAsync();
        Assert.Equal(guard.InstanceId, row!.Value.InstanceId);
    }

    [Fact]
    public async Task Acquire_ThenReleaseThenReacquire_SucceedsImmediately_ForSameProcessRestart()
    {
        var clock = TestTime.Frozen();

        // First boot of a process: claim.
        var first = NewLock(clock);
        await first.TryAcquireAsync();

        // Graceful shutdown releases the row.
        await first.ReleaseAsync();
        Assert.Null(await ReadRowAsync());

        // Immediate restart (a NEW InstanceId, fresh clock — no time advanced) claims without
        // having to wait out the staleness window, because the row was released.
        var second = NewLock(clock);
        await second.TryAcquireAsync();
        var row = await ReadRowAsync();
        Assert.Equal(second.InstanceId, row!.Value.InstanceId);
    }

    [Fact]
    public async Task Refresh_AdvancesHeartbeat_WithFakeClock()
    {
        var clock = TestTime.Frozen();
        var guard = NewLock(clock);
        await guard.TryAcquireAsync();

        string before = (await ReadRowAsync())!.Value.HeartbeatAt;

        // Advance the clock and refresh; the persisted heartbeat_at must move forward.
        clock.Advance(TimeSpan.FromSeconds(40));
        await guard.RefreshAsync();

        string after = (await ReadRowAsync())!.Value.HeartbeatAt;
        Assert.NotEqual(before, after);
        Assert.True(string.CompareOrdinal(after, before) > 0);
    }

    [Fact]
    public async Task Refresh_AfterTakeover_DoesNotResurrectOldHeartbeat()
    {
        var clock = TestTime.Frozen();

        // Original holder claims.
        var original = NewLock(clock);
        await original.TryAcquireAsync();

        // Time passes; a new instance takes over (staleness window elapsed).
        clock.Advance(TimeSpan.FromSeconds(200));
        var taker = NewLock(clock, staleSeconds: 90);
        await taker.TryAcquireAsync();
        Assert.Equal(taker.InstanceId, (await ReadRowAsync())!.Value.InstanceId);

        // The original tries to refresh — it must NOT overwrite the taker's ownership.
        await original.RefreshAsync();
        var row = await ReadRowAsync();
        Assert.Equal(taker.InstanceId, row!.Value.InstanceId);
    }

    [Fact]
    public async Task Release_OnlyDeletesRow_WhenStillOwnedByThisInstance()
    {
        var clock = TestTime.Frozen();

        var original = NewLock(clock);
        await original.TryAcquireAsync();

        clock.Advance(TimeSpan.FromSeconds(200));
        var taker = NewLock(clock, staleSeconds: 90);
        await taker.TryAcquireAsync();

        // The original's late release must not delete the taker's row.
        await original.ReleaseAsync();
        var row = await ReadRowAsync();
        Assert.NotNull(row);
        Assert.Equal(taker.InstanceId, row!.Value.InstanceId);

        // The taker's own release does clear it.
        await taker.ReleaseAsync();
        Assert.Null(await ReadRowAsync());
    }

    [Fact]
    public async Task Acquire_IsNoOp_ForInMemoryStore()
    {
        var clock = TestTime.Frozen();
        await using var memStore = new TestMetadataStore();
        var schema = new SchemaInitializer(memStore, NullLogger<SchemaInitializer>.Instance);
        await schema.InitializeAsync();

        var config = new ConfigurationBuilder().Build();
        var guard = new InstanceLock(memStore, config, clock, NullLogger<InstanceLock>.Instance);

        // Even with a fresh foreign holder seeded, an in-memory store is exempt: acquisition
        // neither throws nor writes a row.
        await using (var conn = await memStore.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO instance_lock (id, instance_id, hostname, heartbeat_at, acquired_at)
                VALUES ('primary', 'foreign', 'h', @hb, @hb)
                """,
                new { hb = clock.GetUtcNow().UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ") });
        }

        await guard.TryAcquireAsync(); // must not throw

        await using var readConn = await memStore.OpenAsync();
        string? holder = await readConn.ExecuteScalarAsync<string?>(
            "SELECT instance_id FROM instance_lock WHERE id = 'primary'");
        // Untouched — the guard did not take over an in-memory store.
        Assert.Equal("foreign", holder);
    }

    [Fact]
    public void RefreshInterval_IsAThirdOfTheStaleWindow_FlooredAtFiveSeconds()
    {
        var clock = TestTime.Frozen();
        Assert.Equal(TimeSpan.FromSeconds(30), NewLock(clock, staleSeconds: 90).RefreshInterval);
        // A very small window still floors the cadence at 5s.
        Assert.Equal(TimeSpan.FromSeconds(5), NewLock(clock, staleSeconds: 6).RefreshInterval);
    }

    [Fact]
    public void PollInterval_SamplesTheHeartbeatSeveralTimesPerRefreshCadence()
    {
        var clock = TestTime.Frozen();
        // 90s window → 30s heartbeat cadence → 5s polls: a live peer's beat is seen within one tick.
        Assert.Equal(TimeSpan.FromSeconds(5), NewLock(clock, staleSeconds: 90).PollInterval);
        // A very small window polls faster, floored at 1s.
        Assert.Equal(TimeSpan.FromSeconds(1), NewLock(clock, staleSeconds: 6).PollInterval);
    }

    private static void TryDeleteDbFiles(string path)
    {
        foreach (string suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(path + suffix); }
            catch (IOException) { /* best-effort cleanup */ }
        }
    }

    // A file-backed SQLite metadata store for these tests. The production SqliteMetadataStore is
    // internal to the DI wiring; this mirror opens the same file per connection so cross-connection
    // (and, in principle, cross-process) writes are visible — which the in-memory TestMetadataStore
    // cannot model.
    private sealed class FileSqliteStore : IMetadataStore, IAsyncDisposable
    {
        private readonly string _connectionString;

        public FileSqliteStore(string path) =>
            _connectionString = $"Data Source={path}";

        public DbProvider Provider => DbProvider.Sqlite;

        public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync(ct);
            await new SqliteCommand("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000", conn)
                .ExecuteNonQueryAsync(ct);
            return conn;
        }

        public ValueTask DisposeAsync()
        {
            SqliteConnection.ClearAllPools();
            return ValueTask.CompletedTask;
        }
    }
}
