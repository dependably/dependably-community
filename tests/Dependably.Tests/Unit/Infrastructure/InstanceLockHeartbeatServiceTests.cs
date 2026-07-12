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
/// Tests <see cref="InstanceLockHeartbeatService"/>: the refresh-once path advances the persisted
/// heartbeat, and graceful shutdown (<see cref="InstanceLockHeartbeatService.StopAsync"/>) releases
/// the lock row so an immediate restart need not wait out the staleness window.
/// </summary>
[Trait("Category", "Unit")]
public sealed class InstanceLockHeartbeatServiceTests : IAsyncLifetime
{
    private string _dbPath = "";
    private FileSqliteStore _db = null!;

    public async Task InitializeAsync()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"dependably_lockhb_{Guid.NewGuid():N}.db");
        _db = new FileSqliteStore(_dbPath);
        var schema = new SchemaInitializer(_db, NullLogger<SchemaInitializer>.Instance);
        await schema.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        foreach (string suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private InstanceLock NewLock(FakeTimeProvider clock)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["INSTANCE_LOCK_STALE_SECONDS"] = "90" })
            .Build();
        return new InstanceLock(_db, config, clock, NullLogger<InstanceLock>.Instance);
    }

    private async Task<int> RowCountAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM instance_lock");
    }

    [Fact]
    public async Task RefreshOnce_AdvancesHeartbeat()
    {
        var clock = TestTime.Frozen();
        var guard = NewLock(clock);
        await guard.TryAcquireAsync();

        await using var conn0 = await _db.OpenAsync();
        string? before = await conn0.ExecuteScalarAsync<string?>(
            "SELECT heartbeat_at FROM instance_lock WHERE id = 'primary'");

        var svc = new InstanceLockHeartbeatService(guard, clock, NullLogger<InstanceLockHeartbeatService>.Instance);
        clock.Advance(TimeSpan.FromSeconds(35));
        await svc.RefreshOnceAsync(CancellationToken.None);

        await using var conn1 = await _db.OpenAsync();
        string? after = await conn1.ExecuteScalarAsync<string?>(
            "SELECT heartbeat_at FROM instance_lock WHERE id = 'primary'");
        Assert.True(string.CompareOrdinal(after, before) > 0);
    }

    [Fact]
    public async Task StopAsync_ReleasesTheLockRow()
    {
        var clock = TestTime.Frozen();
        var guard = NewLock(clock);
        await guard.TryAcquireAsync();
        Assert.Equal(1, await RowCountAsync());

        var svc = new InstanceLockHeartbeatService(guard, clock, NullLogger<InstanceLockHeartbeatService>.Instance);
        await svc.StopAsync(CancellationToken.None);

        Assert.Equal(0, await RowCountAsync());
    }

    [Fact]
    public async Task StopAsync_StillReleases_WhenTheShutdownTokenIsAlreadyCancelled()
    {
        var clock = TestTime.Frozen();
        var guard = NewLock(clock);
        await guard.TryAcquireAsync();
        Assert.Equal(1, await RowCountAsync());

        // The host hands every remaining StopAsync an already-cancelled token once
        // SHUTDOWN_GRACE_PERIOD has elapsed. The release must not ride on that token: skipping the
        // DELETE here is what orphans the row and makes the replacement node wait out the staleness
        // window. Draining the refresh loop on a cancelled token may itself throw — the release still
        // has to happen.
        var svc = new InstanceLockHeartbeatService(guard, clock, NullLogger<InstanceLockHeartbeatService>.Instance);
        await svc.StartAsync(CancellationToken.None);

        try
        {
            await svc.StopAsync(new CancellationToken(canceled: true));
        }
        catch (OperationCanceledException)
        {
            // Expected when the loop has not yet observed the stop signal.
        }

        Assert.Equal(0, await RowCountAsync());
    }

    private sealed class FileSqliteStore : IMetadataStore, IAsyncDisposable
    {
        private readonly string _connectionString;
        public FileSqliteStore(string path) => _connectionString = $"Data Source={path}";
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
