using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using SQLitePCL;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The storage capture's aggregate scans every org-scoped growth table, so it must not hold
/// SQLite's single write lock while it does. These run against a real file-backed database in WAL
/// mode, the production journal, with a short busy timeout so a capture that waits on another
/// writer fails in a quarter of a second instead of five.
/// </summary>
[Trait("Category", "Unit")]
public sealed class StorageSnapshotCaptureLockTests : IAsyncLifetime
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 24, 10, 0, 0, TimeSpan.Zero);
    private static readonly DateOnly Day = new(2026, 9, 24);

    private string _dbPath = "";
    private FileSqliteStore _db = null!;
    private StorageSnapshotRepository _snapshots = null!;
    private UsageRollupRepository _rollups = null!;

    public async Task InitializeAsync()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"dependably_snapshot_{Guid.NewGuid():N}.db");
        _db = new FileSqliteStore(_dbPath);
        await new SchemaInitializer(_db, NullLogger<SchemaInitializer>.Instance).InitializeAsync();
        _snapshots = new StorageSnapshotRepository(_db);
        _rollups = new UsageRollupRepository(_db);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES ('ph', 'o1', 'npm', 'hosted-pkg', 'hosted-pkg', 0)");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin)
            VALUES ('v1', 'ph', '1.0.0', 'pkg:npm/hosted-pkg@1.0.0', 'registry/v1', 1000, 'uploaded')
            """);
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            try
            {
                File.Delete(_dbPath + suffix);
            }
            catch (IOException)
            {
                // A leftover temp file is harmless.
            }
        }
    }

    // Pins only that the aggregate statement needs no write lock. That CaptureAsync runs the
    // aggregate before opening its own write transaction is pinned by
    // Capture_computes_the_aggregate_before_opening_its_write_transaction.
    [Fact]
    public async Task Aggregate_runs_while_another_connection_holds_the_write_lock()
    {
        await using (var writer = new SqliteConnection($"Data Source={_dbPath}"))
        {
            await writer.OpenAsync();
            await using (var begin = new SqliteCommand("BEGIN IMMEDIATE", writer))
            {
                await begin.ExecuteNonQueryAsync();
            }

            await writer.ExecuteAsync(
                """
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin)
                VALUES ('v2', 'ph', '2.0.0', 'pkg:npm/hosted-pkg@2.0.0', 'registry/v2', 5000, 'uploaded')
                """);

            await using (var reader = await _db.OpenAsync())
            {
                var rows = await StorageSnapshotRepository.QueryAggregateAsync(
                    reader, UsageRollupRepository.DayLabel(Day), T0.ToUtcIso());

                var row = Assert.Single(rows);
                Assert.Equal("o1", row.OrgId);
                // The uncommitted 5000-byte version is invisible: the read used its own snapshot
                // and did not wait on the writer.
                Assert.Equal(1000L, row.BillableBytes);
                Assert.Equal(1L, row.HostedVersionCount);
            }

            await using var rollback = new SqliteCommand("ROLLBACK", writer);
            await rollback.ExecuteNonQueryAsync();
        }

        Assert.Equal(1, await _snapshots.CaptureAsync(Day, T0));

        var snapshot = await _snapshots.GetAsync("o1", Day);
        Assert.NotNull(snapshot);
        Assert.Equal(1000L, snapshot.BillableBytes);
        Assert.Equal(T0.ToUtcIso(), snapshot.CapturedAt);

        var marks = await _rollups.GetDailyAsync("o1", Day, Day.AddDays(1));
        Assert.Equal(2, marks.Count);
        var mark = Assert.Single(marks, r => r.Meter == UsageMeters.StorageBytes);
        Assert.Equal(1000L, mark.Quantity);
        Assert.Equal(0L, Assert.Single(marks, r => r.Meter == UsageMeters.CacheStorageBytes).Quantity);
    }

    [Fact]
    public async Task Capture_twice_on_a_file_store_is_idempotent()
    {
        Assert.Equal(1, await _snapshots.CaptureAsync(Day, T0));

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = 'v1'");
        }

        Assert.Equal(1, await _snapshots.CaptureAsync(Day, T0.AddHours(6)));

        await using (var conn = await _db.OpenAsync())
        {
            long rows = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM storage_snapshot WHERE org_id = 'o1' AND day_utc = @day",
                new { day = UsageRollupRepository.DayLabel(Day) });
            Assert.Equal(1L, rows);
        }

        var snapshot = await _snapshots.GetAsync("o1", Day);
        Assert.NotNull(snapshot);
        Assert.Equal(0L, snapshot.BillableBytes);
        Assert.Equal(0L, snapshot.HostedVersionCount);
        Assert.Equal(T0.AddHours(6).ToUtcIso(), snapshot.CapturedAt);

        var mark = Assert.Single(
            await _rollups.GetDailyAsync("o1", Day, Day.AddDays(1)),
            r => r.Meter == UsageMeters.StorageBytes);
        Assert.Equal(1000L, mark.Quantity);
    }

    [Fact]
    public async Task Capture_computes_the_aggregate_before_opening_its_write_transaction()
    {
        // Whether the capturing connection is in autocommit mode as each statement starts: true
        // means no transaction is open, so no write lock is held while that statement runs.
        var observed = new List<(string Statement, bool Autocommit)>();
        _db.OnStatement = (conn, sql) =>
        {
            string trimmed = sql.TrimStart();
            string? name = trimmed.StartsWith("SELECT o.id AS OrgId", StringComparison.Ordinal) ? "aggregate"
                : trimmed.StartsWith("INSERT INTO storage_snapshot", StringComparison.Ordinal) ? "upsert"
                : null;
            if (name is not null)
            {
                observed.Add((name, raw.sqlite3_get_autocommit(conn.Handle) != 0));
            }
        };

        Assert.Equal(1, await _snapshots.CaptureAsync(Day, T0));

        Assert.Equal(
            [("aggregate", true), ("upsert", false)],
            observed);
    }

    private sealed class FileSqliteStore : IMetadataStore, IAsyncDisposable
    {
        private readonly string _connectionString;

        public FileSqliteStore(string path) =>
            _connectionString = $"Data Source={path};Default Timeout=2";

        public DbProvider Provider => DbProvider.Sqlite;

        /// <summary>Called with each connection and statement text as SQLite starts the statement.</summary>
        public Action<SqliteConnection, string>? OnStatement { get; set; }

        public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync(ct);
            await new SqliteCommand("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 250", conn)
                .ExecuteNonQueryAsync(ct);
            raw.sqlite3_trace(
                conn.Handle,
                (_, statement) => OnStatement?.Invoke(conn, statement.utf8_to_string()),
                null);
            return conn;
        }

        public ValueTask DisposeAsync()
        {
            SqliteConnection.ClearAllPools();
            return ValueTask.CompletedTask;
        }
    }
}
