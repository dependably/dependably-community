using System.Collections.Concurrent;
using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// The numeric-column widening migration bounds how long each table's ALTER waits for its lock, so
/// an ALTER queued behind a long-running query cannot stall every later query on that table. Pins
/// the retry on lock_not_available, the loud failure once the budget is spent, that the bound
/// applies to lock acquisition and never to the rewrite, and that no other failure is retried.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresNumericColumnWideningLockTests
{
    private const string WidenMigration = "widen_postgres_numeric_columns";
    private const int SeededBlobs = 50_000;

    // Upper bound on the schema apply reaching the widen step on a loaded machine, and on the
    // first lock-retry warning once the widen holds its blocker (lock_timeout is 2 s there).
    private static readonly TimeSpan ApplyBound = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RetryBound = TimeSpan.FromSeconds(30);

    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests.");

    [Fact]
    public async Task BlockedTable_RetriesAfterLockTimeout_AndSucceedsOnceBlockerReleases()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await ReshapeToPreWidenAsync(pg.Store);
        using var blocker = new AccessShareBlocker(ConnectionString);

        var log = new LockRetryLog(blocker);
        var init = new SchemaInitializer(pg.Store, log)
        {
            WidenLockRetry = new SchemaInitializer.LockRetryPolicy(TimeSpan.FromSeconds(2), [TimeSpan.Zero]),
        };
        var apply = init.InitializeAsync();

        // The schema apply before the widen scales with the machine's load, so the retry is awaited
        // from the moment the widen starts (the blocker is taken then), never from the start of the
        // apply. Each wait is bounded so a regression fails rather than hanging the suite.
        var started = await Task.WhenAny(log.WidenStarted.Task, apply, Task.Delay(ApplyBound, TimeProvider.System));
        Assert.True(started == log.WidenStarted.Task, "The widening migration was never reached.");

        // Without the lock bound the ALTER waits on the blocker indefinitely and never logs a retry.
        var first = await Task.WhenAny(log.FirstRetry.Task, apply, Task.Delay(RetryBound, TimeProvider.System));
        Assert.True(first == log.FirstRetry.Task, "No lock-retry warning was logged while oci_blobs was blocked.");

        blocker.Release();
        await apply;

        await using var conn = await pg.Store.OpenAsync();
        Assert.Equal("bigint", await ColumnTypeAsync(conn, "oci_blobs", "size_bytes"));
        Assert.True(await IsLedgeredAsync(conn, WidenMigration));
        Assert.Equal(1L, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM information_schema.views WHERE table_schema = current_schema() AND table_name = 'org_storage_bytes'"));
        Assert.Equal(1, log.RetryWarnings);
        Assert.Equal(0, log.Errors);

        // The migration after the widen runs on the same connection, so reaching its ledger row
        // proves the lock_timeout reset did not fail and startup carried on past the widen.
        Assert.True(await IsLedgeredAsync(conn, "backfill_upstream_credential_history_from_audit"));
    }

    [Fact]
    public async Task BlockedTable_ExhaustsRetryBudget_FailsWithLockNotAvailable_AndLeavesMigrationUnledgered()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await ReshapeToPreWidenAsync(pg.Store);
        using var blocker = new AccessShareBlocker(ConnectionString);

        var log = new LockRetryLog(blocker);
        var init = new SchemaInitializer(pg.Store, log)
        {
            WidenLockRetry = new SchemaInitializer.LockRetryPolicy(
                TimeSpan.FromMilliseconds(250), [TimeSpan.Zero, TimeSpan.Zero]),
        };

        // An NpgsqlException/TimeoutException here instead would mean the client command timeout
        // fired rather than the lock bound. The outer bound turns an unbounded lock wait (the blocker
        // is never released) into a failure rather than a hung suite.
        var ex = await Assert.ThrowsAsync<PostgresException>(
            () => init.InitializeAsync().WaitAsync(TimeSpan.FromSeconds(60), TimeProvider.System));
        var elapsed = TimeProvider.System.GetElapsedTime(blocker.HeldSince);

        Assert.Equal(PostgresErrorCodes.LockNotAvailable, ex.SqlState);
        Assert.Equal(2, log.RetryWarnings);
        Assert.Equal(1, log.Errors);
        Assert.True(elapsed < TimeSpan.FromSeconds(5), $"The exhausted budget took {elapsed}, not the bounded retries.");

        // The migration gave up; the server did not cancel the blocking session.
        Assert.Equal(1, blocker.Probe());
        blocker.Release();

        await using var conn = await pg.Store.OpenAsync();
        Assert.Equal("integer", await ColumnTypeAsync(conn, "oci_blobs", "size_bytes"));
        Assert.False(await IsLedgeredAsync(conn, WidenMigration));
    }

    [Fact]
    public async Task Unblocked_TinyLockTimeout_StillCompletesRewrite()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await ReshapeToPreWidenAsync(pg.Store);

        var log = new LockRetryLog();
        var init = new SchemaInitializer(pg.Store, log)
        {
            WidenLockRetry = new SchemaInitializer.LockRetryPolicy(TimeSpan.FromMilliseconds(1), []),
        };
        await init.InitializeAsync();

        await using var conn = await pg.Store.OpenAsync();
        Assert.Equal("bigint", await ColumnTypeAsync(conn, "oci_blobs", "size_bytes"));
        Assert.Equal((long)SeededBlobs, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM oci_blobs"));
        Assert.True(await IsLedgeredAsync(conn, WidenMigration));
        Assert.Equal(0, log.RetryWarnings);
    }

    [Fact]
    public async Task NonLockFailure_PropagatesImmediately_WithoutRetry()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await ReshapeToPreWidenAsync(pg.Store);
        await using (var setup = await pg.Store.OpenAsync())
        {
            // Not one of the read-model views, so it survives the pre-migration drop and Postgres
            // refuses to retype the column it reads.
            await setup.ExecuteAsync("CREATE VIEW keep_me AS SELECT size_bytes FROM oci_blobs");
        }

        var log = new LockRetryLog();
        var init = new SchemaInitializer(pg.Store, log)
        {
            WidenLockRetry = new SchemaInitializer.LockRetryPolicy(
                TimeSpan.FromSeconds(2), [TimeSpan.Zero, TimeSpan.Zero]),
        };

        var ex = await Assert.ThrowsAsync<PostgresException>(() => init.InitializeAsync());

        Assert.Equal(PostgresErrorCodes.FeatureNotSupported, ex.SqlState);
        Assert.Equal(0, log.RetryWarnings);
        Assert.Equal(0, log.Errors);
        await using var conn = await pg.Store.OpenAsync();
        Assert.False(await IsLedgeredAsync(conn, WidenMigration));
    }

    // The reshape is one multi-statement command that rewrites the table and inserts the seed; the
    // client's 30 s default command timeout is not headroom a loaded machine can be promised.
    private const int SetupCommandTimeoutSeconds = 300;

    // Applies the current schema, then puts oci_blobs.size_bytes back to int4 with the migration
    // unledgered, and seeds enough rows that the rewrite is measurable.
    //
    // Autovacuum is switched off for oci_blobs before the seed. Inserting the rows crosses the
    // table's autovacuum and autoanalyze thresholds, so a worker can pick it up in the window
    // before the widening ALTER and hold SHARE UPDATE EXCLUSIVE, which conflicts with the ALTER's
    // ACCESS EXCLUSIVE. A worker only yields to a conflicting waiter after deadlock_timeout (1 s by
    // default), so a lock_timeout shorter than that fails against it rather than outwaiting it, and
    // the only lock holder each test intends is the one it takes itself.
    private static async Task ReshapeToPreWidenAsync(IMetadataStore store)
    {
        await new SchemaInitializer(store).InitializeAsync();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(new CommandDefinition(
            """
            ALTER TABLE oci_blobs SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
            DO $$
            DECLARE v record;
            BEGIN
              FOR v IN SELECT table_name FROM information_schema.views WHERE table_schema = current_schema() LOOP
                EXECUTE format('DROP VIEW IF EXISTS %I CASCADE', v.table_name);
              END LOOP;
            END $$;
            ALTER TABLE oci_blobs ALTER COLUMN size_bytes TYPE INTEGER;
            DELETE FROM _applied_migrations WHERE name = 'widen_postgres_numeric_columns';
            INSERT INTO orgs (id, slug) VALUES ('o1', 'acme');
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key)
                SELECT 'sha256:' || g, 'o1', 'application/octet-stream', g, 'k' || g
                FROM generate_series(1, @count) AS g;
            """,
            new { count = SeededBlobs },
            commandTimeout: SetupCommandTimeoutSeconds));
        Assert.Equal("integer", await ColumnTypeAsync(conn, "oci_blobs", "size_bytes"));
    }

    private static async Task<bool> IsLedgeredAsync(DbConnection conn, string name) =>
        await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = @name", new { name }) > 0;

    private static Task<string?> ColumnTypeAsync(DbConnection conn, string table, string column) =>
        conn.ExecuteScalarAsync<string?>(
            """
            SELECT data_type FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = @table AND column_name = @column
            """,
            new { table, column });

    // Counts the widening migration's lock-retry warnings and its give-up error, matched on the
    // message template rather than the rendered text.
    // Holds ACCESS SHARE on oci_blobs through an open transaction that has read it, which conflicts
    // with the ACCESS EXCLUSIVE lock the widening ALTER needs. Taken only once the widening
    // migration starts, so the schema apply that precedes it is not held up; synchronous because
    // it is taken from inside a logger callback.
    private sealed class AccessShareBlocker(string connectionString) : IDisposable
    {
        private NpgsqlConnection? _conn;

        public long HeldSince { get; private set; }

        public void Hold()
        {
            _conn = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false }.ToString());
            _conn.Open();
            _conn.Execute("BEGIN TRANSACTION");
            _conn.ExecuteScalar<int?>("SELECT 1 FROM oci_blobs LIMIT 1");
            HeldSince = TimeProvider.System.GetTimestamp();
        }

        public int Probe() => _conn!.ExecuteScalar<int>("SELECT 1");

        public void Release() => _conn?.Execute("COMMIT TRANSACTION");

        public void Dispose() => _conn?.Dispose();
    }

    private sealed class LockRetryLog(AccessShareBlocker? blocker = null) : ILogger<SchemaInitializer>
    {
        private readonly ConcurrentQueue<LogLevel> _entries = new();

        public TaskCompletionSource WidenStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource FirstRetry { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int RetryWarnings => _entries.Count(level => level == LogLevel.Warning);

        public int Errors => _entries.Count(level => level == LogLevel.Error);

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (state is not IReadOnlyList<KeyValuePair<string, object?>> properties)
            {
                return;
            }

            if (properties
                    .FirstOrDefault(p => string.Equals(p.Key, "{OriginalFormat}", StringComparison.Ordinal))
                    .Value is not string template)
            {
                return;
            }

            if (blocker is not null
                && template.Contains("applying", StringComparison.Ordinal)
                && properties.Any(p => p.Key == "Migration" && (p.Value as string) == WidenMigration))
            {
                blocker.Hold();
                WidenStarted.TrySetResult();
                return;
            }

            if (!template.Contains("could not lock table", StringComparison.Ordinal)
                || !template.Contains("attempt", StringComparison.Ordinal))
            {
                return;
            }

            _entries.Enqueue(logLevel);
            if (logLevel == LogLevel.Warning)
            {
                FirstRetry.TrySetResult();
            }
        }
    }
}
