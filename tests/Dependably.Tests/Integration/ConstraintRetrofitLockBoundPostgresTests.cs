using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Compliance;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// The CHECK / foreign-key / canonical-timestamp retrofits run on every Postgres boot. Their
/// <c>ADD CONSTRAINT</c> needs an exclusive table lock and their <c>VALIDATE CONSTRAINT</c> scans the
/// table, so a session holding a conflicting lock (a long query on the previous release's slot during
/// a blue-green cutover) must delay neither serving nor startup. Each test holds such a lock from a
/// second connection and requires the retrofit to give up within its bound, log a warning, leave the
/// database bootable, and finish the job on a later run once the lock is gone.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class ConstraintRetrofitLockBoundPostgresTests
{
    private const string Table = "org_settings";
    private const string Constraint = "org_settings_verify_sbom_signatures_check";

    internal static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests.");

    private static SchemaInitializer.LockRetryPolicy TinyBudget { get; } =
        new(TimeSpan.FromMilliseconds(200), [TimeSpan.Zero, TimeSpan.Zero]);

    [Fact]
    public async Task ColumnConstraint_AddBlockedByConflictingLock_IsSkippedWithWarning_ThenAddedOnceFree()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();

        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync($"ALTER TABLE {Table} DROP CONSTRAINT {Constraint}");

        using (var blocker = new LockHolder(ConnectionString, $"SELECT 1 FROM {Table} LIMIT 1"))
        {
            long started = TimeProvider.System.GetTimestamp();
            await CompleteWithinAsync(init.RetrofitColumnConstraintsAsync(conn, schema), blocker, TimeSpan.FromSeconds(30));
            var elapsed = TimeProvider.System.GetElapsedTime(started);

            Assert.True(elapsed < TimeSpan.FromSeconds(15), $"The blocked retrofit took {elapsed}.");
            Assert.Null(await ValidatedAsync(conn, Constraint));
            Assert.Contains(log.Warnings, m => m.Contains(Table, StringComparison.Ordinal) && m.Contains("re-attempted on the next boot", StringComparison.Ordinal));
            Assert.Empty(log.Errors);
            Assert.Equal(1, blocker.Probe());
        }

        await new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget }.RetrofitColumnConstraintsAsync(conn, schema);
        Assert.True(await ValidatedAsync(conn, Constraint));
    }

    [Fact]
    public async Task ColumnConstraint_ValidateBlockedByConflictingLock_LeavesNotValid_AndDoesNotFailStartup()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();

        await using var conn = await pg.Store.OpenAsync();
        var declared = SchemaInitializer.DeclaredColumnConstraints(schema).Single(c => c.Name == Constraint);
        await conn.ExecuteAsync($"ALTER TABLE {Table} DROP CONSTRAINT {Constraint}");
        await conn.ExecuteAsync($"ALTER TABLE {Table} ADD CONSTRAINT {Constraint} {declared.Definition} NOT VALID");
        Assert.False(await ValidatedAsync(conn, Constraint));

        // SHARE conflicts with VALIDATE's SHARE UPDATE EXCLUSIVE but not with the catalogue read.
        using (var blocker = new LockHolder(ConnectionString, $"LOCK TABLE {Table} IN SHARE MODE"))
        {
            var ex = await Record.ExceptionAsync(
                () => CompleteWithinAsync(init.RetrofitColumnConstraintsAsync(conn, schema), blocker, TimeSpan.FromSeconds(30)));

            Assert.Null(ex);
            Assert.False(await ValidatedAsync(conn, Constraint));
            Assert.Contains(log.Warnings, m => m.Contains(Constraint, StringComparison.Ordinal) && m.Contains("NOT VALID", StringComparison.Ordinal));
        }

        await init.RetrofitColumnConstraintsAsync(conn, schema);
        Assert.True(await ValidatedAsync(conn, Constraint));
    }

    [Fact]
    public async Task TemporalCheck_AddBlockedByConflictingLock_IsSkippedWithWarning_ThenAddedOnceFree()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();

        var (table, column) = SchemaInitializer.DeclaredTemporalCheckColumns(schema).First();
        string name = table + "_" + column + "_check";
        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync($"ALTER TABLE {table} DROP CONSTRAINT {name}");

        using (var blocker = new LockHolder(ConnectionString, $"SELECT 1 FROM {table} LIMIT 1"))
        {
            var ex = await Record.ExceptionAsync(
                () => CompleteWithinAsync(init.RetrofitTemporalChecksAsync(conn, schema), blocker, TimeSpan.FromSeconds(30)));

            Assert.Null(ex);
            Assert.Null(await ValidatedAsync(conn, name));
            Assert.Contains(log.Warnings, m => m.Contains(table, StringComparison.Ordinal) && m.Contains("re-attempted on the next boot", StringComparison.Ordinal));
        }

        await init.RetrofitTemporalChecksAsync(conn, schema);
        Assert.True(await ValidatedAsync(conn, name));
    }

    private const string LegacyKey = "nuget_symbol_index_org_id_ssqp_key_pdb_filename_package_ver_key";

    [Fact]
    public async Task LegacySymbolKeyDrop_KeyAlreadyGone_DoesNotWaitOnAConflictingLock()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };
        await new SchemaInitializer(pg.Store).InitializeAsync();

        await using var conn = await pg.Store.OpenAsync();
        Assert.Equal(0, await LegacyKeyCountAsync(conn));

        // A plain reader's ACCESS SHARE conflicts with the ACCESS EXCLUSIVE that DROP CONSTRAINT
        // IF EXISTS takes before it looks for the constraint.
        using var blocker = new LockHolder(ConnectionString, "SELECT 1 FROM nuget_symbol_index LIMIT 1");
        var ex = await Record.ExceptionAsync(
            () => CompleteWithinAsync(init.DropLegacySymbolIndexUniqueKeyAsync(conn), blocker, TimeSpan.FromSeconds(30)));

        Assert.Null(ex);
        Assert.Empty(log.Warnings);
        Assert.Empty(log.Errors);
        Assert.Equal(1, blocker.Probe());
    }

    [Fact]
    public async Task LegacySymbolKeyDrop_KeyPresentAndTableLocked_IsDeferredWithWarning_ThenDroppedOnALaterBoot()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var log = new CapturingLogger();
        var init = new SchemaInitializer(pg.Store, log) { ConstraintLockRetry = TinyBudget };
        await new SchemaInitializer(pg.Store).InitializeAsync();

        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync(
            $"ALTER TABLE nuget_symbol_index ADD CONSTRAINT {LegacyKey} "
            + "UNIQUE (org_id, ssqp_key, pdb_filename, package_version_id)");
        Assert.Equal(1, await LegacyKeyCountAsync(conn));

        using (var blocker = new LockHolder(ConnectionString, "SELECT 1 FROM nuget_symbol_index LIMIT 1"))
        {
            var ex = await Record.ExceptionAsync(
                () => CompleteWithinAsync(init.DropLegacySymbolIndexUniqueKeyAsync(conn), blocker, TimeSpan.FromSeconds(30)));

            Assert.Null(ex);
            Assert.Equal(1, await LegacyKeyCountAsync(conn));
            Assert.Contains(log.Warnings, m => m.Contains("nuget_symbol_index", StringComparison.Ordinal) && m.Contains("re-attempted on the next boot", StringComparison.Ordinal));
            Assert.Empty(log.Errors);
        }

        await init.DropLegacySymbolIndexUniqueKeyAsync(conn);
        Assert.Equal(0, await LegacyKeyCountAsync(conn));
    }

    private static Task<long> LegacyKeyCountAsync(System.Data.Common.DbConnection conn) =>
        conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pg_constraint WHERE conname = @name",
            new { name = LegacyKey });

    // Fails the test when the retrofit is still waiting after the bound. The blocker is released
    // before failing so the abandoned statement can finish and the connection is left clean.
    internal static async Task CompleteWithinAsync(Task work, LockHolder blocker, TimeSpan bound)
    {
        var first = await Task.WhenAny(work, Task.Delay(bound, TimeProvider.System));
        if (first == work)
        {
            await work;
            return;
        }

        blocker.Dispose();
        await work;
        Assert.Fail($"The retrofit was still waiting on the conflicting lock after {bound}.");
    }

    internal static async Task<string> SchemaSqlAsync() =>
        await File.ReadAllTextAsync(SchemaTestPaths.PostgresSchema(SchemaTestPaths.SourceRoot()));

    internal static Task<bool?> ValidatedAsync(System.Data.Common.DbConnection conn, string name) =>
        conn.ExecuteScalarAsync<bool?>(
            """
            SELECT c.convalidated
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.conname = @name AND n.nspname = current_schema()
            """,
            new { name });

    // Runs a statement inside an open transaction on a second, unpooled connection and keeps the
    // transaction open, so whatever lock the statement took stays held until disposal.
    internal sealed class LockHolder : IDisposable
    {
        private readonly NpgsqlConnection _conn;
        private bool _disposed;

        public LockHolder(string connectionString, string sql)
        {
            _conn = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false }.ToString());
            _conn.Open();
            _conn.Execute("BEGIN TRANSACTION");
            _conn.Execute(sql);
        }

        public int Probe() => _conn.ExecuteScalar<int>("SELECT 1");

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _conn.Execute("COMMIT TRANSACTION");
            _conn.Dispose();
        }
    }

    internal sealed class CapturingLogger : ILogger<SchemaInitializer>
    {
        private readonly List<(LogLevel Level, string Message)> _records = [];

        public IEnumerable<string> Warnings => _records.Where(r => r.Level == LogLevel.Warning).Select(r => r.Message);

        public IEnumerable<string> Errors => _records.Where(r => r.Level == LogLevel.Error).Select(r => r.Message);

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_records)
            {
                _records.Add((logLevel, formatter(state, exception)));
            }
        }
    }
}
