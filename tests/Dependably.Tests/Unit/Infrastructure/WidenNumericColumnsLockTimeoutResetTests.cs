using System.Collections;
using System.Collections.Concurrent;
using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dependably.Infrastructure;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The numeric-column widening migration resets <c>lock_timeout</c> on its way out. On the failure
/// path a RESET that fails on a connection the ALTER already broke is logged and swallowed, so the
/// ALTER's own exception (which names the cause) is what surfaces; on the success path a failed
/// RESET propagates, because the same connection carries on to the remaining migrations.
/// </summary>
[Trait("Category", "Unit")]
public sealed class WidenNumericColumnsLockTimeoutResetTests
{
    [Fact]
    public async Task AlterFails_ThenResetFails_OriginalAlterExceptionSurfaces_AndResetFailureIsLogged()
    {
        var conn = new ScriptedConnection(
            alter: () => throw new PostgresException("canceling statement due to lock timeout", "ERROR", "ERROR", PostgresErrorCodes.LockNotAvailable),
            reset: () => throw new NpgsqlException("connection is broken"));
        var log = new CapturingLogger();
        var init = new SchemaInitializer(new PostgresProviderStore(), log)
        {
            WidenLockRetry = new SchemaInitializer.LockRetryPolicy(TimeSpan.FromMilliseconds(250), []),
        };

        var ex = await Assert.ThrowsAsync<PostgresException>(() => init.WidenPostgresNumericColumnsAsync(conn));

        Assert.Equal(PostgresErrorCodes.LockNotAvailable, ex.SqlState);
        Assert.Equal(1, conn.ResetAttempts);
        var warning = Assert.Single(log.Entries, e => e.Message.Contains("could not reset lock_timeout", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.IsType<NpgsqlException>(warning.Exception);
    }

    [Fact]
    public async Task AlterFails_ResetSucceeds_OriginalAlterExceptionSurfaces_WithoutResetWarning()
    {
        var conn = new ScriptedConnection(
            alter: () => throw new PostgresException("cannot alter type of a column used by a view", "ERROR", "ERROR", PostgresErrorCodes.FeatureNotSupported),
            reset: () => { });
        var log = new CapturingLogger();
        var init = new SchemaInitializer(new PostgresProviderStore(), log);

        var ex = await Assert.ThrowsAsync<PostgresException>(() => init.WidenPostgresNumericColumnsAsync(conn));

        Assert.Equal(PostgresErrorCodes.FeatureNotSupported, ex.SqlState);
        Assert.Equal(1, conn.ResetAttempts);
        Assert.DoesNotContain(log.Entries, e => e.Message.Contains("could not reset lock_timeout", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AlterSucceeds_ThenResetFails_ResetFailurePropagates()
    {
        var conn = new ScriptedConnection(
            alter: () => { },
            reset: () => throw new NpgsqlException("connection is broken"));
        var log = new CapturingLogger();
        var init = new SchemaInitializer(new PostgresProviderStore(), log);

        var ex = await Assert.ThrowsAsync<NpgsqlException>(() => init.WidenPostgresNumericColumnsAsync(conn));

        Assert.Equal("connection is broken", ex.Message);
        Assert.Equal(1, conn.ResetAttempts);
        Assert.True(conn.AlterAttempts > 0);
        Assert.DoesNotContain(log.Entries, e => e.Message.Contains("could not reset lock_timeout", StringComparison.Ordinal));
    }

    private sealed class PostgresProviderStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Postgres;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException("The widening migration runs on the connection it is handed.");
    }

    private sealed record LogEntry(LogLevel Level, string Message, Exception? Exception);

    private sealed class CapturingLogger : ILogger<SchemaInitializer>
    {
        private readonly ConcurrentQueue<LogEntry> _entries = new();

        public IReadOnlyCollection<LogEntry> Entries => _entries.ToArray();

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            _entries.Enqueue(new LogEntry(logLevel, formatter(state, exception), exception));
    }

    // Answers the widening migration's statements by shape: set_config succeeds, every column probe
    // reports the narrow type (so an ALTER is pending), and the ALTER and RESET run the scripted
    // outcomes.
    [SuppressMessage("Major Code Smell", "S3881", Justification = "Test double; nothing to dispose.")]
    private sealed class ScriptedConnection(Action alter, Action reset) : DbConnection
    {
        public int AlterAttempts { get; private set; }

        public int ResetAttempts { get; private set; }

        [AllowNull]
        public override string ConnectionString { get; set; } = string.Empty;

        public override string Database => "scripted";

        public override string DataSource => "scripted";

        public override string ServerVersion => "16.0";

        public override ConnectionState State => ConnectionState.Open;

        public override void ChangeDatabase(string databaseName) => throw new NotSupportedException();

        public override void Close()
        {
        }

        public override void Open()
        {
        }

        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) => throw new NotSupportedException();

        protected override DbCommand CreateDbCommand() => new ScriptedCommand(this);

        private object? Run(string sql)
        {
            if (sql.StartsWith("SELECT set_config", StringComparison.Ordinal))
            {
                return null;
            }

            if (sql.Contains("information_schema.columns", StringComparison.Ordinal))
            {
                return "integer";
            }

            if (sql.StartsWith("ALTER TABLE", StringComparison.Ordinal))
            {
                AlterAttempts++;
                alter();
                return null;
            }

            if (sql == "RESET lock_timeout")
            {
                ResetAttempts++;
                reset();
                return null;
            }

            throw new InvalidOperationException($"Unexpected statement: {sql}");
        }

        private sealed class ScriptedCommand(ScriptedConnection owner) : DbCommand
        {
            private readonly ScriptedParameterCollection _parameters = new();

            [AllowNull]
            public override string CommandText { get; set; } = string.Empty;

            public override int CommandTimeout { get; set; }

            public override CommandType CommandType { get; set; }

            public override bool DesignTimeVisible { get; set; }

            public override UpdateRowSource UpdatedRowSource { get; set; }

            protected override DbConnection? DbConnection { get; set; }

            protected override DbParameterCollection DbParameterCollection => _parameters;

            protected override DbTransaction? DbTransaction { get; set; }

            public override void Cancel()
            {
            }

            public override int ExecuteNonQuery()
            {
                owner.Run(CommandText);
                return 0;
            }

            public override object? ExecuteScalar() => owner.Run(CommandText);

            public override void Prepare()
            {
            }

            protected override DbParameter CreateDbParameter() => new ScriptedParameter();

            protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) => throw new NotSupportedException();
        }

        private sealed class ScriptedParameter : DbParameter
        {
            public override DbType DbType { get; set; }

            public override ParameterDirection Direction { get; set; }

            public override bool IsNullable { get; set; }

            [AllowNull]
            public override string ParameterName { get; set; } = string.Empty;

            public override int Size { get; set; }

            [AllowNull]
            public override string SourceColumn { get; set; } = string.Empty;

            public override bool SourceColumnNullMapping { get; set; }

            public override object? Value { get; set; }

            public override void ResetDbType()
            {
            }
        }

        private sealed class ScriptedParameterCollection : DbParameterCollection
        {
            private readonly List<DbParameter> _items = [];

            public override int Count => _items.Count;

            public override object SyncRoot => _items;

            public override int Add(object value)
            {
                _items.Add((DbParameter)value);
                return _items.Count - 1;
            }

            public override void AddRange(Array values)
            {
                foreach (object value in values)
                {
                    Add(value);
                }
            }

            public override void Clear() => _items.Clear();

            public override bool Contains(object value) => _items.Contains((DbParameter)value);

            public override bool Contains(string value) => IndexOf(value) >= 0;

            public override void CopyTo(Array array, int index) => ((ICollection)_items).CopyTo(array, index);

            public override IEnumerator GetEnumerator() => _items.GetEnumerator();

            public override int IndexOf(object value) => _items.IndexOf((DbParameter)value);

            public override int IndexOf(string parameterName) =>
                _items.FindIndex(p => string.Equals(p.ParameterName, parameterName, StringComparison.Ordinal));

            public override void Insert(int index, object value) => _items.Insert(index, (DbParameter)value);

            public override void Remove(object value) => _items.Remove((DbParameter)value);

            public override void RemoveAt(int index) => _items.RemoveAt(index);

            public override void RemoveAt(string parameterName) => _items.RemoveAt(IndexOf(parameterName));

            protected override DbParameter GetParameter(int index) => _items[index];

            protected override DbParameter GetParameter(string parameterName) => _items[IndexOf(parameterName)];

            protected override void SetParameter(int index, DbParameter value) => _items[index] = value;

            protected override void SetParameter(string parameterName, DbParameter value) => _items[IndexOf(parameterName)] = value;
        }
    }
}
