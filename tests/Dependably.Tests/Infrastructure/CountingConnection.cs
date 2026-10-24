using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Records the text of every command executed through it, in order, and forwards everything
/// to the real connection. The caller owns, opens, and disposes the inner connection. It wraps
/// the provider-neutral <see cref="DbConnection"/>, so the same counter observes a sweep on
/// SQLite and on Npgsql: a test asserts on the statements a code path issues rather than on how
/// long they took, which a contended runner cannot fail. Each transaction begun through it is
/// recorded as the statement index it began at, so a test can also bound what one transaction
/// spans.
/// </summary>
internal sealed class CountingConnection(DbConnection inner) : DbConnection
{
    private readonly List<string> _statements = [];
    private readonly List<int> _transactionStarts = [];
    private readonly List<int> _affectedRows = [];

    public IReadOnlyList<string> Statements => _statements;

    /// <summary>
    /// For each statement in <see cref="Statements"/>, the row count its non-query execution
    /// reported, or -1 for a statement that was not run as a non-query (or has not finished).
    /// </summary>
    public IReadOnlyList<int> AffectedRows => _affectedRows;

    /// <summary>
    /// For each transaction begun on this connection, in order, the index into
    /// <see cref="Statements"/> of the first statement issued after it began.
    /// </summary>
    public IReadOnlyList<int> TransactionStarts => _transactionStarts;

    [AllowNull]
    public override string ConnectionString
    {
        get => inner.ConnectionString;
        set => inner.ConnectionString = value;
    }

    public override string Database => inner.Database;
    public override string DataSource => inner.DataSource;
    public override string ServerVersion => inner.ServerVersion;
    public override ConnectionState State => inner.State;

    public override void ChangeDatabase(string databaseName) => inner.ChangeDatabase(databaseName);
    public override void Close() => inner.Close();
    public override void Open() => inner.Open();
    public override Task OpenAsync(CancellationToken cancellationToken) => inner.OpenAsync(cancellationToken);

    protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel)
    {
        _transactionStarts.Add(_statements.Count);
        return inner.BeginTransaction(isolationLevel);
    }

    protected override DbCommand CreateDbCommand() => new CountingCommand(inner.CreateCommand(), this);

    private int Record(string commandText)
    {
        _statements.Add(commandText);
        _affectedRows.Add(-1);
        return _statements.Count - 1;
    }

    private void RecordAffected(int index, int rows) => _affectedRows[index] = rows;

    private sealed class CountingCommand(DbCommand innerCommand, CountingConnection owner) : DbCommand
    {
        [AllowNull]
        public override string CommandText
        {
            get => innerCommand.CommandText;
            set => innerCommand.CommandText = value;
        }

        public override int CommandTimeout
        {
            get => innerCommand.CommandTimeout;
            set => innerCommand.CommandTimeout = value;
        }

        public override CommandType CommandType
        {
            get => innerCommand.CommandType;
            set => innerCommand.CommandType = value;
        }

        public override bool DesignTimeVisible
        {
            get => innerCommand.DesignTimeVisible;
            set => innerCommand.DesignTimeVisible = value;
        }

        public override UpdateRowSource UpdatedRowSource
        {
            get => innerCommand.UpdatedRowSource;
            set => innerCommand.UpdatedRowSource = value;
        }

        protected override DbConnection? DbConnection
        {
            get => owner;
            set { /* the inner command keeps its real connection */ }
        }

        protected override DbParameterCollection DbParameterCollection => innerCommand.Parameters;

        protected override DbTransaction? DbTransaction
        {
            get => innerCommand.Transaction;
            set => innerCommand.Transaction = value;
        }

        public override void Cancel() => innerCommand.Cancel();
        public override void Prepare() => innerCommand.Prepare();

        protected override DbParameter CreateDbParameter() => innerCommand.CreateParameter();

        public override int ExecuteNonQuery()
        {
            int index = owner.Record(CommandText);
            int rows = innerCommand.ExecuteNonQuery();
            owner.RecordAffected(index, rows);
            return rows;
        }

        public override object? ExecuteScalar()
        {
            owner.Record(CommandText);
            return innerCommand.ExecuteScalar();
        }

        protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior)
        {
            owner.Record(CommandText);
            return innerCommand.ExecuteReader(behavior);
        }

        public override async Task<int> ExecuteNonQueryAsync(CancellationToken cancellationToken)
        {
            int index = owner.Record(CommandText);
            int rows = await innerCommand.ExecuteNonQueryAsync(cancellationToken);
            owner.RecordAffected(index, rows);
            return rows;
        }

        public override Task<object?> ExecuteScalarAsync(CancellationToken cancellationToken)
        {
            owner.Record(CommandText);
            return innerCommand.ExecuteScalarAsync(cancellationToken);
        }

        protected override Task<DbDataReader> ExecuteDbDataReaderAsync(
            CommandBehavior behavior, CancellationToken cancellationToken)
        {
            owner.Record(CommandText);
            return innerCommand.ExecuteReaderAsync(behavior, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                innerCommand.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
