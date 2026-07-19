using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test seam that fires a one-shot async hook in the window between a repository's DB read
/// returning and its subsequent cache write — the precise interleaving the fill-after-invalidate
/// race findings describe. The hook runs after a scalar read completes, and after a buffered
/// <c>QueryAsync</c> has fully materialized and closed its reader (so a mutation the hook issues
/// on another connection does not deadlock against an open reader).
///
/// Wrap a real <see cref="IMetadataStore"/>, assign <see cref="AfterRead"/>, and drive the repo
/// under test through this store: the hook commits the racing mutation + invalidation exactly
/// between the read and the cache write. Fails on the pre-guard code (stale value survives in the
/// cache), passes once each fill binds its cache entry to a generation token the invalidation cancels.
/// </summary>
public sealed class AfterDbReadHookStore(IMetadataStore inner) : IMetadataStore
{
    /// <summary>Fires once, in the window between the first DB read and the caller's cache write.</summary>
    public Func<Task>? AfterRead { get; set; }

    public DbProvider Provider => inner.Provider;

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = await inner.OpenAsync(ct);
        return new HookConnection(conn, this);
    }

    private async Task FireOnceAsync()
    {
        var hook = AfterRead;
        if (hook is null)
        {
            return;
        }

        AfterRead = null; // one-shot: later re-reads must not re-trigger the race
        await hook();
    }

    private sealed class HookConnection(DbConnection inner, AfterDbReadHookStore owner) : DbConnection
    {
        internal Task FireOnceAsync() => owner.FireOnceAsync();

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
        public override Task OpenAsync(CancellationToken ct) => inner.OpenAsync(ct);

        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) =>
            inner.BeginTransaction(isolationLevel);

        protected override DbCommand CreateDbCommand() => new HookCommand(inner.CreateCommand(), this);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync();
            await base.DisposeAsync();
            GC.SuppressFinalize(this);
        }
    }

    private sealed class HookCommand(DbCommand inner, HookConnection owner) : DbCommand
    {
        [AllowNull]
        public override string CommandText
        {
            get => inner.CommandText;
            set => inner.CommandText = value;
        }

        public override int CommandTimeout
        {
            get => inner.CommandTimeout;
            set => inner.CommandTimeout = value;
        }

        public override CommandType CommandType
        {
            get => inner.CommandType;
            set => inner.CommandType = value;
        }

        public override bool DesignTimeVisible
        {
            get => inner.DesignTimeVisible;
            set => inner.DesignTimeVisible = value;
        }

        public override UpdateRowSource UpdatedRowSource
        {
            get => inner.UpdatedRowSource;
            set => inner.UpdatedRowSource = value;
        }

        protected override DbConnection? DbConnection
        {
            get => owner;
            set { /* the inner command keeps its real connection */ }
        }

        protected override DbParameterCollection DbParameterCollection => inner.Parameters;

        protected override DbTransaction? DbTransaction
        {
            get => inner.Transaction;
            set => inner.Transaction = value;
        }

        public override void Cancel() => inner.Cancel();
        public override int ExecuteNonQuery() => inner.ExecuteNonQuery();
        public override object? ExecuteScalar() => inner.ExecuteScalar();
        public override void Prepare() => inner.Prepare();

        protected override DbParameter CreateDbParameter() => inner.CreateParameter();

        protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) =>
            new HookReader(inner.ExecuteReader(behavior), owner);

        protected override async Task<DbDataReader> ExecuteDbDataReaderAsync(
            CommandBehavior behavior, CancellationToken ct) =>
            new HookReader(await inner.ExecuteReaderAsync(behavior, ct), owner);

        public override Task<int> ExecuteNonQueryAsync(CancellationToken ct) =>
            inner.ExecuteNonQueryAsync(ct);

        public override async Task<object?> ExecuteScalarAsync(CancellationToken ct)
        {
            object? result = await inner.ExecuteScalarAsync(ct);
            await owner.FireOnceAsync();
            return result;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    // Wraps the real reader and fires the one-shot hook when the reader is disposed — i.e. after
    // a buffered QueryAsync has read every row and closed the reader, but before QueryAsync
    // returns to the repository (and therefore before its cache write).
    private sealed class HookReader(DbDataReader inner, HookConnection owner) : DbDataReader
    {
        public override object this[int ordinal] => inner[ordinal];
        public override object this[string name] => inner[name];
        public override int Depth => inner.Depth;
        public override int FieldCount => inner.FieldCount;
        public override bool HasRows => inner.HasRows;
        public override bool IsClosed => inner.IsClosed;
        public override int RecordsAffected => inner.RecordsAffected;

        public override bool GetBoolean(int ordinal) => inner.GetBoolean(ordinal);
        public override byte GetByte(int ordinal) => inner.GetByte(ordinal);
        public override long GetBytes(int ordinal, long dataOffset, byte[]? buffer, int bufferOffset, int length) =>
            inner.GetBytes(ordinal, dataOffset, buffer, bufferOffset, length);
        public override char GetChar(int ordinal) => inner.GetChar(ordinal);
        public override long GetChars(int ordinal, long dataOffset, char[]? buffer, int bufferOffset, int length) =>
            inner.GetChars(ordinal, dataOffset, buffer, bufferOffset, length);
        public override string GetDataTypeName(int ordinal) => inner.GetDataTypeName(ordinal);
        public override DateTime GetDateTime(int ordinal) => inner.GetDateTime(ordinal);
        public override decimal GetDecimal(int ordinal) => inner.GetDecimal(ordinal);
        public override double GetDouble(int ordinal) => inner.GetDouble(ordinal);
        public override Type GetFieldType(int ordinal) => inner.GetFieldType(ordinal);
        public override float GetFloat(int ordinal) => inner.GetFloat(ordinal);
        public override Guid GetGuid(int ordinal) => inner.GetGuid(ordinal);
        public override short GetInt16(int ordinal) => inner.GetInt16(ordinal);
        public override int GetInt32(int ordinal) => inner.GetInt32(ordinal);
        public override long GetInt64(int ordinal) => inner.GetInt64(ordinal);
        public override string GetName(int ordinal) => inner.GetName(ordinal);
        public override int GetOrdinal(string name) => inner.GetOrdinal(name);
        public override string GetString(int ordinal) => inner.GetString(ordinal);
        public override object GetValue(int ordinal) => inner.GetValue(ordinal);
        public override int GetValues(object[] values) => inner.GetValues(values);
        public override bool IsDBNull(int ordinal) => inner.IsDBNull(ordinal);
        public override bool NextResult() => inner.NextResult();
        public override bool Read() => inner.Read();
        public override System.Collections.IEnumerator GetEnumerator() => inner.GetEnumerator();

        public override void Close()
        {
            inner.Close();
            owner.FireOnceAsync().GetAwaiter().GetResult();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
                owner.FireOnceAsync().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync();
            await owner.FireOnceAsync();
            await base.DisposeAsync();
            GC.SuppressFinalize(this);
        }
    }
}
