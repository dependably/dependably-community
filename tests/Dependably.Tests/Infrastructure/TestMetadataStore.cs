using System.Data.Common;
using Dependably.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// In-memory SQLite metadata store for integration tests.
/// Uses a named shared-cache database so multiple connections see the same data.
/// Holds one permanent anchor connection to prevent the DB from being destroyed.
/// Every connection it opens records its write transactions in <see cref="LockDiagnostics"/>.
/// </summary>
public sealed class TestMetadataStore : IMetadataStore, IAsyncDisposable
{
    private readonly SqliteConnection _anchor;

    public TestMetadataStore()
    {
        string dbName = $"dependably_test_{Guid.NewGuid():N}";
        ConnectionString = $"Data Source={dbName};Mode=Memory;Cache=Shared";
        _anchor = new SqliteConnection(ConnectionString);
        _anchor.Open();
    }

    /// <summary>Hold times and owners of the write transactions on this database.</summary>
    public SqliteLockDiagnostics LockDiagnostics { get; } = new();

    public DbProvider Provider => DbProvider.Sqlite;

    /// <summary>
    /// The shared-cache connection string, so a test needing a second store against the same
    /// database — with its own busy timeout, for instance — can open one.
    /// </summary>
    public string ConnectionString { get; }

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = new TrackedSqliteConnection(ConnectionString, LockDiagnostics);
        await conn.OpenAsync(ct);
        LockDiagnostics.Attach(conn);
        return conn;
    }

    public async ValueTask DisposeAsync()
    {
        await _anchor.DisposeAsync();
    }
}
