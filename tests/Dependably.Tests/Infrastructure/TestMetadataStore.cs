using System.Data.Common;
using Dependably.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// In-memory SQLite metadata store for integration tests.
/// Uses a named shared-cache database so multiple connections see the same data.
/// Holds one permanent anchor connection to prevent the DB from being destroyed.
/// </summary>
public sealed class TestMetadataStore : IMetadataStore, IAsyncDisposable
{
    private readonly string _connectionString;
    private readonly SqliteConnection _anchor;

    public TestMetadataStore()
    {
        string dbName = $"dependably_test_{Guid.NewGuid():N}";
        _connectionString = $"Data Source={dbName};Mode=Memory;Cache=Shared";
        _anchor = new SqliteConnection(_connectionString);
        _anchor.Open();
    }

    public DbProvider Provider => DbProvider.Sqlite;

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct);
        return conn;
    }

    public async ValueTask DisposeAsync()
    {
        await _anchor.DisposeAsync();
    }
}
