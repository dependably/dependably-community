using System.Data.Common;
using Microsoft.Data.Sqlite;

namespace Dependably.Infrastructure;

public sealed class SqliteMetadataStore : IMetadataStore
{
    private readonly string _connectionString;

    public SqliteMetadataStore(string connectionString) => _connectionString = connectionString;

    public DbProvider Provider => DbProvider.Sqlite;

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct);
        await new SqliteCommand("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000", conn).ExecuteNonQueryAsync(ct);
        return conn;
    }
}
