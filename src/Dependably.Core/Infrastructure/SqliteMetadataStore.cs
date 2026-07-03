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
        // cache_size = -20000 sets the page cache to ~20 MB (negative value = KiB).
        // With WAL and private per-connection caches (Cache=Shared removed), each
        // connection benefits from its own warm page cache without shared-cache locking.
        await new SqliteCommand("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA cache_size = -20000", conn).ExecuteNonQueryAsync(ct);
        return conn;
    }
}
