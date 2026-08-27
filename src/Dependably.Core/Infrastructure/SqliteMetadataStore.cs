using System.Data.Common;
using Microsoft.Data.Sqlite;

namespace Dependably.Infrastructure;

public sealed class SqliteMetadataStore : IMetadataStore
{
    private readonly string _connectionString;

    public SqliteMetadataStore(string connectionString) => _connectionString = connectionString;

    public DbProvider Provider => DbProvider.Sqlite;

    /// <summary>
    /// Opens a connection and applies the per-connection PRAGMAs. Both native objects this
    /// creates — the <c>sqlite3</c> handle and the PRAGMA statement — are released on the way
    /// out of this method on every path, including a failure part-way through.
    /// <para>
    /// The PRAGMA command is disposed rather than abandoned because a <see cref="SqliteCommand"/>
    /// owns prepared <c>sqlite3_stmt</c> handles. An abandoned command leaves those to the GC and
    /// the finalizer thread, so their lifetime stops being bounded by the scope that created them
    /// — which is not a property worth having for unmanaged state on a path that runs on every
    /// single connection open. Likewise, a connection whose PRAGMA step throws was previously
    /// returned to no one and closed by nothing.
    /// </para>
    /// </summary>
    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = new SqliteConnection(_connectionString);
        try
        {
            await conn.OpenAsync(ct);
            // cache_size = -20000 sets the page cache to ~20 MB (negative value = KiB).
            // With WAL and private per-connection caches (Cache=Shared removed), each
            // connection benefits from its own warm page cache without shared-cache locking.
            await using var pragmas = conn.CreateCommand();
            pragmas.CommandText = "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA cache_size = -20000";
            await pragmas.ExecuteNonQueryAsync(ct);
        }
        catch
        {
            await conn.DisposeAsync();
            throw;
        }

        return conn;
    }
}
