using System.Data.Common;
using Npgsql;

namespace Dependably.Infrastructure;

public sealed class NpgsqlMetadataStore : IMetadataStore
{
    private readonly string _connectionString;

    public NpgsqlMetadataStore(string connectionString) => _connectionString = connectionString;

    public DbProvider Provider => DbProvider.Postgres;

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = new NpgsqlConnection(_connectionString);
        await conn.OpenAsync(ct);
        return conn;
    }
}
