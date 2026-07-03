using System.Data;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit;

public class SqliteMetadataStoreTests
{
    private static SqliteMetadataStore CreateStore()
    {
        string connStr = $"Data Source=sqlite_meta_test_{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        return new SqliteMetadataStore(connStr);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void Provider_ReturnsSqlite()
    {
        var store = CreateStore();
        Assert.Equal(DbProvider.Sqlite, store.Provider);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task OpenAsync_ReturnsOpenConnection_WithForeignKeysEnabled()
    {
        var store = CreateStore();
        await using var conn = await store.OpenAsync();

        Assert.Equal(ConnectionState.Open, conn.State);

        long fkEnabled = await conn.QuerySingleAsync<long>("PRAGMA foreign_keys");
        Assert.Equal(1L, fkEnabled);
    }

    // ── Connection pooling ──────────────────────────────────────────────────

    [Fact]
    [Trait("Category", "Unit")]
    public void BuildSqliteConnectionString_SetsPoolingExplicitly()
    {
        string connStr = StorageStartupExtensions.BuildSqliteConnectionString("/data/dependably.db");

        var parsed = new SqliteConnectionStringBuilder(connStr);
        Assert.True(parsed.Pooling);
        Assert.Equal("/data/dependably.db", parsed.DataSource);
        Assert.Equal(SqliteOpenMode.ReadWriteCreate, parsed.Mode);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task OpenAsync_WithPoolingExplicit_StillAppliesPragmasOnEveryOpen()
    {
        // A file-backed (not :memory:) data source so the native connection is actually
        // eligible for Microsoft.Data.Sqlite's connection pool rather than a private
        // in-memory database that only one connection can ever see.
        string dbFile = Path.Combine(Path.GetTempPath(), $"dependably_pool_test_{Guid.NewGuid():N}.db");
        string connStr = StorageStartupExtensions.BuildSqliteConnectionString(dbFile);
        var store = new SqliteMetadataStore(connStr);

        try
        {
            // Open/close twice — with pooling on, the second OpenAsync may reuse a pooled
            // native handle. SqliteMetadataStore.OpenAsync re-issues its PRAGMA statement on
            // every call regardless, so both connections must still see foreign_keys=ON and
            // the configured busy_timeout — pooling never causes a pragma to fall through.
            await using (var first = await store.OpenAsync())
            {
                Assert.Equal(1L, await first.QuerySingleAsync<long>("PRAGMA foreign_keys"));
                Assert.Equal(5000L, await first.QuerySingleAsync<long>("PRAGMA busy_timeout"));
            }

            await using var second = await store.OpenAsync();
            Assert.Equal(1L, await second.QuerySingleAsync<long>("PRAGMA foreign_keys"));
            Assert.Equal(5000L, await second.QuerySingleAsync<long>("PRAGMA busy_timeout"));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(dbFile);
        }
    }
}
